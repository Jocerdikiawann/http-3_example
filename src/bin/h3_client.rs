#[macro_use]
extern crate log;

use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
    str::FromStr,
};

use learn_h3_rust::common::{
    generate_cid_and_reset_token, make_qlog_writer, std_outsink, HttpConn,
};
use ring::rand::{SecureRandom, SystemRandom};

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

pub fn connect(output_sink: impl FnMut(String) + 'static) -> Result<(), ClientError> {
    env_logger::builder().format_timestamp_nanos().init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let output_sink = Rc::new(RefCell::new(output_sink)) as Rc<RefCell<dyn FnMut(_)>>;
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024); //1mb
    let peer_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433);

    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", 0),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", 0),
    };

    let connect_url = &url::Url::from_str("https://localhost:4433/data").unwrap();
    println!("Connecting to {} from {}\n", peer_addr, bind_addr);
    let mut socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    //config.verify_peer(false);
    config
        .load_verify_locations_from_file(
            "/home/cexup/Documents/Work/rust/learn_h3_rust/src/bin/cert.crt",
        )
        .map_err(|e| ClientError::Other(format!("error loading origin CA file : {}", e)))
        .unwrap();

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10000000);
    config.set_initial_max_stream_data_bidi_local(1000000);
    config.set_initial_max_stream_data_bidi_remote(1000000);
    config.set_initial_max_stream_data_uni(1000000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(2);
    config.set_max_connection_window(25165824);
    config.set_max_stream_window(16777216);

    let mut keylog = None;

    if let Some(keylog_pat) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_pat)
            .unwrap();

        keylog = Some(file);
        config.log_keys();
    }

    config.grease(true);
    config.enable_early_data();
    config.set_cc_algorithm_name("cubic").unwrap();
    //config.enable_hystart(true);
    //config.enable_dgram(true, 1000, 1000);

    let mut http_conn: Option<Box<HttpConn>> = None;
    let mut app_proto_selected = false;

    //Generate a random source connection ID for the connection.
    let rng = SystemRandom::new();

    let scid: Vec<u8> = if !cfg!(feature = "fuzzing") {
        let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
        rng.fill(&mut conn_id[..]).unwrap();

        conn_id.to_vec()
    } else {
        //When fuzzing use an all zero CID
        [0; quiche::MAX_CONN_ID_LEN].to_vec()
    };

    let scid = quiche::ConnectionId::from_ref(&scid);
    let local_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        connect_url.domain(),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog))
        }
    }

    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("{scid:?}");
            let writer = make_qlog_writer(&dir, "client", &id);
            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            )
        }
    }

    //TODO: handle session

    info!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addr,
        socket.local_addr().unwrap(),
        scid
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            trace!(
                "{} -> {}: send_to() would block",
                socket.local_addr().unwrap(),
                send_info.to
            );
            continue;
        }

        return Err(ClientError::Other(format!("send_to() failed: {:?}", e)));
    }

    trace!("written {}", write);

    let app_data_start = std::time::Instant::now();
    let mut migrated = false;

    loop {
        if !conn.is_in_early_data() || app_proto_selected {
            poll.poll(&mut events, conn.timeout()).unwrap();
        }

        if events.is_empty() {
            trace!("timed out");
            conn.on_timeout();
        }

        //Read incoming UDP packet from the socket.
        for event in &events {
            let socket = match event.token() {
                mio::Token(0) => &socket,
                mio::Token(1) => None.as_ref().unwrap(),
                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("{} -> {}: recv_from() would block", local_addr, peer_addr);
                            break 'read;
                        }

                        return Err(ClientError::Other(format!(
                            "{local_addr}: recv_from() failed: {e}"
                        )));
                    }
                };
                trace!("{}: got {} bytes", local_addr, len);

                //pkt_count += 1;
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
                    }
                };

                trace!("{}: processed {} bytes", local_addr, read);
            }
        }

        trace!("done reading");

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!("connection timed out after {:?}", app_data_start.elapsed());
                return Err(ClientError::HandshakeFail);
            }

            //TODO: Session file

            if let Some(h_conn) = &http_conn {
                if h_conn.report_incomplete(&app_data_start) {
                    return Err(ClientError::HttpFail);
                }
            }

            break;
        }

        if (conn.is_established() || conn.is_in_early_data()) && migrated && !app_proto_selected {
            info!("connection established");
            //TODO: u can send datagram here

            http_conn = Some(HttpConn::with_url(
                &mut conn,
                &[connect_url.clone()],
                &[],
                &None,
                &"GET".to_string(),
                false,
                None,
                None,
                None,
                None,
                Rc::clone(&output_sink),
            ));

            app_proto_selected = true;
        }

        if let Some(h_conn) = http_conn.as_mut() {
            h_conn.send_request(&mut conn);
            h_conn.handle_response(&mut conn, &mut buf, &app_data_start);
        }

        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(..) => unreachable!(),
                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!("{} -> {}: path validated", local_addr, peer_addr);
                    conn.migrate(local_addr, peer_addr).unwrap();
                    migrated = true;
                }
                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!("{} -> {}: path validation failed", local_addr, peer_addr);
                }
                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    info!("{} -> {}: path closed", local_addr, peer_addr);
                }
                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    info!(
                        "reusing scid {} -> initialy {:?} on {:?}",
                        cid_seq, old, new
                    );
                }
                quiche::PathEvent::PeerMigrated(..) => unreachable!(),
            }
        }

        while let Some(retired_scid) = conn.retired_scid_next() {
            info!("retired scid {:?}", retired_scid);
        }

        while conn.scids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);
            if conn.new_scid(&scid, reset_token, false).is_err() {
                break;
            }
        }

        let sockets = vec![&socket];
        for socket in sockets {
            let local_addr = socket.local_addr().unwrap();

            for peer_addr in conn.paths_iter(local_addr) {
                loop {
                    let (write, send_info) =
                        match conn.send_on_path(&mut out, Some(local_addr), Some(peer_addr)) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => {
                                trace!("{} -> {}: done writing", local_addr, peer_addr);
                                break;
                            }
                            Err(e) => {
                                error!("{} -> {}: send failed: {:?}", local_addr, peer_addr, e);
                                conn.close(false, 0x1, b"fail").ok();
                                break;
                            }
                        };

                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("{} -> {}: send_to() would block", local_addr, send_info.to);
                            continue;
                        }

                        return Err(ClientError::Other(format!(
                            "{}-> {}: send_to() failed: {:?}",
                            local_addr, peer_addr, e
                        )));
                    }

                    trace!("{} -> {}: written {}", local_addr, send_info.to, write);
                }
            }
        }

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!("connection timed out after {:?}", app_data_start.elapsed());
                return Err(ClientError::HandshakeFail);
            }

            if let Some(h_conn) = http_conn {
                if h_conn.report_incomplete(&app_data_start) {
                    return Err(ClientError::HttpFail);
                }
            }

            break;
        }
    }

    Ok(())
}

fn main() {
    match connect(std_outsink) {
        Err(ClientError::HandshakeFail) => std::process::exit(-1),

        Err(ClientError::HttpFail) => std::process::exit(-2),

        Err(ClientError::Other(e)) => panic!("{}", e),

        Ok(_) => (),
    }
}
