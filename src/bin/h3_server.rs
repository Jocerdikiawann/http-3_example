use std::{cell::RefCell, collections::HashMap, io, rc::Rc};

use learn_h3_rust::{
    common::{
        generate_cid_and_reset_token, make_qlog_writer, std_outsink, Client, ClientId, HttpConn,
    },
    sendto_gs::{detect_gso, send_to},
};
use quiche::{ConnectionId, SendInfo};
use ring::rand::SystemRandom;

const MAX_BUF_SIZE: usize = 65507;
const MAX_DATAGRAM_SIZE: usize = 1305;

pub type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
pub type ClientMap = HashMap<ClientId, Client>;

fn main() {
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut pacing = false;

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut socket = mio::net::UdpSocket::bind("127.0.0.1:4433".parse().unwrap()).unwrap();

    //Pacing
    match set_txtime_sockopt(&socket) {
        Ok(_) => {
            pacing = true;
            println!("successfully set SO_TXTTIME socket option");
        }
        Err(e) => println!("setsockopt failed: {:?}", e),
    }

    println!("Listening on {}", socket.local_addr().unwrap());

    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let max_datagram_size = MAX_DATAGRAM_SIZE;
    let enabale_gso = detect_gso(&socket, max_datagram_size);
    println!("GSO detected: {}", enabale_gso);

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.load_cert_chain_from_pem_file("cert.crt").unwrap();
    config.load_priv_key_from_pem_file("cert.key").unwrap();
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.discover_pmtu(false);
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(max_datagram_size);
    config.set_max_send_udp_payload_size(max_datagram_size);
    config.set_initial_max_data(10000000);
    config.set_initial_max_stream_data_bidi_local(10000000);
    config.set_initial_max_stream_data_bidi_remote(10000000);
    config.set_initial_max_stream_data_uni(10000000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(2);

    config.set_max_connection_window(16777216);
    config.set_max_stream_window(25165824);

    let mut keylog = None;
    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(keylog_path)
            .unwrap();
        keylog = Some(file);
        config.log_keys();
    }

    config.set_cc_algorithm_name(&"cubic".to_string()).unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
    let mut next_client_id = 0;
    let mut clients_ids = ClientIdMap::new();
    let mut clients = ClientMap::new();

    let mut continue_write = false;
    let local_addr = socket.local_addr().unwrap();

    loop {
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),
            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };

        poll.poll(&mut events, timeout).unwrap();

        'read: loop {
            if events.is_empty() && !continue_write {
                println!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        println!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                }
            };

            println!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,
                Err(e) => {
                    println!("Parsing header failed: {:?}", e);
                    continue 'read;
                }
            };

            println!("got packet {:?}", hdr);

            let conn_id: ConnectionId<'static> = if !cfg!(feature = "fuzzing") {
                let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                conn_id.to_vec().into()
            } else {
                [0; quiche::MAX_CONN_ID_LEN].to_vec().into()
            };

            let client = if !clients_ids.contains_key(&hdr.dcid)
                && !clients_ids.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    print!("packet is not initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    print!("Doing version negotiation");
                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();
                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("send() would block");
                            break;
                        }

                        println!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let odcid: Option<ConnectionId> = None;

                //TODO: if want use retry todo generate token
                //let token = hdr.token.as_ref().unwrap();
                //if token.is_empty() {
                //println!("Doing statless retry");
                //let scid = quiche::ConnectionId::from_ref(&scid);
                //let new_token = generate_token(&hdr, &from);
                //}

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());
                println!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn =
                    quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut config).unwrap();

                if let Some(keylog) = &mut keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                #[cfg(feature = "qlog")]
                {
                    if let Some(dir) = std::env::var_os("QLOG_DIR") {
                        let id = format!("{:?}", &scid);

                        let writer = make_qlog_writer(&dir, "server", &id);

                        conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                let client_id = next_client_id;

                let client = Client {
                    conn,
                    http3_conn: None,
                    client_id,
                    partial_request: HashMap::new(),
                    partial_response: HashMap::new(),
                    max_datagram_size,
                    loss_rate: 0.0,
                    max_send_burst: MAX_BUF_SIZE,
                };

                clients.insert(client_id, client);
                clients_ids.insert(scid.clone(), client_id);

                next_client_id += 1;
                clients.get_mut(&client_id).unwrap()
            } else {
                let cid = match clients_ids.get(&hdr.dcid) {
                    Some(v) => v,
                    None => clients_ids.get(&conn_id).unwrap(),
                };
                clients.get_mut(cid).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,
                Err(e) => {
                    println!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                }
            };

            println!("{} processed {} bytes", client.conn.trace_id(), read);

            if client.conn.is_in_early_data() || client.conn.is_established() {
                client.http3_conn = match HttpConn::with_conn(
                    &mut client.conn,
                    None,
                    None,
                    None,
                    None,
                    Rc::new(RefCell::new(std_outsink)),
                ) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        println!("{} {}", client.conn.trace_id(), e);
                        None
                    }
                };

                client.max_datagram_size = client.conn.max_send_udp_payload_size();
            }

            if client.http3_conn.is_some() {
                let conn = &mut client.conn;
                let http_conn = client.http3_conn.as_mut().unwrap();
                let partial_response = &mut client.partial_response;

                for stream_id in conn.writable() {
                    http_conn.handle_writable(conn, partial_response, stream_id);
                }

                if http_conn
                    .handle_requests(
                        conn,
                        &mut client.partial_request,
                        partial_response,
                        &mut buf,
                    )
                    .is_err()
                {
                    continue 'read;
                }
            }

            handle_path_events(client);

            while let Some(retired_scid) = client.conn.retired_scid_next() {
                println!("Retiring sourc CID {:?}", retired_scid);

                clients_ids.remove(&retired_scid);
            }

            while client.conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                if client.conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }

                clients_ids.insert(scid, client.client_id);
            }
        }

        continue_write = false;

        for client in clients.values_mut() {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let loss_rate = client.conn.stats().lost as f64 / client.conn.stats().sent as f64;

            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                client.max_send_burst = client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_send_burst = client.conn.send_quantum().min(client.max_send_burst)
                / client.max_datagram_size
                * client.max_datagram_size;
            let mut total_write = 0;
            let mut dst_info: Option<SendInfo> = None;

            while total_write < max_send_burst {
                let (write, send_info) =
                    match client.conn.send(&mut out[total_write..max_send_burst]) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            println!("{} done writing", client.conn.trace_id());
                            break;
                        }
                        Err(e) => {
                            println!("{} send failed {:?}", client.conn.trace_id(), e);

                            client.conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };

                total_write += write;
                let _ = dst_info.get_or_insert(send_info);

                if write < client.max_datagram_size {
                    continue_write = true;
                    break;
                }
            }

            if let Err(e) = send_to(
                &socket,
                &out[..total_write],
                &dst_info.unwrap(),
                client.max_datagram_size,
                pacing,
                enabale_gso,
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    println!("send() would block");
                    break;
                }

                panic!("send_to() failed: {:?}", e);
            }

            println!("{} written {} bytes", client.conn.trace_id(), total_write);

            if total_write >= max_send_burst {
                println!("{} pause writing", client.conn.trace_id());
                continue_write = true;
                break;
            }
        }

        //Garbage collect closed connections
        clients.retain(|_, ref mut c| {
            println!("Collecting garbage");

            if c.conn.is_closed() {
                println!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );

                for id in c.conn.source_ids() {
                    let id_owned = id.clone().into_owned();
                    clients_ids.remove(&id_owned);
                }
            }

            !c.conn.is_closed()
        });
    }
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                println!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .expect("cannot probe");
            }

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                println!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                println!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::Closed(local_addr, peer_addr) => {
                println!(
                    "{} Path ({}, {}) is now closed and unusable",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                println!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            }

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                println!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            }
        }
    }
}

/// Set SO_TXTIME socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option is set only on linux platforms.
#[cfg(target_os = "linux")]
fn set_txtime_sockopt(sock: &mio::net::UdpSocket) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;
    use std::os::unix::io::AsRawFd;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    // mio::net::UdpSocket doesn't implement AsFd (yet?).
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(sock.as_raw_fd()) };

    setsockopt(&fd, TxTime, &config)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_txtime_sockopt(_: &mio::net::UdpSocket) -> io::Result<()> {
    use std::io::Error;
    use std::io::ErrorKind;

    Err(Error::new(
        ErrorKind::Other,
        "Not supported on this platform",
    ))
}
