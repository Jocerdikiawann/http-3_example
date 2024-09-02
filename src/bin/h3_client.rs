use core::panic;
use std::net::SocketAddr;

use learn_h3_rust::quic::{handle_client_get_response, make_quic_config, TypeQuic};
use log::{error, info, trace, warn};
use quiche::h3::Connection;

fn main() {
    const SCID: quiche::ConnectionId<'static> =
        quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
    const MAX_DATAGRAM_SIZE: usize = 1350;
    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut buf = [0; 65535];

    let mut config: quiche::Config = make_quic_config(TypeQuic::Client);

    let h3_config = quiche::h3::Config::new().unwrap();

    let from: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let to: SocketAddr = "127.0.0.1:3344".parse().unwrap();

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);
    let mut socket = mio::net::UdpSocket::bind("0.0.0.0:1234".parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let mut quic_conn = quiche::connect(Some("quiche.tech"), &SCID, to, from, &mut config).unwrap();
    let mut h3_conn: Option<Connection> = None;

    let (write, send_info) = quic_conn.send(&mut out).expect("initial send failed");
    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            warn!(
                "{}->{}: send() would block",
                socket.local_addr().unwrap(),
                send_info.to
            );
            continue;
        }
        error!("send() failed: {e:?}");
        return;
    }

    let app_data_start = std::time::Instant::now();

    loop {
        if !quic_conn.is_in_early_data() {
            poll.poll(&mut events, quic_conn.timeout()).unwrap();
        }

        if events.is_empty() {
            quic_conn.timeout();
        }

        for event in &events {
            let socket = match event.token() {
                mio::Token(0) => &socket,
                _ => unreachable!("unexpected token"),
            };
            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            warn!("{}: recv() would block", local_addr);
                            break 'read;
                        }
                        panic!("{}: recv() failed: {:?}", local_addr, e);
                    }
                };

                trace!("{}: got {} bytes", local_addr, len);

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                let read = match quic_conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
                    }
                };

                trace!("{}: processed {} bytes", local_addr, read);
            }
        }

        if quic_conn.is_closed() {
            info!("{:?}, connection closed", quic_conn.stats());

            if !quic_conn.is_established() {
                panic!("connection timed out, Handshake Fail");
            }

            break;
        }

        if quic_conn.is_established() {
            h3_conn =
                Some(quiche::h3::Connection::with_transport(&mut quic_conn, &h3_config).unwrap());
        }

        //if we have a h3 connection, send requests and responses
        if let Some(h_conn) = &mut h3_conn {
            let req = vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"quiche.tech"),
                quiche::h3::Header::new(b":path", b"/"),
                quiche::h3::Header::new(b"user-agent", b"quiche"),
            ];

            //Set fin false if you want send body()
            let stream_id = h_conn.send_request(&mut quic_conn, &req, false).unwrap();
            h_conn
                .send_body(&mut quic_conn, stream_id, b"hello body", true)
                .unwrap();

            handle_client_get_response(h_conn, &mut quic_conn, &mut buf);
        }

        if quic_conn.is_closed() {
            info!("{:?}, connection closed", quic_conn.stats());
            if !quic_conn.is_established() {
                error!("connection timed out after {:?}", app_data_start.elapsed())
            }
            break;
        }
    }
}
