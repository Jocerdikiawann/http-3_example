use std::net::SocketAddr;

use learn_h3_rust::quic::{make_quic_config, TypeQuic};
use log::trace;

fn main() {
    const SCID: quiche::ConnectionId<'static> =
        quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
    const MAX_DATAGRAM_SIZE: usize = 1350;
    let mut out = [0; MAX_DATAGRAM_SIZE];
    let mut buf = [0; 65535];

    let mut config: quiche::Config = make_quic_config(TypeQuic::Server);

    let h3_config = quiche::h3::Config::new().unwrap();

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);
    let mut socket = mio::net::UdpSocket::bind("0.0.0.0:1234".parse().unwrap()).unwrap();

    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let to = socket.local_addr().unwrap();


    let quic_conn = quiche::accept(&SCID, None, to, from, &mut config).unwrap();
    let h3_conn = quiche::h3::Connection::with_transport(quic_conn, h3_config).unwrap();

    'h3_recv: loop {
        match h3_conn.poll(&mut out) {
            Ok((stream_id, quiche::h3::Event::Headers{list, has_body}) => {
                trace!("got headers on stream {}", stream_id);
                let mut header = list.into_iter();
                
                let method = header.find(|h| h.name() == ":method").unwrap().value();
                let path = header.find(|h| h.name() == ":path").unwrap().value();

                if method != "GET" && path.value() != "/" {
                    let resp = vec![
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"server", b"quiche"),
                    ];
                    
                    h3_conn.send_response(&mut conn, stream_id, &resp, true).unwrap();
                    h3_conn.send_body(&mut conn, stream_id, b"Hello response", true).unwrap();
                }
            }


        }
    }


    loop {
        let (read, from) = match socket.recv_from(&mut buf).unwrap();
        let recv_info = quiche::RecvInfo { from, to };

        let read = match quic_conn.recv(&mut buf[..read], recv_info) {
            Ok(v) => v,
            Err(quiche::Error::Done) => {
                trace!("Done reading");
                break;
            }
            Err(e) => {
                eprintln!("recv failed: {:?}", e);
                return;
            }
        };

    }


}
