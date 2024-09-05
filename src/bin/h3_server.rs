use quiche::h3::NameValue;

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

    //infinite loop to keep the server running
    loop {
        poll.poll(&mut events, None).unwrap();

        let (read, from) = socket.recv_from(&mut buf).unwrap();
        let recv_info = quiche::RecvInfo { from, to };

        let mut quic_conn = quiche::accept(&SCID, None, to, from, &mut config).unwrap();
        let mut h3_conn =
            quiche::h3::Connection::with_transport(&mut quic_conn, &h3_config).unwrap();

        //Receive quic packet
        match quic_conn.recv(&mut buf[..read], recv_info) {
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

        if quic_conn.is_established() {
            loop {
                match h3_conn.poll(&mut quic_conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, has_body })) => {
                        trace!("got request headers {:?} has body {} ", list, has_body);
                        let mut headers = list.into_iter();
                        let method = headers.find(|h| h.name() == b":method").unwrap();
                        let path = headers.find(|h| h.name() == b":path").unwrap();

                        if method.value() == b"GET" && path.value() == b"/" {
                            let resp_headers = vec![
                                quiche::h3::Header::new(b":status", b"200"),
                                quiche::h3::Header::new(b"server", b"quiche"),
                            ];

                            h3_conn
                                .send_response(&mut quic_conn, stream_id, &resp_headers, false)
                                .unwrap();

                            h3_conn
                                .send_body(&mut quic_conn, stream_id, b"hello from server", true)
                                .unwrap();
                        }
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => {
                        trace!("Done reading");
                        break;
                    }
                    Err(e) => {
                        eprintln!("h3_conn.poll failed: {:?}", e);
                        return;
                    }
                }
            }
        }

        while let Ok((write, send_info)) = quic_conn.send(&mut out) {
            socket.send_to(&out[..write], send_info.to).unwrap();
        }
    }
}
