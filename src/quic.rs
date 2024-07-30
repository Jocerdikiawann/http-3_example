use quiche::h3::NameValue;

pub enum TypeQuic {
    Server,
    Client,
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

pub fn make_quic_config(type_config: TypeQuic) -> quiche::Config {
    const MAX_DATAGRAM_SIZE: usize = 1350;
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
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
    config.enable_early_data();
    config.set_cc_algorithm_name("cubic").unwrap();

    match type_config {
        TypeQuic::Server => {
            config.set_initial_congestion_window_packets(usize::try_from(10).unwrap());
            config.enable_pacing(true);
            config.set_cc_algorithm_name("cubic").unwrap();
        }
        TypeQuic::Client => {
            config.verify_peer(false);
            config.grease(true);
        }
    }

    config
}

pub fn handle_client_get_response(
    http_conn: &mut quiche::h3::Connection,
    quic_conn: &mut quiche::Connection,
    buf: &mut [u8],
) {
    loop {
        match http_conn.poll(quic_conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, has_body })) => {
                let status = list.iter().find(|h| h.name() == b":status").unwrap();
                info!(
                    "received {} response on stream {}",
                    std::str::from_utf8(status.value()).unwrap(),
                    stream_id
                );
            }
            Ok((stream_id, quiche::h3::Event::Data)) => {
                while let Ok(read) = http_conn.recv_body(quic_conn, stream_id, buf) {
                    info!("Received {} bytes of payload on stream {}", read, stream_id);
                }
            }
            Ok(_) => todo!(),
            Err(quiche::h3::Error::Done) => {
                break;
            }
            Err(e) => {
                error!("http3 poll failed: {:?}", e);
                break;
            }
        }
    }
}

pub fn handle_server_send_responses(
    http_conn: &mut quiche::h3::Connection,
    quic_conn: &mut quiche::Connection,
) {
    loop {
        match http_conn.poll(quic_conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                info!(
                    "got response headers {:?} on stream {}",
                    hdrs_to_strings(&list),
                    stream_id
                );

                let mut headers = list.into_iter();
                let method = headers.find(|h| h.name() == b":method").unwrap();
                let path = headers.find(|h| h.name() == b":path").unwrap();

                if method.value() == b"GET" && path.value() == b"/" {
                    let resp = vec![
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"server", b"quiche"),
                    ];
                    http_conn
                        .send_response(quic_conn, stream_id, &resp, false)
                        .unwrap();
                    http_conn
                        .send_body(quic_conn, stream_id, b"Hello response", true)
                        .unwrap();
                }
            }
            Ok(_) => todo!(),
            Err(quiche::h3::Error::Done) => {
                break;
            }
            Err(e) => {
                error!("http3 poll failed: {:?}", e);
                break;
            }
        }
    }
}
