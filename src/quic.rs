pub struct QuicConnection {}
pub enum TypeQuic {
    Server,
    Client,
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
