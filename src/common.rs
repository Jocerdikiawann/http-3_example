/*
TODO: Process Response, Process Request, Process Headers,
TODO: Process Body (Only JSON), Process Datagram
*/

use std::collections::HashMap;

#[cfg(feature = "sfv")]
use std::convert::TryFrom;

use std::fmt::Write as _;

use std::rc::Rc;

use std::cell::RefCell;

use quiche::h3::NameValue;
use quiche::h3::Priority;

const H3_MESSAGE_ERROR: u64 = 0x10E;

//Alias
pub type ClientId = u64;
type HttpResponseBuilderResult =
    std::result::Result<(Vec<quiche::h3::Header>, Vec<u8>, Vec<u8>), (u64, String)>;

pub struct PartialRequest {
    pub request: Vec<u8>,
}

pub struct PartialResponse {
    pub headers: Option<Vec<quiche::h3::Header>>,
    pub priority: Option<quiche::h3::Priority>,
    pub body: Vec<u8>,
    pub written: usize,
}

pub struct Client {
    pub conn: quiche::Connection,
    pub http3_conn: Option<Box<HttpConn>>,
    pub client_id: ClientId,
    pub partial_request: std::collections::HashMap<u64, PartialRequest>,
    pub partial_response: std::collections::HashMap<u64, PartialResponse>,
    pub max_datagram_size: usize,
    pub loss_rate: f64,
    pub max_send_burst: usize,
}

pub struct Http3DgramSender {
    dgram_count: u64,
    pub dgram_content: String,
    pub flow_id: u64,
    pub dgrams_sent: u64,
}

pub struct HttpRequest {
    url: url::Url,
    stream_id: Option<u64>,
    headers: Vec<quiche::h3::Header>,
    priority: Option<Priority>,
    response_headers: Vec<quiche::h3::Header>,
    response_body: Vec<u8>,
    response_body_max: usize,
}

pub struct HttpConn {
    h3_conn: quiche::h3::Connection,
    reqs_headers_sent: usize,
    reqs_complete: usize,
    largest_processed_request: u64,
    reqs: Vec<HttpRequest>,
    body: Option<Vec<u8>>,
    sent_body_bytes: HashMap<u64, usize>,
    dgram_sender: Option<Http3DgramSender>,
    output_sink: Rc<RefCell<dyn FnMut(String)>>,
    dump_json: bool,
}

pub fn std_outsink(out: String) {
    println!("{}", out);
}

pub fn hdrs_to_string(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();
            (name, value)
        })
        .collect()
}

fn dump_json(reqs: &[HttpRequest], output_sink: &mut dyn FnMut(String)) {
    let mut out = String::new();

    writeln!(out, "{{").unwrap();
    writeln!(out, "  \"entries\": [").unwrap();
    let mut reqs = reqs.iter().peekable();

    while let Some(req) = reqs.next() {
        writeln!(out, "  {{").unwrap();
        writeln!(out, "    \"request\":{{").unwrap();
        writeln!(out, "      \"headers\":[").unwrap();

        let mut req_hdrs = req.headers.iter().peekable();
        while let Some(h) = req_hdrs.next() {
            writeln!(out, "        {{").unwrap();
            writeln!(
                out,
                "          \"name\": \"{}\",",
                std::str::from_utf8(h.name()).unwrap()
            )
            .unwrap();
            writeln!(
                out,
                "          \"value\": \"{}\"",
                std::str::from_utf8(h.value()).unwrap().replace('"', "\\\"")
            )
            .unwrap();

            if req_hdrs.peek().is_some() {
                writeln!(out, "        }},").unwrap();
            } else {
                writeln!(out, "        }}").unwrap();
            }
        }
        writeln!(out, "      ]}},").unwrap();

        writeln!(out, "    \"response\":{{").unwrap();
        writeln!(out, "      \"headers\":[").unwrap();

        let mut response_hdrs = req.response_headers.iter().peekable();
        while let Some(h) = response_hdrs.next() {
            writeln!(out, "        {{").unwrap();
            writeln!(
                out,
                "          \"name\": \"{}\",",
                std::str::from_utf8(h.name()).unwrap()
            )
            .unwrap();
            writeln!(
                out,
                "          \"value\": \"{}\"",
                std::str::from_utf8(h.value()).unwrap().replace('"', "\\\"")
            )
            .unwrap();

            if response_hdrs.peek().is_some() {
                writeln!(out, "        }},").unwrap();
            } else {
                writeln!(out, "        }}").unwrap();
            }
        }
        writeln!(out, "      ],").unwrap();
        writeln!(out, "      \"body\": {:?}", req.response_body).unwrap();
        writeln!(out, "    }}").unwrap();

        if reqs.peek().is_some() {
            writeln!(out, "}},").unwrap();
        } else {
            writeln!(out, "}}").unwrap();
        }
    }
    writeln!(out, "]").unwrap();
    writeln!(out, "}}").unwrap();

    output_sink(out);
}

pub fn make_qlog_writer(
    dir: &std::ffi::OsStr,
    role: &str,
    id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{role}-{id}.sqlog");
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),
        Err(e) => panic!(
            "Error creating qlog file attempted pat was {:?} : {}",
            path, e
        ),
    }
}

pub fn priority_from_query_string(url: &url::Url) -> Option<Priority> {
    let mut urgency = None;
    let mut incremental = None;
    for param in url.query_pairs() {
        //Means urgency
        if param.0 == "u" {
            urgency = Some(param.1.parse::<u8>().unwrap());
        }
        if param.0 == "i" && param.1 == "1" {
            incremental = Some(true);
        }
    }

    match (urgency, incremental) {
        (Some(u), Some(i)) => Some(quiche::h3::Priority::new(u, i)),
        (Some(u), None) => Some(Priority::new(u, false)),

        (None, Some(i)) => Some(Priority::new(3, i)),

        (None, None) => None,
    }
}

pub fn priority_from_value_from_query_string(url: &url::Url) -> Option<String> {
    let mut priority = "".to_string();
    for param in url.query_pairs() {
        if param.0 == "u" {
            write!(priority, "{}={}", param.0, param.1).ok();
        }

        if param.0 == "i" && param.1 == "1" {
            priority.push_str("i,");
        }
    }
    if !priority.is_empty() {
        priority.pop();
        Some(priority)
    } else {
        None
    }
}

fn make_h3_config(
    max_field_section_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
) -> quiche::h3::Config {
    let mut config = quiche::h3::Config::new().unwrap();

    if let Some(v) = max_field_section_size {
        config.set_max_field_section_size(v);
    }

    if let Some(qpack_max_table_capacity) = qpack_max_table_capacity {
        config.set_qpack_max_table_capacity(qpack_max_table_capacity.clamp(0, 0));
    }

    if let Some(qpack_blocked_streams) = qpack_blocked_streams {
        config.set_qpack_blocked_streams(qpack_blocked_streams.clamp(0, 0));
    }

    config
}

fn send_dgram(
    conn: &mut quiche::Connection,
    flow_id: u64,
    dgram_content: &[u8],
) -> quiche::Result<()> {
    println!(
        "sending HTTP/3 DATAGRAM on flow_id={} with data {:?}",
        flow_id, dgram_content
    );

    let len = octets::varint_len(flow_id) + dgram_content.len();
    let mut d = vec![0; len];
    let mut b = octets::OctetsMut::with_slice(&mut d);

    b.put_varint(flow_id)
        .map_err(|_| quiche::Error::BufferTooShort)?;
    b.put_bytes(dgram_content)
        .map_err(|_| quiche::Error::BufferTooShort)?;

    conn.dgram_send(&d)
}

/// Generate a new pair of Source Connection ID and reset token.
pub fn generate_cid_and_reset_token<T: ring::rand::SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

impl HttpConn {
    pub fn with_url(
        conn: &mut quiche::Connection,
        urls: &[url::Url],
        req_headers: &[String],
        body: &Option<Vec<u8>>,
        method: &str,
        send_priority_update: bool,
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        dgram_sender: Option<Http3DgramSender>,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> Box<Self> {
        //U can loop request if u want
        let mut request = Vec::new();
        for url in urls {
            let authority = match url.port() {
                Some(port) => format!("{}:{}", url.host_str().unwrap(), port),
                None => url.host_str().unwrap().to_string(),
            };
            let mut headers = vec![
                quiche::h3::Header::new(b":method", method.as_bytes()),
                quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
                quiche::h3::Header::new(b":authority", authority.as_bytes()),
                quiche::h3::Header::new(b":path", url[url::Position::BeforePath..].as_bytes()),
                quiche::h3::Header::new(b"user-agent", b"quiche"),
            ];

            let priority = if send_priority_update {
                priority_from_query_string(&url)
            } else {
                None
            };

            for header in req_headers {
                let header_split: Vec<&str> = header.splitn(2, ": ").collect();
                if header_split.len() != 2 {
                    panic!("Malformed header provided: \"{}\"", header);
                }
                headers.push(quiche::h3::Header::new(
                    header_split[0].as_bytes(),
                    header_split[1].as_bytes(),
                ));
            }

            if body.is_some() {
                headers.push(quiche::h3::Header::new(
                    b"content-length",
                    body.as_ref().unwrap().len().to_string().as_bytes(),
                ));
            }

            request.push(HttpRequest {
                url: url.clone(),
                headers,
                priority,
                response_headers: Vec::new(),
                response_body: Vec::new(),
                response_body_max: 100000000000000,
                stream_id: None,
            });
        }

        Box::new(HttpConn {
            h3_conn: quiche::h3::Connection::with_transport(
                conn,
                &make_h3_config(
                    max_field_section_size,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                ),
            )
            .expect("Unable to create HTTP/3 connection,  check the server's uni stream limit and window size"),
            reqs_headers_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs: request,
            body: body.as_ref().map(|b| b.to_vec()),
            sent_body_bytes: HashMap::new(),
            dgram_sender,
            output_sink,
            dump_json: true
        })
    }

    pub fn with_conn(
        conn: &mut quiche::Connection,
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        dgram_sender: Option<Http3DgramSender>,
        output_sink: Rc<RefCell<dyn FnMut(String)>>,
    ) -> std::result::Result<Box<HttpConn>, String> {
        let h3_conn = quiche::h3::Connection::with_transport(
            conn,
            &make_h3_config(
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            ),
        )
        .map_err(|_| "Unable to create HTTP/3 connection")?;

        Ok(Box::new(HttpConn {
            h3_conn,
            reqs_headers_sent: 0,
            reqs_complete: 0,
            largest_processed_request: 0,
            reqs: Vec::new(),
            body: None,
            sent_body_bytes: HashMap::new(),
            dgram_sender,
            output_sink,
            dump_json: false,
        }))
    }

    //Body Response h3
    //TODO: i think it's better handle on client
    pub fn build_h3_response(request: &[quiche::h3::Header]) -> HttpResponseBuilderResult {
        let mut scheme = None;
        let mut authority = None;
        let mut host = None;
        let mut path = None;
        let mut method = None;
        let mut priority = vec![];

        for header in request {
            match header.name() {
                b":scheme" => {
                    if scheme.is_some() {
                        return Err((H3_MESSAGE_ERROR, ":scheme cannot be duplicated".to_string()));
                    }

                    scheme = Some(std::str::from_utf8(header.value()).unwrap())
                }

                b":authority" => {
                    if authority.is_some() {
                        return Err((
                            H3_MESSAGE_ERROR,
                            ":authority cannot be duplicated".to_string(),
                        ));
                    }

                    authority = Some(std::str::from_utf8(header.value()).unwrap())
                }

                b":path" => {
                    if path.is_some() {
                        return Err((H3_MESSAGE_ERROR, ":path cannot be duplicated".to_string()));
                    }

                    path = Some(std::str::from_utf8(header.value()).unwrap())
                }

                b":method" => {
                    if method.is_some() {
                        return Err((H3_MESSAGE_ERROR, ":method cannot be duplicated".to_string()));
                    }

                    method = Some(std::str::from_utf8(header.value()).unwrap())
                }

                b":protocol" => {
                    return Err((H3_MESSAGE_ERROR, ":protocol is not allowed".to_string()))
                }

                b"priority" => priority = header.value().to_vec(),
                b"host" => host = Some(std::str::from_utf8(header.value()).unwrap()),
                _ => (),
            }
        }

        let dedicated_method = match method {
            Some(method) => match method {
                "" => {
                    return Err((
                        H3_MESSAGE_ERROR,
                        ":method value cannot be empty".to_string(),
                    ));
                }

                "CONNECT" => {
                    let headers = vec![
                        quiche::h3::Header::new(b":status", "405".to_string().as_bytes()),
                        quiche::h3::Header::new(b"server", b"quiche"),
                    ];

                    return Ok((headers, b"".to_vec(), Default::default()));
                }

                _ => method,
            },

            None => {
                return Err((H3_MESSAGE_ERROR, ":method value is required".to_string()));
            }
        };

        let dedicated_scheme = match scheme {
            Some(scheme) => {
                if scheme != "http" && scheme != "https" {
                    let headers = vec![
                        quiche::h3::Header::new(b":status", "400".to_string().as_bytes()),
                        quiche::h3::Header::new(b"server", b"quiche"),
                    ];

                    return Ok((headers, b"Invalid scheme".to_vec(), Default::default()));
                }

                scheme
            }

            None => {
                return Err((H3_MESSAGE_ERROR, ":scheme value is required".to_string()));
            }
        };

        let dedicated_host = match (authority, host) {
            (None, Some("")) => {
                return Err((H3_MESSAGE_ERROR, "host value is required".to_string()));
            }
            (Some(""), None) => {
                return Err((H3_MESSAGE_ERROR, ":authority value is required".to_string()));
            }
            (Some(""), Some("")) => {
                return Err((
                    H3_MESSAGE_ERROR,
                    ":authority and host values are required".to_string(),
                ));
            }
            (None, None) => {
                return Err((
                    H3_MESSAGE_ERROR,
                    ":authority and host values are required".to_string(),
                ));
            }
            (..) => authority.unwrap(),
        };

        let dedicated_path = match path {
            Some("") => {
                return Err((H3_MESSAGE_ERROR, ":path value is required".to_string()));
            }

            None => {
                return Err((H3_MESSAGE_ERROR, ":path value is required".to_string()));
            }
            Some(path) => path,
        };

        let url = format!(
            "{}://{}{}",
            dedicated_scheme, dedicated_host, dedicated_path
        );
        let url = url::Url::parse(&url).unwrap();

        let query_priority = priority_from_value_from_query_string(&url);
        if let Some(p) = query_priority {
            priority = p.as_bytes().to_vec();
        }

        println!("{} Path", url.path());

        //TODO: Process Response (Send back data)
        let (status, body) = match dedicated_method {
            "GET" => (200, b"data ada".to_vec()),
            _ => (405, Vec::new()),
        };

        let headers = vec![
            quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
            quiche::h3::Header::new(b"server", b"quiche"),
            quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        Ok((headers, body, priority))
    }

    //For client send request
    pub fn send_request(&mut self, conn: &mut quiche::Connection) {
        let mut reqs_done = 0;

        //Send Headers
        for req in self.reqs.iter_mut().skip(self.reqs_headers_sent) {
            let s = match self
                .h3_conn
                .send_request(conn, &req.headers, self.body.is_none())
            {
                Ok(v) => v,
                Err(quiche::h3::Error::TransportError(quiche::Error::StreamLimit)) => {
                    println!("not enough stream credits, retry later...");
                    break;
                }

                Err(quiche::h3::Error::StreamBlocked) => {
                    println!("stream blocked, retry later...");
                    break;
                }

                Err(e) => {
                    println!("failed to send request: {:?}", e);
                    break;
                }
            };

            println!("sent request: {:?}", &req.headers);
            if let Some(priority) = &req.priority {
                self.h3_conn
                    .send_priority_update_for_request(conn, s, priority)
                    .ok();
            }
            req.stream_id = Some(s);
            self.sent_body_bytes.insert(s, 0);
            reqs_done += 1;
        }

        self.reqs_headers_sent += reqs_done;
        if let Some(body) = &self.body {
            for (stream_id, sent_bytes) in self.sent_body_bytes.iter_mut() {
                if *sent_bytes == body.len() {
                    continue;
                }

                let sent =
                    match self
                        .h3_conn
                        .send_body(conn, *stream_id, &body[*sent_bytes..], true)
                    {
                        Ok(v) => v,
                        Err(quiche::h3::Error::Done) => 0,
                        Err(e) => {
                            println!("failed to send request body {:?}", e);
                            continue;
                        }
                    };

                *sent_bytes += sent;
            }
        }

        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;
            for _ in ds.dgrams_sent..ds.dgram_count {
                match send_dgram(conn, ds.flow_id, ds.dgram_content.as_bytes()) {
                    Ok(v) => v,
                    Err(e) => {
                        println!("failed to send datagram: {:?}", e);
                        break;
                    }
                }

                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }
    }

    pub fn handle_response(
        &mut self,
        conn: &mut quiche::Connection,
        buf: &mut [u8],
        req_start: &std::time::Instant,
    ) {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    println!(
                        "got response headers {:?} on stream id {}",
                        hdrs_to_string(&list),
                        stream_id
                    );

                    let req = self
                        .reqs
                        .iter_mut()
                        .find(|r| r.stream_id == Some(stream_id))
                        .unwrap();
                    req.response_headers = list;
                }

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    while let Ok(read) = self.h3_conn.recv_body(conn, stream_id, buf) {
                        debug!(
                            "got {} bytes of response data on stream id {}",
                            read, stream_id
                        );

                        let req = self
                            .reqs
                            .iter_mut()
                            .find(|r| r.stream_id == Some(stream_id))
                            .unwrap();

                        let len =
                            std::cmp::min(read, req.response_body_max - req.response_body.len());

                        req.response_body.extend_from_slice(&buf[..len]);

                        if !self.dump_json {
                            self.output_sink.borrow_mut()(unsafe {
                                String::from_utf8_unchecked(buf[..read].to_vec())
                            })
                        }
                    }
                }
                Ok((_stream_id, quiche::h3::Event::Finished)) => {
                    self.reqs_complete += 1;
                    let reqs_count = self.reqs.len();
                    debug!("Response received: {}/{}", self.reqs_complete, reqs_count);
                    if self.reqs_complete == reqs_count {
                        info!(
                            "{}/{} responses received in {:?}, closing...",
                            self.reqs_complete,
                            reqs_count,
                            req_start.elapsed()
                        );

                        if self.dump_json {
                            dump_json(&self.reqs, &mut *self.output_sink.borrow_mut());
                        }
                        match conn.close(true, 0x100, b"kthxbye") {
                            Ok(_) => (),
                            Err(e) => println!("failed to close connection: {:?}", e),
                        }

                        break;
                    }
                }

                Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                    println!("stream reset: {:?}", e);
                    match conn.close(true, 0x100, b"kthxbye") {
                        Ok(_) => (),
                        Err(e) => println!("failed to close connection when reset: {:?}", e),
                    }
                    break;
                }

                Ok((prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => {
                    println!(
                        "Priority Update: {:?} on Connection ID {}",
                        prioritized_element_id,
                        conn.trace_id()
                    );
                }

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    info!(
                        "GoAway: {:?} on Connection ID {}",
                        goaway_id,
                        conn.trace_id()
                    );
                }

                Err(quiche::h3::Error::Done) => {
                    ("all done!");
                    break;
                }
                Err(e) => {
                    error!("HTTP/3 processing failed: {:?}", e);
                    break;
                }
            }
        }

        while let Ok(len) = conn.dgram_recv(buf) {
            let mut b = octets::Octets::with_slice(buf);
            if let Ok(flow_id) = b.get_varint() {
                println!(
                    "Got datagram from flow={} data={:?}",
                    flow_id,
                    buf[b.off()..len].to_vec()
                );
            }
        }
    }
    pub fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.reqs_complete != self.reqs.len() {
            println!(
                "incomplete requests: {}/{} in {:?}, closing...",
                self.reqs_complete,
                self.reqs.len(),
                start.elapsed()
            );
            if self.dump_json {
                dump_json(&self.reqs, &mut *self.output_sink.borrow_mut());
            }
            return true;
        }
        false
    }

    //For server handle request
    pub fn handle_requests(
        &mut self,
        conn: &mut quiche::Connection,
        _partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_response: &mut HashMap<u64, PartialResponse>,
        buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    println!(
                        "{} got request {:?} on stream id {}",
                        conn.trace_id(),
                        hdrs_to_string(&list),
                        stream_id
                    );

                    self.largest_processed_request =
                        std::cmp::max(self.largest_processed_request, stream_id);

                    conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                        .unwrap();

                    let (mut headers, body, mut priority) = match HttpConn::build_h3_response(&list)
                    {
                        Ok(v) => v,
                        Err((code, _)) => {
                            conn.stream_shutdown(stream_id, quiche::Shutdown::Write, code)
                                .unwrap();
                            continue;
                        }
                    };

                    match self.h3_conn.take_last_priority_update(stream_id) {
                        Ok(v) => {
                            priority = v;
                        }
                        Err(quiche::h3::Error::Done) => (),
                        Err(e) => println!(
                            "{} failed to take last priority update: {}",
                            conn.trace_id(),
                            e
                        ),
                    }

                    if !priority.is_empty() {
                        headers.push(quiche::h3::Header::new(b"priority", priority.as_slice()))
                    }

                    #[cfg(feature = "sfv")]
                    let priority = match quiche::h3::Priority::try_from(priority.as_slice()) {
                        Ok(v) => v,
                        Err(_) => quiche::h3::Priority::default(),
                    };

                    #[cfg(not(feature = "sfv"))]
                    let priority = quiche::h3::Priority::default();

                    println!(
                        "{} prioritizing response on stream {} as {:?}",
                        conn.trace_id(),
                        stream_id,
                        priority,
                    );

                    match self
                        .h3_conn
                        .send_response_with_priority(conn, stream_id, &headers, &priority, false)
                    {
                        Ok(v) => v,
                        Err(quiche::h3::Error::StreamBlocked) => {
                            let response = PartialResponse {
                                headers: Some(headers),
                                priority: Some(priority),
                                body,
                                written: 0,
                            };
                            partial_response.insert(stream_id, response);
                            continue;
                        }
                        Err(e) => {
                            println!("{} stream send failed {:?}", conn.trace_id(), e);
                            break;
                        }
                    }

                    let response = PartialResponse {
                        headers: None,
                        priority: None,
                        body,
                        written: 0,
                    };

                    partial_response.insert(stream_id, response);
                }

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    println!("{} got data on stream id {}", conn.trace_id(), stream_id);
                }
                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),
                Ok((prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => {
                    println!(
                        "{} PRIORITY_UPDATE triggered for element ID={}",
                        conn.trace_id(),
                        prioritized_element_id
                    )
                }
                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    println!(
                        "{} GOAWAY triggered for element ID={}",
                        conn.trace_id(),
                        goaway_id
                    );
                    self.h3_conn
                        .send_goaway(conn, self.largest_processed_request)?;
                }

                Err(quiche::h3::Error::Done) => {
                    break;
                }
                Err(e) => {
                    println!("{} HTTP/3 processing failed: {:?}", conn.trace_id(), e);
                    return Err(e);
                }
            }
        }

        while let Ok(len) = conn.dgram_recv(buf) {
            let mut b = octets::Octets::with_slice(buf);
            if let Ok(flow_id) = b.get_varint() {
                println!(
                    "Got datagram from flow={} data={:?}",
                    flow_id,
                    buf[b.off()..len].to_vec()
                );
            }
        }

        if let Some(ds) = self.dgram_sender.as_mut() {
            let mut dgrams_done = 0;
            for _ in ds.dgrams_sent..ds.dgram_count {
                match send_dgram(conn, ds.flow_id, ds.dgram_content.as_bytes()) {
                    Ok(v) => v,
                    Err(e) => {
                        println!("failed to send datagram: {:?}", e);
                        break;
                    }
                }
                dgrams_done += 1;
            }

            ds.dgrams_sent += dgrams_done;
        }
        Ok(())
    }

    pub fn handle_writable(
        &mut self,
        conn: &mut quiche::Connection,
        partial_response: &mut HashMap<u64, PartialResponse>,
        stream_id: u64,
    ) {
        info!("{} stream {} is writable", conn.trace_id(), stream_id);

        if !partial_response.contains_key(&stream_id) {
            return;
        }

        let resp = partial_response.get_mut(&stream_id).unwrap();

        if let (Some(headers), Some(priority)) = (&resp.headers, &resp.priority) {
            match self
                .h3_conn
                .send_response_with_priority(conn, stream_id, headers, priority, false)
            {
                Ok(_) => (),
                Err(quiche::h3::Error::StreamBlocked) => {
                    return;
                }
                Err(e) => {
                    error!("{} failed to send response: {:?}", conn.trace_id(), e);
                    return;
                }
            }
        }

        resp.headers = None;
        resp.priority = None;

        let body = &resp.body[resp.written..];
        let written = match self.h3_conn.send_body(conn, stream_id, body, true) {
            Ok(v) => v,
            Err(quiche::h3::Error::Done) => 0,
            Err(e) => {
                partial_response.remove(&stream_id);
                error!("{} failed to send response body: {:?}", conn.trace_id(), e);
                return;
            }
        };

        resp.written += written;

        if resp.written == resp.body.len() {
            partial_response.remove(&stream_id);
        }
    }
}
