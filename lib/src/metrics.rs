use crate::http1_codec::Http1Codec;
use crate::http_codec::HttpCodec;
use crate::tls_demultiplexer::Protocol;
use crate::user_traffic::UserTraffic;
use crate::{core, http_codec, log_id, log_utils};
use bytes::Bytes;
use prometheus::Encoder;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

const LOG_FMT: &str = "METRICS={}";
const HEALTH_CHECK_PATH: &str = "/health-check";
const METRICS_PATH: &str = "/metrics";

pub(crate) struct Metrics {
    _registry: prometheus::Registry,
    client_sessions: prometheus::IntGaugeVec,
    inbound_traffic: prometheus::IntCounterVec,
    outbound_traffic: prometheus::IntCounterVec,
    outbound_tcp_sockets: prometheus::IntGauge,
    outbound_udp_sockets: prometheus::IntGauge,
    /// Per-account totals, kept beside the Prometheus registry rather than in
    /// it: these are read and reset by whoever is billing for them, which is
    /// not something a Prometheus counter can express. See
    /// [`crate::user_traffic`].
    user_traffic: UserTraffic,
}

pub(crate) struct ClientSessionsCounter {
    metrics: Arc<Metrics>,
    protocol: Protocol,
}

pub(crate) struct OutboundTcpSocketCounter {
    metrics: Arc<Metrics>,
}

pub(crate) struct OutboundUdpSocketCounter {
    metrics: Arc<Metrics>,
}

impl Metrics {
    pub fn new() -> io::Result<Arc<Self>> {
        let registry = prometheus::Registry::new();
        Ok(Arc::new(Self {
            client_sessions: prometheus::register_int_gauge_vec_with_registry!(
                "client_sessions",
                "Number of active client sessions",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            inbound_traffic: prometheus::register_int_counter_vec_with_registry!(
                "inbound_traffic_bytes",
                "Total number of bytes uploaded by clients",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_traffic: prometheus::register_int_counter_vec_with_registry!(
                "outbound_traffic_bytes",
                "Total number of bytes downloaded by clients",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_tcp_sockets: prometheus::register_int_gauge_with_registry!(
                "outbound_tcp_sockets",
                "Number of active outbound TCP connections",
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_udp_sockets: prometheus::register_int_gauge_with_registry!(
                "outbound_udp_sockets",
                "Number of active outbound UDP sockets",
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            user_traffic: UserTraffic::new(),
            _registry: registry,
        }))
    }

    pub fn user_traffic(&self) -> &UserTraffic {
        &self.user_traffic
    }

    pub fn client_sessions_counter(self: Arc<Self>, protocol: Protocol) -> ClientSessionsCounter {
        ClientSessionsCounter::new(self, protocol)
    }

    pub fn outbound_tcp_socket_counter(self: Arc<Self>) -> OutboundTcpSocketCounter {
        OutboundTcpSocketCounter::new(self)
    }

    pub fn outbound_udp_socket_counter(self: Arc<Self>) -> OutboundUdpSocketCounter {
        OutboundUdpSocketCounter::new(self)
    }

    pub fn add_inbound_bytes(&self, protocol: Protocol, n: usize) {
        self.inbound_traffic
            .with_label_values(&[protocol.as_str()])
            .inc_by(n as u64);
    }

    pub fn add_outbound_bytes(&self, protocol: Protocol, n: usize) {
        self.outbound_traffic
            .with_label_values(&[protocol.as_str()])
            .inc_by(n as u64);
    }

    fn collect(&self) -> (String, Bytes) {
        let encoder = prometheus::TextEncoder::new();

        let mut metric_families = self._registry.gather();
        metric_families.extend(prometheus::gather());
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        (encoder.format_type().to_string(), Bytes::from(buffer))
    }
}

impl ClientSessionsCounter {
    fn new(metrics: Arc<Metrics>, protocol: Protocol) -> Self {
        metrics
            .client_sessions
            .with_label_values(&[protocol.as_str()])
            .inc();

        Self { metrics, protocol }
    }
}

impl Drop for ClientSessionsCounter {
    fn drop(&mut self) {
        self.metrics
            .client_sessions
            .with_label_values(&[self.protocol.as_str()])
            .dec();
    }
}

impl OutboundTcpSocketCounter {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.outbound_tcp_sockets.inc();
        Self { metrics }
    }
}

impl Drop for OutboundTcpSocketCounter {
    fn drop(&mut self) {
        self.metrics.outbound_tcp_sockets.dec();
    }
}

impl OutboundUdpSocketCounter {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.outbound_udp_sockets.inc();
        Self { metrics }
    }
}

impl Drop for OutboundUdpSocketCounter {
    fn drop(&mut self) {
        self.metrics.outbound_udp_sockets.dec();
    }
}

pub(crate) async fn listen(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let (mut shutdown_notification, _shutdown_completion) = {
        let shutdown = context.shutdown.lock().unwrap();
        (shutdown.notification_handler(), shutdown.completion_guard())
    };

    tokio::select! {
        x = shutdown_notification.wait() => {
            match x {
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::other(format!("{}", e))),
            }
        }
        x = listen_inner(context, log_chain) => x,
    }
}

async fn listen_inner(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let settings = context.settings.metrics.as_ref();
    if settings.is_none() {
        return Ok(());
    }

    let next_id = AtomicU64::default();
    let listener = TcpListener::bind(settings.unwrap().address).await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let log_id = log_chain.extended(log_utils::IdItem::new(
            LOG_FMT,
            next_id.fetch_add(1, Ordering::Relaxed),
        ));
        log_id!(trace, log_id, "New connection from {}", peer);
        let context = context.clone();
        tokio::spawn(async move { handle_request(context, stream, log_id).await });
    }
}

async fn handle_request(
    context: Arc<core::Context>,
    io: TcpStream,
    log_id: log_utils::IdChain<u64>,
) {
    let mut codec = Http1Codec::new(context.settings.clone(), io, log_id.clone());
    let timeout = context.settings.metrics.as_ref().unwrap().request_timeout;
    let stream = match tokio::time::timeout(timeout, codec.listen()).await {
        Ok(Ok(Some(x))) => {
            log_id!(trace, log_id, "Got request: {:?}", x.request().request());
            x
        }
        Ok(Ok(None)) => {
            log_id!(debug, log_id, "Connection closed immediately");
            return;
        }
        Ok(Err(e)) => {
            log_id!(debug, log_id, "Listen failed: {}", e);
            return;
        }
        Err(_elapsed) => {
            log_id!(
                debug,
                log_id,
                "Didn't receive any request during configured period"
            );
            return;
        }
    };

    let dispatch = async {
        match codec.listen().await {
            Ok(Some(x)) => log_id!(
                debug,
                log_id,
                "Got unexpected request while processing previous: {:?}",
                x.request().request(),
            ),
            Ok(None) => (),
            Err(e) => log_id!(debug, log_id, "IO error during processing: {}", e),
        }
    };

    let handle = async {
        let path = stream.request().request().uri.path();
        let result = match path {
            HEALTH_CHECK_PATH => handle_health_check(stream),
            METRICS_PATH => handle_metrics_collect(&context.metrics, stream).await,
            x => {
                log_id!(debug, log_id, "Unexpected path: {}", x);
                let respond = stream.split().1;
                if let Err(e) =
                    respond.send_bad_response(http::status::StatusCode::BAD_REQUEST, vec![])
                {
                    log_id!(debug, log_id, "Failed to send response: {}", e);
                }
                return;
            }
        };

        if let Err(e) = result {
            log_id!(debug, log_id, "Failed to handle request: {}", e);
        }
    };

    tokio::select! {
        _ = dispatch => (),
        _ = handle => (),
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shutdown HTTP session: {}", e);
    }
}

fn handle_health_check(stream: Box<dyn http_codec::Stream>) -> io::Result<()> {
    stream.split().1.send_ok_response(true).map(|_| ())
}

async fn handle_metrics_collect(
    metrics: &Metrics,
    stream: Box<dyn http_codec::Stream>,
) -> io::Result<()> {
    let (content_type, mut content) = metrics.collect();
    let response = http::Response::builder()
        .version(stream.request().request().version)
        .status(http::status::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, content.len())
        .body(())
        .unwrap()
        .into_parts()
        .0;

    let mut sink = stream
        .split()
        .1
        .send_response(response, false)?
        .into_pipe_sink();

    while !content.is_empty() {
        content = sink.write(content)?;
        sink.wait_writable().await?;
    }

    sink.eof()
}

fn prometheus_to_io_error(e: prometheus::Error) -> io::Error {
    match e {
        prometheus::Error::Io(e) => e,
        e => io::Error::other(e.to_string()),
    }
}
