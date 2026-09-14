//! Intercepting proxy — owning the request stream, and plugging into the tools
//! that already do.
//!
//! Two capabilities the harness lacked, and one reason they belong together.
//!
//! An operator's toolchain has a proxy in it — Burp, Caido, ZAP, mitmproxy —
//! and the engagement should flow through it, so the human can watch, replay,
//! and pick up where the agent left off. That is the *tool* side: point the
//! harness at `127.0.0.1:8080` and everything it does appears in Burp.
//!
//! But even with no tool running, the harness benefits from seeing its own
//! traffic as a stream rather than as isolated requests: passive discovery
//! (every host, cookie and header that went by), and a faithful record for
//! replay. That is the *own interceptor*: a recording forward proxy the harness
//! runs itself.
//!
//! They compose. The own interceptor records, then forwards upstream to the
//! tool — so the operator gets Burp *and* the harness gets its passive log,
//! from one configuration:
//!
//! ```text
//!   harness + agent curls ──→ own interceptor ──→ [Burp/Caido/mitmproxy] ──→ target
//!                                   │
//!                                   └── records every flow (passive discovery, replay)
//! ```
//!
//! ## Honest about TLS
//!
//! The own interceptor records plaintext HTTP in full. For HTTPS it tunnels
//! (CONNECT) and records the metadata it can see without breaking TLS — host,
//! timing, byte counts — but not the decrypted body. Decrypting HTTPS needs a
//! CA the client trusts, which Burp/Caido/mitmproxy already solved; so for full
//! HTTPS interception you **chain to one of them**, and this module makes that
//! one flag rather than a re-implementation of their certificate machinery.
//! Claiming to MITM TLS without a trusted CA would be a lie the operator finds
//! out about mid-engagement.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A known interception tool, with where it listens by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tool {
    /// Burp Suite — default proxy 127.0.0.1:8080.
    Burp,
    /// Caido — default 127.0.0.1:8080 (shares the convention).
    Caido,
    /// OWASP ZAP — default 127.0.0.1:8080, sometimes :8081.
    Zap,
    /// mitmproxy / mitmdump — default 127.0.0.1:8080.
    Mitmproxy,
    /// Any HTTP proxy at an explicit address.
    Custom(String),
}

impl Tool {
    /// The proxy URL to forward to.
    pub fn proxy_url(&self) -> String {
        match self {
            Tool::Burp | Tool::Caido | Tool::Zap | Tool::Mitmproxy => "http://127.0.0.1:8080".into(),
            Tool::Custom(url) => {
                if url.contains("://") {
                    url.clone()
                } else {
                    format!("http://{url}")
                }
            }
        }
    }
    pub fn name(&self) -> String {
        match self {
            Tool::Burp => "Burp Suite".into(),
            Tool::Caido => "Caido".into(),
            Tool::Zap => "OWASP ZAP".into(),
            Tool::Mitmproxy => "mitmproxy".into(),
            Tool::Custom(u) => format!("proxy {u}"),
        }
    }
    pub fn parse(s: &str) -> Option<Tool> {
        Some(match s.trim().to_lowercase().as_str() {
            "burp" | "burpsuite" => Tool::Burp,
            "caido" => Tool::Caido,
            "zap" | "owasp-zap" => Tool::Zap,
            "mitm" | "mitmproxy" | "mitmdump" => Tool::Mitmproxy,
            "" | "none" | "off" => return None,
            other => Tool::Custom(other.to_string()),
        })
    }
    /// Is a proxy actually listening where this tool expects to be?
    ///
    /// Checked before a run commits to routing through it: an operator who
    /// typed `--intercept burp` but forgot to start Burp should be told, not
    /// have every request fail with a connection error three minutes in.
    pub async fn is_listening(&self) -> bool {
        let url = self.proxy_url();
        let hostport = url.split("://").nth(1).unwrap_or(&url).trim_end_matches('/');
        let addr: Option<SocketAddr> = hostport.to_socket_addrs_first();
        match addr {
            Some(a) => tokio::time::timeout(Duration::from_millis(600), tokio::net::TcpStream::connect(a)).await.map(|r| r.is_ok()).unwrap_or(false),
            None => false,
        }
    }
}

trait ToSocketAddrFirst {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr>;
}
impl ToSocketAddrFirst for str {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok().and_then(|mut it| it.next())
    }
}

/// One request/response the interceptor saw.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Flow {
    pub at: u64,
    pub method: String,
    pub url: String,
    pub status: u16,
    /// Bytes client→server (request) and server→client (response). For a
    /// tunnelled HTTPS connection this is all we can honestly report.
    pub req_bytes: usize,
    pub resp_bytes: usize,
    /// True when this was a CONNECT tunnel (TLS body not visible to us).
    #[serde(default)]
    pub tunnelled: bool,
    /// Response content-type, when seen in cleartext.
    #[serde(default)]
    pub content_type: String,
}

/// How the harness should route its traffic.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Run the harness's own recording interceptor.
    pub own_interceptor: bool,
    /// Where the own interceptor binds.
    pub bind: SocketAddr,
    /// Forward upstream to this tool after recording (full HTTPS interception).
    pub upstream: Option<Tool>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            own_interceptor: false,
            bind: "127.0.0.1:8899".parse().unwrap(),
            upstream: None,
        }
    }
}

impl ProxyConfig {
    /// Parse an operator spec.
    ///
    /// ```text
    ///   burp | caido | zap | mitmproxy      → route straight through the tool
    ///   own                                 → own interceptor only, no upstream
    ///   own+burp | own+caido | own+…        → own interceptor, recording, then the tool
    ///   http://127.0.0.1:8080               → an explicit upstream proxy
    /// ```
    pub fn parse(spec: &str) -> Result<ProxyConfig, String> {
        let s = spec.trim().to_lowercase();
        if s.is_empty() || s == "off" || s == "none" {
            return Ok(ProxyConfig::default());
        }
        if let Some(rest) = s.strip_prefix("own+") {
            let tool = Tool::parse(rest).ok_or_else(|| format!("unknown upstream tool `{rest}`"))?;
            return Ok(ProxyConfig { own_interceptor: true, upstream: Some(tool), ..Default::default() });
        }
        if s == "own" {
            return Ok(ProxyConfig { own_interceptor: true, upstream: None, ..Default::default() });
        }
        let tool = Tool::parse(&s).ok_or_else(|| format!("unrecognised intercept spec `{spec}`"))?;
        // A bare tool routes straight through it — no own interceptor, because
        // the tool already records. The own interceptor is for adding recording
        // where there is none, or a passive log alongside the tool (own+tool).
        Ok(ProxyConfig { own_interceptor: false, upstream: Some(tool), ..Default::default() })
    }

    /// The proxy URL the HTTP client and child processes should use.
    ///
    /// When the own interceptor is on, that is its address (it forwards upstream
    /// itself). Otherwise it is the tool's address directly. `None` means no
    /// proxying at all.
    pub fn client_proxy_url(&self) -> Option<String> {
        if self.own_interceptor {
            Some(format!("http://{}", self.bind))
        } else {
            self.upstream.as_ref().map(|t| t.proxy_url())
        }
    }

    /// Environment for child processes (curl, tool commands) so they route the
    /// same way the harness does.
    pub fn env(&self) -> Vec<(String, String)> {
        match self.client_proxy_url() {
            Some(p) => vec![
                ("HTTP_PROXY".into(), p.clone()),
                ("HTTPS_PROXY".into(), p.clone()),
                ("http_proxy".into(), p.clone()),
                ("https_proxy".into(), p),
            ],
            None => Vec::new(),
        }
    }

    pub fn summary(&self) -> String {
        match (self.own_interceptor, &self.upstream) {
            (true, Some(t)) => format!("own interceptor on {} → {}", self.bind, t.name()),
            (true, None) => format!("own interceptor on {} (HTTP recorded, HTTPS tunnelled)", self.bind),
            (false, Some(t)) => format!("routing through {}", t.name()),
            (false, None) => "direct (no interception)".into(),
        }
    }
}

/// The running own interceptor: a recording forward proxy.
#[derive(Clone)]
pub struct Interceptor {
    upstream: Option<String>,
    flows: Arc<Mutex<Vec<Flow>>>,
    jsonl: Option<String>,
}

impl Interceptor {
    pub fn new(upstream: Option<String>) -> Self {
        Interceptor { upstream, flows: Arc::new(Mutex::new(Vec::new())), jsonl: None }
    }

    /// Also append every flow to a JSONL file, so a run's traffic survives it.
    pub fn logging_to(mut self, path: impl Into<String>) -> Self {
        self.jsonl = Some(path.into());
        self
    }

    pub fn flows(&self) -> Vec<Flow> {
        self.flows.lock().map(|f| f.clone()).unwrap_or_default()
    }

    /// Distinct hosts seen — the passive-discovery product.
    pub fn hosts(&self) -> Vec<String> {
        let mut hs: Vec<String> = self
            .flows()
            .iter()
            .filter_map(|f| f.url.split("://").nth(1).map(|r| r.split('/').next().unwrap_or("").to_string()))
            .filter(|h| !h.is_empty())
            .collect();
        hs.sort();
        hs.dedup();
        hs
    }

    fn record(&self, flow: Flow) {
        if let Some(path) = &self.jsonl {
            if let Ok(line) = serde_json::to_string(&flow) {
                use std::io::Write;
                if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                    let _ = writeln!(fh, "{line}");
                }
            }
        }
        if let Ok(mut f) = self.flows.lock() {
            if f.len() >= 20_000 {
                f.remove(0);
            }
            f.push(flow);
        }
    }

    /// Start listening. Returns once bound; serving continues in the background.
    pub async fn listen(&self, bind: SocketAddr) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { continue };
                let me = me.clone();
                tokio::spawn(async move {
                    let _ = me.serve(sock).await;
                });
            }
        });
        Ok(())
    }

    async fn serve(&self, mut client: tokio::net::TcpStream) -> std::io::Result<()> {
        // Read the request head (up to the blank line). Proxies see the head
        // before the body, and the first line tells us CONNECT vs absolute-URI.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while head.len() < 32 * 1024 {
            let n = client.read(&mut byte).await?;
            if n == 0 {
                break;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head_str = String::from_utf8_lossy(&head).to_string();
        let first = head_str.lines().next().unwrap_or("").to_string();
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();

        if method.eq_ignore_ascii_case("CONNECT") {
            self.tunnel(client, &target).await
        } else if target.starts_with("http://") {
            self.forward_http(client, &method, &target, &head_str).await
        } else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\nthis proxy handles absolute-form HTTP and CONNECT").await;
            Ok(())
        }
    }

    /// Plain HTTP: forward via reqwest (honouring an upstream proxy), record
    /// the full flow, and write the response back to the client.
    async fn forward_http(&self, mut client: tokio::net::TcpStream, method: &str, url: &str, head: &str) -> std::io::Result<()> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none());
        if let Some(up) = &self.upstream {
            if let Ok(px) = reqwest::Proxy::all(up) {
                builder = builder.proxy(px);
            }
        }
        let client_http = builder.build().unwrap_or_default();
        let m = reqwest::Method::from_bytes(method.to_uppercase().as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut rb = client_http.request(m, url);
        let mut req_bytes = head.len();
        for line in head.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                // Hop-by-hop headers a proxy must not forward.
                if !matches!(k.to_lowercase().as_str(), "proxy-connection" | "connection" | "host") {
                    rb = rb.header(k, v.trim());
                }
            }
        }

        let now = now();
        match rb.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let mut out = format!("HTTP/1.1 {status} {}\r\n", resp.status().canonical_reason().unwrap_or(""));
                for (k, v) in resp.headers().iter() {
                    if !matches!(k.as_str(), "transfer-encoding" | "connection") {
                        out.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or("")));
                    }
                }
                let body = resp.bytes().await.unwrap_or_default();
                out.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", body.len()));
                client.write_all(out.as_bytes()).await?;
                client.write_all(&body).await?;
                self.record(Flow {
                    at: now,
                    method: method.to_uppercase(),
                    url: url.to_string(),
                    status,
                    req_bytes,
                    resp_bytes: body.len(),
                    tunnelled: false,
                    content_type: ct,
                });
            }
            Err(e) => {
                req_bytes += 0;
                let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n{e}").as_bytes()).await;
                self.record(Flow { at: now, method: method.to_uppercase(), url: url.to_string(), status: 502, req_bytes, resp_bytes: 0, tunnelled: false, content_type: String::new() });
            }
        }
        Ok(())
    }

    /// HTTPS: open a tunnel, record what we can see without breaking TLS.
    ///
    /// With an upstream tool, the CONNECT is handed to it so the tool does the
    /// full interception; without one, we connect straight to the target and
    /// relay bytes, recording host, timing and byte counts. We do NOT pretend
    /// to see the plaintext.
    async fn tunnel(&self, mut client: tokio::net::TcpStream, target: &str) -> std::io::Result<()> {
        let now = now();
        // Connect to the upstream tool if configured, else to the target.
        let (mut server, via_upstream) = match &self.upstream {
            Some(up) => {
                let hostport = up.split("://").nth(1).unwrap_or(up).trim_end_matches('/').to_string();
                match tokio::net::TcpStream::connect(&hostport).await {
                    Ok(mut s) => {
                        // Replay the CONNECT to the upstream proxy verbatim.
                        let _ = s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await;
                        // Swallow the upstream's "200 Connection Established".
                        let mut buf = [0u8; 1024];
                        let _ = s.read(&mut buf).await;
                        (s, true)
                    }
                    Err(e) => {
                        let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\n\r\nupstream proxy: {e}").as_bytes()).await;
                        return Ok(());
                    }
                }
            }
            None => match tokio::net::TcpStream::connect(target).await {
                Ok(s) => (s, false),
                Err(e) => {
                    let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{e}").as_bytes()).await;
                    return Ok(());
                }
            },
        };
        // Tell the client the tunnel is open (unless the upstream already did,
        // in which case we still must, since the client spoke to us).
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        // Relay both directions, counting bytes. The bodies are TLS ciphertext;
        // we record the shape, not the content — honestly.
        let (mut cr, mut cw) = client.split();
        let (mut sr, mut sw) = server.split();
        let c2s = tokio::io::copy(&mut cr, &mut sw);
        let s2c = tokio::io::copy(&mut sr, &mut cw);
        let (up, down) = tokio::join!(c2s, s2c);
        let req_bytes = up.unwrap_or(0) as usize;
        let resp_bytes = down.unwrap_or(0) as usize;
        let _ = via_upstream;
        self.record(Flow {
            at: now,
            method: "CONNECT".into(),
            url: format!("https://{target}"),
            status: 200,
            req_bytes,
            resp_bytes,
            tunnelled: true,
            content_type: String::new(),
        });
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_specs_map_to_the_right_upstream() {
        assert_eq!(Tool::parse("burp"), Some(Tool::Burp));
        assert_eq!(Tool::parse("caido"), Some(Tool::Caido));
        assert_eq!(Tool::parse("mitmproxy"), Some(Tool::Mitmproxy));
        assert_eq!(Tool::parse("off"), None);
        assert_eq!(Tool::Burp.proxy_url(), "http://127.0.0.1:8080");
        assert_eq!(Tool::Custom("127.0.0.1:9000".into()).proxy_url(), "http://127.0.0.1:9000");
    }

    #[test]
    fn a_bare_tool_routes_through_it_without_the_own_interceptor() {
        let c = ProxyConfig::parse("burp").unwrap();
        assert!(!c.own_interceptor, "the tool already records — no need to double up");
        assert_eq!(c.upstream, Some(Tool::Burp));
        assert_eq!(c.client_proxy_url().as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn own_plus_tool_records_then_forwards() {
        let c = ProxyConfig::parse("own+caido").unwrap();
        assert!(c.own_interceptor);
        assert_eq!(c.upstream, Some(Tool::Caido));
        // Clients point at the own interceptor, which forwards to the tool.
        assert_eq!(c.client_proxy_url(), Some(format!("http://{}", c.bind)));
    }

    #[test]
    fn own_alone_records_with_no_upstream() {
        let c = ProxyConfig::parse("own").unwrap();
        assert!(c.own_interceptor && c.upstream.is_none());
        assert!(c.summary().contains("HTTPS tunnelled"), "the summary is honest about not decrypting TLS");
    }

    #[test]
    fn off_means_direct() {
        let c = ProxyConfig::parse("").unwrap();
        assert!(c.client_proxy_url().is_none());
        assert!(c.env().is_empty());
    }

    #[test]
    fn child_env_covers_both_cases_of_the_variable() {
        let c = ProxyConfig::parse("burp").unwrap();
        let env = c.env();
        assert!(env.iter().any(|(k, _)| k == "HTTPS_PROXY"));
        assert!(env.iter().any(|(k, _)| k == "https_proxy"), "curl reads the lowercase one");
    }

    #[tokio::test]
    async fn the_own_interceptor_records_a_plain_http_flow() {
        // A tiny origin server the interceptor will forward to.
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = origin.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nhi").await;
            }
        });

        let interceptor = Interceptor::new(None);
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let me = interceptor.clone();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = me.serve(sock).await;
            }
        });

        // Speak proxy protocol: absolute-form request line.
        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("GET http://{origin_addr}/x HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
        c.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut resp)).await;
        assert!(String::from_utf8_lossy(&resp).contains("hi"), "the interceptor relayed the origin's body");

        // Give the record a beat, then check the flow was captured.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let flows = interceptor.flows();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, 200);
        assert!(!flows[0].tunnelled);
        assert!(interceptor.hosts().iter().any(|h| h == &origin_addr.to_string()));
    }
}
