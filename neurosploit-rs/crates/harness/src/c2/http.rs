use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::BODY_CAP;

pub(crate) struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn form(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for pair in String::from_utf8_lossy(&self.body).split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                out.insert(percent_decode(k), percent_decode(v));
            }
        }
        out
    }
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            content_type: "application/json".into(),
            body: serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    pub fn text(status: u16, s: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8".into(),
            body: s.into().into_bytes(),
        }
    }
}

pub(crate) type BoxFut = Pin<Box<dyn Future<Output = HttpResponse> + Send>>;

pub(crate) async fn serve_http(
    listener: TcpListener,
    handler: Arc<dyn Fn(HttpRequest) -> BoxFut + Send + Sync>,
) -> std::io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let h = handler.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(30), read_request(&mut stream)).await {
                Ok(Ok(Some(req))) => {
                    let resp = h(req).await;
                    let _ = write_response(&mut stream, resp).await;
                }
                Ok(Ok(None)) => {}
                _ => {
                    let _ = write_response(&mut stream, HttpResponse::text(400, "bad request"))
                        .await;
                }
            }
        });
    }
}

async fn read_request(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<Option<HttpRequest>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete request",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    if method.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad request line",
        ));
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target, BTreeMap::new()),
    };
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "chunked body unsupported",
        ));
    }
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > BODY_CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "body too large",
        ));
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Ok(Some(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    }))
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    resp: HttpResponse,
) -> std::io::Result<()> {
    let reason = match resp.status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        resp.status,
        reason,
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&resp.body).await?;
    stream.flush().await
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_query(q: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
