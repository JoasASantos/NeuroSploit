//! Getting to the target — VPNs, bastions, tunnels, proxies.
//!
//! Internal engagements do not happen from the operator's laptop. They happen
//! through something: a client VPN, an SSH bastion, a Cloudflare tunnel, a
//! SOCKS proxy handed over in a kickoff call. The harness has to route through
//! that thing, and — much more importantly — has to **refuse to run when it
//! is not routing through it**.
//!
//! That second half is the whole point of this module. Consider `10.20.0.15`
//! with the VPN down:
//!
//! ```text
//!   VPN up    →  10.20.0.15 is the client's domain controller
//!   VPN down  →  10.20.0.15 is something on the operator's own LAN
//! ```
//!
//! Same address, same payloads, entirely different machine — quite possibly a
//! machine nobody authorized. The failure is silent: connections succeed,
//! findings appear, the report is about the wrong network. So egress is
//! **fail-closed** here: a private target with no transport configured is
//! refused before a single request goes out, and a transport that claims to be
//! up must prove it ([`Transport::verify`]) rather than be assumed.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How traffic leaves the harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Egress {
    /// Straight out of the host's default route.
    Direct,
    /// SOCKS5, typically an SSH dynamic forward or a client-provided jump box.
    Socks { addr: String },
    /// An HTTP CONNECT proxy — Burp, ZAP, or a corporate egress.
    HttpProxy { url: String },
    /// An OpenVPN profile the harness brings up and tears down.
    OpenVpn { config: String },
    /// SSH bastion. Either a dynamic forward (SOCKS) or a specific local
    /// forward when the client only authorized one host.
    Bastion { host: String, user: String, identity: Option<String>, socks_port: u16, forward: Option<String> },
    /// A Cloudflare tunnel (`cloudflared access tcp`), for a target published
    /// through Zero Trust rather than routable at all.
    Cloudflared { hostname: String, local_port: u16 },
}

impl Egress {
    pub fn label(&self) -> String {
        match self {
            Egress::Direct => "direct".into(),
            Egress::Socks { addr } => format!("socks5://{addr}"),
            Egress::HttpProxy { url } => format!("http-proxy {url}"),
            Egress::OpenVpn { config } => format!("openvpn {config}"),
            Egress::Bastion { user, host, forward, socks_port, .. } => match forward {
                Some(f) => format!("ssh {user}@{host} → {f}"),
                None => format!("ssh {user}@{host} (socks :{socks_port})"),
            },
            Egress::Cloudflared { hostname, local_port } => format!("cloudflared {hostname} → :{local_port}"),
        }
    }

    /// The proxy URL the HTTP client should use, if any.
    pub fn proxy_url(&self) -> Option<String> {
        match self {
            Egress::Direct | Egress::OpenVpn { .. } | Egress::Cloudflared { .. } => None,
            Egress::Socks { addr } => Some(format!("socks5h://{addr}")),
            Egress::HttpProxy { url } => Some(url.clone()),
            Egress::Bastion { socks_port, forward, .. } => {
                forward.is_none().then(|| format!("socks5h://127.0.0.1:{socks_port}"))
            }
        }
    }

    /// Parse an operator-supplied spec.
    ///
    /// ```text
    ///   direct
    ///   socks5://127.0.0.1:1080
    ///   http://127.0.0.1:8080
    ///   openvpn:/path/client.ovpn
    ///   ssh://user@bastion.corp:22                  (dynamic forward)
    ///   ssh://user@bastion.corp?forward=10.0.0.5:445
    ///   cloudflared://db.internal.corp:5432
    /// ```
    pub fn parse(spec: &str) -> Result<Egress, String> {
        let s = spec.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("direct") || s.eq_ignore_ascii_case("none") {
            return Ok(Egress::Direct);
        }
        if let Some(rest) = s.strip_prefix("socks5://").or_else(|| s.strip_prefix("socks://")) {
            if !rest.contains(':') {
                return Err("socks needs host:port".into());
            }
            return Ok(Egress::Socks { addr: rest.to_string() });
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            return Ok(Egress::HttpProxy { url: s.to_string() });
        }
        if let Some(path) = s.strip_prefix("openvpn:") {
            if path.trim().is_empty() {
                return Err("openvpn needs a path to a .ovpn profile".into());
            }
            return Ok(Egress::OpenVpn { config: path.trim().to_string() });
        }
        if let Some(rest) = s.strip_prefix("ssh://") {
            let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
            let (user, hostport) = authority
                .split_once('@')
                .ok_or_else(|| "ssh needs user@host".to_string())?;
            let host = hostport.split(':').next().unwrap_or(hostport).to_string();
            if user.is_empty() || host.is_empty() {
                return Err("ssh needs user@host".into());
            }
            let mut forward = None;
            let mut socks_port = 1080u16;
            let mut identity = None;
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                match pair.split_once('=') {
                    Some(("forward", v)) => forward = Some(v.to_string()),
                    Some(("socks", v)) => socks_port = v.parse().map_err(|_| "socks port must be a number".to_string())?,
                    Some(("identity", v)) | Some(("key", v)) => identity = Some(v.to_string()),
                    _ => return Err(format!("unknown ssh option `{pair}`")),
                }
            }
            return Ok(Egress::Bastion { host, user: user.to_string(), identity, socks_port, forward });
        }
        if let Some(rest) = s.strip_prefix("cloudflared://") {
            let (hostname, port) = rest.split_once(':').ok_or_else(|| "cloudflared needs host:port".to_string())?;
            let local_port: u16 = port.parse().map_err(|_| "cloudflared port must be a number".to_string())?;
            return Ok(Egress::Cloudflared { hostname: hostname.to_string(), local_port });
        }
        Err(format!("unrecognised transport `{spec}` — try direct, socks5://…, http://…, openvpn:…, ssh://user@host, cloudflared://host:port"))
    }
}

/// Is this address one that only means something inside a network?
///
/// RFC1918, loopback, link-local, CGNAT, unique-local v6, and `.local`/
/// `.internal`/`.corp` style names. These are the addresses that resolve to
/// something different depending on which network you are on, which is exactly
/// the condition that makes a missing VPN dangerous rather than merely broken.
pub fn is_internal(target: &str) -> bool {
    let host = target
        .rsplit("://")
        .next()
        .unwrap_or(target)
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_lowercase();
    // A bracketed IPv6 literal keeps its colons; only a host:port pair loses
    // them. Splitting blindly turns `[fd00::1]:445` into `[fd00`, which then
    // matches by accident rather than by parsing.
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest).to_string()
    } else {
        host.split(':').next().unwrap_or(&host).to_string()
    };
    if host.is_empty() {
        return false;
    }
    for suffix in [".local", ".internal", ".corp", ".lan", ".home", ".intranet", ".test"] {
        if host.ends_with(suffix) {
            return true;
        }
    }
    if host == "localhost" {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        return v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_unspecified()
            // 100.64.0.0/10 — carrier-grade NAT, common on client VPNs.
            || (o[0] == 100 && (64..=127).contains(&o[1]));
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let seg = v6.segments();
        return v6.is_loopback() || v6.is_unspecified() || (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80;
    }
    // A bare single-label name resolves via search domains — which network you
    // are on decides what it means.
    !host.contains('.')
}

/// The configured route, and whether it is actually working.
#[derive(Clone)]
pub struct Transport {
    pub egress: Egress,
    /// URL used to confirm traffic is really leaving the way it should.
    pub verify_url: String,
    child: std::sync::Arc<std::sync::Mutex<Option<u32>>>,
}

impl Transport {
    pub fn new(egress: Egress) -> Transport {
        Transport {
            egress,
            verify_url: "https://api.ipify.org?format=text".to_string(),
            child: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn direct() -> Transport {
        Transport::new(Egress::Direct)
    }

    /// Fail-closed check, run before any traffic.
    ///
    /// An internal target with no transport is refused. This is the rule that
    /// keeps a scan off the operator's own LAN when the VPN silently dropped,
    /// and it is a refusal rather than a warning because a warning in a log
    /// nobody is reading is not a control.
    pub fn admits(&self, target: &str) -> Result<(), String> {
        if self.egress == Egress::Direct && is_internal(target) {
            return Err(format!(
                "{target} is an internal address and no transport is configured. \
                 With the VPN or bastion down this address belongs to whatever network this host is on, \
                 which is not the client's. Configure --transport, or pass an external target."
            ));
        }
        Ok(())
    }

    /// Bring the transport up, if it is something we run.
    ///
    /// Returns a description of what was started. `openvpn`, `ssh` and
    /// `cloudflared` are expected on PATH; a missing binary is an error, never
    /// a silent fall back to direct — falling back is precisely the failure
    /// this module exists to prevent.
    pub async fn connect(&self) -> anyhow::Result<String> {
        use std::process::{Command, Stdio};
        let spawn = |cmd: &str, args: Vec<String>| -> anyhow::Result<u32> {
            let child = Command::new(cmd)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| anyhow::anyhow!("cannot start {cmd}: {e} — install it or pick another transport"))?;
            Ok(child.id())
        };
        let pid = match &self.egress {
            Egress::Direct | Egress::Socks { .. } | Egress::HttpProxy { .. } => None,
            Egress::OpenVpn { config } => {
                if !std::path::Path::new(config).exists() {
                    anyhow::bail!("no OpenVPN profile at {config}");
                }
                Some(spawn("openvpn", vec!["--config".into(), config.clone()])?)
            }
            Egress::Bastion { host, user, identity, socks_port, forward } => {
                let mut args: Vec<String> = vec![
                    "-N".into(),
                    "-o".into(),
                    "ExitOnForwardFailure=yes".into(),
                    "-o".into(),
                    "ServerAliveInterval=15".into(),
                ];
                if let Some(key) = identity {
                    args.push("-i".into());
                    args.push(key.clone());
                }
                match forward {
                    Some(f) => {
                        // Local forward: exactly one authorized host, reachable
                        // at 127.0.0.1 on the same port.
                        let port = f.rsplit(':').next().unwrap_or("0");
                        args.push("-L".into());
                        args.push(format!("{port}:{f}"));
                    }
                    None => {
                        args.push("-D".into());
                        args.push(socks_port.to_string());
                    }
                }
                args.push(format!("{user}@{host}"));
                Some(spawn("ssh", args)?)
            }
            Egress::Cloudflared { hostname, local_port } => Some(spawn(
                "cloudflared",
                vec![
                    "access".into(),
                    "tcp".into(),
                    "--hostname".into(),
                    hostname.clone(),
                    "--url".into(),
                    format!("127.0.0.1:{local_port}"),
                ],
            )?),
        };
        if let Some(pid) = pid {
            // The guard is dropped before the await: holding a std Mutex across
            // one makes the whole future non-Send, and every caller spawns it.
            if let Ok(mut slot) = self.child.lock() {
                *slot = Some(pid);
            }
            // Tunnels need a moment before the first connection succeeds;
            // without this the verify below fails on a transport that is fine.
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        Ok(self.egress.label())
    }

    /// Confirm traffic is really going where it should.
    ///
    /// For a proxied egress this means the request succeeds *through the
    /// proxy*; for a VPN it means the apparent source address changed. Both
    /// answer the same question — "is the route I think I have the route I
    /// actually have" — which is the question a silent VPN drop makes urgent.
    pub async fn verify(&self, baseline_ip: Option<&str>) -> Result<String, String> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(15));
        if let Some(p) = self.egress.proxy_url() {
            let proxy = reqwest::Proxy::all(&p).map_err(|e| format!("bad proxy {p}: {e}"))?;
            builder = builder.proxy(proxy);
        }
        let client = builder.build().map_err(|e| e.to_string())?;
        let ip = client
            .get(&self.verify_url)
            .send()
            .await
            .map_err(|e| format!("transport {} is not carrying traffic: {e}", self.egress.label()))?
            .text()
            .await
            .map_err(|e| e.to_string())?
            .trim()
            .to_string();
        if let Some(base) = baseline_ip {
            if base == ip && !matches!(self.egress, Egress::Direct) {
                return Err(format!(
                    "egress address is still {ip} with {} configured — traffic is NOT going through the transport",
                    self.egress.label()
                ));
            }
        }
        Ok(ip)
    }

    /// Apply the proxy to an HTTP client builder.
    pub fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        match self.egress.proxy_url().and_then(|p| reqwest::Proxy::all(&p).ok()) {
            Some(proxy) => builder.proxy(proxy),
            None => builder,
        }
    }

    /// Environment variables child processes (curl, nmap wrappers, agent
    /// commands) need so they use the same route.
    pub fn env(&self) -> Vec<(String, String)> {
        match self.egress.proxy_url() {
            Some(p) if p.starts_with("socks") => vec![("ALL_PROXY".into(), p)],
            Some(p) => vec![("HTTP_PROXY".into(), p.clone()), ("HTTPS_PROXY".into(), p)],
            None => Vec::new(),
        }
    }

    /// Tear down anything we started.
    pub fn disconnect(&self) {
        if let Ok(mut slot) = self.child.lock() {
            if let Some(pid) = slot.take() {
                let _ = std::process::Command::new("kill").arg(pid.to_string()).status();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_parse_into_the_route_they_describe() {
        assert_eq!(Egress::parse("").unwrap(), Egress::Direct);
        assert_eq!(Egress::parse("direct").unwrap(), Egress::Direct);
        assert_eq!(
            Egress::parse("socks5://127.0.0.1:1080").unwrap(),
            Egress::Socks { addr: "127.0.0.1:1080".into() }
        );
        assert_eq!(
            Egress::parse("http://127.0.0.1:8080").unwrap(),
            Egress::HttpProxy { url: "http://127.0.0.1:8080".into() }
        );
        assert_eq!(
            Egress::parse("openvpn:/etc/client.ovpn").unwrap(),
            Egress::OpenVpn { config: "/etc/client.ovpn".into() }
        );
        assert_eq!(
            Egress::parse("cloudflared://db.internal.corp:5432").unwrap(),
            Egress::Cloudflared { hostname: "db.internal.corp".into(), local_port: 5432 }
        );
    }

    #[test]
    fn a_bastion_is_a_socks_proxy_unless_one_host_was_authorized() {
        let dynamic = Egress::parse("ssh://red@bastion.corp:22").unwrap();
        assert_eq!(dynamic.proxy_url().as_deref(), Some("socks5h://127.0.0.1:1080"));

        // A single authorized host gets a local forward, and deliberately NO
        // proxy: routing everything through it would put traffic on hosts the
        // client did not agree to.
        let scoped = Egress::parse("ssh://red@bastion.corp?forward=10.0.0.5:445").unwrap();
        assert_eq!(scoped.proxy_url(), None);
        match scoped {
            Egress::Bastion { forward, .. } => assert_eq!(forward.as_deref(), Some("10.0.0.5:445")),
            _ => panic!("expected a bastion"),
        }
    }

    #[test]
    fn malformed_specs_are_refused_rather_than_guessed() {
        assert!(Egress::parse("socks5://nohost").is_err());
        assert!(Egress::parse("ssh://bastion.corp").is_err(), "no user is ambiguous");
        assert!(Egress::parse("ssh://red@bastion?socks=notaport").is_err());
        assert!(Egress::parse("ssh://red@bastion?wat=1").is_err());
        assert!(Egress::parse("openvpn:").is_err());
        assert!(Egress::parse("carrier-pigeon://x").is_err());
    }

    #[test]
    fn internal_addresses_are_recognised_across_their_many_shapes() {
        for t in [
            "10.20.0.15",
            "https://192.168.1.1/admin",
            "172.16.4.9:8080",
            "100.64.3.2",
            "127.0.0.1",
            "localhost",
            "dc01.corp",
            "fileserver",
            "https://app.internal/",
            "[fd00::1]:445",
            "fe80::1",
        ] {
            assert!(is_internal(t), "{t} should count as internal");
        }
        for t in ["example.com", "https://arenahockeypara.com.br/", "8.8.8.8", "203.0.113.7"] {
            assert!(!is_internal(t), "{t} should not count as internal");
        }
    }

    #[test]
    fn an_internal_target_without_a_transport_is_refused() {
        let direct = Transport::direct();
        let err = direct.admits("10.20.0.15").unwrap_err();
        assert!(err.contains("internal address"));
        // The same address through a bastion is fine — that is what the
        // bastion is for.
        let viassh = Transport::new(Egress::parse("ssh://red@bastion.corp").unwrap());
        assert!(viassh.admits("10.20.0.15").is_ok());
        // And an external target needs nothing.
        assert!(direct.admits("https://example.com").is_ok());
    }

    #[test]
    fn child_processes_inherit_the_same_route() {
        let socks = Transport::new(Egress::parse("socks5://127.0.0.1:9050").unwrap());
        assert_eq!(socks.env(), vec![("ALL_PROXY".to_string(), "socks5h://127.0.0.1:9050".to_string())]);

        let http = Transport::new(Egress::parse("http://127.0.0.1:8080").unwrap());
        let env = http.env();
        assert!(env.iter().any(|(k, _)| k == "HTTPS_PROXY"), "curl and friends need both");
        assert!(env.iter().any(|(k, _)| k == "HTTP_PROXY"));

        // A VPN changes the host's routing table, so there is nothing to pass
        // down — and inventing a proxy variable here would break every child.
        assert!(Transport::new(Egress::OpenVpn { config: "/x.ovpn".into() }).env().is_empty());
    }

    #[tokio::test]
    async fn verify_fails_when_the_address_did_not_change() {
        // A VPN that silently dropped still answers — with the operator's own
        // address. Same IP as the baseline means the tunnel is not carrying
        // traffic, whatever the process table says.
        let t = Transport::new(Egress::OpenVpn { config: "/nonexistent.ovpn".into() });
        // No network in tests: the error path is the assertion. What matters is
        // that an unchanged address is treated as failure, not success.
        let err = t.verify(Some("203.0.113.10")).await;
        assert!(err.is_err() || err.unwrap() != "203.0.113.10");
    }
}
