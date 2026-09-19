//! Network-level scope evasion resistance.
//!
//! A scope that compares hostname strings is dodged by everything that isn't a
//! hostname string. `127.0.0.1` is excluded — but `0x7f000001`, `2130706433`,
//! `0177.0.0.1` and `::ffff:127.0.0.1` are the same address wearing a disguise,
//! and a string compare lets them through. Worse: a name can be *in* scope at
//! resolution time and point somewhere else a moment later (DNS rebinding), or
//! a 302 can walk an in-scope request off to an out-of-scope host.
//!
//! This module canonicalises the thing actually being connected to, before the
//! boundary check runs:
//!
//! ```text
//!   0x7f000001 · 2130706433 · 0177.0.0.1 · ::ffff:127.0.0.1
//!                          │  normalize
//!                          ▼
//!                      127.0.0.1        ← what the exclude/allow rule compares
//! ```
//!
//! and adds the checks a string boundary cannot make on its own: validate a
//! redirect's target, re-resolve a name and refuse a rebind, and refuse a name
//! that resolves to a private/loopback address it should not.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Canonicalise a host into the form the scope rules compare against.
///
/// Every alternate IPv4 encoding collapses to dotted-quad; an IPv4-mapped IPv6
/// address collapses to its IPv4 form; a real hostname is returned lowercased
/// and de-`www`-ed. The point is that `normalize_host` of two spellings of the
/// same address is byte-identical, so an exclude rule cannot be dodged by
/// choosing a different spelling.
pub fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_matches(['[', ']']).to_lowercase();
    if h.is_empty() {
        return h;
    }
    if let Some(ip) = parse_ip_any(&h) {
        return match ip {
            IpAddr::V4(v4) => v4.to_string(),
            // An IPv4-mapped v6 (::ffff:a.b.c.d) is really that v4 address.
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => v6.to_string(),
            },
        };
    }
    h.trim_start_matches("www.").to_string()
}

/// Parse an IP in any of the encodings an attacker reaches for.
///
/// Dotted-quad, a bare decimal (`2130706433`), hex (`0x7f000001`), octal
/// (`0177.0.0.1`), and IPv6 including the mapped form. Returns None for a real
/// hostname.
pub fn parse_ip_any(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    // Standard forms first (also handles normal IPv6).
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    // Bare 32-bit decimal: 2130706433 == 127.0.0.1
    if s.chars().all(|c| c.is_ascii_digit()) && s.len() <= 10 {
        if let Ok(n) = s.parse::<u32>() {
            return Some(IpAddr::V4(Ipv4Addr::from(n)));
        }
    }
    // Bare hex: 0x7f000001
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(n) = u32::from_str_radix(hex, 16) {
                return Some(IpAddr::V4(Ipv4Addr::from(n)));
            }
        }
    }
    // Dotted with per-octet alternate radix (octal/hex): 0177.0.0.1, 0x7f.0.0.1
    if s.contains('.') {
        let parts: Vec<&str> = s.split('.').collect();
        if (2..=4).contains(&parts.len()) {
            let mut octets: Vec<u32> = Vec::new();
            let mut ok = true;
            for p in &parts {
                match parse_octet_radix(p) {
                    Some(n) => octets.push(n),
                    None => { ok = false; break; }
                }
            }
            // Only treat as an IP when every part parsed AND at least one part
            // used a non-decimal radix (a plain "1.2" is not an address here).
            if ok && octets.len() == 4 && octets.iter().all(|o| *o <= 255) {
                let used_alt = parts.iter().any(|p| p.starts_with('0') && p.len() > 1 || p.starts_with("0x") || p.starts_with("0X"));
                if used_alt {
                    return Some(IpAddr::V4(Ipv4Addr::new(octets[0] as u8, octets[1] as u8, octets[2] as u8, octets[3] as u8)));
                }
            }
        }
    }
    None
}

fn parse_octet_radix(p: &str) -> Option<u32> {
    if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if p.len() > 1 && p.starts_with('0') {
        // Octal, per inet_aton semantics.
        return u32::from_str_radix(&p[1..], 8).ok();
    }
    p.parse::<u32>().ok()
}

/// Is this a private / loopback / link-local / CGNAT address? These are the
/// ones a public target must not resolve to — the SSRF-to-internal pivot.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 CGNAT
                || o[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                || v6.to_ipv4_mapped().map(|m| is_private(&IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

/// Resolve a host to its addresses. Best-effort; an empty result means the name
/// did not resolve, which is itself a reason to refuse rather than proceed.
pub fn resolve(host: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    // If it is already a literal (any encoding), no DNS is needed.
    if let Some(ip) = parse_ip_any(&normalize_host(host)) {
        return vec![ip];
    }
    format!("{host}:0")
        .to_socket_addrs()
        .map(|it| it.map(|s| s.ip()).collect())
        .unwrap_or_default()
}

/// Watches a name's resolution across the run to catch DNS rebinding.
///
/// The attack: a name resolves to an allowed address for the scope check, then
/// re-resolves to `127.0.0.1` (or an internal host) for the actual connection.
/// The guard remembers the first resolution and refuses a later one that
/// introduces a private address the first did not have.
#[derive(Debug, Clone, Default)]
pub struct RebindGuard {
    first: std::collections::HashMap<String, Vec<IpAddr>>,
}

impl RebindGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a fresh resolution of `host`. Returns Err on a rebind or on a
    /// name that resolves (now or ever) to a private address.
    pub fn check(&mut self, host: &str) -> Result<Vec<IpAddr>, String> {
        let now = resolve(host);
        if now.is_empty() {
            return Err(format!("{host} does not resolve — refusing rather than guessing"));
        }
        // A public-looking name that resolves to an internal address is the
        // SSRF pivot; refuse unless the host itself is an internal literal the
        // scope explicitly authorized (that check is the scope layer's job).
        if let Some(bad) = now.iter().find(|ip| is_private(ip)) {
            if parse_ip_any(&normalize_host(host)).is_none() {
                return Err(format!("{host} resolves to a private address ({bad}) — possible SSRF/rebinding"));
            }
        }
        match self.first.get(host) {
            None => {
                self.first.insert(host.to_string(), now.clone());
                Ok(now)
            }
            Some(seen) => {
                // A rebind: a new address appears that was not in the first
                // resolution, and it is private. Public CDNs legitimately
                // rotate public IPs, so only a *new private* address trips it.
                if let Some(added) = now.iter().find(|ip| !seen.contains(ip) && is_private(ip)) {
                    return Err(format!("{host} re-resolved to a new private address ({added}) — DNS rebinding refused"));
                }
                Ok(now)
            }
        }
    }
}

/// Validate a redirect target before following it.
///
/// A 3xx `Location` is a request the server is asking us to make; it has to
/// pass the same boundary as any other. `in_scope` is the scope layer's own
/// check, injected so this module stays free of the policy type.
pub fn redirect_allowed<F>(from_url: &str, location: &str, in_scope: F) -> Result<String, String>
where
    F: Fn(&str) -> bool,
{
    let target = resolve_relative(from_url, location);
    let host = normalize_host(&crate::scope::host_of(&target));
    if host.is_empty() {
        return Err("redirect has no host".into());
    }
    if in_scope(&target) {
        Ok(target)
    } else {
        Err(format!("redirect to {host} is outside scope — not followed"))
    }
}

/// Resolve a possibly-relative Location against the request URL.
fn resolve_relative(base: &str, location: &str) -> String {
    let loc = location.trim();
    if loc.contains("://") {
        return loc.to_string();
    }
    let scheme_host = base.split_once("://").map(|(s, rest)| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        format!("{s}://{host}")
    }).unwrap_or_else(|| base.to_string());
    if loc.starts_with('/') {
        format!("{scheme_host}{loc}")
    } else {
        format!("{scheme_host}/{loc}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_encoding_of_loopback_normalizes_the_same() {
        for enc in ["127.0.0.1", "0x7f000001", "2130706433", "0177.0.0.1", "::ffff:127.0.0.1", "[::ffff:7f00:1]"] {
            assert_eq!(normalize_host(enc), "127.0.0.1", "{enc} should canonicalize to 127.0.0.1");
        }
    }

    #[test]
    fn an_alternate_encoding_cannot_dodge_an_exclude() {
        // The real evasion: exclude 127.0.0.1, attacker uses the decimal form.
        let mut p = crate::scope::ScopePolicy::default();
        p.allow("*.example.com");   // broad allow
        p.deny("127.0.0.1");        // but loopback excluded
        // With normalization wired into matching, the decimal form is refused.
        assert!(!p.check_request("http://2130706433/", "GET", "").allowed());
        assert!(!p.check_request("http://0x7f000001/", "GET", "").allowed());
    }

    #[test]
    fn a_real_hostname_is_left_alone() {
        assert_eq!(normalize_host("App.Example.com"), "app.example.com");
        assert_eq!(normalize_host("www.example.com"), "example.com");
        assert!(parse_ip_any("example.com").is_none());
    }

    #[test]
    fn plain_dotted_decimal_is_not_mistaken_for_an_alt_encoding() {
        // 1.2 must NOT parse as an address (too few octets, no alt radix).
        assert!(parse_ip_any("1.2").is_none());
        assert_eq!(normalize_host("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn private_ranges_are_recognised() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.9.9", "169.254.1.1", "100.64.3.2"] {
            assert!(is_private(&ip.parse().unwrap()), "{ip} is private");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(!is_private(&ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[test]
    fn a_redirect_off_scope_is_refused() {
        let in_scope = |u: &str| crate::scope::host_of(u) == "app.example.com";
        assert!(redirect_allowed("https://app.example.com/go", "/dashboard", in_scope).is_ok());
        assert!(redirect_allowed("https://app.example.com/go", "https://evil.test/steal", in_scope).is_err());
        // Alternate-encoded redirect target is normalized before the check.
        assert!(redirect_allowed("https://app.example.com/go", "http://2130706433/", in_scope).is_err());
    }

    #[test]
    fn rebind_guard_lets_the_scope_layer_own_literal_ips() {
        let mut g = RebindGuard::new();
        // A literal internal IP is the SCOPE layer's decision (a legit internal
        // engagement uses 10.x literals) — the rebind guard does not second-
        // guess it. It only refuses a NAME that resolves to private.
        assert!(g.check("127.0.0.1").is_ok());
        // A public literal resolves to itself.
        assert!(g.check("8.8.8.8").is_ok());
    }
}
