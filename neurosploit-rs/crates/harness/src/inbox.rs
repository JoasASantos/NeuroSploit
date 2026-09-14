//! Receiving what the target sends — email and SMS.
//!
//! Half the interesting authentication surface is behind something the target
//! *sends you*: a confirmation link, a 6-digit code, a password reset token. On
//! a real engagement this is where runs stop. The harness registers an account,
//! the target says "check your email", and everything past that point —
//! authenticated IDOR, privilege boundaries, the actual application — is
//! unreachable. The run reports what it could see from the doormat.
//!
//! It is also where rate-limit testing becomes real. "No throttling on the OTP
//! endpoint" is a weak finding when all you counted was HTTP 200s; it is a
//! strong one when you can show twenty distinct codes arrived and each still
//! worked.
//!
//! Two channels, one interface:
//!
//! ```text
//!   target ──email──→ mail.tm inbox ─┐
//!                                    ├─→ Message ─→ code / link
//!   target ──SMS────→ SMS provider  ─┘
//! ```
//!
//! ## Codes are extracted carefully, on purpose
//!
//! A naive "first run of digits" grabs the year out of a copyright footer, a
//! support phone number, or a price. Then the harness confidently submits
//! `2026` as the OTP, gets rejected, and concludes the code expired. So
//! [`extract_code`] scores candidates by how the surrounding text reads, and
//! returns nothing rather than a guess when nothing looks like a code —
//! because "no code found" is recoverable and a wrong code is not.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// One received message, from either channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    /// Sender address or shortcode.
    pub from: String,
    /// Recipient — which identity it arrived for.
    pub to: String,
    #[serde(default)]
    pub subject: String,
    pub body: String,
    /// Unix seconds, as reported by the provider.
    #[serde(default)]
    pub at: u64,
}

impl Message {
    /// The one-time code, if this message carries one.
    pub fn code(&self) -> Option<String> {
        extract_code(&format!("{}\n{}", self.subject, self.body))
    }
    /// The first confirmation/reset link.
    pub fn link(&self) -> Option<String> {
        extract_link(&self.body)
    }
}

/// Pull a one-time code out of a message.
///
/// Returns `None` unless something in the text actually reads like a code.
pub fn extract_code(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let bytes: Vec<char> = text.chars().collect();
    let mut best: Option<(i32, String)> = None;

    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let digits: String = bytes[start..i].iter().collect();
        // Codes are 4–8 digits. Anything longer is an id, a timestamp or a
        // card number; anything shorter is a quantity.
        if digits.len() < 4 || digits.len() > 8 {
            continue;
        }
        // A run of digits glued to other characters (an id in a URL, a version,
        // part of a longer token) is not a code.
        let before = if start == 0 { ' ' } else { bytes[start - 1] };
        let after = if i >= bytes.len() { ' ' } else { bytes[i] };
        if before.is_alphanumeric() || after.is_alphanumeric() || before == '-' || after == '-' {
            continue;
        }

        let mut score = 0i32;
        // Six digits is the overwhelmingly common shape.
        score += match digits.len() {
            6 => 3,
            4 | 5 | 8 => 2,
            _ => 1,
        };
        // What the surrounding sentence says matters more than the shape.
        let window_start = start.saturating_sub(60);
        let window_end = (i + 40).min(bytes.len());
        let window: String = bytes[window_start..window_end].iter().collect::<String>().to_lowercase();
        for kw in ["code", "otp", "one-time", "one time", "verification", "verify", "pin", "token", "confirm", "2fa", "código", "codigo", "verificação", "verificacao"] {
            if window.contains(kw) {
                score += 4;
                break;
            }
        }
        // A year in a footer looks exactly like a 4-digit code, and never is.
        if digits.len() == 4 {
            if let Ok(n) = digits.parse::<i32>() {
                if (1990..=2100).contains(&n) && (window.contains("©") || window.contains("copyright") || window.contains("all rights")) {
                    continue;
                }
            }
        }
        // Phone numbers and prices are not codes.
        if window.contains("call ") || window.contains("phone") || window.contains("tel:") || window.contains('$') || window.contains("r$") {
            score -= 3;
        }
        if lower.contains("expires") || lower.contains("expira") || lower.contains("valid for") {
            score += 1;
        }
        if best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
            best = Some((score, digits));
        }
    }
    // A candidate that only scored on shape is a guess, not a reading.
    best.filter(|(score, _)| *score >= 4).map(|(_, d)| d)
}

/// First http(s) link in a message.
pub fn extract_link(text: &str) -> Option<String> {
    let idx = text.find("http://").or_else(|| text.find("https://"))?;
    let rest = &text[idx..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == '>' || c == ')')
        .unwrap_or(rest.len());
    let link = rest[..end].trim_end_matches(['.', ',', ';', ']']).to_string();
    (link.len() > 10).then_some(link)
}

/// Where messages come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// mail.tm — free disposable inboxes, no API key. What the harness uses by
    /// default for email confirmation flows.
    MailTm { address: String, token: String },
    /// Twilio inbound SMS, polled. `sid`/`token` are account credentials; the
    /// number is the one the target texts.
    Twilio { sid: String, token: String, number: String },
    /// Any provider that can POST a webhook, received on the harness's own OOB
    /// HTTP listener. The escape hatch for the dozen SMS gateways nobody has
    /// written a client for.
    Webhook { endpoint: String, number: String },
}

/// An inbox the harness can read.
#[derive(Clone)]
pub struct Inbox {
    pub source: std::sync::Arc<Source>,
    client: reqwest::Client,
}

impl Inbox {
    /// Create a disposable email inbox on mail.tm.
    ///
    /// Two calls the provider requires in order: pick a live domain, then
    /// create the account against it. Inventing a domain gets a 422, which is
    /// how this silently failed before.
    pub async fn mail_tm() -> anyhow::Result<Inbox> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?;
        let domains: serde_json::Value =
            client.get("https://api.mail.tm/domains").send().await?.json().await?;
        let domain = domains
            .get("hydra:member")
            .and_then(|m| m.get(0))
            .and_then(|d| d.get("domain"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow::anyhow!("mail.tm returned no usable domain"))?
            .to_string();

        let local = crate::validation::canary("ns").to_lowercase();
        let address = format!("{local}@{domain}");
        let password = crate::validation::canary("pw");
        let created = client
            .post("https://api.mail.tm/accounts")
            .json(&serde_json::json!({"address": address, "password": password}))
            .send()
            .await?;
        if !created.status().is_success() {
            anyhow::bail!("mail.tm refused the account: {}", created.status());
        }
        let tok: serde_json::Value = client
            .post("https://api.mail.tm/token")
            .json(&serde_json::json!({"address": address, "password": password}))
            .send()
            .await?
            .json()
            .await?;
        let token = tok
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow::anyhow!("mail.tm issued no token"))?
            .to_string();
        Ok(Inbox { source: std::sync::Arc::new(Source::MailTm { address, token }), client })
    }

    pub fn twilio(sid: &str, token: &str, number: &str) -> Inbox {
        Inbox {
            source: std::sync::Arc::new(Source::Twilio {
                sid: sid.into(),
                token: token.into(),
                number: number.into(),
            }),
            client: reqwest::Client::new(),
        }
    }

    pub fn webhook(endpoint: &str, number: &str) -> Inbox {
        Inbox {
            source: std::sync::Arc::new(Source::Webhook { endpoint: endpoint.into(), number: number.into() }),
            client: reqwest::Client::new(),
        }
    }

    /// The address or number to hand the target.
    pub fn identity(&self) -> String {
        match &*self.source {
            Source::MailTm { address, .. } => address.clone(),
            Source::Twilio { number, .. } => number.clone(),
            Source::Webhook { number, .. } => number.clone(),
        }
    }

    /// Everything currently in the inbox, newest first.
    pub async fn messages(&self) -> anyhow::Result<Vec<Message>> {
        match &*self.source {
            Source::MailTm { token, address } => {
                let list: serde_json::Value = self
                    .client
                    .get("https://api.mail.tm/messages")
                    .bearer_auth(token)
                    .send()
                    .await?
                    .json()
                    .await?;
                let empty = vec![];
                let items = list.get("hydra:member").and_then(|m| m.as_array()).unwrap_or(&empty);
                let mut out = Vec::new();
                for item in items {
                    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                    // The list view carries only a snippet; the code is often
                    // in the part it truncates, so each message is fetched.
                    let full: serde_json::Value = self
                        .client
                        .get(format!("https://api.mail.tm/messages/{id}"))
                        .bearer_auth(token)
                        .send()
                        .await?
                        .json()
                        .await?;
                    out.push(Message {
                        id,
                        from: full.get("from").and_then(|f| f.get("address")).and_then(|a| a.as_str()).unwrap_or_default().to_string(),
                        to: address.clone(),
                        subject: full.get("subject").and_then(|s| s.as_str()).unwrap_or_default().to_string(),
                        body: full
                            .get("text")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| full.get("html").and_then(|h| h.as_array()).map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("\n")))
                            .unwrap_or_default(),
                        at: 0,
                    });
                }
                Ok(out)
            }
            Source::Twilio { sid, token, number } => {
                let url = format!("https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json?To={number}&PageSize=50");
                let resp: serde_json::Value =
                    self.client.get(url).basic_auth(sid, Some(token)).send().await?.json().await?;
                let empty = vec![];
                let items = resp.get("messages").and_then(|m| m.as_array()).unwrap_or(&empty);
                Ok(items
                    .iter()
                    .map(|m| Message {
                        id: m.get("sid").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        from: m.get("from").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        to: number.clone(),
                        subject: String::new(),
                        body: m.get("body").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        at: 0,
                    })
                    .collect())
            }
            Source::Webhook { endpoint, number } => {
                let resp = self.client.get(endpoint).send().await?.text().await?;
                let items: Vec<Message> = serde_json::from_str(&resp).unwrap_or_default();
                Ok(items.into_iter().filter(|m| m.to.is_empty() || m.to == *number).collect())
            }
        }
    }

    /// Wait for a message matching `want`, up to `timeout`.
    ///
    /// Polls, because none of these providers push. Returns `None` on timeout
    /// — which is a finding of its own: "the target never sent it" is a
    /// different result from "the code did not work".
    pub async fn wait_for<F>(&self, timeout: Duration, want: F) -> Option<Message>
    where
        F: Fn(&Message) -> bool,
    {
        let deadline = std::time::Instant::now() + timeout;
        let mut seen: Vec<String> = Vec::new();
        loop {
            if let Ok(msgs) = self.messages().await {
                for m in msgs {
                    if seen.contains(&m.id) {
                        continue;
                    }
                    seen.push(m.id.clone());
                    if want(&m) {
                        return Some(m);
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Wait for a one-time code.
    pub async fn wait_for_code(&self, timeout: Duration) -> Option<String> {
        self.wait_for(timeout, |m| m.code().is_some()).await.and_then(|m| m.code())
    }

    /// Wait for a confirmation link.
    pub async fn wait_for_link(&self, timeout: Duration) -> Option<String> {
        self.wait_for(timeout, |m| m.link().is_some()).await.and_then(|m| m.link())
    }
}

/// Evidence that an OTP/reset endpoint is not throttled.
///
/// Counting HTTP 200s is not evidence — an endpoint can accept twenty requests
/// and send one message. What matters is how many **distinct** codes actually
/// arrived, which is only observable from the receiving end. This is the
/// difference between a finding that survives a vendor's review and one that
/// does not.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeliveryBurst {
    pub requested: usize,
    pub delivered: usize,
    pub distinct_codes: usize,
    pub window_secs: u64,
    #[serde(default)]
    pub codes: Vec<String>,
}

impl DeliveryBurst {
    pub fn from_messages(requested: usize, msgs: &[Message], window_secs: u64) -> DeliveryBurst {
        let mut codes: Vec<String> = msgs.iter().filter_map(|m| m.code()).collect();
        codes.sort();
        codes.dedup();
        DeliveryBurst {
            requested,
            delivered: msgs.len(),
            distinct_codes: codes.len(),
            window_secs,
            codes,
        }
    }

    /// Is this actually a throttling failure?
    ///
    /// Two or three messages could be a retry, a user double-tapping, or the
    /// provider's own duplicate. A handful of distinct codes in one window is
    /// behaviour.
    pub fn proves_no_throttle(&self) -> bool {
        self.distinct_codes >= 5 && self.delivered >= 5
    }

    pub fn summary(&self) -> String {
        format!(
            "{} request(s) in {}s produced {} delivered message(s) carrying {} distinct code(s){}",
            self.requested,
            self.window_secs,
            self.delivered,
            self.distinct_codes,
            if self.proves_no_throttle() { "" } else { " — under the bar for a throttling claim" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(body: &str) -> Message {
        Message { id: "1".into(), body: body.into(), ..Default::default() }
    }

    #[test]
    fn a_real_otp_email_yields_its_code() {
        let m = msg("Your verification code is 483920. It expires in 10 minutes.");
        assert_eq!(m.code().as_deref(), Some("483920"));

        let pt = msg("Seu código de verificação é 5521. Não compartilhe.");
        assert_eq!(pt.code().as_deref(), Some("5521"));
    }

    #[test]
    fn a_copyright_year_is_not_a_code() {
        let m = msg("Welcome aboard!\n\nHappy testing.\n\n© 2026 Example Corp. All rights reserved.");
        assert_eq!(m.code(), None, "submitting the year as an OTP is worse than finding nothing");
    }

    #[test]
    fn ids_phone_numbers_and_prices_are_not_codes() {
        assert_eq!(extract_code("Order #99341 shipped. Call 555-0142 with questions."), None);
        assert_eq!(extract_code("Your total is $1299 including tax."), None);
        // A digit run glued into a URL path is an id, not a code.
        assert_eq!(extract_code("Open https://app.test/orders/48213 to review."), None);
    }

    #[test]
    fn the_keyworded_candidate_wins_over_a_bare_number() {
        let text = "Invoice 88213 is ready.\nYour one-time code: 119284\nThanks.";
        assert_eq!(extract_code(text).as_deref(), Some("119284"));
    }

    #[test]
    fn confirmation_links_survive_surrounding_punctuation() {
        let m = msg("Confirm here: https://app.test/verify?token=abc123def. Thanks!");
        assert_eq!(m.link().as_deref(), Some("https://app.test/verify?token=abc123def"));

        let html = msg("<a href=\"https://app.test/r/9f2\">Reset</a>");
        assert_eq!(html.link().as_deref(), Some("https://app.test/r/9f2"));
    }

    #[test]
    fn nothing_is_returned_when_nothing_looks_like_a_code() {
        assert_eq!(extract_code("Thanks for signing up. We'll be in touch."), None);
        assert_eq!(extract_link("no links here"), None);
    }

    #[test]
    fn a_throttling_claim_needs_delivered_codes_not_http_200s() {
        // Twenty requests accepted, one message sent: the endpoint returned
        // 200 nineteen times and did nothing. Not a finding.
        let one = vec![msg("Your code is 111111")];
        let weak = DeliveryBurst::from_messages(20, &one, 60);
        assert!(!weak.proves_no_throttle());
        assert!(weak.summary().contains("under the bar"));

        // Six distinct codes actually arrived. That is behaviour.
        let many: Vec<Message> = (0..6).map(|i| msg(&format!("Your code is 10000{i}"))).collect();
        let strong = DeliveryBurst::from_messages(6, &many, 45);
        assert_eq!(strong.distinct_codes, 6);
        assert!(strong.proves_no_throttle());
    }

    #[test]
    fn duplicate_codes_do_not_inflate_the_burst() {
        // A provider that redelivers the same message must not read as six
        // separate codes.
        let dupes: Vec<Message> = (0..6).map(|_| msg("Your code is 424242")).collect();
        let b = DeliveryBurst::from_messages(6, &dupes, 30);
        assert_eq!(b.distinct_codes, 1);
        assert!(!b.proves_no_throttle());
    }
}
