//! Command rectification for the REPL.
//!
//! A mistyped command used to cost the operator a full round trip: `unknown
//! command '/staus' — try /help`, then reading the help, then retyping. During a
//! live run that is the worst possible moment to lose your place. This module
//! turns a typo into either the command that was obviously meant, or a short
//! list of what was probably meant — never a silent guess.
//!
//! Three rules, in order, and the order is the point:
//!
//! 1. **Accepted as typed** wins over everything. The dispatch accepts ~70
//!    literals including aliases (`/q`, `/url`, `/log`), so correction must only
//!    ever see input the dispatch would have rejected — otherwise `/url` gets
//!    "corrected" to `/ua` and a working command starts doing something else.
//! 2. **Unique prefix**: `/stat` completes to `/status` when nothing else starts
//!    that way. This is what Tab would have done.
//! 3. **Edit distance** with transpositions (`/staus`, `/sttaus` → `/status`),
//!    with the budget scaled to word length, and only when one candidate is
//!    strictly closer than the runner-up. A tie is ambiguity, and ambiguity is
//!    reported, not resolved — running the wrong command against a live target
//!    is worse than asking.
//!
//! Arguments get the same treatment where a mistake has one obvious reading: a
//! bare host is a URL missing its scheme, and an out-of-range count is a clamp
//! with a note, not a silent default.

/// What to do with an input command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// The dispatch accepts it as typed.
    Accepted,
    /// Unambiguously a typo for `to`; `note` explains the substitution.
    Corrected { to: String, note: String },
    /// Several equally plausible commands — the operator has to pick.
    Ambiguous(Vec<String>),
    /// Nothing close enough; `Vec` holds any weak suggestions (possibly empty).
    Unknown(Vec<String>),
}

/// Damerau-Levenshtein (optimal string alignment) distance.
///
/// Plain Levenshtein scores a transposition as two edits, which is exactly the
/// typo a fast typist makes most (`/sttaus`); counting it as one is what lets a
/// tight budget still catch it.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate().take(n + 1) {
        row[0] = i;
    }
    for j in 0..=m {
        d[0][j] = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

/// Edit budget for a word of this length. Two edits on `/ua` would reach half
/// the command list, so short commands get a tighter budget than long ones.
fn budget(len: usize) -> usize {
    match len {
        0..=3 => 0,
        4..=5 => 1,
        _ => 2,
    }
}

/// Decide what a typed command should become. `accepted` is every literal the
/// dispatch handles, aliases included.
pub fn rectify_command(input: &str, accepted: &[&str]) -> Fix {
    let raw = input.trim();
    if raw.is_empty() {
        return Fix::Unknown(vec![]);
    }
    let lower = raw.to_lowercase();
    if accepted.iter().any(|c| *c == lower) {
        return Fix::Accepted;
    }

    // A command typed without its slash (`status`) is a command, not prose —
    // prose does not collide with the dispatch table.
    let slashed = if lower.starts_with('/') { lower.clone() } else { format!("/{lower}") };
    if !lower.starts_with('/') && accepted.iter().any(|c| *c == slashed) {
        return Fix::Corrected { to: slashed.clone(), note: format!("read '{raw}' as '{slashed}'") };
    }

    // Unique prefix — what Tab completion would have produced.
    if slashed.len() >= 3 {
        let pre: Vec<&str> = accepted.iter().copied().filter(|c| c.starts_with(&slashed)).collect();
        if pre.len() == 1 {
            return Fix::Corrected { to: pre[0].to_string(), note: format!("completed '{raw}' → '{}'", pre[0]) };
        }
        if pre.len() > 1 {
            let mut v: Vec<String> = pre.iter().map(|s| s.to_string()).collect();
            v.sort();
            v.dedup();
            return Fix::Ambiguous(v);
        }
    }

    let mut scored: Vec<(usize, &str)> = accepted.iter().map(|c| (distance(&slashed, c), *c)).collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    let budget = budget(slashed.len());
    let best = scored.first().copied();

    if let Some((d0, c0)) = best {
        if d0 <= budget {
            let runner_up = scored.iter().skip(1).find(|(_, c)| *c != c0).map(|(d, _)| *d).unwrap_or(usize::MAX);
            if d0 < runner_up {
                return Fix::Corrected { to: c0.to_string(), note: format!("corrected '{raw}' → '{c0}'") };
            }
            let tied: Vec<String> = scored.iter().filter(|(d, _)| *d == d0).map(|(_, c)| c.to_string()).collect();
            return Fix::Ambiguous(tied);
        }
    }
    // Nothing within budget: offer the nearest few as a hint, not a correction.
    let hints: Vec<String> = scored.iter().filter(|(d, _)| *d <= budget + 2).take(3).map(|(_, c)| c.to_string()).collect();
    Fix::Unknown(hints)
}

/// Normalize a target the way an operator meant it: add the missing scheme, fix
/// a mistyped one, and drop trailing punctuation a shell or a paste left behind.
/// Returns `None` when the input is already fine.
pub fn rectify_url(input: &str) -> Option<String> {
    let raw = input.trim();
    if raw.is_empty() {
        return None;
    }
    let mut s = raw.trim_end_matches(['.', ',', ';', ')', '\'', '"']).to_string();
    let mut changed = s != raw;

    // Common near-misses of the scheme, including the single-slash paste.
    for (bad, good) in [
        ("htp://", "http://"),
        ("htttp://", "http://"),
        ("htps://", "https://"),
        ("htpps://", "https://"),
        ("httpss://", "https://"),
        ("hhttp://", "http://"),
        ("http:/", "http://"),
        ("https:/", "https://"),
    ] {
        if s.starts_with(bad) && !s.starts_with(good) {
            s = format!("{good}{}", &s[bad.len()..]);
            changed = true;
            break;
        }
    }

    if !s.contains("://") {
        // A local path is a repo, not a URL — leave it for /repo to handle.
        if s.starts_with('/') || s.starts_with("./") || s.starts_with("~") {
            return None;
        }
        s = format!("https://{s}");
        changed = true;
    }
    if changed {
        Some(s)
    } else {
        None
    }
}

/// Parse a count, clamped into range. Returns the value and an optional note
/// explaining what was changed — an out-of-range number is a typo worth
/// reporting, and silently falling back to the old value hides it.
pub fn rectify_count(input: &str, min: usize, max: usize, current: usize) -> (usize, Option<String>) {
    let t = input.trim();
    if t.is_empty() {
        return (current, None);
    }
    // Tolerate "3x", "3 votes", "v3" — the digits are the intent.
    let digits: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
    let Ok(n) = digits.parse::<usize>() else {
        return (current, Some(format!("'{t}' is not a number — keeping {current}")));
    };
    if n < min {
        (min, Some(format!("{n} is below the minimum — using {min}")))
    } else if n > max {
        (max, Some(format!("{n} is above the maximum — using {max}")))
    } else if digits != t {
        (n, Some(format!("read '{t}' as {n}")))
    } else {
        (n, None)
    }
}

/// Nearest `provider:model` in the catalog, for `/model` typos. Only returns a
/// candidate when it is close enough to be the same identifier mistyped.
pub fn nearest_model(input: &str, catalog: &[String]) -> Option<String> {
    let q = input.trim().to_lowercase();
    if q.is_empty() || catalog.iter().any(|m| m.to_lowercase() == q) {
        return None;
    }
    let mut best: Option<(usize, &String)> = None;
    for m in catalog {
        let d = distance(&q, &m.to_lowercase());
        if best.map(|(bd, _)| d < bd).unwrap_or(true) {
            best = Some((d, m));
        }
    }
    // Scale with the identifier's length: `gpt-5.4` and `gpt-5.1` differ by one
    // character and are different models, so the budget has to stay tight.
    best.filter(|(d, m)| *d <= (m.len() / 6).clamp(1, 3)).map(|(_, m)| m.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCEPTED: &[&str] = &[
        "/help", "/status", "/stop", "/show", "/sub", "/run", "/runs", "/report", "/results",
        "/target", "/ua", "/url", "/model", "/models", "/mcp", "/only", "/onboard", "/q", "/quit",
        "/log", "/logs", "/votes", "/recon", "/repo",
    ];

    #[test]
    fn an_accepted_alias_is_never_rewritten() {
        // The regression this whole ordering exists to prevent: /url is a real
        // alias and must not be "corrected" to the nearby /ua.
        for c in ["/url", "/ua", "/q", "/log", "/models"] {
            assert_eq!(rectify_command(c, ACCEPTED), Fix::Accepted, "{c}");
        }
    }

    #[test]
    fn a_transposition_is_one_edit_away() {
        assert_eq!(distance("/staus", "/status"), 1, "a dropped character");
        assert_eq!(distance("/sttaus", "/status"), 1, "a swapped pair is one edit, not two");
        assert_eq!(distance("/status", "/statsu"), 1);
        match rectify_command("/staus", ACCEPTED) {
            Fix::Corrected { to, .. } => assert_eq!(to, "/status"),
            other => panic!("expected a correction, got {other:?}"),
        }
    }

    #[test]
    fn a_unique_prefix_completes() {
        match rectify_command("/onb", ACCEPTED) {
            Fix::Corrected { to, .. } => assert_eq!(to, "/onboard"),
            other => panic!("expected completion, got {other:?}"),
        }
    }

    #[test]
    fn a_shared_prefix_asks_instead_of_guessing() {
        match rectify_command("/ru", ACCEPTED) {
            Fix::Ambiguous(v) => assert_eq!(v, vec!["/run".to_string(), "/runs".to_string()]),
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_slash_is_read_as_the_command() {
        match rectify_command("status", ACCEPTED) {
            Fix::Corrected { to, .. } => assert_eq!(to, "/status"),
            other => panic!("expected /status, got {other:?}"),
        }
    }

    #[test]
    fn nonsense_is_not_forced_onto_a_command() {
        match rectify_command("/zzzzzzzz", ACCEPTED) {
            Fix::Unknown(_) => {}
            other => panic!("expected unknown, got {other:?}"),
        }
    }

    #[test]
    fn short_commands_get_no_edit_budget() {
        // With a budget, "/ub" would land on "/ua" or "/sub" — both wrong, and
        // both a command that changes how the engagement runs.
        match rectify_command("/ub", ACCEPTED) {
            Fix::Unknown(_) => {}
            other => panic!("expected unknown for a 3-char typo, got {other:?}"),
        }
    }

    #[test]
    fn urls_get_the_scheme_they_were_missing() {
        assert_eq!(rectify_url("example.com").as_deref(), Some("https://example.com"));
        assert_eq!(rectify_url("htp://example.com").as_deref(), Some("http://example.com"));
        assert_eq!(rectify_url("https:/example.com").as_deref(), Some("https://example.com"));
        assert_eq!(rectify_url("https://example.com/x,").as_deref(), Some("https://example.com/x"));
        assert_eq!(rectify_url("https://example.com"), None, "a correct URL is left alone");
        assert_eq!(rectify_url("/opt/src/repo"), None, "a local path is not a URL");
    }

    #[test]
    fn counts_clamp_and_say_so() {
        assert_eq!(rectify_count("3", 1, 9, 3), (3, None));
        let (v, note) = rectify_count("99", 1, 9, 3);
        assert_eq!(v, 9);
        assert!(note.unwrap().contains("above the maximum"));
        let (v, note) = rectify_count("banana", 1, 9, 4);
        assert_eq!(v, 4);
        assert!(note.unwrap().contains("not a number"));
        let (v, note) = rectify_count("5 votes", 1, 9, 3);
        assert_eq!(v, 5);
        assert!(note.is_some());
    }

    #[test]
    fn a_near_model_id_is_offered_but_a_sibling_version_is_not() {
        let catalog: Vec<String> = vec!["openai:gpt-5.4".into(), "anthropic:claude-opus-5".into()];
        assert_eq!(nearest_model("openai:gpt5.4", &catalog).as_deref(), Some("openai:gpt-5.4"));
        assert_eq!(nearest_model("openai:gpt-5.4", &catalog), None, "an exact id needs no fix");
    }
}
