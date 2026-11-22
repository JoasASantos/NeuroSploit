//! Safe string budgets for command output and model payloads.
//!
//! Two failure modes motivated this module:
//!
//! - `String::truncate(n)` **panics** unless `n` is a UTF-8 character
//!   boundary. Command output is arbitrary bytes — a tool that prints a
//!   multi-byte character right at the 256 KiB line was enough to take down a
//!   run. Every clip now walks back to a boundary first.
//! - Keeping only the head loses the part operators actually need: a compiler,
//!   a scanner or an exploit usually puts the verdict in the **last** lines
//!   ("0 rows", "access denied", the stack trace). The clip keeps a head and a
//!   tail with an explicit omission marker in between.
//!
//! Limits are configurable (`NEUROSPLOIT_CMD_CAP`, `NEUROSPLOIT_C2_OUTPUT_CAP`,
//! `NEUROSPLOIT_PROMPT_CAP`) and default generously: a truncated log that
//! silently drops evidence is worse than a large one that is stored once.

/// Largest boundary at or below `i`, so slicing `&s[..i]` is always valid.
pub fn boundary(s: &str, i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    let mut i = i;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Clip to at most `max` **bytes**, preserving the head and the tail and
/// marking what was omitted. Never panics on multi-byte input.
pub fn clip(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.len() <= max {
        return s.to_string();
    }
    let omitted = s.len().saturating_sub(max) + 40;
    let marker = format!("\n…[{omitted} bytes omitted]…\n");
    if marker.len() >= max {
        let cut = boundary(s, max);
        return s[..cut].to_string();
    }
    let budget = max - marker.len();
    // Favor the tail slightly: verdicts and errors live there.
    let head = budget * 2 / 5;
    let tail = budget - head;
    let h = boundary(s, head);
    let t = boundary(s, s.len().saturating_sub(tail));
    let mut out = String::with_capacity(max);
    out.push_str(&s[..h]);
    out.push_str(&marker);
    out.push_str(&s[t..]);
    out
}

/// A byte cap from the environment, clamped to something sane.
pub fn env_cap(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v >= 1024)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clips_on_a_char_boundary_without_panicking() {
        // "é" is two bytes; cutting at an odd index would panic with
        // String::truncate.
        let s = "aaaaaaaaaaéééééééééé";
        for n in 0..s.len() {
            let out = clip(s, n);
            assert!(out.len() <= n.max(1) + 64, "cap {n}: {}", out.len());
        }
    }

    #[test]
    fn keeps_head_and_tail() {
        let s = format!("HEAD{}TAIL", "x".repeat(10_000));
        let out = clip(&s, 400);
        assert!(out.starts_with("HEAD"));
        assert!(out.ends_with("TAIL"));
        assert!(out.contains("bytes omitted"));
        assert!(out.len() <= 400);
    }

    #[test]
    fn short_input_is_untouched() {
        assert_eq!(clip("hello", 100), "hello");
    }

    #[test]
    fn boundary_is_valid() {
        let s = "aé";
        assert_eq!(boundary(s, 1), 1);
        assert_eq!(boundary(s, 2), 1, "index 2 is inside 'é'");
        assert_eq!(boundary(s, 3), 3);
    }
}
