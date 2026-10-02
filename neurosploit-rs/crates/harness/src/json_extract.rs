//! Robust extraction of JSON from language-model replies.
//!
//! Models rarely return exactly the JSON we asked for. They wrap it in prose,
//! fence it (sometimes as ```JSON with a capitalised tag), add trailing commas
//! or `// comments`, quote with single quotes, and — most damaging — get cut
//! off mid-array by a token limit. The strict [`serde_json`] path throws on
//! every one of these and the agent's findings are lost. The two failures seen
//! on live runs were the two ends of this: `JSON parse failed` (a region was
//! found but was not valid JSON) and `no JSON array/object found` (the greedy
//! `[`…`]` span never located one).
//!
//! This module recovers both in three stages:
//!
//! 1. **Locate** every *balanced* `[...]` / `{...}` region in the reply, scanning
//!    with string- and escape-awareness so brackets inside prose (`[low] …`) or
//!    inside a string value never fool the matcher. Fenced blocks are preferred,
//!    and later regions beat earlier ones (models narrate, then answer).
//! 2. **Parse leniently**: strict `serde_json` first (the fast path for good
//!    input), then [`json5`] for the common relaxations — trailing commas,
//!    comments, single quotes and unquoted keys.
//! 3. **Repair truncation**: when a region never closes, drop the dangling
//!    partial element and append the closers the open structure still needs, so
//!    a reply cut off after three complete findings still yields three.
//!
//! Every candidate is parse-checked, so a region that cannot be made into valid
//! JSON is simply skipped — the function never returns a half-parsed value, and
//! `None` means the reply genuinely held no recoverable JSON.

use serde_json::Value;

/// Parse a model reply into a JSON value, trying each located candidate in
/// best-first order and returning the first that parses. `None` means the reply
/// contained no recoverable JSON (genuine prose, a refusal, or an empty reply).
pub fn parse_reply(text: &str) -> Option<Value> {
    for cand in candidates(text) {
        if let Some(v) = parse_lenient(&cand) {
            return Some(v);
        }
    }
    None
}

/// Parse one slice: strict JSON, then json5, then a truncation-repair retry.
pub fn parse_lenient(slice: &str) -> Option<Value> {
    let s = slice.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<Value>(s) {
        return Some(v);
    }
    if let Ok(v) = json5::from_str::<Value>(s) {
        return Some(v);
    }
    if let Some(repaired) = close_truncated(s) {
        if let Ok(v) = serde_json::from_str::<Value>(&repaired) {
            return Some(v);
        }
        if let Ok(v) = json5::from_str::<Value>(&repaired) {
            return Some(v);
        }
    }
    None
}

/// Candidate JSON slices, in the order we should try them.
fn candidates(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // Fenced blocks first, last fence winning — models draft, then give the
    // final answer in the last block.
    for block in fenced_blocks(text).into_iter().rev() {
        let (regions, _) = regions_and_truncation(block);
        if regions.is_empty() {
            out.push(block.to_string());
        } else {
            for r in regions.into_iter().rev() {
                out.push(r);
            }
        }
    }
    // Then balanced regions anywhere in the reply, again last-wins.
    let (regions, trunc) = regions_and_truncation(text);
    for r in regions.into_iter().rev() {
        out.push(r);
    }
    // If the scan hit a structure that never closed, hand the whole truncated
    // tail (from where it opened) to `parse_lenient`, which will try to close it.
    // Doing this for the *outer* opener is what keeps a cut-off array of findings
    // whole, instead of salvaging only its first complete element.
    if let Some(start) = trunc {
        out.push(text[start..].to_string());
    } else if out.is_empty() {
        if let Some(start) = text.find(|c| c == '[' || c == '{') {
            out.push(text[start..].to_string());
        }
    }
    out.dedup();
    out
}

/// The body of every ```fenced``` block, in order. A language tag on the opening
/// line (```json, ```JSON, ```json5) is irrelevant: the balanced scanner finds
/// the JSON inside regardless of it — which is exactly what the old
/// `starts_with('[')` check got wrong for a capitalised tag.
fn fenced_blocks(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("```") {
        let after = &rest[open + 3..];
        let Some(close) = after.find("```") else { break };
        out.push(after[..close].trim());
        rest = &after[close + 3..];
    }
    out
}

/// Every balanced top-level `[...]` / `{...}` region, in order of appearance,
/// plus — if the scan reaches an opener that never closes — the byte index where
/// that truncated structure begins. Brackets inside string literals (and escaped
/// quotes) are ignored, so prose like `[low] …` or a payload string containing
/// `]` does not break matching.
///
/// When an opener does not close, scanning stops there: everything after it is
/// *inside* that unclosed structure, not an independent region, so the inner
/// objects of a cut-off array must not be mistaken for the whole answer.
fn regions_and_truncation(text: &str) -> (Vec<String>, Option<usize>) {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' || bytes[i] == b'{' {
            match scan_balanced(bytes, i) {
                Some(end) => {
                    out.push(text[i..end].to_string());
                    i = end;
                    continue;
                }
                None => return (out, Some(i)),
            }
        }
        i += 1;
    }
    (out, None)
}

/// From an opener at `start`, return the byte index just past its matching
/// closer, or `None` if the structure never closes (a truncated reply). JSON
/// structural bytes are all ASCII and never appear inside a UTF-8 multibyte
/// sequence, so byte scanning is UTF-8-safe and the returned index lands on a
/// char boundary.
fn scan_balanced(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut esc = false;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'[' | b'{' => depth += 1,
                b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Repair a reply cut off mid-structure: cut back to the last complete element
/// (a closed container, or the position just before the last comma) and append
/// the closers the still-open containers need. Returns `None` when nothing is
/// open to close, or there is no complete element to cut back to.
fn close_truncated(slice: &str) -> Option<String> {
    let bytes = slice.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut in_str = false;
    let mut esc = false;
    // (byte index to cut to, open-container stack at that point).
    let mut cut: Option<(usize, Vec<u8>)> = None;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'[' => stack.push(b']'),
                b'{' => stack.push(b'}'),
                b']' | b'}' => {
                    stack.pop();
                    // A complete element just closed: cutting here keeps it.
                    cut = Some((i + 1, stack.clone()));
                }
                // Between elements: cut before the comma, dropping whatever
                // partial element follows it.
                b',' => cut = Some((i, stack.clone())),
                _ => {}
            }
        }
        i += 1;
    }
    let (idx, open) = cut?;
    if open.is_empty() {
        return None;
    }
    let mut repaired = slice[..idx].trim_end().to_string();
    if repaired.ends_with(',') {
        repaired.pop();
    }
    for close in open.iter().rev() {
        repaired.push(*close as char);
    }
    Some(repaired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_is_untouched() {
        let v = parse_reply(r#"[{"title":"x"}]"#).unwrap();
        assert!(v.is_array());
    }

    #[test]
    fn prose_brackets_before_the_answer_are_ignored() {
        // `[low] …` is a balanced `[...]` region but not valid JSON; the real
        // answer is the fenced block.
        let t = "[low] cookie missing Secure\n\n```json\n[{\"title\":\"real\"}]\n```";
        let v = parse_reply(t).unwrap();
        assert_eq!(v[0]["title"], "real");
    }

    #[test]
    fn capitalised_fence_tag_still_parses() {
        let t = "```JSON\n[{\"title\":\"x\"}]\n```";
        assert!(parse_reply(t).unwrap().is_array());
    }

    #[test]
    fn last_block_wins() {
        let t = "```json\n[{\"title\":\"draft\"}]\n```\nthen\n```json\n[{\"title\":\"final\"}]\n```";
        assert_eq!(parse_reply(t).unwrap()[0]["title"], "final");
    }

    #[test]
    fn trailing_comma_comments_and_single_quotes() {
        let t = "```json5\n[ {'title': 'x'}, ] // note\n```";
        let v = parse_reply(t).unwrap();
        assert_eq!(v[0]["title"], "x");
    }

    #[test]
    fn bracket_inside_a_string_value() {
        let t = r#"[{"title":"he said ]"}]"#;
        assert_eq!(parse_reply(t).unwrap()[0]["title"], "he said ]");
    }

    #[test]
    fn truncated_array_keeps_the_complete_elements() {
        // Cut off by a token limit mid-way through the third object.
        let t = r#"[{"title":"a"},{"title":"b"},{"title":"#;
        let v = parse_reply(t).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[1]["title"], "b");
    }

    #[test]
    fn truncated_unclosed_string_in_value() {
        let t = r#"[{"title":"a"},{"title":"bbb"#;
        let v = parse_reply(t).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["title"], "a");
    }

    #[test]
    fn pure_prose_yields_none() {
        assert!(parse_reply("I could not find any injectable parameters.").is_none());
    }

    #[test]
    fn empty_array_is_recovered_not_lost() {
        assert!(parse_reply("```json\n[]\n```").unwrap().as_array().unwrap().is_empty());
    }
}
