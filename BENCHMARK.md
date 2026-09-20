# NeuroSploit vs. the open-source AI pentest agents

**A rough benchmark, written honestly.** Last updated 14 September 2026.

This is a capability comparison, not a scored competition. Nobody in this
space has published a head-to-head on a shared target set, so anyone claiming
a rank order — including this document — is comparing designs, not results.
Where NeuroSploit is behind, it says so. The table is the summary; the prose below is only the honest caveats.

The tools compared: [Strix](https://github.com/usestrix/strix) (Apache 2.0),
[Shannon](https://github.com/KeygraphHQ/shannon) (AGPLv3, Keygraph),
[Penligent](https://www.penligent.ai/) (commercial SaaS),
[PentAGI](https://github.com/vxcontrol/pentagi) and
[PentestGPT](https://github.com/GreyDGL/PentestGPT) (open source), with
[XBOW](https://xbow.com/) as the commercial reference point.

---

## The short version

| | Strix | Shannon | Penligent | NeuroSploit |
|---|---|---|---|---|
| Language | Python | Node + Docker | SaaS | Rust (+ Node web console) |
| Black-box | ✅ | ⚠️ needs source | ✅ | ✅ |
| White-box | ✅ SAST+DAST | ✅ core design | ⚠️ | ✅ + grey-box |
| Browser validation | ✅ built-in | ✅ | ✅ | ✅ Playwright, XSS proven by execution |
| Intercepting proxy | ✅ Caido | — | ✅ Burp | ✅ own interceptor + Burp/Caido/ZAP/mitmproxy |
| Container isolation | ✅ | ✅ ephemeral Docker | ✅ | ✅ Kali docker/podman (no host net, no socket) |
| Exploit-only reporting | ✅ "working PoCs" | ✅ "no exploit, no report" | ✅ | ⚠️ **different rule — see below** |
| CVSS | tag on the finding | not scored | ✅ | ✅ **evidence-graded, computed not guessed** |
| Multi-model adversarial vote | — | — | — | ✅ |
| Signed authorization (capability tokens) | — | — | — | ✅ |
| Hash-chained audit trail | — | — | — | ✅ |
| OT/SCADA/ICS safety policy | — | — | — | ✅ |
| Internal network / AD attack graph | — | — | — | ✅ |
| Self-hosted OOB channel (blind SSRF/XXE/RCE) | via tools | — | ✅ Burp | ✅ own DNS+HTTP listeners |
| Fail-closed egress (VPN/bastion/tunnel) | — | — | — | ✅ |
| WAF-aware inference (block ≠ "not vulnerable") | — | — | — | ✅ |
| Calibrated adjudication (TypeSafe System One) | — | — | — | ✅ evidence-graded, data-type aware |
| PoC re-validation (re-run, demote what's gone) | — | — | — | ✅ |
| Compliance mapping (PCI-DSS/HIPAA/SOC 2) | SOC2/ISO/PCI report shapes | — | ✅ | ✅ control-level, disclaimer enforced |
| Deterministic per-CWE validators | — | — | — | ✅ 27 classes |
| FAIR loss quantification | — | — | — | ✅ |
| Provenance / watermarking | — | — | — | ✅ |
| Published benchmark results | dir exists, empty | — | marketing | ❌ **none, including this one** |
| Stars / adoption | growing | ~40k | commercial | small |

---

## Where NeuroSploit is behind — honestly

- **Container isolation is young.** It runs commands in a Kali docker/podman
  container (no host net, no socket, `no-new-privileges`), but wiring *every*
  agent-authored command through it is still partial.
- **TLS interception delegates to the tools.** The own interceptor records HTTP
  fully and tunnels HTTPS honestly; decrypted HTTPS chains to Burp/Caido/ZAP.
- **No cross-tool benchmark.** The only run published here is with/without
  TypeSafe on one target. This document is not evidence of comparative performance.
- **Adoption.** Shannon has ~40k stars and a company; sharp edges get found by users.
- **Exploit-dev ergonomics.** Strix's interactive Python PoC sandbox is nicer than agent-authored scripts.

## So: Strix or NeuroSploit?

Different halves of the problem. Strix optimises *finding things* and is the
more finished product to hand someone today. NeuroSploit optimises *being able
to defend what you reported*: signed scope, per-action audit, a recomputable
CVSS, findings neither silently dropped nor inflated, OT rules in code, and now
TypeSafe calibrated adjudication. Better in front of a client's legal and
compliance team; still closing the isolation and cross-tool-benchmark gaps.

## Current scale

| | |
|---|---|
| Agents / skills | 446 (255 vulnerability, plus recon, code, infra, AI, chains, meta) |
| Deterministic validators | 27 CWE classes with evidence preconditions |
| Rust modules | 47 |
| Rust LOC | ~24k |
| Tests | 383, all passing |

## Next, to make this a real benchmark

1. Ephemeral container execution (closes the largest gap).
2. Own the request stream — a real intercepting proxy.
3. Run all four tools against a fixed target set (Juice Shop, WebGoat, a
   deliberately vulnerable API, one real authorized scope) and publish:
   true positives, false positives, time, and cost per finding.
4. Publish the CVSS deltas — where the evidence-graded score differs from the
   by-class score, and which one the target's own team agreed with.
