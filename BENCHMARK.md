# NeuroSploit vs. the open-source AI pentest agents

**A rough benchmark, written honestly.** Last updated 14 September 2026.

This is a capability comparison, not a scored competition. Nobody in this
space has published a head-to-head on a shared target set, so anyone claiming
a rank order — including this document — is comparing designs, not results.
Where NeuroSploit is behind, it says so.

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
| Intercepting proxy | ✅ Caido | — | ✅ Burp | ⚠️ upstream proxy only |
| Container isolation | ✅ | ✅ ephemeral Docker | ✅ | ❌ **runs on the host** |
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
| FAIR loss quantification | — | — | — | ✅ |
| Provenance / watermarking | — | — | — | ✅ |
| Published benchmark results | dir exists, empty | — | marketing | ❌ **none, including this one** |
| Stars / adoption | growing | ~40k | commercial | small |

---

## Where NeuroSploit is genuinely ahead

**1. Evidence is a first-class object, not a field on a finding.**
Every claim carries an evidence ledger (`E01`, `E02`, …), and a claim's
asserted status can never outrun its citations. A finding whose impact loses
its evidence is not deleted — it is *rewritten* down to the mechanic that
survived, and only rejected if nothing security-relevant is left:

```rust
if remove_unproven_impact(f).still_security_relevant() { retain_and_rewrite() }
else { reject() }
```

Strix and Shannon both take the simpler rule — no exploit, no report. That is
a good rule and it produces clean reports, but it throws away the middle
ground, and the middle ground is where most real engagements live: a
rate-limit failure you measured but could not chain, a credential path you
proved up to the authenticated surface. NeuroSploit keeps those, downgraded
and labelled, instead of discarding them or inflating them.

**2. CVSS is computed, not asked for.**
The model proposes metrics and must point each one at evidence; a
deterministic calculator produces the number; a demonstrated-impact ladder
caps it (*reached* < *read data* < *wrote data* < *RCE* < *crossed systems*).
So SQL injection without extraction lands Medium/High and the same class with
a sensitive table read lands High/Critical — by class it would be Critical
every time, which is how scanners produce reports nobody believes.

**3. Authorization is enforced in code, not in a prompt.**
Scope is a signed capability token (HMAC, expiry, max action, risk ceiling)
that acts as a ceiling nothing in-session can widen — a bug we found and fixed
when `/inscope` managed to widen scope past its own grant. Every action lands
in a hash-chained audit log. No other tool on this list has an answer for
"prove the agent stayed inside what the client authorized" beyond "we told it
to".

**4. OT/SCADA/ICS is modelled, not banned.**
`effective_risk = action_risk + asset_criticality + protocol_risk +
privilege_level + blast_radius`, scaled by environment. The OT profile forbids
write/disruptive *action kinds* and specific industrial function codes
(Modbus 5/6/8/15/16/22/23/43, S7 0x28/0x29, DNP3 13/14/18) while still
allowing the reads OT findings actually come from. Calibrating that took a
real correction: our first ceiling refused a plain read of a critical PLC,
which would have made the whole profile useless.

**5. Internal network and AD as a graph.**
The layered taxonomy (Asset → Exposure → Weakness → Credential → Privilege →
Movement → Crown Jewel, with business impact, detection and remediation on the
**edges**) plus the credential→identity→permission→machine loop. The output
that matters is `choke_points()`: the single edge whose removal cuts the most
value to crown jewels. A CVSS-sorted list of 40 findings cannot answer "what
do we fix first"; this can. The web-focused tools do not attempt this at all.

**6. Provenance.** Per-build fingerprint, `JOASNSCOPE` sigil on every canary,
signed run manifests, and a structural signature that survives rewording but
not a changed result set. Nobody else on this list can tell you whether a
report that came back to them is theirs.

**7. Resilience.** Model fallback, pause on quota exhaustion with every
finding kept, resume on a different backend, and "report from where it
stopped". Long engagements die of token exhaustion more often than of bugs.

---

## Where NeuroSploit is behind — honestly

**1. No container isolation.** Strix and Shannon run each scan in an ephemeral
container. NeuroSploit runs on the operator's host. For a tool that executes
attacker-supplied-shaped payloads this is the largest single gap in the
comparison, and the next thing worth building.

**2. No real intercepting proxy.** Strix ships Caido integration; Penligent
drives Burp. NeuroSploit can route through an upstream proxy — and now through
a VPN, bastion, or Cloudflare tunnel, fail-closed — but it does not own the
request/response stream, which limits replay fidelity and passive discovery.

**3. Nobody has run it against a benchmark.** Strix has an empty `benchmarks/`
directory, Shannon publishes none, and neither does this project. Until
NeuroSploit is run against something like a Juice Shop / DVWA / OWASP
Benchmark suite alongside the others, every claim in the "ahead" section above
is an argument about design. **This document is not evidence of performance.**

**4. Adoption.** Shannon has roughly 40k stars and a company behind it. Most
of the sharp edges in a security tool are found by other people using it.

**5. Exploit-development ergonomics.** Strix's Python sandbox for writing PoCs
interactively is better developer experience than our agent-authored scripts.

**6. Compliance report templates.** Strix advertises SOC 2 / ISO 27001 / PCI
DSS report shapes. Ours is one (good) template.

---

## So: Strix or NeuroSploit?

**If you want a well-packaged autonomous scanner today**, with container
isolation, a proxy, a Python exploit sandbox and compliance report templates —
Strix is the more finished product, and its team is shipping.

**If the engagement has to withstand scrutiny** — a signed scope you can prove
you stayed inside, an audit trail per action, a CVSS number someone can
recompute from the evidence, findings that were not silently dropped or
silently inflated, and OT rules that are enforced by code — NeuroSploit is
built for that and Strix is not attempting it.

They are aimed at different halves of the problem. Strix optimises *finding
things*; NeuroSploit optimises *being able to defend what you reported*. A
harness that finds ten bugs and cannot show its work is not obviously better
than one that finds six and can.

The honest summary: **Strix is the better tool to hand someone today;
NeuroSploit is the better tool to put in front of a client's legal and
compliance team.** Closing the isolation and proxy gaps, then publishing a
real benchmark run, is what would make that a comparison of results instead of
a comparison of intentions.

---

## Current scale

| | |
|---|---|
| Agents / skills | 446 (255 vulnerability, plus recon, code, infra, AI, chains, meta) |
| Deterministic validators | 22 CWE classes with evidence preconditions |
| Rust modules | 37 |
| Rust LOC | ~24k |
| Tests | 296, all passing |

## Next, to make this a real benchmark

1. Ephemeral container execution (closes the largest gap).
2. Own the request stream — a real intercepting proxy.
3. Run all four tools against a fixed target set (Juice Shop, WebGoat, a
   deliberately vulnerable API, one real authorized scope) and publish:
   true positives, false positives, time, and cost per finding.
4. Publish the CVSS deltas — where the evidence-graded score differs from the
   by-class score, and which one the target's own team agreed with.
