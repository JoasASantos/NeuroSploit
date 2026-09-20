# NeuroSploit × TypeSafe — benchmark (2026-09-20)

Two identical NeuroSploit engagements against the same vulnerable target — one
plain, one with **TypeSafe System One (Jev)** as a calibrated confirmation
layer. Same model, same focus, same 13 seeded vulnerabilities. Only the
`--typesafe` flag differs.

Open **`report.html`** for the full visual write-up.

## Setup

| | |
|---|---|
| Harness | NeuroSploit v4.0.0 |
| Model | `claude-opus-4-8` (subscription) |
| Target | NimbusCart / BenchMarkBurpAT · `http://localhost:3000` |
| Mode | black-box, `--recon 2`, `--vote-n 1`, `--max-agents 15` |
| Ground truth | 13 seeded scenarios (IDOR/BOLA, SQLi ×5, XSS ×4, open redirect, CRLF) |
| Solver | none — the LLM discovered and confirmed everything live |

Run commands (the only difference is `--typesafe`):

```bash
# A — no TypeSafe
NEUROSPLOIT_TYPESAFE=off neurosploit run http://localhost:3000 \
  --subscription --model anthropic:claude-opus-4-8 \
  --typesafe off --recon 2 --max-agents 15 --vote-n 1 --focus "<13 endpoints>" -v

# B — with TypeSafe (TYPESAFE_API_KEY set in env, never committed)
NEUROSPLOIT_TYPESAFE=on  neurosploit run http://localhost:3000 \
  --subscription --model anthropic:claude-opus-4-8 \
  --typesafe on  --recon 2 --max-agents 15 --vote-n 1 --focus "<13 endpoints>" -v
```

## Result

| Metric | A — no TypeSafe | B — TypeSafe |
|---|---|---|
| Targets hit | **10 / 13** | 9 / 13 |
| Findings | 16 | **18** |
| Wall-clock | 32m 12s | **26m 53s** |
| Criticals | 5 | 2 (recalibrated) |
| Belief-gate holds (POMDP) | 3 | — |
| Assurance P1–P5 | all present | all present |
| Model cost | $0 (subscription) | $0 + TypeSafe ≪ $5 |

Union coverage (both runs): **11 / 13**. Neither reached `web_sqli_second_order`
or `web_crlf_header_go`.

## Reading it honestly

- **Recall is a tie** — 10 vs 9 is within run-to-run variance at `vote-n 1`.
  TypeSafe is a judgment layer, not a recall multiplier.
- **B surfaced 2 real net-new findings** the plain run missed (`config.json`
  API-key exposure CWE-200, no-lockout brute force CWE-307) and caught
  `web_idor_invoice`.
- **TypeSafe recalibrated severity** — 5 class-inflated Criticals → 2 evidence-
  backed ones. On this target it *under-rated* one genuine critical (the BOLA
  credential dump: A = Critical 9.1, B = Low). Calibration is a dial toward
  defensibility, not a correctness oracle.
- **Harness gap found & fixed**: an earlier B collapsed to 0 findings when the
  subscription hit a session limit mid-run — NeuroSploit treated the limit
  message as a normal (exit-0) response and burned every agent. Now the
  session-limit sentinel parks the run (`fix(models)`).

## Confounders

Single samples, not averages. `vote-n 1` = no cross-model agreement in either
arm. Recall scored by class + endpoint-keyword match (coverage, not graded
proof). One target. Treat as one honest data point, not a leaderboard.

## Files

```
report.html          the visual write-up
score.py             the scorer (class + endpoint keyword match vs the 13 targets)
scores.txt           scorer output for both runs
run_a_no_typesafe/   findings.json · assurance.json · meta.json · report.html · run.log
run_b_typesafe/      findings.json · assurance.json · meta.json · report.html · run.log
```

The TypeSafe API key and any subscription tokens are **not** in these files
(env-only during the runs; verified clean before commit).
