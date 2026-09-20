# NeuroSploit + TypeSafe — benchmark (2026-09-20)

NeuroSploit driving **TypeSafe System One (Jev)** against a web app seeded with
13 vulnerabilities, black-box, no solver. Every scenario is confirmed with a
live receipt, and severity is graded from the evidence and the kind of data
exposed, not from the vulnerability class.

Open **`report.html`** for the visual write-up.

## Setup

| | |
|---|---|
| Harness | NeuroSploit v4.1.0 |
| Model | `claude-opus-4-8` (subscription) |
| Target | NimbusCart / BenchMarkBurpAT · `http://localhost:3000` |
| Mode | black-box, `--typesafe on`, `--vote-n 1` |
| Ground truth | 13 seeded scenarios (SQLi ×5, XSS ×4, IDOR/BOLA ×2, open redirect, CRLF) |
| Solver | none — the LLM discovered and confirmed everything live |

## Result (A vs B·TS, gap re-test)

Same gap scenarios run without TypeSafe (A) and with (B). Both arms now close the
previously-missed CRLF, second-order SQLi and UNION SQLi (the chaining/skill
fixes are prompt-level). TypeSafe's difference is severity shape: it consolidates
the Low tail into fewer, better-justified High findings and keeps the
credential-dump BOLA at Critical.

### Coverage

- **Scenario coverage: 13 / 13** — every seeded class confirmed with a
  reproducible receipt.
- **3 Critical**, including the object-level auth flaw on `GET /api/v2/users/:id`
  (a customer token reads any user's plaintext password + API key).
- Chained beyond the seeded set into **full admin takeover** (BOLA-leaked admin
  credential → `/admin`), a **GraphQL authorization bypass**, secrets in
  `/config.json`, and an authenticated RCE via report-template upload.

## Severity is computed, and data-type aware

The score comes from the FIRST v3.1 equation, graded on two axes: whether
impact was demonstrated, and the **kind of data** that impact touched. A
credential or API-key exposure grants the confidentiality metric on its own, so
the credential-dump BOLA holds **Critical** rather than being softened to a
generic access-control note. TypeSafe's role is calibration: it keeps a
demonstrated secret exposure at its true weight while deflating a
class-inflated finding that shows no real impact. It never resurrects a rejected
claim; the operator owns the final severity.

## Confounders

One target, single sample, `vote-n 1` (no cross-model agreement). Coverage is a
class + endpoint match against the ground truth, so a match is a confirmed
receipt, not a graded proof. Treat as one honest data point, not a leaderboard.

## Files

```
report.html   the visual write-up
score.py      the scorer (class + endpoint match vs the 13 scenarios)
scores.txt    scorer output
run/          findings.json · assurance.json · meta.json · report.html · run.log
```

No secrets are committed (the TypeSafe key was env-only during the run,
verified clean before commit).
