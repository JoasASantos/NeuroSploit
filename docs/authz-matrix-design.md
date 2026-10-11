# Design: Authorization Matrix Engine

## Implementation status (2026-10-07)

- **Slice 1 — validator core: DONE.** `validation.rs`: `Evidence.{matrix,oracle}`,
  `Expect`/`MatrixProbe`/`OracleProbe`, `AuthzMatrixValidator` (CWE 862/863/285,
  split out of `IdorValidator`), the 403-vs-business-error oracle, the judge
  override, title routing, 7 unit tests.
- **Slice 2 — identity fixtures: DONE.** `creds.rs`: `Identity.{tier,known_id}`,
  `Tier`, `SampleValues`, `Identity::{tier_kind,expected,is_explicit_anonymous}`,
  `Creds::{authz_matrix_ready,highest_identity}`, parser for `identities`/
  `sample_values` + anonymous-preserving `retain`, 3 unit tests.
- **Slice 3 — engine: DONE.** `authz_matrix.rs`: `Route`/`RouteKind`/
  `RouteInventory` (template dedup), `run`/`run_pass` (generic over an async
  `send` closure — no new dep), `send_via` (reqwest adapter), scope + budget
  guards, non-existent-id oracle, 11 unit tests. Registered in `lib.rs`.
  Workspace: **420 tests green**.
- **Pipeline plumbing: DONE.** `types.rs`: `RunConfig.{authz_matrix, creds_file}`.
  `pipeline.rs`: `endpoints_from_recon` (parses the recon JSON `endpoints`/`apis`),
  `authz_matrix_pass` (loads creds, builds inventory, reqwest client, `run_pass`,
  400-request cap), called as step 4b right after `validate_with_persist` and
  merged into `findings`. `app/src/main.rs`: global `--authz-matrix on|off|auto`,
  and `--creds` now also populates `cfg.creds_file`. Workspace builds clean;
  harness 420 tests green. (Pre-existing unrelated repl test `/sandbox` failure
  is not touched by this change.)

**Usage:** `neurosploit run <url> --creds creds.yaml --authz-matrix auto`, with a
`creds.yaml` carrying the multi-identity block from the `creds.rs` module doc.

---

Status: proposal · Target crate: `crates/harness` · Touches: `validation.rs`, `pipeline.rs`, `scope.rs`/`creds.rs`, new `authz_matrix.rs`, `types.rs`

## Problem

Broken authorization is the dominant finding class in real backoffice/business
apps, and it is **systemic**: one missing check repeats across dozens of routes
("read-only role can write", "permission declared but never required",
"protected route served to anonymous"). The current engine tests one class at a
time, usually with one identity. `IdorValidator` already proves object-level
access (BOLA) from an `identity_a`/`identity_b` pair, but there is no engine that
sweeps the **whole route surface against every identity** and decides
function-level authorization (BFLA), missing-auth, and read-only-can-write.

This design adds that engine and a deterministic validator for it, reusing the
existing `Exchange`/`Evidence`/`Verdict`/`CweValidator` machinery.

## Core idea

```
  recon ──▶ RouteInventory ─┐
                            ├─▶ AuthzMatrix.run() ─▶ Finding{ evidence.matrix } ─▶ judge()/apply() ─▶ report
  creds.yaml ─▶ IdentitySet ┘                                                         │
                                                              AuthzMatrixValidator ◀──┘
```

The engine produces ordinary `Finding`s carrying a new `Evidence.matrix`; they
flow through the same `validation::judge` path as every other finding, so CVSS
grading, voting reconciliation, scope withholding and the assurance bundle all
work unchanged.

## 1. Data model (`validation.rs` + `types.rs`)

Extend `Evidence` (all `#[serde(default)]`, fully backward compatible):

```rust
pub struct Evidence {
    // … existing fields (baseline, attack, repeats, marker, identity_a/b, …)
    /// One probe per identity for a single route+method.
    #[serde(default)]
    pub matrix: Vec<MatrixProbe>,
    /// The same route+method as a should-be-denied identity, probed with a
    /// well-formed NON-EXISTENT id (the 403-vs-business-error oracle).
    #[serde(default)]
    pub oracle: Option<OracleProbe>,
}

/// Privilege tier an identity is expected to have on a route.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expect { Allow, Deny }

pub struct MatrixProbe {
    pub identity: String,     // "admin" | "readonly" | "tenantB" | "anonymous"
    pub expect: Expect,       // what policy SAYS should happen
    pub exchange: Exchange,   // what actually happened (reuses Exchange)
}

pub struct OracleProbe {
    /// Denied identity calling a WRITE route with a non-existent well-formed id.
    pub denied: Exchange,
    /// Same call, same non-existent id, as the privileged identity — the
    /// control: both should hit the SAME business error if authz is absent.
    pub privileged: Exchange,
}
```

`Exchange` already carries `identity`, `status`, `body`, `headers` — no change.

## 2. Validator (`validation.rs`)

### CWE reassignment (keeps the disjointness test green)

The test at `validation.rs:1895` asserts every validator owns ≥1 CWE and no two
share one. Today `IdorValidator` owns `639/862/863/284/285/566/425` (verified at
`validation.rs:366`). Split by semantics:

| Validator | CWEs | Scope |
|---|---|---|
| `IdorValidator` (narrow) | `639`, `284`, `566`, `425` | object-level / BOLA (identity B reads A's object), forced browsing |
| `AuthzMatrixValidator` (new) | `862`, `863`, `285` | function-level / missing-auth / improper-authorization |

`862` = Missing Authorization, `863` = Incorrect Authorization, `285` = Improper
Authorization — all function/decision level, correctly the matrix engine's.
Object-level `639`/`284` and forced-browsing `425`/`566` stay with Idor. Update `validator_for` title routing:
move `"broken access control"`, `"bola"` stays→Idor; add `"bfla"`,
`"function-level"`, `"missing authorization"`, `"read-only"`, `"authorization matrix"`
→ `AuthzMatrixValidator`.

### Dispatch override

In `judge`/`apply`, before CWE/title routing, add:

```rust
if ev.map_or(false, |e| !e.matrix.is_empty() || e.oracle.is_some()) {
    return AuthzMatrixValidator.validate(f, ev.unwrap());
}
```

So any finding that arrives with matrix/oracle evidence is judged by the matrix
rule regardless of how the agent labeled it.

### Verdict logic

```rust
impl CweValidator for AuthzMatrixValidator {
    fn name(&self) -> &'static str { "authz-matrix" }
    fn cwes(&self) -> &'static [&'static str] { &["862","863","285"] }

    fn validate(&self, _f: &Finding, ev: &Evidence) -> Verdict {
        // (A) Oracle path — non-destructive proof for write routes.
        if let Some(o) = &ev.oracle {
            if is_auth_denied(&o.denied) {                 // 401/403
                return Verdict::Rejected("authorization enforced — denied identity got 401/403".into());
            }
            if looks_like_login_or_public(&o.denied) {
                return Verdict::Rejected("response is a login page / public view, not the protected handler".into());
            }
            // Denied identity reached business logic iff it got the SAME
            // business-level outcome as the privileged control for a
            // non-existent id (e.g. both "record not found"/422/409, or both 2xx).
            if reached_business_logic(&o.denied) && same_business_outcome(&o.denied, &o.privileged) {
                return Verdict::Confirmed(format!(
                    "write route reached business logic as a should-be-denied identity \
                     (non-existent id → {} like the privileged control, not 403)", o.denied.status));
            }
            return Verdict::NeedsReview("ambiguous — generic 5xx/WAF/empty; cannot tell authz from error".into());
        }

        // (B) Matrix path — read/data routes across identities.
        let denied_but_served: Vec<&MatrixProbe> = ev.matrix.iter()
            .filter(|p| p.expect == Expect::Deny)
            .filter(|p| p.exchange.is_success()
                     && !looks_like_login_or_public(&p.exchange)
                     && !is_empty_or_own_data(&p.exchange))
            .collect();

        if ev.matrix.iter().filter(|p| p.expect == Expect::Deny).count() == 0 {
            return Verdict::NeedsReview("no should-be-denied identity in the matrix — nothing to prove".into());
        }
        match denied_but_served.first() {
            Some(p) => Verdict::Confirmed(format!(
                "identity '{}' (expected deny) was served the protected resource ({}, {} bytes)",
                p.identity, p.exchange.status, p.exchange.len())),
            None => Verdict::Rejected("every should-be-denied identity was correctly refused".into()),
        }
    }
}
```

Helper predicates (new, small, unit-tested):

- `is_auth_denied(x)` → `x.status == 401 || 403`.
- `reached_business_logic(x)` → `x.is_success()` OR a business-error status
  (`404/409/422/400`) whose body carries a business signature
  (`not found`/`invalid state`/`does not exist`), NOT an auth signature
  (`forbidden`/`unauthorized`/`access denied`).
- `same_business_outcome(a, b)` → same status class AND same business-error
  signature (so the denied call got identical treatment to the privileged one).
- `looks_like_login_or_public(x)` → body matches a login form / redirect to
  `/login` / equals the recorded unauthenticated baseline.
- `is_empty_or_own_data(x)` → empty body, or body contains only the denied
  identity's own identifier (so it is not cross-boundary).

These guards encode the FP rules already in the agent markdown: a 200 login
page, a response equal to the public view, a 403, or own-data-only is **not** a
finding; a write 200 without read-back persistence is `needs-review`.

## 3. Identity fixtures (`scope.rs`/`creds.rs`)

Extend the `creds.yaml` schema (already loaded by the creds parser) with an
`identities` block and seed values, so the engine has multiple role sessions and
valid domain inputs to pass business validation:

```yaml
identities:
  - label: admin        # free-form, used in evidence
    role: admin
    auth: { header: "Authorization", value: "Bearer <admin-token>" }
    tier: high
  - label: readonly
    role: viewer
    auth: { header: "Authorization", value: "Bearer <viewer-token>" }
    tier: readonly        # expected Deny on write routes
  - label: tenantB
    role: user
    auth: { cookie: "session=<other-tenant>" }
    tier: tenant
  - label: anonymous
    auth: {}              # no credential; expected Deny on protected routes
    tier: none

sample_values:            # valid domain inputs to get past format gates
  nfe_key: "35200114200166000187550010000000071000000017"
  cnpj:    "11222333000181"
  known_ids: ["6531aa…", "6531bb…"]   # real ids per identity for BOLA
```

New types:

```rust
pub struct Identity { pub label: String, pub role: String, pub tier: Tier,
                      pub auth: AuthMaterial }
pub enum Tier { High, ReadOnly, Tenant, None }
pub enum AuthMaterial { Header{name:String,value:String}, Cookie(String), Anonymous }
pub struct IdentitySet { pub identities: Vec<Identity>, pub samples: SampleValues }
```

`IdentitySet::expected(route, identity)` returns `Expect`: a write/decision
route expects `Deny` for `ReadOnly/None` and for `Tenant` on another tenant's
object; a protected read route expects `Deny` for `None`. This is the policy the
matrix diffs against. The engine never needs the app's real policy table —
"anonymous and read-only should not write" is the universal prior, and any
`Allow` observed where `Deny` was expected is the finding.

## 4. Engine (`authz_matrix.rs`, new)

```rust
pub struct Route { pub method: String, pub path: String, pub kind: RouteKind }
pub enum RouteKind { Read, Write }   // Write = state-changing (POST/PUT/PATCH/DELETE, or a decision verb)

pub struct RouteInventory { pub routes: Vec<Route> }
impl RouteInventory {
    /// Aggregate from everything recon already produced.
    pub fn build(recon: &Recon, ids: &IdentitySet, http: &Http) -> Self { … }
    //   sources: OpenAPI/Swagger JSON, GraphQL introspection, JS-bundle route
    //   mining, an AUTHENTICATED crawl per identity (the readonly/admin crawls
    //   reveal backoffice routes anon never sees), and sensitive-path guessing.
}

pub struct MatrixResult { pub findings: Vec<(Finding, Evidence)> }

pub async fn run(inv: &RouteInventory, ids: &IdentitySet, http: &Http,
                 scope: &Scope, budget: &Budget) -> MatrixResult {
    for route in dedupe_templates(&inv.routes) {           // collapse /x/{id} variants
        scope.check(&route)?;                              // existing guard: never out of scope
        let privileged = replay(route, ids.highest(), http).await;
        let mut ev = Evidence::default();
        for id in ids.iter().filter(|i| i.tier != Tier::High) {
            let expect = ids.expected(route, id);
            match route.kind {
                RouteKind::Read => {
                    let x = replay_read(route, id, &ids.samples, http).await;
                    ev.matrix.push(MatrixProbe{ identity:id.label.clone(), expect, exchange:x });
                }
                RouteKind::Write if expect == Expect::Deny => {
                    // 403-vs-business-error oracle: non-existent well-formed id,
                    // NEVER a real object → no mutation of real data.
                    let denied     = replay_write_nonexistent(route, id, &ids.samples, http).await;
                    let privileged = replay_write_nonexistent(route, ids.highest(), &ids.samples, http).await;
                    ev.oracle = Some(OracleProbe{ denied, privileged });
                }
                _ => {}
            }
            budget.tick()?;                                // reasoning-budget governor
        }
        if ev.matrix.iter().any(|p| p.expect==Expect::Deny) || ev.oracle.is_some() {
            findings.push((synth_finding(route, &privileged), ev));
        }
    }
}
```

Safety built in: writes only ever use a **non-existent** well-formed id, so the
oracle proves reachability without mutating real objects; `scope.check` (the
existing `scope.rs` guard) still gates every request; the budget governor caps
`routes × identities`; `dedupe_templates` collapses `/users/{id}` so the matrix
is O(routes) not O(objects).

## 5. Pipeline wiring (`pipeline.rs`)

Add an engine pass after recon + agent selection, before/alongside the exploit
agents (it is a deterministic engine, not an LLM agent, so it is cheap and
reproducible):

```rust
if identities.len() >= 2 || cfg.authz_matrix {           // auto when ≥2 roles, or --authz-matrix
    let inv = RouteInventory::build(&recon, &identities, &http);
    let res = authz_matrix::run(&inv, &identities, &http, &scope, &budget).await;
    for (mut f, ev) in res.findings {
        let verdict = validation::apply(&mut f, Some(&ev));   // deterministic judge
        emit_finding(f, ev, verdict).await;                  // same sink as agents
    }
}
```

- Flag: `--authz-matrix on|off|auto` (auto = run when ≥2 identities loaded),
  mirroring `--typesafe`.
- The synthesized findings carry `owasp = "A01:2025-Broken Access Control"`,
  `cwe = "862"/"863"/"639"`, `stage = "privesc"`, and feed the attack graph as
  `weakness` nodes on the affected endpoints, so the "systemic" pattern (one
  module, many routes) is visible as a cluster.

## 6. Tests

- Keep `validation.rs:1895` disjointness green after the CWE split (add a case:
  Idor owns `639/284`, AuthzMatrix owns `862/863/285`, no overlap).
- Unit-test `AuthzMatrixValidator`:
  - oracle: denied 403 → Rejected; denied business-404 matching privileged → Confirmed; denied generic-500 → NeedsReview; denied login-page → Rejected.
  - matrix: readonly 200 real body → Confirmed; anonymous 401 → Rejected; denied-but-empty → Rejected; denied-but-own-data → Rejected; no-deny-identity → NeedsReview.
- Golden run: a seeded app with a read-only role that can write; assert one
  Confirmed per vulnerable write route and zero on the enforced ones.

## 7. Why this fits NeuroSploit's invariants

- Deterministic and model-independent: the verdict is computed from status/body
  signatures, never a vote, so it holds across backends (the benchmark property).
- Absent evidence is never a pass: no deny-identity probe → `needs-review`.
- Non-destructive: the oracle uses non-existent ids; scope guard unchanged.
- Reuses `Exchange`/`Evidence`/`Verdict`/`judge`/report/attack-graph end to end.

## Effort estimate

- `Evidence` fields + types: ~0.5 day.
- `AuthzMatrixValidator` + helpers + tests: ~1 day.
- `IdentitySet`/creds schema: ~1 day.
- `RouteInventory` (reusing recon outputs): ~2–3 days (the crawl-per-identity is
  the real work).
- `authz_matrix::run` + pipeline wiring + flag: ~1–2 days.

The validator and data model (the deterministic core) are the smallest and
highest-leverage slice and can ship first against agent-emitted matrix evidence,
before the engine crawls routes on its own.
```
