# Graph memory & attack-path reasoning (Neo4j)

NeuroSploit keeps three graphs: the **knowledge graph** (what was learned about a
target, across runs), the **internal graph** (hosts, identities, credentials, the
AD credential loop) and the **chain links** (which finding hands which capability
to which). `graph_memory.rs` projects all three into one typed schema, reasons
over it, and — when configured — MERGEs it into Neo4j and reads accumulated paths
back.

It works without Neo4j. Every run writes `graph/` next to the report:

| file | what |
|---|---|
| `graph/attack-chains.md` | chains in the 11-field analyst format, plus next moves |
| `graph/graph.cypher` | idempotent MERGE script: `cypher-shell -a <uri> -u <user> -p <pw> -f graph.cypher` |
| `graph/graph.json` | nodes/edges as JSON |
| `graph/queries.cypher` | ready-made analyst queries |

## The graph is a phase of the test

The pipeline runs a **graph checkpoint** at each stage, in every mode (black-box,
grey-box, host/infra, container, mobile, AI):

| checkpoint | what goes in | what it changes |
|---|---|---|
| `recon` | recon surface (in-scope hosts, services, endpoints, tech, secret fingerprints) + this target's cross-run memory + saved internal graph + Neo4j paths | black-box selection adds **graph-directed agents** (e.g. SSRF → `ssrf_cloud`, authz/identities → `authorization_matrix`, yielded secret → `session_lifecycle`, PostgreSQL+SQLi → `postgres_superuser_rce`, datastore tech → `exposed_datastore`) |
| `validated` | the validated findings | every chaining agent sees the new chains |
| `chain round N` | each round's validated findings | footholds on the most valuable chains are expanded first |
| `final` | final findings (before secrets are masked) | Neo4j sync, report |

Each checkpoint publishes a **live context** that `operator_directives` adds to
every exploit and chaining prompt: the surface, the top chains with their status,
the next moves, and the graph discipline (report obtained credentials in
`secret`/`account`, dependencies in `chains_from`, unproven steps as hypotheses).
It also writes `graph/live-chains.md` and `graph/live.json` so the operator can
watch the graph evolve, and MERGEs the run's slice into Neo4j when configured.

**Dependency todolist** (`graph/todo.md`). Every unconfirmed chain is laid out
step by step: `done` when the graph holds evidence for the step, `ready` when every
earlier step is done, `blocked` otherwise. The graph *is* the persistent list, so
it survives rounds and restarts. The chaining rounds dispatch `ready` steps first,
one per foothold, each with the exact step to perform and an instruction not to
jump ahead; a step already attempted is not re-sent.

**Shared traces** (`traces/<agent>.md`). Each agent's transcript is written as it
finishes. Every prompt carries a structured digest of the other agents' traces
(endpoint paths, parameter names, error signatures, product versions, block
signals — never raw lines), fenced as untrusted data, plus the directory to
`grep` for full context.

**Wire-bound evidence** (always on, before validation). Each exchange an agent
reports is checked against recorded traffic (when the recording interceptor ran)
and re-sent by the harness itself through the scope-guarded replay engine
(non-mutating verbs only; identities only when their credentials were recorded).
When the wire reproduces the account, the harness's observation replaces it and
the validators judge real bytes (`[wire-verified]`). When it does not, the
disagreement is recorded and the finding cannot stand as confirmed. What cannot be
checked stays as reported and is counted as unverifiable.

Cross-run memory is scoped to the target: only the component reachable from this
target's asset node, through target-specific nodes, is used — another
engagement's history never enters this one's prompts.

## Using it

```bash
# During a run: chaining rounds get the graph's chains and next moves, and the
# result is pushed to Neo4j at the end.
export NEO4J_USER=neo4j NEO4J_PASSWORD='…'
neurosploit run https://app.example --neo4j bolt://localhost:7687

# After a run (offline, or with --push to MERGE + read back accumulated paths)
neurosploit graph <run-id|dir> [--internal internal-graph.json] [--push] [--top 10]

# Internal network: save the AD/host graph into the run, then reason over both
neurosploit internal --graph ad.json --from <node> --save runs/<id>/internal-graph.json
neurosploit graph <run-id>
```

Configuration: `--neo4j <uri>` or `NEO4J_URI` (`bolt://`, `neo4j://`, `neo4j+s://`
are mapped to the HTTP transactional endpoint on 7474/7473; `http(s)://` is used
as is). Credentials only from `NEO4J_USER` (or `NEO4J_USERNAME`),
`NEO4J_PASSWORD`, `NEO4J_DATABASE` — never from flags, never written to disk.

## Schema

Labels: Target, Asset, Host, IPAddress, Domain, Service, Endpoint, Technology,
Vulnerability, Finding, Evidence, Credential, Identity, Role, Permission, Secret,
ExploitAttempt, ValidationResult, AttackStep, AttackPath, BusinessImpact, Control,
Mitigation.

Relationships: HAS_ASSET, RESOLVES_TO, EXPOSES, RUNS, HOSTS, USES_TECH,
HAS_ENDPOINT, HAS_VULNERABILITY, HAS_FINDING, SUPPORTED_BY, OBSERVED_IN, REQUIRES,
ENABLES, YIELDS, CAN_ACCESS, HAS_PERMISSION, ESCALATES_TO, PIVOTS_TO, DEPENDS_ON,
VALIDATED_BY, MITIGATED_BY, IMPACTS, PART_OF_PATH.

Stable keys (MERGE): Host = target + host; Service = host + port + proto; Endpoint =
method + normalized URL (ids collapsed to `{id}`, query dropped); Vulnerability =
CWE/type + endpoint; Finding = target + type + host + evidence hash; Evidence =
hash of the observed exchange (write-once); Credential/Secret = salted fingerprint.

How web and internal meet: a finding whose evidence demonstrates code execution or
internal reach gets `AttackStep -CAN_ACCESS-> Host`. The internal graph's node for
the same host shares the key, so its credentials and pivots continue the path.

## Reasoning rules (enforced in code)

- **Local vs chain severity.** A chain is only scored above its findings' local
  severity when it is `confirmed` — every finding confirmed by the validation
  engine and every edge evidenced. Otherwise it keeps the local severity and states
  the severity it would have once validated (`High — Critical once validated`).
- **Impact must be demonstrated.** An `IMPACTS` edge is confirmed only when the
  evidence reached that rung: code execution needs a nonce in output or an
  out-of-band callback; sensitive-data exposure needs sensitive data actually read.
  "Could lead to RCE" stays `needs_validation`.
- **Derived links are hypotheses.** Capability-matched links between findings are
  `needs_validation`; cross-run memory is never more than `needs_review`.
- **Status.** `confirmed` / `needs_validation` / `hypothesis` (rests on an
  unconfirmed finding, an unproven node, or history).
- **Next moves.** The first unproven edge of the most valuable chains, yielded
  credentials not yet tried against in-scope services (lockout-aware), code
  execution not yet connected to the internal network, SSRF without a recorded
  internal target. These feed the attack-chaining rounds, and footholds on the
  most valuable chains are expanded first.

## Data minimisation

No raw secret, token, cookie, password, response body or model narrative becomes a
graph property. Secrets are fingerprints salted per installation
(`~/.neurosploit/graph-salt`, or `NEUROSPLOIT_GRAPH_SALT` — share one value across a
team that shares a Neo4j so credential reuse still correlates). Identities that
look like personal data are masked (`a***@corp.test`). Endpoints lose their query
strings. Internal credential nodes are named from the node id and kind, never from
the label. Labels and relationship types come from closed enums; all values are
statement parameters.

## Queries

See `graph/queries.cypher`. Examples:

```cypher
// Hypotheses still worth validating, best first
MATCH (p:AttackPath) WHERE p.status IN ['needs_validation','hypothesis']
RETURN p ORDER BY p.risk_score DESC;

// Credentials that reach privileged identities (internal)
MATCH path = (c)-[:CAN_ACCESS|HAS_PERMISSION|ESCALATES_TO*1..6]->(r)
WHERE (c:Credential OR c:Secret) AND (r:Role OR r:Identity) AND r.privileged = true
RETURN path;
```

The LLM-facing version of these rules is `agents_md/meta/graph_reasoning.md`.
