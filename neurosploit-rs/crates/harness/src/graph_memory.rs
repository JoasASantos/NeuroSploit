//! Graph memory & attack-path reasoning — web and internal network in one graph.
//!
//! NeuroSploit already keeps three graphs, each good at one thing:
//! [`crate::knowledge_graph`] (what was learned about a target, across runs),
//! [`crate::internal`] (hosts, identities, credentials and the AD credential
//! loop) and [`crate::chain`] (which finding hands which capability to which).
//! This layer projects all three into a single typed schema — the one an
//! analyst would draw in Neo4j — and reasons over it:
//!
//! - **local vs chain severity.** A finding has a local severity. A path from it
//!   to a business impact, a crown-jewel asset or a privileged identity has a
//!   chain severity, and the chain severity is only *raised* when every step of
//!   the path is evidenced. An unproven path keeps the local severity and states
//!   what it would become, and what evidence would prove it.
//! - **status.** `confirmed` (every finding confirmed and every edge evidenced),
//!   `needs_validation` (findings real, a link between them derived or
//!   unproven) or `hypothesis` (rests on an unconfirmed finding).
//! - **decision support.** The chains and the missing evidence become the next
//!   moves fed to the attack-chaining rounds, so exploration goes where a
//!   validated edge would complete the highest-value path.
//!
//! It works with no database at all: projection, reasoning and a Cypher export
//! are in-process. When Neo4j is configured (`--neo4j` or `NEO4J_URI`, with
//! `NEO4J_USER`/`NEO4J_PASSWORD`), the graph is MERGEd into it through the HTTP
//! transactional API with parameterised statements, and paths accumulated across
//! runs and engagements are read back into the same reasoning.
//!
//! Data minimisation is a hard rule here: no raw secret, token, cookie,
//! password, response body or narrative ever becomes a graph property. Secrets
//! are fingerprints, identities with personal data are masked, endpoints lose
//! their query strings, and evidence is referenced by hash.

use crate::internal::{InternalGraph, Kind as IKind, Layer as ILayer};
use crate::knowledge_graph::{EdgeKind as KEdge, KnowledgeGraph, NodeKind as KKind};
use crate::types::Finding;
use crate::validation::{Evidence, Exchange};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Schema

/// Node labels. Closed set: labels are never built from data, so a Cypher
/// statement can only ever name one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Label {
    Target,
    Asset,
    Host,
    IPAddress,
    Domain,
    Service,
    Endpoint,
    Technology,
    Vulnerability,
    Finding,
    Evidence,
    Credential,
    Identity,
    Role,
    Permission,
    Secret,
    ExploitAttempt,
    ValidationResult,
    AttackStep,
    AttackPath,
    BusinessImpact,
    Control,
    Mitigation,
}

impl Label {
    pub const ALL: [Label; 23] = [
        Label::Target, Label::Asset, Label::Host, Label::IPAddress, Label::Domain, Label::Service,
        Label::Endpoint, Label::Technology, Label::Vulnerability, Label::Finding, Label::Evidence,
        Label::Credential, Label::Identity, Label::Role, Label::Permission, Label::Secret,
        Label::ExploitAttempt, Label::ValidationResult, Label::AttackStep, Label::AttackPath,
        Label::BusinessImpact, Label::Control, Label::Mitigation,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Target => "Target",
            Label::Asset => "Asset",
            Label::Host => "Host",
            Label::IPAddress => "IPAddress",
            Label::Domain => "Domain",
            Label::Service => "Service",
            Label::Endpoint => "Endpoint",
            Label::Technology => "Technology",
            Label::Vulnerability => "Vulnerability",
            Label::Finding => "Finding",
            Label::Evidence => "Evidence",
            Label::Credential => "Credential",
            Label::Identity => "Identity",
            Label::Role => "Role",
            Label::Permission => "Permission",
            Label::Secret => "Secret",
            Label::ExploitAttempt => "ExploitAttempt",
            Label::ValidationResult => "ValidationResult",
            Label::AttackStep => "AttackStep",
            Label::AttackPath => "AttackPath",
            Label::BusinessImpact => "BusinessImpact",
            Label::Control => "Control",
            Label::Mitigation => "Mitigation",
        }
    }
    pub fn parse(s: &str) -> Option<Label> {
        Label::ALL.iter().copied().find(|l| l.as_str() == s)
    }
}

/// Relationship types. Closed set, like [`Label`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rel {
    HasAsset,
    ResolvesTo,
    Exposes,
    Runs,
    Hosts,
    UsesTech,
    HasEndpoint,
    HasVulnerability,
    HasFinding,
    SupportedBy,
    ObservedIn,
    Requires,
    Enables,
    Yields,
    CanAccess,
    HasPermission,
    EscalatesTo,
    PivotsTo,
    DependsOn,
    ValidatedBy,
    MitigatedBy,
    Impacts,
    PartOfPath,
}

impl Rel {
    pub const ALL: [Rel; 23] = [
        Rel::HasAsset, Rel::ResolvesTo, Rel::Exposes, Rel::Runs, Rel::Hosts, Rel::UsesTech,
        Rel::HasEndpoint, Rel::HasVulnerability, Rel::HasFinding, Rel::SupportedBy, Rel::ObservedIn,
        Rel::Requires, Rel::Enables, Rel::Yields, Rel::CanAccess, Rel::HasPermission,
        Rel::EscalatesTo, Rel::PivotsTo, Rel::DependsOn, Rel::ValidatedBy, Rel::MitigatedBy,
        Rel::Impacts, Rel::PartOfPath,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Rel::HasAsset => "HAS_ASSET",
            Rel::ResolvesTo => "RESOLVES_TO",
            Rel::Exposes => "EXPOSES",
            Rel::Runs => "RUNS",
            Rel::Hosts => "HOSTS",
            Rel::UsesTech => "USES_TECH",
            Rel::HasEndpoint => "HAS_ENDPOINT",
            Rel::HasVulnerability => "HAS_VULNERABILITY",
            Rel::HasFinding => "HAS_FINDING",
            Rel::SupportedBy => "SUPPORTED_BY",
            Rel::ObservedIn => "OBSERVED_IN",
            Rel::Requires => "REQUIRES",
            Rel::Enables => "ENABLES",
            Rel::Yields => "YIELDS",
            Rel::CanAccess => "CAN_ACCESS",
            Rel::HasPermission => "HAS_PERMISSION",
            Rel::EscalatesTo => "ESCALATES_TO",
            Rel::PivotsTo => "PIVOTS_TO",
            Rel::DependsOn => "DEPENDS_ON",
            Rel::ValidatedBy => "VALIDATED_BY",
            Rel::MitigatedBy => "MITIGATED_BY",
            Rel::Impacts => "IMPACTS",
            Rel::PartOfPath => "PART_OF_PATH",
        }
    }
    pub fn parse(s: &str) -> Option<Rel> {
        Rel::ALL.iter().copied().find(|r| r.as_str() == s)
    }
    /// Edges an attacker moves along. Structural edges (HAS_ENDPOINT,
    /// SUPPORTED_BY, …) describe the graph but are not steps of an attack.
    pub fn is_traversal(self) -> bool {
        matches!(
            self,
            Rel::Enables | Rel::Yields | Rel::CanAccess | Rel::HasPermission | Rel::EscalatesTo | Rel::PivotsTo | Rel::Impacts
        )
    }
}

/// How well a node or relationship is established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    Confirmed,
    NeedsReview,
    NeedsValidation,
    Hypothesis,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Confirmed => "confirmed",
            Status::NeedsReview => "needs_review",
            Status::NeedsValidation => "needs_validation",
            Status::Hypothesis => "hypothesis",
        }
    }
    pub fn parse(s: &str) -> Status {
        match s.trim().to_lowercase().replace('-', "_").as_str() {
            "confirmed" => Status::Confirmed,
            "needs_review" => Status::NeedsReview,
            "hypothesis" => Status::Hypothesis,
            _ => Status::NeedsValidation,
        }
    }
    fn strength(self) -> u8 {
        match self {
            Status::Confirmed => 3,
            Status::NeedsReview => 2,
            Status::NeedsValidation => 1,
            Status::Hypothesis => 0,
        }
    }
}

pub type NodeRef = (Label, String);

#[derive(Clone, Debug)]
pub struct GNode {
    pub label: Label,
    pub key: String,
    /// Flat, primitive-valued properties only (Neo4j cannot store maps).
    pub props: BTreeMap<String, Value>,
}

#[derive(Clone, Debug)]
pub struct GEdge {
    pub rel: Rel,
    pub from: NodeRef,
    pub to: NodeRef,
    pub status: Status,
    pub confidence: f64,
    /// Evidence references (hash prefixes / artifact refs) backing this edge.
    pub evidence: BTreeSet<String>,
    pub props: BTreeMap<String, Value>,
}

/// A deduplicated set of nodes and relationships, ready to reason over or MERGE.
#[derive(Clone, Debug, Default)]
pub struct GraphBatch {
    pub target_id: String,
    pub nodes: BTreeMap<NodeRef, GNode>,
    pub edges: BTreeMap<(Rel, NodeRef, NodeRef), GEdge>,
}

impl GraphBatch {
    pub fn new(target: &str) -> GraphBatch {
        GraphBatch { target_id: target_id(target), ..Default::default() }
    }

    /// Upsert a node. Empty values are ignored; Evidence properties are
    /// write-once (evidence hashes are immutable).
    pub fn put(&mut self, label: Label, key: &str, props: &[(&str, Value)]) -> NodeRef {
        let r = (label, key.to_string());
        let n = self.nodes.entry(r.clone()).or_insert_with(|| GNode { label, key: key.to_string(), props: BTreeMap::new() });
        for (k, v) in props {
            if !is_storable(v) {
                continue;
            }
            if label == Label::Evidence && n.props.contains_key(*k) {
                continue;
            }
            n.props.insert((*k).to_string(), v.clone());
        }
        r
    }

    /// Upsert a relationship. A stronger status, a higher confidence and new
    /// evidence references accumulate; nothing is ever downgraded.
    #[allow(clippy::too_many_arguments)]
    pub fn link(&mut self, rel: Rel, from: &NodeRef, to: &NodeRef, status: Status, confidence: f64, evidence: &[String], props: &[(&str, Value)]) {
        if from == to {
            return;
        }
        let e = self.edges.entry((rel, from.clone(), to.clone())).or_insert_with(|| GEdge {
            rel,
            from: from.clone(),
            to: to.clone(),
            status,
            confidence: 0.0,
            evidence: BTreeSet::new(),
            props: BTreeMap::new(),
        });
        if status.strength() > e.status.strength() {
            e.status = status;
        }
        e.confidence = e.confidence.max(confidence.clamp(0.0, 1.0));
        e.evidence.extend(evidence.iter().filter(|s| !s.is_empty()).cloned());
        for (k, v) in props {
            if is_storable(v) {
                e.props.insert((*k).to_string(), v.clone());
            }
        }
    }

    pub fn node(&self, r: &NodeRef) -> Option<&GNode> {
        self.nodes.get(r)
    }

    /// Human-readable name of a node.
    pub fn name(&self, r: &NodeRef) -> String {
        let n = self.nodes.get(r);
        for k in ["title", "name", "category", "address", "path"] {
            if let Some(Value::String(s)) = n.and_then(|n| n.props.get(k)) {
                if !s.is_empty() {
                    return format!("{} `{}`", r.0.as_str(), short(s, 90));
                }
            }
        }
        format!("{} `{}`", r.0.as_str(), short(&r.1, 40))
    }

    fn prop_str(&self, r: &NodeRef, k: &str) -> String {
        match self.nodes.get(r).and_then(|n| n.props.get(k)) {
            Some(Value::String(s)) => s.clone(),
            Some(v) if !v.is_null() => v.to_string(),
            _ => String::new(),
        }
    }

    fn prop_bool(&self, r: &NodeRef, k: &str) -> bool {
        matches!(self.nodes.get(r).and_then(|n| n.props.get(k)), Some(Value::Bool(true)))
    }

    /// Merge another batch in (e.g. paths read back from Neo4j).
    pub fn absorb(&mut self, other: GraphBatch) {
        for (r, n) in other.nodes {
            let props: Vec<(String, Value)> = n.props.into_iter().collect();
            let refs: Vec<(&str, Value)> = props.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            self.put(r.0, &r.1, &refs);
        }
        for (_, e) in other.edges {
            let ev: Vec<String> = e.evidence.into_iter().collect();
            let props: Vec<(String, Value)> = e.props.into_iter().collect();
            let refs: Vec<(&str, Value)> = props.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            self.link(e.rel, &e.from, &e.to, e.status, e.confidence, &ev, &refs);
        }
    }
}

/// Neo4j properties must be primitives or arrays of primitives.
fn is_storable(v: &Value) -> bool {
    match v {
        Value::Null | Value::Object(_) => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => a.iter().all(|x| matches!(x, Value::String(_) | Value::Number(_) | Value::Bool(_))),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Small helpers

fn sha(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Per-installation salt for fingerprints. A bare SHA-256 of a weak password
/// can be reversed with a dictionary by anyone who can read the graph; a salted
/// one cannot, while equal secrets still produce equal fingerprints (which is
/// what makes credential-reuse correlation work). Share one salt across a team
/// that shares a Neo4j via `NEUROSPLOIT_GRAPH_SALT`.
fn salt() -> &'static str {
    static SALT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SALT.get_or_init(|| {
        if let Ok(s) = std::env::var("NEUROSPLOIT_GRAPH_SALT") {
            if !s.trim().is_empty() {
                return s.trim().to_string();
            }
        }
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
        let path = std::path::Path::new(&home).join(".neurosploit").join("graph-salt");
        if let Ok(s) = std::fs::read_to_string(&path) {
            if s.trim().len() >= 32 {
                return s.trim().to_string();
            }
        }
        let mut seed = [0u8; 32];
        let random = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
            .is_ok();
        let fresh = if random {
            seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
        } else {
            sha(&format!("{:?}{}{:p}", std::time::SystemTime::now(), std::process::id(), &seed))
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&path, &fresh);
        fresh
    })
}

/// A stable, salted, non-reversible fingerprint (for secrets and identities).
pub fn fingerprint(s: &str) -> String {
    sha(&format!("{}\u{1f}{s}", salt()))[..24].to_string()
}

/// A secret the pipeline has already replaced with a vault pointer or mask.
fn is_masked(s: &str) -> bool {
    let t = s.trim().to_lowercase();
    t.is_empty() || t.contains('\u{2022}') || t.contains("see vault") || t.contains("redacted") || t.chars().all(|c| c == '*')
}

pub fn target_id(target: &str) -> String {
    sha(&target.trim().trim_end_matches('/').to_lowercase())[..12].to_string()
}

fn short(s: &str, n: usize) -> String {
    let s = s.replace(['\n', '\r'], " ");
    if s.chars().count() <= n { s } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn cwe_num(c: &str) -> String {
    c.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn sev_rank(s: &str) -> u8 {
    let s = s.trim().to_lowercase();
    if s.starts_with("crit") {
        4
    } else if s.starts_with("high") {
        3
    } else if s.starts_with("med") {
        2
    } else if s.starts_with("low") {
        1
    } else {
        0
    }
}

fn sev_name(r: u8) -> &'static str {
    match r {
        4 => "Critical",
        3 => "High",
        2 => "Medium",
        1 => "Low",
        _ => "Info",
    }
}

/// (scheme, host, port) of a URL; falls back sensibly for bare hosts.
fn split_url(url: &str) -> (String, String, u16) {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => ("http".to_string(), url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // [v6]:port
        let (h, after) = stripped.split_once(']').unwrap_or((stripped, ""));
        (h.to_string(), after.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h.to_string(), p.parse().ok()),
            _ => (authority.to_string(), None),
        }
    };
    let default = match scheme.as_str() {
        "https" | "wss" => 443,
        "ssh" => 22,
        "ldap" => 389,
        "smb" => 445,
        _ => 80,
    };
    (scheme, host.to_lowercase(), port.unwrap_or(default))
}

fn is_ip(h: &str) -> bool {
    h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok()
}

/// Path of a URL without query or fragment (query strings can carry tokens).
fn clean_path(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let path = match rest.find('/') {
        Some(i) if url.contains("://") => &rest[i..],
        _ if !url.contains("://") && url.starts_with('/') => url,
        _ => "/",
    };
    path.split(['?', '#']).next().unwrap_or("/").to_string()
}

fn endpoint_key(method: &str, url: &str) -> String {
    let no_q = url.split(['?', '#']).next().unwrap_or(url);
    format!("{} {}", method.to_uppercase(), crate::authz_matrix::template(no_q))
}

/// Identity names that look like personal data (e-mail, long digit runs) are
/// masked; role-like names (admin, svc_backup) are kept — they are the point.
fn mask_identity(a: &str) -> String {
    let name = a.split(':').next().unwrap_or(a).trim();
    if let Some((u, d)) = name.split_once('@') {
        return format!("{}***@{}", u.chars().next().unwrap_or('*'), d);
    }
    if name.chars().filter(|c| c.is_ascii_digit()).count() >= 8 {
        return "***".into();
    }
    short(name, 48)
}

fn privileged_name(n: &str) -> bool {
    let n = n.to_lowercase();
    ["admin", "root", "domain admins", "enterprise admins", "administrator", "superuser", "sudo", "wheel", "owner", "da ", "krbtgt", "system"]
        .iter()
        .any(|k| n.contains(k))
}

fn finding_status(f: &Finding) -> Option<Status> {
    match f.review_status.as_str() {
        "rejected" => None,
        "confirmed" => Some(Status::Confirmed),
        _ if f.validated => Some(Status::Confirmed),
        _ => Some(Status::NeedsReview),
    }
}

fn exchanges(ev: &Evidence) -> Vec<(String, &Exchange)> {
    let mut v: Vec<(String, &Exchange)> = Vec::new();
    if let Some(x) = &ev.baseline {
        v.push(("control".into(), x));
    }
    if let Some(x) = &ev.attack {
        v.push(("attack".into(), x));
    }
    for (i, x) in ev.repeats.iter().enumerate() {
        v.push((format!("repeat-{}", i + 1), x));
    }
    if let Some(x) = &ev.identity_a {
        v.push(("identity-a".into(), x));
    }
    if let Some(x) = &ev.identity_b {
        v.push(("identity-b".into(), x));
    }
    if let Some(o) = &ev.oracle {
        v.push(("oracle-privileged".into(), &o.privileged));
        v.push(("oracle-denied".into(), &o.denied));
    }
    for p in &ev.matrix {
        v.push((format!("matrix-{}", p.identity), &p.exchange));
    }
    v
}

/// The business/security impact categories a finding bears on, each with
/// whether the recorded evidence actually reached it. Theoretical impact is
/// kept but marked `needs_validation`, so it can never raise a severity.
fn impacts(f: &Finding, finding: Status) -> Vec<(&'static str, Status)> {
    use crate::attack_graph::{data_class, demonstrated_rung, DataClass, Rung};
    use crate::chain::Capability as C;
    let rung = demonstrated_rung(f);
    let class = data_class(f);
    let confirmed = finding == Status::Confirmed;
    let prove = |ok: bool| if confirmed && ok { Status::Confirmed } else { Status::NeedsValidation };
    let mut out: Vec<(&'static str, Status)> = Vec::new();
    let mut add = |cat: &'static str, st: Status| {
        if let Some(e) = out.iter_mut().find(|(c, _)| *c == cat) {
            if st.strength() > e.1.strength() {
                e.1 = st;
            }
        } else {
            out.push((cat, st));
        }
    };
    for c in crate::chain::provides(f) {
        match c {
            C::CodeExecution => add("code-execution", prove(rung >= Rung::Executed)),
            C::PrivilegedContext => add("privileged-access", prove(rung >= Rung::Wrote || class != DataClass::None)),
            C::DataAccess => {
                if class == DataClass::Sensitive {
                    add("sensitive-data-exposure", prove(rung >= Rung::ReadSensitive || class == DataClass::Sensitive));
                } else {
                    add("data-access", prove(rung >= Rung::ReadData));
                }
            }
            C::InternalNetwork => add("lateral-movement", prove(rung >= Rung::CrossedSystem)),
            C::SessionMaterial | C::WeakCredentials => add("credential-compromise", prove(class == DataClass::Sensitive)),
            _ => {}
        }
    }
    if ["287", "288", "290", "306", "1390"].contains(&cwe_num(&f.cwe).as_str()) {
        add("auth-bypass", prove(true));
    }
    out
}

fn impact_rank(cat: &str) -> u8 {
    match cat {
        "code-execution" | "privileged-access" | "sensitive-data-exposure" | "domain-compromise" | "cloud-compromise" | "production-compromise" => 4,
        "lateral-movement" | "auth-bypass" | "credential-compromise" => 3,
        "data-access" => 2,
        _ => 2,
    }
}

// ---------------------------------------------------------------------------
// Projection: findings (web & host), the internal graph, the knowledge graph

/// Project a run's findings. Rejected findings are left out — the control
/// worked, there is nothing to chain from.
pub fn project_findings(b: &mut GraphBatch, target: &str, run: &str, findings: &[Finding]) {
    let tid = b.target_id.clone();
    let t = b.put(Label::Target, &tid, &[("name", json!(target)), ("target_id", json!(tid))]);
    let ts = now();
    let mut by_id: HashMap<String, (NodeRef, Status)> = HashMap::new();

    for f in findings {
        let Some(st) = finding_status(f) else { continue };
        let conf = f.confidence.clamp(0.0, 1.0).max(if st == Status::Confirmed { 0.8 } else { 0.3 });
        let attack = f.evidence_data.as_ref().and_then(|e| e.attack.as_ref().or(e.identity_b.as_ref()));
        let url = if !f.endpoint.trim().is_empty() {
            f.endpoint.trim().to_string()
        } else if let Some(a) = attack {
            a.url.clone()
        } else {
            target.to_string()
        };
        let url = if url.contains("://") || !url.starts_with('/') { url } else { format!("{}{}", target.trim_end_matches('/'), url) };
        let method = attack.map(|a| a.method.clone()).filter(|m| !m.is_empty()).unwrap_or_else(|| "GET".into());
        let (scheme, host, port) = split_url(&url);
        let host = if host.is_empty() { split_url(target).1 } else { host };

        // Asset topology.
        let hk = format!("{tid}|{host}");
        let h = b.put(Label::Host, &hk, &[("name", json!(host)), ("target_id", json!(tid))]);
        b.link(Rel::HasAsset, &t, &h, Status::Confirmed, 1.0, &[], &[]);
        if is_ip(&host) {
            let ip = b.put(Label::IPAddress, &host, &[("address", json!(host))]);
            b.link(Rel::ResolvesTo, &h, &ip, Status::Confirmed, 1.0, &[], &[]);
        } else {
            let d = b.put(Label::Domain, &host, &[("name", json!(host))]);
            b.link(Rel::ResolvesTo, &d, &h, Status::Confirmed, 1.0, &[], &[]);
        }
        let sk = format!("{hk}|{port}|tcp");
        let s = b.put(Label::Service, &sk, &[("port", json!(port)), ("protocol", json!("tcp")), ("app_protocol", json!(scheme))]);
        b.link(Rel::Exposes, &h, &s, Status::Confirmed, 1.0, &[], &[]);
        let ek = endpoint_key(&method, &url);
        let ep = b.put(Label::Endpoint, &ek, &[("method", json!(method.to_uppercase())), ("path", json!(crate::authz_matrix::template(&clean_path(&url))))]);
        b.link(Rel::HasEndpoint, &s, &ep, Status::Confirmed, 1.0, &[], &[]);

        // Vulnerability (CWE/type + component).
        let n = cwe_num(&f.cwe);
        let vclass = if n.is_empty() { short(&f.title.to_lowercase(), 60) } else { format!("CWE-{n}") };
        let v = b.put(Label::Vulnerability, &format!("{vclass}|{ek}"), &[("type", json!(vclass)), ("component", json!(ek))]);
        b.link(Rel::HasVulnerability, &ep, &v, st, conf, &[], &[]);

        // Evidence — hashes only, immutable.
        let mut ev_nodes: Vec<NodeRef> = Vec::new();
        let mut body_hashes: Vec<String> = Vec::new();
        if let Some(ev) = &f.evidence_data {
            for (role, x) in exchanges(ev) {
                let bh = sha(&x.body);
                let key = sha(&format!("{}|{}|{}|{}|{}|{}", f.id, role, x.method, x.url, x.status, bh));
                let e = b.put(
                    Label::Evidence,
                    &key,
                    &[
                        ("evidence_id", json!(key[..16].to_string())),
                        ("hash", json!(bh)),
                        ("role", json!(role)),
                        ("method", json!(x.method)),
                        ("path", json!(clean_path(&x.url))),
                        ("status_code", json!(x.status)),
                        ("source", json!("wire")),
                        ("tool", json!("neurosploit")),
                        ("timestamp", json!(ts)),
                        ("confidence", json!(1.0)),
                    ],
                );
                ev_nodes.push(e);
                body_hashes.push(bh);
            }
        }
        let evh = if body_hashes.is_empty() { sha(&format!("{}|{}", f.id, f.title)) } else { sha(&body_hashes.join(",")) };
        let refs: Vec<String> = ev_nodes.iter().map(|e| e.1[..16].to_string()).collect();

        // Finding: target + type + asset + evidence hash.
        let fk = sha(&format!("{tid}|{vclass}|{hk}|{evh}"))[..32].to_string();
        let fnode = b.put(
            Label::Finding,
            &fk,
            &[
                ("finding_id", json!(f.id)),
                ("title", json!(short(&f.title, 160))),
                ("local_severity", json!(sev_name(sev_rank(&f.severity)))),
                ("status", json!(st.as_str())),
                ("cwe", json!(f.cwe)),
                ("stage", json!(f.stage)),
                ("exploitability", json!(f.exploitability)),
                ("confidence", json!(conf)),
                ("evidence_hash", json!(evh)),
                ("target_id", json!(tid)),
                ("source_agent", json!(f.agent)),
                ("tool_name", json!("neurosploit")),
                ("run", json!(run)),
            ],
        );
        b.link(Rel::HasFinding, &v, &fnode, st, conf, &refs, &[]);
        for e in &ev_nodes {
            b.link(Rel::SupportedBy, &fnode, e, Status::Confirmed, 1.0, &[e.1[..16].to_string()], &[]);
            b.link(Rel::ObservedIn, e, &ep, Status::Confirmed, 1.0, &[], &[]);
        }
        let vr = b.put(
            Label::ValidationResult,
            &format!("val:{fk}"),
            &[("verdict", json!(st.as_str())), ("engine", json!("deterministic")), ("reason", json!(short(&f.review_reason, 160))), ("votes", json!(f.votes))],
        );
        b.link(Rel::ValidatedBy, &fnode, &vr, Status::Confirmed, 1.0, &[], &[]);

        // Exploitation step and what it yields.
        let step = b.put(Label::AttackStep, &format!("step:{fk}"), &[("title", json!(format!("exploit {}", short(&f.title, 100)))), ("mitre", json!(f.mitre)), ("stage", json!(f.stage))]);
        b.link(Rel::Enables, &fnode, &step, st, conf, &refs, &[]);
        if !f.secret.trim().is_empty() {
            // A masked secret cannot be correlated: give it its own node rather
            // than collapsing every vaulted secret into one (a false link).
            let (fp, kind) = if is_masked(&f.secret) {
                (fingerprint(&format!("{tid}|vaulted|{}", f.id)), "vaulted secret")
            } else {
                (fingerprint(f.secret.trim()), "secret")
            };
            let c = b.put(Label::Secret, &format!("fp:{fp}"), &[("fingerprint", json!(fp)), ("kind", json!(kind)), ("redacted", json!("****")), ("target_id", json!(tid))]);
            b.link(Rel::Yields, &step, &c, st, conf, &refs, &[]);
        }
        if !f.account.trim().is_empty() {
            let name = f.account.split(':').next().unwrap_or(&f.account).trim().to_string();
            let i = b.put(
                Label::Identity,
                &format!("id:{}", fingerprint(&format!("{tid}|{name}"))),
                &[("name", json!(mask_identity(&name))), ("privileged", json!(privileged_name(&name))), ("target_id", json!(tid))],
            );
            b.link(Rel::Yields, &step, &i, st, conf, &refs, &[]);
            // The identity was used on this host during the engagement.
            b.link(Rel::CanAccess, &i, &h, st, conf, &refs, &[("via", json!("session observed in evidence"))]);
        }
        for (cat, ist) in impacts(f, st) {
            let bi = b.put(Label::BusinessImpact, &format!("impact:{tid}:{cat}"), &[("category", json!(cat)), ("title", json!(cat.replace('-', " "))), ("target_id", json!(tid))]);
            b.link(Rel::Impacts, &fnode, &bi, ist, if ist == Status::Confirmed { conf } else { conf * 0.5 }, &refs, &[]);
            // Web → internal bridge: code execution or internal reach is a
            // foothold ON the host, which is where the internal graph (the
            // credentials and pivots found from that host) continues.
            if matches!(cat, "code-execution" | "lateral-movement") {
                b.link(Rel::CanAccess, &step, &h, ist, if ist == Status::Confirmed { conf } else { conf * 0.5 }, &refs, &[("via", json!(format!("foothold via {cat}")))]);
            }
        }
        if !f.remediation.trim().is_empty() {
            let m = b.put(Label::Mitigation, &format!("mit:{}", fingerprint(&f.remediation)), &[("title", json!(short(&f.remediation, 200)))]);
            b.link(Rel::MitigatedBy, &v, &m, Status::Confirmed, 1.0, &[], &[]);
        }
        by_id.insert(f.id.clone(), (fnode, st));
    }

    // Finding → finding. Asserted links between two confirmed findings are
    // confirmed; derived ones (capability matching) stay needs_validation.
    for f in findings {
        let Some((to, to_st)) = by_id.get(&f.id).cloned() else { continue };
        for src in &f.chains_from {
            if let Some((from, from_st)) = by_id.get(src).cloned() {
                let st = if from_st == Status::Confirmed && to_st == Status::Confirmed { Status::Confirmed } else { Status::NeedsValidation };
                b.link(Rel::EscalatesTo, &from, &to, st, 0.8, &[], &[("basis", json!("asserted"))]);
            }
        }
    }
    for l in crate::chain::derive_links(findings) {
        let (Some(fa), Some(fb)) = (findings.get(l.from), findings.get(l.to)) else { continue };
        let (Some((a, sa)), Some((c, sc))) = (by_id.get(&fa.id).cloned(), by_id.get(&fb.id).cloned()) else { continue };
        let st = if !l.inferred && sa == Status::Confirmed && sc == Status::Confirmed { Status::Confirmed } else { Status::NeedsValidation };
        b.link(
            Rel::EscalatesTo,
            &a,
            &c,
            st,
            if l.inferred { 0.35 } else { 0.8 },
            &[],
            &[("via", json!(l.via.as_str())), ("reason", json!(short(&l.reason, 200))), ("basis", json!(if l.inferred { "derived" } else { "asserted" }))],
        );
    }
}

/// Map an internal-graph technique onto a relationship type.
fn rel_for_technique(t: &str, from: Label, to: Label) -> Rel {
    let t = t.to_lowercase();
    let has = |ks: &[&str]| ks.iter().any(|k| t.contains(k));
    if has(&["memberof", "member of", "member"]) {
        return Rel::HasPermission;
    }
    if has(&["dump", "extract", "crack", "kerberoast", "as-rep", "asrep", "secretsdump", "lsass", "dcsync", "harvest", "leak", "loot", "read password", "laps", "gmsa"]) {
        return Rel::Yields;
    }
    if has(&["escalat", "privesc", "impersonat", "delegat", "genericall", "genericwrite", "writedacl", "writeowner", "owns", "forcechangepassword", "addmember", "esc1", "esc8", "adcs", "rbcd", "s4u", "golden", "silver"]) {
        return Rel::EscalatesTo;
    }
    if has(&["pivot", "lateral", "relay", "tunnel", "psexec", "wmiexec", "smbexec", "winrm", "rdp", "ssh", "pass-the", "pth", "ptt"]) {
        return if from == Label::Host && to == Label::Host { Rel::PivotsTo } else { Rel::CanAccess };
    }
    if has(&["admin to", "adminto", "local admin", "logon", "login", "authenticat", "access", "read", "write", "mount"]) {
        return if from == Label::Host && to == Label::Host { Rel::PivotsTo } else { Rel::CanAccess };
    }
    if has(&["hosts", "runs on", "runs"]) {
        return Rel::Hosts;
    }
    if from == Label::Host && to == Label::Host {
        Rel::PivotsTo
    } else {
        Rel::Enables
    }
}

/// Project the internal-network / AD graph. Credentials become fingerprints;
/// crown jewels become critical assets; privileged groups become privileged roles.
pub fn project_internal(b: &mut GraphBatch, g: &InternalGraph) {
    let tid = b.target_id.clone();
    let t = b.put(Label::Target, &tid, &[("target_id", json!(tid))]);
    let mut map: HashMap<String, NodeRef> = HashMap::new();
    for n in &g.nodes {
        let st = if n.proven { Status::Confirmed } else { Status::NeedsValidation };
        let critical = n.layer == ILayer::CrownJewel;
        let base: Vec<(&str, Value)> = vec![
            ("layer", json!(n.layer.as_str())),
            ("kind", json!(n.kind.as_str())),
            ("status", json!(st.as_str())),
            ("value", json!(n.value)),
            ("target_id", json!(tid)),
            ("source", json!("internal-graph")),
        ];
        let r = if n.layer == ILayer::BusinessImpact {
            let mut p = base.clone();
            p.push(("title", json!(short(&n.label, 120))));
            p.push(("category", json!(if privileged_name(&n.label) { "domain-compromise" } else { "business-impact" })));
            b.put(Label::BusinessImpact, &format!("int:{}", n.id), &p)
        } else if n.kind.is_credential() {
            // Never the label — it may be the secret itself.
            let fp = fingerprint(&format!("{tid}|{}", n.id));
            let mut p = base.clone();
            p.push(("fingerprint", json!(fp)));
            p.push(("redacted", json!("****")));
            // Display name from the node id the operator chose and the kind —
            // never from the label, which may be the secret itself.
            p.push(("name", json!(format!("{} {}", n.kind.as_str(), short(&n.id, 40)))));
            let label = if matches!(n.kind, IKind::Token | IKind::Session | IKind::Ticket) { Label::Secret } else { Label::Credential };
            b.put(label, &format!("fp:{fp}"), &p)
        } else {
            match n.kind {
                IKind::Host | IKind::Computer => {
                    let name = if !n.host.trim().is_empty() { n.host.trim().to_lowercase() } else { n.label.trim().to_lowercase() };
                    let mut p = base.clone();
                    p.push(("name", json!(name)));
                    p.push(("critical", json!(critical)));
                    let h = b.put(Label::Host, &format!("{tid}|{name}"), &p);
                    b.link(Rel::HasAsset, &t, &h, Status::Confirmed, 1.0, &[], &[]);
                    h
                }
                IKind::Service => {
                    let mut p = base.clone();
                    p.push(("name", json!(short(&n.label, 120))));
                    b.put(Label::Service, &format!("int:{}", n.id), &p)
                }
                IKind::User | IKind::ServiceAccount => {
                    let mut p = base.clone();
                    p.push(("name", json!(mask_identity(&n.label))));
                    p.push(("privileged", json!(n.layer == ILayer::Privilege || privileged_name(&n.label))));
                    b.put(Label::Identity, &format!("int:{}", n.id), &p)
                }
                IKind::Group => {
                    let mut p = base.clone();
                    p.push(("name", json!(short(&n.label, 120))));
                    p.push(("privileged", json!(n.layer == ILayer::Privilege || privileged_name(&n.label) || critical)));
                    b.put(Label::Role, &format!("int:{}", n.id), &p)
                }
                IKind::Acl => {
                    let mut p = base.clone();
                    p.push(("name", json!(short(&n.label, 120))));
                    b.put(Label::Permission, &format!("int:{}", n.id), &p)
                }
                IKind::Control => {
                    let mut p = base.clone();
                    p.push(("name", json!(short(&n.label, 120))));
                    b.put(Label::Control, &format!("int:{}", n.id), &p)
                }
                _ => {
                    let mut p = base.clone();
                    p.push(("name", json!(short(&n.label, 120))));
                    p.push(("critical", json!(critical)));
                    p.push(("entry", json!(n.layer == ILayer::Exposure)));
                    let a = b.put(Label::Asset, &format!("int:{}", n.id), &p);
                    if !n.host.trim().is_empty() {
                        let h = b.put(Label::Host, &format!("{tid}|{}", n.host.trim().to_lowercase()), &[("name", json!(n.host.trim().to_lowercase()))]);
                        b.link(Rel::Hosts, &h, &a, Status::Confirmed, 1.0, &[], &[]);
                    }
                    a
                }
            }
        };
        map.insert(n.id.clone(), r);
    }
    for e in &g.edges {
        let (Some(a), Some(c)) = (map.get(&e.from), map.get(&e.to)) else { continue };
        let rel = rel_for_technique(&e.technique, a.0, c.0);
        let st = if e.proven { Status::Confirmed } else { Status::NeedsValidation };
        let refs: Vec<String> = e.evidence.iter().map(|x| short(x, 80)).collect();
        b.link(
            rel,
            a,
            c,
            st,
            if e.proven { 0.9 } else { 0.4 },
            &refs,
            &[
                ("technique", json!(short(&e.technique, 120))),
                ("mitre", json!(e.mitre)),
                ("remediation", json!(short(&e.remediation, 200))),
                ("detection", json!(short(&e.detection, 200))),
                ("source", json!("internal-graph")),
            ],
        );
    }
}

/// Project the project-wide knowledge graph — *other* runs only, so the
/// current run is not duplicated. This is the cross-run memory: footholds and
/// credentials from last week's run are still start points today.
pub fn project_history(b: &mut GraphBatch, kg: &KnowledgeGraph, current_run: &str, target: &str) {
    let tid = b.target_id.clone();
    // The project graph spans every engagement run from this directory. Only
    // this target's component may enter — another client's history must never
    // reach this engagement's prompts. Walk out from this target's asset node,
    // through target-specific nodes only (asset, endpoint, finding, account);
    // shared generic nodes (a CWE, a MITRE technique, a technology) are kept as
    // leaves and never traversed, or every target sharing CWE-89 would connect.
    let root = format!("asset:{}", crate::memory::engagement_key(target));
    if !kg.nodes.contains_key(&root) {
        return;
    }
    let traversable = |id: &str| kg.nodes.get(id).map(|n| matches!(n.kind, KKind::Asset | KKind::Endpoint | KKind::Finding | KKind::Account)).unwrap_or(false);
    let mut keep: HashSet<&str> = HashSet::from([root.as_str()]);
    let mut queue: Vec<&str> = vec![root.as_str()];
    while let Some(cur) = queue.pop() {
        for e in &kg.edges {
            let other = if e.from == cur {
                e.to.as_str()
            } else if e.to == cur {
                e.from.as_str()
            } else {
                continue;
            };
            // Never hop to another target's asset.
            if other.starts_with("asset:") && other != root {
                continue;
            }
            if keep.insert(other) && traversable(other) {
                queue.push(other);
            }
        }
    }
    let mut map: HashMap<String, NodeRef> = HashMap::new();
    for (id, n) in &kg.nodes {
        if !keep.contains(id.as_str()) || n.runs.iter().all(|r| r == current_run) {
            continue;
        }
        let runs: Vec<String> = n.runs.iter().take(10).cloned().collect();
        let common: Vec<(&str, Value)> = vec![("source", json!("history")), ("runs", json!(runs)), ("target_id", json!(tid))];
        let (label, key, mut extra): (Label, String, Vec<(&str, Value)>) = match n.kind {
            KKind::Asset => (Label::Asset, format!("kg:{id}"), vec![("name", json!(short(&n.label, 120)))]),
            KKind::Endpoint => (Label::Endpoint, format!("kg:{id}"), vec![("path", json!(short(&clean_path(&n.label), 160)))]),
            KKind::Tech => (Label::Technology, format!("kg:{id}"), vec![("name", json!(short(&n.label, 80)))]),
            KKind::Weakness => (Label::Vulnerability, format!("kg:{id}"), vec![("type", json!(short(&n.label, 80)))]),
            KKind::Technique => (Label::AttackStep, format!("kg:{id}"), vec![("mitre", json!(short(&n.label, 40)))]),
            KKind::Finding => {
                let sev = n.meta.get("severity").cloned().unwrap_or_default();
                (
                    Label::Finding,
                    format!("kg:{id}"),
                    vec![
                        ("title", json!(short(&n.label, 160))),
                        ("local_severity", json!(sev_name(sev_rank(&sev)))),
                        ("status", json!(Status::NeedsReview.as_str())),
                    ],
                )
            }
            KKind::Account => (Label::Identity, format!("kg:{id}"), vec![("name", json!(mask_identity(&n.label))), ("privileged", json!(privileged_name(&n.label)))]),
            KKind::Credential => {
                let fp = fingerprint(&format!("{tid}|{id}"));
                (Label::Credential, format!("fp:{fp}"), vec![("fingerprint", json!(fp)), ("redacted", json!("****"))])
            }
            KKind::Impact => (Label::BusinessImpact, format!("kg:{id}"), vec![("title", json!(short(&n.label, 80))), ("category", json!("historical-impact"))]),
        };
        extra.extend(common);
        let r = b.put(label, &key, &extra);
        map.insert(id.clone(), r);
    }
    for e in &kg.edges {
        let (Some(a), Some(c)) = (map.get(&e.from), map.get(&e.to)) else { continue };
        let (rel, from, to) = match e.kind {
            KEdge::Exposes => (Rel::HasEndpoint, a, c),
            KEdge::Runs => (Rel::UsesTech, a, c),
            KEdge::Vulnerable => (Rel::HasVulnerability, a, c),
            KEdge::Proves => (Rel::HasFinding, c, a),
            KEdge::ObservedOn => (Rel::ObservedIn, a, c),
            KEdge::Uses => (Rel::Enables, a, c),
            KEdge::Chains => (Rel::EscalatesTo, a, c),
            KEdge::Grants => (Rel::Yields, a, c),
            KEdge::Leads => (Rel::Impacts, a, c),
        };
        // History is memory, not proof for this run: it never counts as confirmed.
        let st = if e.inferred { Status::Hypothesis } else { Status::NeedsReview };
        b.link(rel, from, to, st, e.p.min(0.7), &[], &[("source", json!("history"))]);
    }
}

/// Build the full batch for a run.
pub fn build(target: &str, run: &str, findings: &[Finding], internal: Option<&InternalGraph>, history: Option<&KnowledgeGraph>) -> GraphBatch {
    let mut b = GraphBatch::new(target);
    project_findings(&mut b, target, run, findings);
    if let Some(g) = internal {
        project_internal(&mut b, g);
    }
    if let Some(kg) = history {
        project_history(&mut b, kg, run, target);
    }
    b
}

// ---------------------------------------------------------------------------
// Reasoning

/// One attack chain, in the analyst format.
#[derive(Clone, Debug)]
pub struct AttackChain {
    pub title: String,
    pub status: Status,
    /// (title, local severity, status) of each finding on the path.
    pub findings: Vec<(String, String, String)>,
    pub steps: Vec<String>,
    pub evidence: Vec<String>,
    pub assumptions: Vec<String>,
    pub local_severity: String,
    pub chain_severity: String,
    /// What the chain severity would be once every step is validated.
    pub potential_severity: Option<String>,
    pub confidence: f64,
    pub blast_radius: usize,
    pub exploitability: String,
    pub impact: String,
    pub validation: Vec<String>,
    pub remediation: Vec<String>,
    pub score: f64,
    pub nodes: Vec<NodeRef>,
    /// Finding ids on the path (for seed prioritisation).
    pub finding_ids: Vec<String>,
    /// The path's relationships, in order (for the dependency todolist).
    pub edges: Vec<GEdge>,
}

fn is_goal(b: &GraphBatch, r: &NodeRef) -> bool {
    match r.0 {
        Label::BusinessImpact => true,
        Label::Asset | Label::Host => b.prop_bool(r, "critical"),
        Label::Role | Label::Identity => b.prop_bool(r, "privileged"),
        _ => false,
    }
}

fn is_start(b: &GraphBatch, r: &NodeRef) -> bool {
    match r.0 {
        Label::Finding => matches!(b.prop_str(r, "status").as_str(), "confirmed" | "needs_review"),
        Label::Credential | Label::Secret => true,
        Label::Asset => b.prop_bool(r, "entry"),
        _ => false,
    }
}

fn validation_for(b: &GraphBatch, e: &GEdge) -> String {
    let (a, c) = (b.name(&e.from), b.name(&e.to));
    match e.rel {
        Rel::EscalatesTo => format!("Replay {a}, feed its output into {c}, and capture the request/response showing {c} succeeds only with that output."),
        Rel::Yields => format!("Re-run {a} and record (redacted, hashed) the material it returns as {c}."),
        Rel::CanAccess => format!("Authenticate as / with {a} against {c} (in scope, lockout-aware, stop at first success) and keep the success receipt."),
        Rel::PivotsTo => format!("From a foothold on {a}, demonstrate network reach to {c} (connect + banner) and log it."),
        Rel::HasPermission => format!("Enumerate {a}'s permission on {c} with a read-only query and attach the output."),
        Rel::Impacts => format!("Demonstrate {c} from {a} with a benign proof (masked sample, harmless command output, or read-back)."),
        Rel::Enables => format!("Re-run the exploit for {a} and attach the receipt."),
        _ => format!("Collect evidence that {a} {} {c}.", e.rel.as_str()),
    }
}

/// Indexes computed once per reasoning pass, so assembling a chain never
/// rescans every edge (internal graphs get large).
struct Ctx<'a> {
    /// finding → the host it was proven on
    host_of: HashMap<&'a NodeRef, &'a NodeRef>,
    /// finding → evidence nodes supporting it
    evidence_of: HashMap<&'a NodeRef, Vec<&'a NodeRef>>,
    /// finding → mitigation title
    mitigation_of: HashMap<&'a NodeRef, String>,
    /// node → what it reaches (CAN_ACCESS / PIVOTS_TO / HAS_PERMISSION / HOSTS)
    reach: HashMap<&'a NodeRef, Vec<&'a NodeRef>>,
    /// finding → what its exploitation step yields (credentials, identities)
    yields_of: HashMap<&'a NodeRef, Vec<&'a NodeRef>>,
}

impl<'a> Ctx<'a> {
    fn new(b: &'a GraphBatch) -> Ctx<'a> {
        let mut by_to: HashMap<(Rel, &NodeRef), &NodeRef> = HashMap::new();
        let mut evidence_of: HashMap<&NodeRef, Vec<&NodeRef>> = HashMap::new();
        let mut mit_of_vuln: HashMap<&NodeRef, String> = HashMap::new();
        let mut reach: HashMap<&NodeRef, Vec<&NodeRef>> = HashMap::new();
        let mut step_of: HashMap<&NodeRef, &NodeRef> = HashMap::new();
        let mut yields_of_step: HashMap<&NodeRef, Vec<&NodeRef>> = HashMap::new();
        for e in b.edges.values() {
            match e.rel {
                Rel::HasFinding | Rel::HasVulnerability | Rel::HasEndpoint | Rel::Exposes => {
                    by_to.insert((e.rel, &e.to), &e.from);
                }
                Rel::SupportedBy => evidence_of.entry(&e.from).or_default().push(&e.to),
                Rel::MitigatedBy => {
                    let t = b.prop_str(&e.to, "title");
                    if !t.is_empty() {
                        mit_of_vuln.insert(&e.from, t);
                    }
                }
                Rel::CanAccess | Rel::PivotsTo | Rel::HasPermission | Rel::Hosts => reach.entry(&e.from).or_default().push(&e.to),
                Rel::Enables if e.from.0 == Label::Finding && e.to.0 == Label::AttackStep => {
                    step_of.insert(&e.from, &e.to);
                }
                Rel::Yields => yields_of_step.entry(&e.from).or_default().push(&e.to),
                _ => {}
            }
        }
        let mut host_of = HashMap::new();
        let mut mitigation_of = HashMap::new();
        let mut yields_of = HashMap::new();
        for r in b.nodes.keys().filter(|r| r.0 == Label::Finding) {
            let vuln = by_to.get(&(Rel::HasFinding, r)).copied();
            if let Some(v) = vuln {
                if let Some(m) = mit_of_vuln.get(v) {
                    mitigation_of.insert(r, m.clone());
                }
                let host = by_to
                    .get(&(Rel::HasVulnerability, v))
                    .and_then(|ep| by_to.get(&(Rel::HasEndpoint, *ep)))
                    .and_then(|svc| by_to.get(&(Rel::Exposes, *svc)))
                    .copied();
                if let Some(h) = host {
                    host_of.insert(r, h);
                }
            }
            if let Some(step) = step_of.get(r) {
                if let Some(y) = yields_of_step.get(*step) {
                    yields_of.insert(r, y.clone());
                }
            }
        }
        Ctx { host_of, evidence_of, mitigation_of, reach, yields_of }
    }
}

/// Find attack chains: paths of ≥2 attack steps from a start (finding,
/// credential, exposed asset) to a goal (business impact, critical asset,
/// privileged identity/role), scored and labelled per the reasoning rules.
pub fn chains(b: &GraphBatch, max_depth: usize, limit: usize) -> Vec<AttackChain> {
    let ctx = Ctx::new(b);
    let mut adj: HashMap<&NodeRef, Vec<&GEdge>> = HashMap::new();
    for e in b.edges.values().filter(|e| e.rel.is_traversal()) {
        adj.entry(&e.from).or_default().push(e);
    }
    let starts: Vec<&NodeRef> = b.nodes.keys().filter(|r| is_start(b, r)).collect();
    let mut found: HashMap<(NodeRef, NodeRef), AttackChain> = HashMap::new();
    let mut budget = 20_000usize;

    for s in starts {
        // Iterative DFS over simple paths.
        let mut stack: Vec<(Vec<&NodeRef>, Vec<&GEdge>)> = vec![(vec![s], vec![])];
        let mut per_start = 0;
        while let Some((path, edges)) = stack.pop() {
            if budget == 0 || per_start >= 40 {
                break;
            }
            budget -= 1;
            let last = *path.last().unwrap();
            if edges.len() >= 2 && is_goal(b, last) {
                let c = assemble(b, &ctx, &path, &edges);
                per_start += 1;
                let k = (s.clone(), last.clone());
                if found.get(&k).map(|old| c.score > old.score).unwrap_or(true) {
                    found.insert(k, c);
                }
            }
            if edges.len() >= max_depth {
                continue;
            }
            if let Some(next) = adj.get(last) {
                for e in next {
                    if path.contains(&&e.to) {
                        continue;
                    }
                    let mut p = path.clone();
                    p.push(&e.to);
                    let mut es = edges.clone();
                    es.push(e);
                    stack.push((p, es));
                }
            }
        }
    }

    let mut out: Vec<AttackChain> = found.into_values().collect();
    out.sort_by(|a, c| c.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal).then(a.title.cmp(&c.title)));

    // Choke points: the node most chains pass through is the cheapest place
    // to break them.
    let mut count: HashMap<NodeRef, usize> = HashMap::new();
    for c in &out {
        for n in c.nodes.iter().skip(1).take(c.nodes.len().saturating_sub(2)) {
            *count.entry(n.clone()).or_default() += 1;
        }
    }
    for c in out.iter_mut() {
        if let Some((n, k)) = c.nodes.iter().skip(1).filter_map(|n| count.get(n).map(|k| (n, *k))).max_by_key(|(_, k)| *k) {
            if k > 1 {
                c.remediation.push(format!("Choke point: {} sits on {k} chain(s) — fixing it breaks all of them.", b.name(n)));
            }
        }
    }
    out.truncate(limit);
    out
}

fn assemble(b: &GraphBatch, ctx: &Ctx, path: &[&NodeRef], edges: &[&GEdge]) -> AttackChain {
    let nodes: Vec<NodeRef> = path.iter().map(|r| (*r).clone()).collect();
    let goal = nodes.last().unwrap();

    // Findings on the path.
    let mut findings = Vec::new();
    let mut finding_ids = Vec::new();
    let mut local = 0u8;
    let mut all_confirmed = true;
    let mut any_hypothesis = false;
    let mut exploit_worst = 0u8;
    let mut evidence: Vec<String> = Vec::new();
    for r in &nodes {
        if r.0 == Label::Finding {
            let st = b.prop_str(r, "status");
            let sev = b.prop_str(r, "local_severity");
            local = local.max(sev_rank(&sev));
            if st != "confirmed" {
                all_confirmed = false;
            }
            if st == "hypothesis" || b.prop_str(r, "source") == "history" {
                any_hypothesis = true;
            }
            exploit_worst = exploit_worst.max(match b.prop_str(r, "exploitability").to_lowercase().as_str() {
                "hard" => 3,
                "moderate" => 2,
                "trivial" => 1,
                _ => 0,
            });
            findings.push((b.name(r), if sev.is_empty() { "Info".into() } else { sev }, if st.is_empty() { "unknown".into() } else { st }));
            let fid = b.prop_str(r, "finding_id");
            if !fid.is_empty() {
                finding_ids.push(fid);
            }
            for e in ctx.evidence_of.get(r).into_iter().flatten() {
                evidence.push(format!("{} ← evidence `{}`", b.name(r), &e.1[..16.min(e.1.len())]));
            }
        }
    }

    // Steps, assumptions, validation.
    let mut steps = Vec::new();
    let mut assumptions = Vec::new();
    let mut validation = Vec::new();
    let mut conf = 1.0f64;
    let mut edges_confirmed = true;
    for e in edges {
        conf *= e.confidence.max(0.05);
        steps.push(format!("{} —[{}]→ {} ({}, conf {:.2})", b.name(&e.from), e.rel.as_str(), b.name(&e.to), e.status.as_str(), e.confidence));
        for r in &e.evidence {
            evidence.push(format!("{} edge ← `{}`", e.rel.as_str(), r));
        }
        if e.status != Status::Confirmed {
            edges_confirmed = false;
            if e.status == Status::Hypothesis {
                any_hypothesis = true;
            }
            let basis = e.props.get("basis").or_else(|| e.props.get("technique")).and_then(|v| v.as_str()).unwrap_or("not evidenced");
            assumptions.push(format!("{} {} {} — {} ({})", b.name(&e.from), e.rel.as_str(), b.name(&e.to), basis, e.status.as_str()));
            validation.push(validation_for(b, e));
        }
    }
    if findings.iter().any(|(_, _, st)| st != "confirmed") {
        assumptions.push("At least one finding on the path is not confirmed by the validation engine.".into());
    }
    evidence.sort();
    evidence.dedup();

    // Nodes that are themselves only hypothesised (e.g. an unproven internal
    // credential) make the whole path a hypothesis.
    if nodes.iter().any(|r| b.prop_str(r, "status") == "hypothesis") {
        any_hypothesis = true;
    }
    let has_findings = !findings.is_empty();
    let status = if all_confirmed && edges_confirmed {
        Status::Confirmed
    } else if any_hypothesis || (has_findings && !findings.iter().any(|(_, _, st)| st == "confirmed")) {
        Status::Hypothesis
    } else {
        Status::NeedsValidation
    };

    // What the goal is worth.
    let (goal_rank, impact) = match goal.0 {
        Label::BusinessImpact => {
            let cat = b.prop_str(goal, "category");
            (impact_rank(&cat), format!("{} ({})", cat.replace('-', " "), b.name(goal)))
        }
        Label::Asset | Label::Host => (4, format!("control of critical asset {}", b.name(goal))),
        Label::Role | Label::Identity => (4, format!("privileged identity {}", b.name(goal))),
        _ => (2, b.name(goal)),
    };
    let escalates = edges.iter().any(|e| matches!(e.rel, Rel::EscalatesTo | Rel::PivotsTo));
    let potential = goal_rank.max(if escalates { 3 } else { 0 }).max(local);
    let (chain_sev, potential_sev) = if status == Status::Confirmed {
        (sev_name(potential).to_string(), None)
    } else {
        // Never upgrade without an evidenced path.
        let base = if local == 0 { "Needs Review".to_string() } else { sev_name(local).to_string() };
        (base, (potential > local).then(|| sev_name(potential).to_string()))
    };

    // Blast radius: hosts the path's findings were proven on, what their
    // exploitation yielded, assets/identities on the path, and what the goal
    // side reaches in two more hops.
    let mut reach: HashSet<NodeRef> = nodes
        .iter()
        .filter(|r| matches!(r.0, Label::Host | Label::Asset | Label::Identity | Label::Credential | Label::Secret | Label::Role))
        .cloned()
        .collect();
    for r in nodes.iter().filter(|r| r.0 == Label::Finding) {
        if let Some(h) = ctx.host_of.get(r) {
            reach.insert((*h).clone());
        }
        for y in ctx.yields_of.get(r).into_iter().flatten() {
            reach.insert((*y).clone());
        }
    }
    let mut frontier: Vec<NodeRef> = reach.iter().cloned().chain(std::iter::once(goal.clone())).collect();
    for _ in 0..2 {
        let mut nxt = Vec::new();
        for f in &frontier {
            for t in ctx.reach.get(f).into_iter().flatten() {
                if reach.insert((*t).clone()) {
                    nxt.push((*t).clone());
                }
            }
        }
        frontier = nxt;
    }
    let blast = reach.len();

    let exploitability = format!(
        "{} · {} step(s)",
        match exploit_worst {
            3 => "hard",
            2 => "moderate",
            1 => "trivial",
            _ => "unknown",
        },
        edges.len()
    );
    let mut remediation: Vec<String> = Vec::new();
    if let Some(r) = nodes.iter().find(|r| r.0 == Label::Finding) {
        // Earliest finding: fixing it removes the chain's entry.
        match ctx.mitigation_of.get(r) {
            Some(m) => remediation.push(format!("Break the entry point ({}): {}", b.name(r), m)),
            None => remediation.push(format!("Break the entry point: remediate {}.", b.name(r))),
        }
    }
    if let Some(Value::String(s)) = edges.iter().find_map(|e| e.props.get("remediation")) {
        if !s.is_empty() {
            remediation.push(format!("Cut the step that relies on it: {s}"));
        }
    }

    let first = b.name(&nodes[0]);
    let title = format!("{} → {}", short(&first, 70), short(&b.name(goal), 70));
    let status_w = match status {
        Status::Confirmed => 1.0,
        Status::NeedsValidation | Status::NeedsReview => 0.6,
        Status::Hypothesis => 0.3,
    };
    let score = (potential as f64 / 4.0) * status_w * (0.5 + 0.5 * conf) + 0.02 * blast as f64;

    AttackChain {
        title,
        status,
        findings,
        steps,
        evidence,
        assumptions,
        local_severity: sev_name(local).to_string(),
        chain_severity: chain_sev,
        potential_severity: potential_sev,
        confidence: conf,
        blast_radius: blast,
        exploitability,
        impact,
        validation,
        remediation,
        score,
        nodes,
        finding_ids,
        edges: edges.iter().map(|e| (*e).clone()).collect(),
    }
}

impl AttackChain {
    /// The 11-field analyst format.
    pub fn to_markdown(&self, n: usize) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "## {n}. {}\n", self.title);
        let _ = writeln!(s, "- **Status:** {}", self.status.as_str());
        let _ = writeln!(
            s,
            "- **Chain severity:** {}{} (local max: {})",
            self.chain_severity,
            self.potential_severity.as_deref().map(|p| format!(" — {p} once validated")).unwrap_or_default(),
            self.local_severity
        );
        let _ = writeln!(s, "- **Confidence:** {:.2} · **blast radius:** {} node(s) · **exploitability:** {}", self.confidence, self.blast_radius, self.exploitability);
        let _ = writeln!(s, "- **Impact:** {}\n", self.impact);
        s.push_str("**Local findings involved**\n\n");
        if self.findings.is_empty() {
            s.push_str("- none (path starts from a credential or exposed asset)\n");
        }
        for (t, sev, st) in &self.findings {
            let _ = writeln!(s, "- {t} — {sev} ({st})");
        }
        s.push_str("\n**Attack path**\n\n");
        for (i, st) in self.steps.iter().enumerate() {
            let _ = writeln!(s, "{}. {st}", i + 1);
        }
        s.push_str("\n**Evidence references**\n\n");
        if self.evidence.is_empty() {
            s.push_str("- none recorded — this chain is unproven\n");
        }
        for e in &self.evidence {
            let _ = writeln!(s, "- {e}");
        }
        s.push_str("\n**Required assumptions**\n\n");
        if self.assumptions.is_empty() {
            s.push_str("- none — every step is evidenced\n");
        }
        for a in &self.assumptions {
            let _ = writeln!(s, "- {a}");
        }
        s.push_str("\n**Recommended validation**\n\n");
        if self.validation.is_empty() {
            s.push_str("- none needed — confirmed end to end\n");
        }
        for v in &self.validation {
            let _ = writeln!(s, "- {v}");
        }
        s.push_str("\n**Recommended remediation**\n\n");
        for r in &self.remediation {
            let _ = writeln!(s, "- {r}");
        }
        s.push('\n');
        s
    }
}

/// One step of an attack chain in dependency order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TodoState {
    /// Evidenced — the fact it needed exists.
    Done,
    /// Every earlier step is done: dispatch this next.
    Ready,
    /// Waiting on an earlier step (1-based index in the same chain).
    Blocked(usize),
}

#[derive(Clone, Debug)]
pub struct TodoStep {
    pub chain: String,
    /// 1-based position in the chain, and the chain length.
    pub index: usize,
    pub of: usize,
    pub step: String,
    pub state: TodoState,
    /// What to do to complete this step (the evidence it needs).
    pub action: String,
    /// The finding to expand from (the last finding at or before the step).
    pub seed_finding: Option<String>,
    pub chain_severity: String,
    pub potential: Option<String>,
}

/// The shared, persistent attack todolist — derived from the graph itself, so
/// it survives every round and every restart: a step is done exactly when the
/// graph holds evidence for it. Steps are released strictly in dependency
/// order; nothing later in a chain is dispatched before what it depends on.
pub fn todo(b: &GraphBatch, chains: &[AttackChain]) -> Vec<TodoStep> {
    let mut out = Vec::new();
    for c in chains.iter().filter(|c| c.status != Status::Confirmed) {
        let of = c.edges.len() + 1;
        // Step 1 is the chain's own entry: a finding must be confirmed first.
        let start = &c.nodes[0];
        let start_ok = start.0 != Label::Finding || b.prop_str(start, "status") == "confirmed";
        let start_seed = (start.0 == Label::Finding).then(|| b.prop_str(start, "finding_id")).filter(|s| !s.is_empty());
        out.push(TodoStep {
            chain: c.title.clone(),
            index: 1,
            of,
            step: format!("entry: {}", b.name(start)),
            state: if start_ok { TodoState::Done } else { TodoState::Ready },
            action: if start_ok { "confirmed".into() } else { format!("Confirm {} with a reproducible receipt (baseline vs attack, or the harness marker).", b.name(start)) },
            seed_finding: start_seed.clone(),
            chain_severity: c.chain_severity.clone(),
            potential: c.potential_severity.clone(),
        });
        let mut first_open: Option<usize> = if start_ok { None } else { Some(1) };
        let mut seed = start_seed;
        for (i, e) in c.edges.iter().enumerate() {
            let idx = i + 2;
            if e.from.0 == Label::Finding {
                let fid = b.prop_str(&e.from, "finding_id");
                if !fid.is_empty() {
                    seed = Some(fid);
                }
            }
            let done = e.status == Status::Confirmed;
            let state = if done {
                TodoState::Done
            } else if let Some(k) = first_open {
                TodoState::Blocked(k)
            } else {
                first_open = Some(idx);
                TodoState::Ready
            };
            out.push(TodoStep {
                chain: c.title.clone(),
                index: idx,
                of,
                step: format!("{} —[{}]→ {}", b.name(&e.from), e.rel.as_str(), b.name(&e.to)),
                action: if done { "evidenced".into() } else { validation_for(b, e) },
                state,
                seed_finding: seed.clone(),
                chain_severity: c.chain_severity.clone(),
                potential: c.potential_severity.clone(),
            });
        }
    }
    out
}

/// The steps to dispatch now, deduplicated by action, best chains first.
pub fn ready_steps(todo: &[TodoStep]) -> Vec<&TodoStep> {
    let mut seen = HashSet::new();
    todo.iter().filter(|t| t.state == TodoState::Ready && seen.insert(t.action.clone())).collect()
}

pub fn todo_markdown(target: &str, todo: &[TodoStep]) -> String {
    let mut s = format!(
        "# Attack todolist — {target}\n\nEach unconfirmed chain, step by step in dependency order. A step is `done` when the graph holds evidence for it, `ready` when everything before it is done, `blocked` otherwise. The chaining rounds dispatch `ready` steps only.\n\n"
    );
    let mut cur = String::new();
    for t in todo {
        if t.chain != cur {
            cur = t.chain.clone();
            let _ = writeln!(s, "\n## {}  ({}{})\n", t.chain, t.chain_severity, t.potential.as_deref().map(|p| format!(" → {p} once validated")).unwrap_or_default());
        }
        let state = match &t.state {
            TodoState::Done => "✅ done".to_string(),
            TodoState::Ready => "▶ ready".to_string(),
            TodoState::Blocked(k) => format!("⏸ blocked by step {k}"),
        };
        let _ = writeln!(s, "{}. [{}] {}", t.index, state, t.step);
        if t.state != TodoState::Done {
            let _ = writeln!(s, "   - {}", t.action);
        }
    }
    if todo.is_empty() {
        s.push_str("_Nothing pending: every chain is confirmed or there is no multi-step path._\n");
    }
    s
}

/// Chains as JSON (for the web console).
pub fn chains_json(chains: &[AttackChain], moves: &[String]) -> String {
    let cs: Vec<Value> = chains
        .iter()
        .map(|c| {
            json!({
                "title": c.title, "status": c.status.as_str(), "chain_severity": c.chain_severity,
                "potential_severity": c.potential_severity, "local_severity": c.local_severity,
                "confidence": c.confidence, "blast_radius": c.blast_radius, "exploitability": c.exploitability,
                "impact": c.impact, "score": c.score,
                "findings": c.findings.iter().map(|(t, sev, st)| json!({"title": t, "severity": sev, "status": st})).collect::<Vec<_>>(),
                "finding_ids": c.finding_ids,
                "steps": c.edges.iter().map(|e| json!({"rel": e.rel.as_str(), "from": e.from.0.as_str(), "to": e.to.0.as_str(), "status": e.status.as_str(), "confidence": e.confidence})).collect::<Vec<_>>(),
                "step_text": c.steps, "evidence": c.evidence, "assumptions": c.assumptions,
                "validation": c.validation, "remediation": c.remediation,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({"chains": cs, "next_moves": moves})).unwrap_or_default()
}

/// The dependency todolist as JSON (for the web console).
pub fn todo_json(todo: &[TodoStep]) -> String {
    let rows: Vec<Value> = todo
        .iter()
        .map(|t| {
            let (state, blocked_by) = match &t.state {
                TodoState::Done => ("done", None),
                TodoState::Ready => ("ready", None),
                TodoState::Blocked(k) => ("blocked", Some(*k)),
            };
            json!({"chain": t.chain, "index": t.index, "of": t.of, "step": t.step, "state": state, "blocked_by": blocked_by,
                   "action": t.action, "seed_finding": t.seed_finding, "chain_severity": t.chain_severity, "potential": t.potential})
        })
        .collect();
    serde_json::to_string_pretty(&rows).unwrap_or_default()
}

/// Decision support: the moves most likely to complete a high-value path.
pub fn next_moves(b: &GraphBatch, chains: &[AttackChain], limit: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let push = |out: &mut Vec<String>, s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    // 1. The first unvalidated step of the best unconfirmed chains.
    for c in chains.iter().filter(|c| c.status != Status::Confirmed) {
        if let Some(v) = c.validation.first() {
            let unlock = c.potential_severity.as_deref().unwrap_or(&c.chain_severity);
            push(&mut out, format!("VALIDATE ({unlock} if proven — {}): {v}", short(&c.impact, 80)));
        }
    }
    // 2. Yielded credentials/secrets/identities that nobody has tried yet.
    let hosts: Vec<String> = b.nodes.keys().filter(|r| r.0 == Label::Host).map(|r| b.name(r)).take(6).collect();
    for r in b.nodes.keys().filter(|r| matches!(r.0, Label::Credential | Label::Secret | Label::Identity)) {
        let yielded = b.edges.values().any(|e| e.rel == Rel::Yields && &e.to == r);
        let used = b.edges.values().any(|e| matches!(e.rel, Rel::CanAccess | Rel::HasPermission) && &e.from == r);
        if yielded && !used && !hosts.is_empty() {
            push(&mut out, format!("REUSE: try {} against in-scope services on {} (lockout-aware, stop at first success, record the receipt).", b.name(r), hosts.join(", ")));
        }
    }
    // 3. Code execution with no recorded reach beyond the host.
    for e in b.edges.values().filter(|e| e.rel == Rel::Impacts && b.prop_str(&e.to, "category") == "code-execution" && e.status == Status::Confirmed) {
        let host_pivot = b.edges.values().any(|p| p.rel == Rel::PivotsTo);
        if !host_pivot {
            push(&mut out, format!("PIVOT: {} gives code execution — enumerate internal reach from that host (in-scope ranges only) to connect the web foothold to the internal graph.", b.name(&e.from)));
        }
    }
    // 4. SSRF without a recorded internal target.
    for r in b.nodes.keys().filter(|r| r.0 == Label::Finding && b.prop_str(r, "cwe").contains("918")) {
        let reached = b.edges.values().any(|e| &e.from == r && e.rel == Rel::Impacts && e.status == Status::Confirmed);
        if !reached {
            push(&mut out, format!("SSRF: use {} to reach cloud metadata / internal admin services in scope and record a canary or retrieved resource.", b.name(r)));
        }
    }
    out.truncate(limit);
    out
}

/// Compact block for the attack-chaining prompt.
pub fn prompt_block(chains: &[AttackChain], moves: &[String]) -> String {
    if chains.is_empty() && moves.is_empty() {
        return String::new();
    }
    let mut s = String::from(
        "GRAPH REASONING (attack graph across web + internal network). Rules: an unvalidated chain keeps its local severity; prove the missing edge before claiming the chain. Never invent credentials or access.\n",
    );
    for c in chains.iter().take(6) {
        let _ = writeln!(
            s,
            "- [{}] {} — chain {}{} · conf {:.2}",
            c.status.as_str(),
            short(&c.title, 140),
            c.chain_severity,
            c.potential_severity.as_deref().map(|p| format!(" (→{p} if validated)")).unwrap_or_default(),
            c.confidence
        );
    }
    if !moves.is_empty() {
        s.push_str("NEXT MOVES (highest value first):\n");
        for m in moves.iter().take(8) {
            let _ = writeln!(s, "- {}", short(m, 260));
        }
    }
    s.push('\n');
    s.chars().take(3500).collect()
}

/// Seed priority for the chaining frontier: a finding on a valuable chain is
/// expanded first.
pub fn seed_priority(chains: &[AttackChain]) -> HashMap<String, f64> {
    let mut p: HashMap<String, f64> = HashMap::new();
    for c in chains {
        for id in &c.finding_ids {
            let e = p.entry(id.clone()).or_insert(0.0);
            *e = e.max(c.score);
        }
    }
    p
}

/// Write each chain back as an AttackPath node with PART_OF_PATH edges, so
/// Neo4j can answer "which hypotheses still need validation".
pub fn record_paths(b: &mut GraphBatch, chains: &[AttackChain], run: &str) {
    for c in chains {
        let key = sha(&c.nodes.iter().map(|n| format!("{}:{}", n.0.as_str(), n.1)).collect::<Vec<_>>().join(">"))[..32].to_string();
        let p = b.put(
            Label::AttackPath,
            &key,
            &[
                ("title", json!(short(&c.title, 200))),
                ("status", json!(c.status.as_str())),
                ("chain_severity", json!(c.chain_severity)),
                ("potential_severity", json!(c.potential_severity.clone().unwrap_or_default())),
                ("local_severity", json!(c.local_severity)),
                ("confidence", json!(c.confidence)),
                ("risk_score", json!(c.score)),
                ("blast_radius", json!(c.blast_radius)),
                ("hops", json!(c.steps.len())),
                ("target_id", json!(b.target_id.clone())),
                ("run", json!(run)),
            ],
        );
        for (i, n) in c.nodes.iter().enumerate() {
            b.link(Rel::PartOfPath, n, &p, c.status, c.confidence, &[], &[("position", json!(i))]);
        }
    }
}

/// The chains report written next to the other deliverables.
pub fn chains_markdown(target: &str, chains: &[AttackChain], moves: &[String]) -> String {
    let mut s = format!(
        "# Attack chains — {target}\n\nPaths through the attack graph (web + internal network) from a foothold to a business impact, crown-jewel asset or privileged identity. A chain's severity is only raised above its findings' local severity when every step is evidenced; otherwise it is reported as `needs_validation` or `hypothesis` with the evidence that would prove it.\n\n"
    );
    let conf = chains.iter().filter(|c| c.status == Status::Confirmed).count();
    let _ = writeln!(s, "{} chain(s): {} confirmed, {} awaiting validation.\n", chains.len(), conf, chains.len() - conf);
    if !moves.is_empty() {
        s.push_str("## Next moves\n\n");
        for m in moves {
            let _ = writeln!(s, "- {m}");
        }
        s.push('\n');
    }
    for (i, c) in chains.iter().enumerate() {
        s.push_str(&c.to_markdown(i + 1));
    }
    if chains.is_empty() {
        s.push_str("_No multi-step path to an impact was found in the evidence. Isolated findings keep their local severity._\n");
    }
    s
}

// ---------------------------------------------------------------------------
// Cypher (parameterised) + offline export

/// Parameterised MERGE statements: constraints, nodes per label, edges per
/// (type, from-label, to-label). Labels/types come from the closed enums only.
pub fn cypher_statements(b: &GraphBatch, run: &str) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Vec::new();
    let labels: BTreeSet<Label> = b.nodes.keys().map(|k| k.0).collect();
    for l in &labels {
        out.push((
            format!("CREATE CONSTRAINT ns_{}_key IF NOT EXISTS FOR (n:{}) REQUIRE n.key IS UNIQUE", l.as_str().to_lowercase(), l.as_str()),
            json!({}),
        ));
    }
    for l in &labels {
        let rows: Vec<Value> = b.nodes.values().filter(|n| n.label == *l).map(|n| json!({"key": n.key, "props": n.props})).collect();
        for chunk in rows.chunks(500) {
            let stmt = if *l == Label::Evidence {
                format!("UNWIND $rows AS row MERGE (n:{} {{key: row.key}}) ON CREATE SET n += row.props, n.created_at = timestamp(), n.first_run = $run", l.as_str())
            } else {
                format!(
                    "UNWIND $rows AS row MERGE (n:{} {{key: row.key}}) ON CREATE SET n.created_at = timestamp(), n.first_run = $run SET n += row.props, n.updated_at = timestamp(), n.last_run = $run",
                    l.as_str()
                )
            };
            out.push((stmt, json!({"rows": chunk, "run": run})));
        }
    }
    let mut groups: BTreeMap<(Rel, Label, Label), Vec<Value>> = BTreeMap::new();
    for e in b.edges.values() {
        let mut props = e.props.clone();
        if !e.evidence.is_empty() {
            props.insert("evidence".into(), json!(e.evidence.iter().cloned().collect::<Vec<_>>()));
        }
        props.insert("tool_name".into(), json!("neurosploit"));
        groups.entry((e.rel, e.from.0, e.to.0)).or_default().push(json!({
            "from": e.from.1, "to": e.to.1, "status": e.status.as_str(), "confidence": e.confidence, "props": props,
        }));
    }
    for ((rel, fl, tl), rows) in groups {
        for chunk in rows.chunks(500) {
            let stmt = format!(
                "UNWIND $rows AS row MATCH (a:{} {{key: row.from}}) MATCH (b:{} {{key: row.to}}) MERGE (a)-[r:{}]->(b) \
                 ON CREATE SET r.created_at = timestamp() \
                 SET r += row.props, \
                     r.status = CASE WHEN r.status = 'confirmed' THEN 'confirmed' ELSE row.status END, \
                     r.confidence = CASE WHEN r.confidence IS NULL OR row.confidence > r.confidence THEN row.confidence ELSE r.confidence END, \
                     r.updated_at = timestamp(), r.last_run = $run",
                fl.as_str(),
                tl.as_str(),
                rel.as_str()
            );
            out.push((stmt, json!({"rows": chunk, "run": run})));
        }
    }
    out
}

/// A Cypher literal for an offline script (strings escaped; keys backticked).
fn cypher_literal(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            let mut o = String::from("'");
            for ch in s.chars() {
                match ch {
                    '\\' => o.push_str("\\\\"),
                    '\'' => o.push_str("\\'"),
                    '\n' => o.push_str("\\n"),
                    '\r' => o.push_str("\\r"),
                    '\t' => o.push_str("\\t"),
                    c => o.push(c),
                }
            }
            o.push('\'');
            o
        }
        Value::Array(a) => format!("[{}]", a.iter().map(cypher_literal).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => format!(
            "{{{}}}",
            m.iter().map(|(k, v)| format!("`{}`: {}", k.replace('`', "``"), cypher_literal(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// An offline Cypher script: `cypher-shell -u neo4j -p … -f graph.cypher`.
/// Values are emitted as escaped literals bound once per statement.
pub fn export_cypher(b: &GraphBatch, run: &str) -> String {
    let mut s = String::from(
        "// NeuroSploit attack graph — load with:\n//   cypher-shell -a <uri> -u <user> -p <password> -f graph.cypher\n// Idempotent: MERGE on stable keys; secrets are fingerprints only.\n\n",
    );
    for (stmt, params) in cypher_statements(b, run) {
        let rows = params.get("rows").map(cypher_literal);
        let run_lit = cypher_literal(&json!(run));
        let mut st = stmt.replace("$run", &run_lit);
        if let Some(r) = rows {
            st = st.replacen("UNWIND $rows AS row", &format!("UNWIND {r} AS row"), 1);
        }
        let _ = writeln!(s, "{st};\n");
    }
    s
}

/// Plain JSON of the batch (nodes/edges), for tooling and the web console.
pub fn export_json(b: &GraphBatch) -> String {
    let nodes: Vec<Value> = b.nodes.values().map(|n| json!({"label": n.label.as_str(), "key": n.key, "props": n.props})).collect();
    let edges: Vec<Value> = b
        .edges
        .values()
        .map(|e| {
            json!({
                "type": e.rel.as_str(), "from": {"label": e.from.0.as_str(), "key": e.from.1},
                "to": {"label": e.to.0.as_str(), "key": e.to.1}, "status": e.status.as_str(),
                "confidence": e.confidence, "evidence": e.evidence.iter().cloned().collect::<Vec<_>>(), "props": e.props,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({"target_id": b.target_id, "nodes": nodes, "edges": edges})).unwrap_or_default()
}

/// Ready-made queries for analysts (also in the docs).
pub const QUERIES: &[(&str, &str)] = &[
    (
        "Findings that reach critical assets",
        "MATCH path = (f:Finding)-[:ENABLES|YIELDS|CAN_ACCESS|ESCALATES_TO|PIVOTS_TO*1..6]->(a) WHERE f.status IN ['confirmed','needs_review'] AND ((a:Asset OR a:Host) AND a.critical = true) RETURN path",
    ),
    ("Secrets that grant access", "MATCH path = (s)-[:CAN_ACCESS|HAS_PERMISSION*1..4]->(a) WHERE (s:Secret OR s:Credential) AND (a:Asset OR a:Host) RETURN path"),
    (
        "Evidenced paths to business impact",
        "MATCH path = (f:Finding)-[:ENABLES|YIELDS|CAN_ACCESS|ESCALATES_TO|PIVOTS_TO|IMPACTS*1..8]->(i:BusinessImpact) MATCH (f)-[:SUPPORTED_BY]->(e:Evidence) RETURN path, collect(e)",
    ),
    ("Hypotheses awaiting validation", "MATCH (p:AttackPath) WHERE p.status IN ['needs_validation','hypothesis'] RETURN p ORDER BY p.risk_score DESC"),
    ("SSRF to metadata/internal", "MATCH path = (f:Finding)-[*1..5]->(x) WHERE f.cwe CONTAINS '918' AND (x:Credential OR x:Secret OR x:Host) RETURN path"),
    ("Credentials to privileged identities (internal)", "MATCH path = (c)-[:CAN_ACCESS|HAS_PERMISSION|ESCALATES_TO*1..6]->(r) WHERE (c:Credential OR c:Secret) AND (r:Role OR r:Identity) AND r.privileged = true RETURN path"),
];

// ---------------------------------------------------------------------------
// Neo4j over HTTP (transactional API) — optional

/// A Neo4j endpoint. Credentials come from the environment
/// (`NEO4J_USER`/`NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`) and are
/// never written anywhere.
pub struct Neo4j {
    base: String,
    db: String,
    user: String,
    pass: String,
    http: reqwest::Client,
}

impl Neo4j {
    /// From an explicit URI, else `NEO4J_URI`. `None` when neither is set.
    pub fn resolve(explicit: Option<&str>) -> Option<Neo4j> {
        let uri = explicit.map(str::to_string).filter(|s| !s.trim().is_empty()).or_else(|| std::env::var("NEO4J_URI").ok().filter(|s| !s.trim().is_empty()))?;
        Some(Neo4j::new(&uri))
    }

    pub fn new(uri: &str) -> Neo4j {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Neo4j {
            base: http_base(uri),
            db: env("NEO4J_DATABASE").unwrap_or_else(|| "neo4j".into()),
            user: env("NEO4J_USER").or_else(|| env("NEO4J_USERNAME")).unwrap_or_else(|| "neo4j".into()),
            pass: env("NEO4J_PASSWORD").unwrap_or_default(),
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap_or_default(),
        }
    }

    pub fn label(&self) -> String {
        format!("{} (db {})", self.base, self.db)
    }

    async fn tx(&self, statements: Vec<Value>) -> anyhow::Result<Value> {
        let url = format!("{}/db/{}/tx/commit", self.base, self.db);
        let resp = self.http.post(&url).basic_auth(&self.user, Some(&self.pass)).json(&json!({ "statements": statements })).send().await?;
        let code = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !code.is_success() {
            anyhow::bail!("neo4j HTTP {code}");
        }
        if let Some(e) = v.get("errors").and_then(|e| e.as_array()).and_then(|a| a.first()) {
            anyhow::bail!("neo4j: {}", e.get("message").and_then(|m| m.as_str()).unwrap_or("statement failed"));
        }
        Ok(v)
    }

    /// MERGE the batch. Returns (nodes, relationships) sent.
    pub async fn push(&self, b: &GraphBatch, run: &str) -> anyhow::Result<(usize, usize)> {
        let stmts = cypher_statements(b, run);
        // Constraints are schema operations: run them on their own first.
        let (schema, data): (Vec<_>, Vec<_>) = stmts.into_iter().partition(|(s, _)| s.starts_with("CREATE CONSTRAINT"));
        for (s, p) in schema {
            self.tx(vec![json!({"statement": s, "parameters": p})]).await?;
        }
        for chunk in data.chunks(10) {
            self.tx(chunk.iter().map(|(s, p)| json!({"statement": s, "parameters": p})).collect()).await?;
        }
        Ok((b.nodes.len(), b.edges.len()))
    }

    /// Read back attack-relevant paths for this target (accumulated across runs
    /// and engagements) as a batch, to merge into the in-process reasoning.
    pub async fn fetch_paths(&self, target_id: &str, limit: usize) -> anyhow::Result<GraphBatch> {
        let q = "MATCH p = (s)-[:ENABLES|YIELDS|CAN_ACCESS|HAS_PERMISSION|ESCALATES_TO|PIVOTS_TO|IMPACTS*1..8]->(g) \
                 WHERE s.target_id = $tid \
                   AND ((s:Finding AND s.status IN ['confirmed','needs_review']) OR s:Credential OR s:Secret OR (s:Asset AND s.entry = true)) \
                   AND (g:BusinessImpact OR ((g:Asset OR g:Host) AND g.critical = true) OR ((g:Role OR g:Identity) AND g.privileged = true)) \
                 RETURN [n IN nodes(p) | {key: n.key, labels: labels(n), props: properties(n)}] AS ns, \
                        [r IN relationships(p) | {type: type(r), props: properties(r)}] AS rs \
                 LIMIT $limit";
        let v = self
            .tx(vec![json!({"statement": q, "parameters": {"tid": target_id, "limit": limit}, "resultDataContents": ["row"]})])
            .await?;
        let mut b = GraphBatch { target_id: target_id.to_string(), ..Default::default() };
        let rows = v.pointer("/results/0/data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
        for row in rows {
            let Some(r) = row.get("row").and_then(|r| r.as_array()) else { continue };
            let (Some(ns), Some(rs)) = (r.first().and_then(|x| x.as_array()), r.get(1).and_then(|x| x.as_array())) else { continue };
            let mut refs: Vec<Option<NodeRef>> = Vec::new();
            for n in ns {
                let key = n.get("key").and_then(|k| k.as_str()).unwrap_or("");
                let label = n.get("labels").and_then(|l| l.as_array()).and_then(|l| l.iter().filter_map(|x| x.as_str()).find_map(Label::parse));
                match (label, key.is_empty()) {
                    (Some(l), false) => {
                        let props: Vec<(String, Value)> = n.get("props").and_then(|p| p.as_object()).map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
                        let pr: Vec<(&str, Value)> = props.iter().filter(|(k, _)| k != "key").map(|(k, v)| (k.as_str(), v.clone())).collect();
                        refs.push(Some(b.put(l, key, &pr)));
                    }
                    _ => refs.push(None),
                }
            }
            for (i, rel) in rs.iter().enumerate() {
                let (Some(Some(a)), Some(Some(c))) = (refs.get(i), refs.get(i + 1)) else { continue };
                let Some(t) = rel.get("type").and_then(|t| t.as_str()).and_then(Rel::parse) else { continue };
                let props = rel.get("props").and_then(|p| p.as_object());
                let st = Status::parse(props.and_then(|p| p.get("status")).and_then(|s| s.as_str()).unwrap_or("needs_validation"));
                let conf = props.and_then(|p| p.get("confidence")).and_then(|c| c.as_f64()).unwrap_or(0.4);
                let ev: Vec<String> = props.and_then(|p| p.get("evidence")).and_then(|e| e.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                b.link(t, a, c, st, conf, &ev, &[]);
            }
        }
        Ok(b)
    }
}

/// `bolt://host:7687` / `neo4j+s://host` → the HTTP base the transactional API
/// listens on. HTTP(S) URIs pass through.
fn http_base(uri: &str) -> String {
    let u = uri.trim().trim_end_matches('/');
    if u.starts_with("http://") || u.starts_with("https://") {
        return u.to_string();
    }
    let (scheme, rest) = u.split_once("://").unwrap_or(("bolt", u));
    let secure = scheme.ends_with("+s") || scheme.ends_with("+ssc");
    let hostport = rest.split('/').next().unwrap_or(rest);
    let host = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => hostport,
    };
    if secure {
        format!("https://{host}:7473")
    } else {
        format!("http://{host}:7474")
    }
}

// ---------------------------------------------------------------------------
// The graph as a phase of the test
//
// The pipeline runs a graph checkpoint after recon, after validation, on every
// chaining round and at the end. Each checkpoint publishes a live context that
// every agent prompt reads (through `operator_directives`), so the graph shapes
// what is tested next instead of only describing what was found.

static LIVE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();

fn live() -> &'static std::sync::Mutex<HashMap<String, String>> {
    LIVE.get_or_init(Default::default)
}

/// Publish the current graph context for a run.
pub fn set_live_context(run: &str, ctx: String) {
    if let Ok(mut m) = live().lock() {
        m.insert(run.to_string(), ctx);
    }
}

/// The graph context agent prompts include (empty before the first checkpoint).
pub fn live_context(run: &str) -> String {
    live().lock().ok().and_then(|m| m.get(run).cloned()).unwrap_or_default()
}

/// Forget a run's live context once the run is over.
pub fn clear_live(run: &str) {
    if let Ok(mut m) = live().lock() {
        m.remove(run);
    }
}

fn arr<'v>(v: &'v Value, key: &str) -> Vec<&'v Value> {
    match v.get(key) {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(x @ Value::String(_)) => vec![x],
        _ => Vec::new(),
    }
}

/// Project the recon model's JSON (`tech`, `versions`, `endpoints`, `apis`,
/// `hosts`, `subdomains`, `secrets`) onto the graph. Only in-scope hosts enter;
/// recon-reported secrets become fingerprints. Everything recon reports is
/// `needs_review` — it is the model's summary of tool output, not a receipt.
/// Returns the number of nodes added.
pub fn project_recon(b: &mut GraphBatch, target: &str, recon: &str, in_scope: &dyn Fn(&str) -> bool) -> usize {
    let (Some(s), Some(e)) = (recon.find('{'), recon.rfind('}')) else { return 0 };
    if e <= s {
        return 0;
    }
    let Ok(v) = serde_json::from_str::<Value>(&recon[s..=e]) else { return 0 };
    let before = b.nodes.len();
    let tid = b.target_id.clone();
    let t = b.put(Label::Target, &tid, &[("name", json!(target)), ("target_id", json!(tid))]);
    let (tscheme, thost, tport) = split_url(target);
    let host_node = |b: &mut GraphBatch, host: &str, discovered: bool| -> NodeRef {
        let hk = format!("{tid}|{host}");
        let h = b.put(Label::Host, &hk, &[("name", json!(host)), ("target_id", json!(tid)), ("discovered_by", json!(if discovered { "recon" } else { "target" }))]);
        b.link(Rel::HasAsset, &t, &h, if discovered { Status::NeedsReview } else { Status::Confirmed }, if discovered { 0.6 } else { 1.0 }, &[], &[]);
        if is_ip(host) {
            let ip = b.put(Label::IPAddress, host, &[("address", json!(host))]);
            b.link(Rel::ResolvesTo, &h, &ip, Status::Confirmed, 1.0, &[], &[]);
        } else if !host.is_empty() {
            let d = b.put(Label::Domain, host, &[("name", json!(host))]);
            b.link(Rel::ResolvesTo, &d, &h, Status::Confirmed, 1.0, &[], &[]);
        }
        h
    };
    let th = host_node(b, &thost, false);
    let tsvc = b.put(Label::Service, &format!("{tid}|{thost}|{tport}|tcp"), &[("port", json!(tport)), ("protocol", json!("tcp")), ("app_protocol", json!(tscheme))]);
    b.link(Rel::Exposes, &th, &tsvc, Status::Confirmed, 1.0, &[], &[]);

    // Hosts discovered by recon — only in-scope ones; discovery is not authorization.
    for key in ["hosts", "subdomains"] {
        for item in arr(&v, key) {
            let raw = item.as_str().map(str::to_string).or_else(|| item.get("host").or_else(|| item.get("name")).and_then(|x| x.as_str()).map(str::to_string)).unwrap_or_default();
            let host = if raw.contains("://") { split_url(&raw).1 } else { raw.trim().trim_start_matches("*.").to_lowercase() };
            if host.is_empty() || host.contains(' ') || host == thost || !in_scope(&format!("https://{host}")) {
                continue;
            }
            host_node(b, &host, true);
        }
    }

    // Technologies and versions (on the target host).
    let mut techs: Vec<(String, String)> = Vec::new();
    match v.get("tech") {
        Some(Value::Array(a)) => {
            for x in a {
                if let Some(n) = x.as_str() {
                    techs.push((n.to_string(), String::new()));
                } else if let Some(n) = x.get("name").and_then(|n| n.as_str()) {
                    techs.push((n.to_string(), x.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string()));
                }
            }
        }
        Some(Value::Object(m)) => {
            for (k, x) in m {
                techs.push((k.clone(), x.as_str().unwrap_or("").to_string()));
            }
        }
        Some(Value::String(t)) => {
            for n in t.split(',') {
                techs.push((n.trim().to_string(), String::new()));
            }
        }
        _ => {}
    }
    match v.get("versions") {
        Some(Value::Object(m)) => {
            for (k, x) in m {
                techs.push((k.clone(), x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())));
            }
        }
        Some(Value::Array(a)) => {
            for x in a.iter().filter_map(|x| x.as_str()) {
                let (n, ver) = x.rsplit_once(' ').unwrap_or((x, ""));
                techs.push((n.to_string(), ver.to_string()));
            }
        }
        _ => {}
    }
    for (name, ver) in techs {
        let name = short(name.trim(), 60);
        if name.is_empty() {
            continue;
        }
        let tk = b.put(Label::Technology, &format!("tech:{}", name.to_lowercase()), &[("name", json!(name)), ("version", json!(short(ver.trim(), 40)))]);
        b.link(Rel::UsesTech, &th, &tk, Status::NeedsReview, 0.7, &[], &[("source", json!("recon"))]);
    }

    // Endpoints / API routes.
    let base = target.trim_end_matches('/').to_string();
    for key in ["endpoints", "apis"] {
        for item in arr(&v, key) {
            let (method, path) = if let Some(st) = item.as_str() {
                match st.split_once(char::is_whitespace) {
                    Some((m, p)) if m.len() <= 7 && m.chars().all(|c| c.is_ascii_alphabetic()) => (m.to_uppercase(), p.trim().to_string()),
                    _ => ("GET".to_string(), st.trim().to_string()),
                }
            } else {
                let m = item.get("method").and_then(|x| x.as_str()).unwrap_or("GET").to_uppercase();
                let p = item.get("url").or_else(|| item.get("path")).or_else(|| item.get("endpoint")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                (m, p)
            };
            if path.is_empty() {
                continue;
            }
            let url = if path.starts_with("http://") || path.starts_with("https://") {
                path.clone()
            } else if path.starts_with('/') {
                format!("{base}{path}")
            } else {
                format!("{base}/{path}")
            };
            if !in_scope(&url) {
                continue;
            }
            let (scheme, host, port) = split_url(&url);
            let h = if host == thost { th.clone() } else { host_node(b, &host, true) };
            let svc = b.put(Label::Service, &format!("{tid}|{host}|{port}|tcp"), &[("port", json!(port)), ("protocol", json!("tcp")), ("app_protocol", json!(scheme))]);
            b.link(Rel::Exposes, &h, &svc, Status::Confirmed, 1.0, &[], &[]);
            let ek = endpoint_key(&method, &url);
            let ep = b.put(Label::Endpoint, &ek, &[("method", json!(method)), ("path", json!(crate::authz_matrix::template(&clean_path(&url)))), ("source", json!("recon"))]);
            b.link(Rel::HasEndpoint, &svc, &ep, Status::NeedsReview, 0.7, &[], &[]);
        }
    }

    // Secrets recon reported: fingerprint + location only.
    for item in arr(&v, "secrets") {
        let (val, loc) = if let Some(st) = item.as_str() {
            (st.to_string(), String::new())
        } else {
            let val = item.get("value").or_else(|| item.get("secret")).or_else(|| item.get("match")).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let loc = item.get("location").or_else(|| item.get("file")).or_else(|| item.get("url")).and_then(|x| x.as_str()).unwrap_or("").to_string();
            (val, loc)
        };
        if val.trim().is_empty() {
            continue;
        }
        let fp = fingerprint(val.trim());
        let sec = b.put(
            Label::Secret,
            &format!("fp:{fp}"),
            &[("fingerprint", json!(fp)), ("kind", json!("recon-exposure")), ("redacted", json!("****")), ("location", json!(short(&clean_path(&loc), 120))), ("target_id", json!(tid))],
        );
        let step = b.put(Label::AttackStep, &format!("step:recon:{fp}"), &[("title", json!("secret exposed to recon")), ("stage", json!("recon"))]);
        b.link(Rel::Yields, &step, &sec, Status::NeedsReview, 0.6, &[], &[("source", json!("recon"))]);
        b.link(Rel::Enables, &th, &step, Status::NeedsReview, 0.6, &[], &[]);
    }
    b.nodes.len().saturating_sub(before)
}

/// (hosts, services, endpoints, credential/secret fingerprints) in the graph.
pub fn surface_counts(b: &GraphBatch) -> (usize, usize, usize, usize) {
    let c = |l: &[Label]| b.nodes.keys().filter(|r| l.contains(&r.0)).count();
    (c(&[Label::Host]), c(&[Label::Service]), c(&[Label::Endpoint]), c(&[Label::Credential, Label::Secret]))
}

/// The live context every agent prompt includes: surface, chains, next moves,
/// and the discipline that keeps the graph correct.
pub fn context_block(b: &GraphBatch, chains: &[AttackChain], moves: &[String]) -> String {
    let (h, s, e, sec) = surface_counts(b);
    if h + s + e + sec == 0 && chains.is_empty() {
        return String::new();
    }
    let mut out = String::from("ATTACK GRAPH (live — web + internal network; updated after recon, validation and every chaining round):\n");
    let _ = writeln!(out, "Surface: {h} host(s), {s} service(s), {e} endpoint(s); {sec} credential/secret fingerprint(s) (values stay in the vault, never in prompts).");
    if !chains.is_empty() {
        out.push_str("Chains (status — chain severity):\n");
        for c in chains.iter().take(4) {
            let _ = writeln!(
                out,
                "- [{}] {} — {}{}",
                c.status.as_str(),
                short(&c.title, 150),
                c.chain_severity,
                c.potential_severity.as_deref().map(|p| format!(" (→{p} if validated)")).unwrap_or_default()
            );
        }
    }
    let td = todo(b, chains);
    let ready = ready_steps(&td);
    if !ready.is_empty() {
        out.push_str("Dependency todolist — the next step of each open chain (do not jump ahead; later steps depend on these facts):\n");
        for t in ready.iter().take(4) {
            let _ = writeln!(out, "- step {}/{} of `{}`: {}", t.index, t.of, short(&t.chain, 90), short(&t.action, 220));
        }
    }
    if !moves.is_empty() {
        out.push_str("Next moves that would complete a path:\n");
        for m in moves.iter().take(5) {
            let _ = writeln!(out, "- {}", short(m, 240));
        }
    }
    out.push_str(
        "Graph discipline: put any credential, token or session you obtain in the finding's `secret` and the account in `account` (the harness fingerprints and vaults it and tests reuse); list the ids of findings your exploit relied on in `chains_from`; a step you could not prove is a hypothesis — say so, it will not raise any severity.\n\n",
    );
    out.chars().take(2600).collect()
}

/// Agents the graph says would complete or extend a path, from those available.
pub fn directed_agents(b: &GraphBatch, available: &[String]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut add = |name: &str, why: &str| {
        if available.iter().any(|a| a == name) && !out.iter().any(|(n, _)| n == name) {
            out.push((name.to_string(), why.to_string()));
        }
    };
    let techs: Vec<String> = b.nodes.keys().filter(|r| r.0 == Label::Technology).map(|r| b.prop_str(r, "name").to_lowercase()).collect();
    let tech_has = |k: &str| techs.iter().any(|t| t.contains(k));
    let cwes: Vec<String> = b.nodes.keys().filter(|r| r.0 == Label::Finding).map(|r| cwe_num(&b.prop_str(r, "cwe"))).collect();
    let any_cwe = |l: &[&str]| cwes.iter().any(|c| l.contains(&c.as_str()));
    let identities = b.nodes.keys().filter(|r| r.0 == Label::Identity).count();
    let unused_secret = b.nodes.keys().filter(|r| matches!(r.0, Label::Credential | Label::Secret)).any(|r| {
        b.edges.values().any(|e| e.rel == Rel::Yields && &e.to == r) && !b.edges.values().any(|e| matches!(e.rel, Rel::CanAccess | Rel::HasPermission) && &e.from == r)
    });

    if any_cwe(&["918"]) {
        add("ssrf_cloud", "SSRF in the graph — complete the path to cloud metadata / internal services");
        add("cloud_metadata_exposure", "SSRF in the graph — metadata credentials are the next hop");
    }
    if any_cwe(&["639", "862", "863", "285", "284", "566", "425"]) || identities >= 2 {
        add("authorization_matrix", "authorization flaws / multiple identities in the graph — sweep route × identity");
        add("api_bola_chained", "object-level flaws in the graph — chain them across objects");
    }
    if unused_secret {
        add("session_lifecycle", "credentials/sessions yielded but not yet tried — test reuse, revocation, token exchange");
        add("api_token_structure", "yielded tokens — check whether they are forgeable");
    }
    if tech_has("postgres") && any_cwe(&["89", "943", "564"]) {
        add("postgres_superuser_rce", "PostgreSQL + SQL injection in the graph — escalate database access to the OS");
    }
    if ["mongo", "redis", "elasticsearch", "solr", "couchdb", "memcached", "cassandra", "rethinkdb"].iter().any(|k| tech_has(k)) {
        add("exposed_datastore", "datastore technology in the graph — check for unauthenticated access");
    }
    if tech_has("graphql") {
        add("graphql_introspection", "GraphQL in the graph");
        add("graphql_injection", "GraphQL in the graph");
    }
    out.truncate(6);
    out
}

// ---------------------------------------------------------------------------
// One-call helpers for the pipeline and the CLI

/// Everything the report writes: chains, export, JSON. Best-effort.
pub fn write_artifacts(target: &str, run: &str, findings: &[Finding], dir: &std::path::Path) -> std::io::Result<usize> {
    let internal: Option<InternalGraph> = std::fs::read_to_string(dir.join("internal-graph.json")).ok().and_then(|t| serde_json::from_str(&t).ok());
    let mut b = build(target, run, findings, internal.as_ref(), None);
    let cs = chains(&b, 8, 50);
    let moves = next_moves(&b, &cs, 12);
    record_paths(&mut b, &cs, run);
    let out = dir.join("graph");
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("attack-chains.md"), chains_markdown(target, &cs, &moves))?;
    std::fs::write(out.join("chains.json"), chains_json(&cs, &moves))?;
    let td = todo(&b, &cs);
    std::fs::write(out.join("todo.md"), todo_markdown(target, &td))?;
    std::fs::write(out.join("todo.json"), todo_json(&td))?;
    std::fs::write(out.join("graph.cypher"), export_cypher(&b, run))?;
    std::fs::write(out.join("graph.json"), export_json(&b))?;
    let mut q = String::from("// Analyst queries for the NeuroSploit attack graph\n\n");
    for (t, c) in QUERIES {
        let _ = writeln!(q, "// {t}\n{c};\n");
    }
    std::fs::write(out.join("queries.cypher"), q)?;
    Ok(cs.len())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::{Edge as IEdge, Node as INode};

    fn ex(method: &str, url: &str, status: u16, body: &str) -> Exchange {
        Exchange { method: method.into(), url: url.into(), status, body: body.into(), ..Default::default() }
    }

    fn f(id: &str, title: &str, cwe: &str, sev: &str, url: &str, body: &str) -> Finding {
        Finding {
            id: id.into(),
            title: title.into(),
            cwe: cwe.into(),
            severity: sev.into(),
            endpoint: url.into(),
            review_status: "confirmed".into(),
            validated: true,
            confidence: 0.9,
            evidence_data: Some(Evidence { attack: Some(ex("GET", url, 200, body)), ..Default::default() }),
            ..Default::default()
        }
    }

    #[test]
    fn secrets_never_become_properties() {
        let mut x = f("F1", "SQLi dumps users", "CWE-89", "High", "https://app.test/search?q=1&token=SUPERSECRET", "admin password hash $2y$10$abc");
        x.secret = "P@ssw0rd-Real".into();
        x.account = "alice@corp.test:P@ssw0rd-Real".into();
        let b = build("https://app.test", "r1", &[x], None, None);
        let dump = export_json(&b) + &export_cypher(&b, "r1");
        assert!(!dump.contains("P@ssw0rd-Real"), "raw secret leaked");
        assert!(!dump.contains("SUPERSECRET"), "query-string token leaked");
        assert!(!dump.contains("alice@corp.test"), "personal identity not masked");
        assert!(dump.contains("a***@corp.test"));
    }

    #[test]
    fn unvalidated_chain_does_not_upgrade_severity() {
        // Medium info leak + medium IDOR, linked only by derivation.
        let a = f("A", "User enumeration", "CWE-200", "Medium", "https://app.test/api/users", "user list");
        let mut c = f("B", "IDOR on invoices", "CWE-639", "Medium", "https://app.test/api/invoices/1", "invoice of another user");
        c.chains_from = vec![];
        let mut b = build("https://app.test", "r1", &[a, c], None, None);
        // Add an explicit derived edge to be sure there is a 2-hop path to an impact.
        let fa = b.nodes.keys().find(|r| r.0 == Label::Finding && b.prop_str(r, "finding_id") == "A").cloned().unwrap();
        let fb = b.nodes.keys().find(|r| r.0 == Label::Finding && b.prop_str(r, "finding_id") == "B").cloned().unwrap();
        b.link(Rel::EscalatesTo, &fa, &fb, Status::NeedsValidation, 0.35, &[], &[("basis", json!("derived"))]);
        let cs = chains(&b, 8, 20);
        let ch = cs.iter().find(|c| c.nodes.first() == Some(&fa)).expect("a chain from A");
        assert_ne!(ch.status, Status::Confirmed);
        assert_eq!(ch.chain_severity, "Medium", "unproven path must keep the local severity");
        assert!(!ch.validation.is_empty(), "must say what evidence is missing");
    }

    #[test]
    fn confirmed_chain_raises_severity() {
        let a = f("A", "SQLi leaks admin hash", "CWE-89", "Medium", "https://app.test/search", "admin password bcrypt $2y$10$x");
        let mut c = f("B", "RCE via admin template upload", "CWE-94", "High", "https://app.test/admin/template", "uid=33(www-data)");
        c.chains_from = vec!["A".into()];
        // Proof of execution: an out-of-band callback carrying the nonce.
        if let Some(e) = c.evidence_data.as_mut() {
            e.marker = "ns-nonce-1".into();
            e.callback_received = true;
        }
        let b = build("https://app.test", "r1", &[a, c], None, None);
        let cs = chains(&b, 8, 20);
        assert!(cs.iter().any(|c| c.status == Status::Confirmed), "asserted link between confirmed findings + evidenced impact should confirm");
    }

    #[test]
    fn internal_graph_paths_to_domain_admin() {
        let mut g = InternalGraph::new();
        g.add(INode::new("cred1", ILayer::Credential, IKind::Password, "svc_sql password").proven_by(&["ev1"]));
        g.add(INode::new("srv1", ILayer::Asset, IKind::Host, "SQL01").on("sql01.corp.local").proven_by(&["ev2"]));
        g.add(INode::new("da", ILayer::Privilege, IKind::Group, "Domain Admins"));
        g.link(IEdge::new("cred1", "srv1", "local admin logon").proven_by(&["ev3"]));
        g.link(IEdge::new("srv1", "da", "lsass dump yields DA session"));
        let b = build("corp.local", "r1", &[], Some(&g), None);
        let dump = export_json(&b);
        assert!(!dump.contains("svc_sql password"), "credential label must not be stored");
        let cs = chains(&b, 8, 20);
        let ch = cs.iter().find(|c| c.impact.contains("Domain Admins")).expect("path to Domain Admins");
        assert_eq!(ch.status, Status::NeedsValidation, "last hop unproven");
        assert!(ch.validation.iter().any(|v| !v.is_empty()));
    }

    #[test]
    fn cypher_is_parameterised_and_labels_are_closed() {
        let b = build("https://app.test", "r1", &[f("A", "X'); DROP", "CWE-89", "High", "https://app.test/x", "y")], None, None);
        for (stmt, params) in cypher_statements(&b, "r1") {
            assert!(!stmt.contains("DROP"), "data must never be interpolated into a statement: {stmt}");
            if stmt.starts_with("UNWIND") {
                assert!(params.get("rows").is_some());
            }
        }
        // Offline literal escaping keeps the quote inside the string.
        let script = export_cypher(&b, "r1");
        assert!(script.contains("X\\'); DROP"));
    }

    #[test]
    fn next_moves_suggest_reuse_and_validation() {
        let mut x = f("A", "Config leaks DB password", "CWE-200", "High", "https://app.test/config.json", "db password secret");
        x.secret = "dbpass".into();
        let b = build("https://app.test", "r1", &[x], None, None);
        let cs = chains(&b, 8, 20);
        let mv = next_moves(&b, &cs, 10);
        assert!(mv.iter().any(|m| m.starts_with("REUSE")), "{mv:?}");
    }

    #[test]
    fn web_rce_bridges_into_internal_graph() {
        let mut rce = f("R", "RCE via template upload", "CWE-94", "Critical", "https://web01.corp.local/admin/template", "uid=33");
        if let Some(e) = rce.evidence_data.as_mut() {
            e.marker = "ns-nonce-9".into();
            e.callback_received = true;
        }
        let mut g = InternalGraph::new();
        g.add(INode::new("web01", ILayer::Asset, IKind::Host, "web01").on("web01.corp.local").proven_by(&["rce"]));
        g.add(INode::new("pw", ILayer::Credential, IKind::Password, "svc : S3cret!").proven_by(&["cfg"]));
        g.add(INode::new("da", ILayer::Privilege, IKind::Group, "Domain Admins"));
        g.link(IEdge::new("web01", "pw", "harvest credential from config").proven_by(&["cfg"]));
        g.link(IEdge::new("pw", "da", "member of Domain Admins"));
        let b = build("https://web01.corp.local", "r1", &[rce], Some(&g), None);
        let cs = chains(&b, 8, 50);
        let ch = cs.iter().find(|c| c.nodes.first().map(|n| n.0) == Some(Label::Finding) && c.impact.contains("Domain Admins"));
        assert!(ch.is_some(), "web RCE should chain into the internal path to Domain Admins: {:?}", cs.iter().map(|c| &c.title).collect::<Vec<_>>());
        assert!(!export_json(&b).contains("S3cret!"));
    }

    #[test]
    fn blast_radius_counts_affected_hosts() {
        let a = f("A", "SQLi leaks admin hash", "CWE-89", "Medium", "https://app.test/search", "admin password bcrypt $2y$10$x");
        let mut c = f("B", "Admin takeover", "CWE-306", "High", "https://admin.app.test/panel", "admin panel");
        c.chains_from = vec!["A".into()];
        let b = build("https://app.test", "r1", &[a, c], None, None);
        let cs = chains(&b, 8, 20);
        assert!(cs.iter().all(|c| c.blast_radius >= 1), "{:?}", cs.iter().map(|c| c.blast_radius).collect::<Vec<_>>());
    }

    #[test]
    fn rce_claim_without_execution_proof_stays_unconfirmed() {
        let a = f("A", "SQLi leaks admin hash", "CWE-89", "Medium", "https://app.test/search", "admin password bcrypt $2y$10$x");
        let mut c = f("B", "RCE via template", "CWE-94", "High", "https://app.test/admin/template", "looks like it ran");
        c.chains_from = vec!["A".into()];
        let b = build("https://app.test", "r1", &[a, c], None, None);
        let cs = chains(&b, 8, 20);
        let ch = cs.iter().find(|c| c.impact.contains("code execution")).expect("a chain to code execution");
        assert_ne!(ch.status, Status::Confirmed, "no nonce/callback → impact not demonstrated");
    }

    #[test]
    fn masked_secrets_do_not_collapse_into_one_node() {
        let mut a = f("A", "Leak one", "CWE-200", "High", "https://app.test/a", "x");
        let mut c = f("B", "Leak two", "CWE-200", "High", "https://app.test/b", "y");
        a.secret = "\u{2022}\u{2022}\u{2022}\u{2022} (see vault.json)".into();
        c.secret = "\u{2022}\u{2022}\u{2022}\u{2022} (see vault.json)".into();
        let b = build("https://app.test", "r1", &[a, c], None, None);
        assert_eq!(b.nodes.keys().filter(|r| r.0 == Label::Secret).count(), 2);
    }

    #[test]
    fn equal_secrets_share_a_fingerprint() {
        let mut a = f("A", "Leak one", "CWE-200", "High", "https://app.test/a", "x");
        let mut c = f("B", "Leak two", "CWE-200", "High", "https://app.host2.test/b", "y");
        a.secret = "Reused!Pass1".into();
        c.secret = "Reused!Pass1".into();
        let b = build("https://app.test", "r1", &[a, c], None, None);
        assert_eq!(b.nodes.keys().filter(|r| r.0 == Label::Secret).count(), 1, "reuse must correlate");
        assert!(!export_json(&b).contains(&sha("Reused!Pass1")[..24]), "fingerprint must be salted");
    }

    #[test]
    fn recon_projection_respects_scope_and_fingerprints_secrets() {
        let recon = r#"noise {"tech":["PostgreSQL 14","nginx"],"endpoints":["POST /api/login","/api/orders/12"],
            "subdomains":["admin.app.test","evil.other.test"],"secrets":[{"value":"AKIAREALKEY0000000000","location":"/static/app.js?v=1"}]} trailing"#;
        let mut b = GraphBatch::new("https://app.test");
        let in_scope = |u: &str| u.contains("app.test") && !u.contains("other.test");
        let n = project_recon(&mut b, "https://app.test", recon, &in_scope);
        assert!(n > 0);
        let dump = export_json(&b);
        assert!(dump.contains("admin.app.test"));
        assert!(!dump.contains("evil.other.test"), "out-of-scope host entered the graph");
        assert!(!dump.contains("AKIAREALKEY"), "recon secret value leaked");
        assert!(dump.contains("/api/orders/{id}"));
        let agents: Vec<String> = ["postgres_superuser_rce", "session_lifecycle", "api_token_structure"].iter().map(|s| s.to_string()).collect();
        let d = directed_agents(&b, &agents);
        assert!(d.iter().any(|(n, _)| n == "session_lifecycle"), "unused recon secret should direct reuse testing: {d:?}");
    }

    #[test]
    fn history_never_leaks_across_engagements() {
        let mut kg = KnowledgeGraph::new();
        let a = f("A", "SQLi on client A", "CWE-89", "High", "https://client-a.test/search", "x");
        let c = f("C", "SQLi on client C", "CWE-89", "High", "https://client-c.test/find", "y");
        kg.ingest("https://client-a.test", "old-run-a", &[a]);
        kg.ingest("https://client-c.test", "old-run-c", &[c]);
        let b = build("https://client-a.test", "new-run", &[], None, Some(&kg));
        let dump = export_json(&b);
        assert!(dump.contains("SQLi on client A"), "own history should be present");
        assert!(!dump.contains("client C") && !dump.contains("client-c"), "another engagement leaked through a shared CWE node");
    }

    #[test]
    fn todolist_releases_steps_in_dependency_order() {
        let mut g = InternalGraph::new();
        g.add(INode::new("cred1", ILayer::Credential, IKind::Password, "x").proven_by(&["ev1"]));
        g.add(INode::new("srv1", ILayer::Asset, IKind::Host, "SQL01").on("sql01.corp.local").proven_by(&["ev2"]));
        g.add(INode::new("sess", ILayer::Credential, IKind::Session, "s"));
        g.add(INode::new("da", ILayer::Privilege, IKind::Group, "Domain Admins"));
        g.link(IEdge::new("cred1", "srv1", "local admin logon").proven_by(&["ev3"]));
        g.link(IEdge::new("srv1", "sess", "lsass dump"));
        g.link(IEdge::new("sess", "da", "member of Domain Admins"));
        let b = build("corp.local", "r1", &[], Some(&g), None);
        let cs = chains(&b, 8, 20);
        let td = todo(&b, &cs);
        let da: Vec<&TodoStep> = td.iter().filter(|t| t.chain.contains("Domain Admins")).collect();
        assert!(!da.is_empty());
        let states: Vec<&TodoState> = da.iter().map(|t| &t.state).collect();
        // entry done, logon proven (done), lsass dump ready, membership blocked by it
        assert_eq!(states[1], &TodoState::Done, "{states:?}");
        assert_eq!(states[2], &TodoState::Ready, "{states:?}");
        assert!(matches!(states[3], TodoState::Blocked(3)), "{states:?}");
        assert_eq!(ready_steps(&td).iter().filter(|t| t.chain.contains("Domain Admins")).count(), 1);
    }

    #[test]
    fn live_context_round_trip() {
        set_live_context("run-x", "ATTACK GRAPH test".into());
        assert!(live_context("run-x").contains("ATTACK GRAPH"));
        clear_live("run-x");
        assert!(live_context("run-x").is_empty());
    }

    #[test]
    fn bolt_uri_maps_to_http() {
        assert_eq!(http_base("bolt://neo.local:7687"), "http://neo.local:7474");
        assert_eq!(http_base("neo4j+s://x.databases.neo4j.io"), "https://x.databases.neo4j.io:7473");
        assert_eq!(http_base("http://localhost:7474/"), "http://localhost:7474");
    }
}
