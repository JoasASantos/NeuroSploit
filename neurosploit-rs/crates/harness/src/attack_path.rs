//! Cross-domain attack paths — the engagement as one chained story.
//!
//! `crate::chain` answers "which web weakness enables which other web weakness
//! on the same host". That is the right question for one application and the
//! wrong one for an engagement: a real path crosses hosts, protocols and
//! identity planes, and it is the crossing that produces the impact. A syslog
//! traversal on a hypervisor is a Medium until the root it yields is used to
//! pull a machine-account keytab, and the keytab authenticates to a directory,
//! and a share on that directory holds a database administrator password, and
//! that database runs commands as a service account that can impersonate
//! SYSTEM, and SYSTEM reads a domain administrator hash out of memory, and that
//! hash reaches a workstation whose logged-in session holds a cloud token. No
//! single step in that sequence is the finding. The sequence is.
//!
//! So this module models what the steps *exchange* rather than what class they
//! belong to:
//!
//! * [`Artifact`] — what a step hands the attacker (a hash, a ticket, a token,
//!   a shell, an implant, a file, reach into a network).
//! * [`Reach`] — how far that artifact travels. A writable cron job is useless
//!   one host over; a domain hash is good anywhere in the realm; a plaintext
//!   password is tried everywhere. This is the rule that lets a path leave the
//!   host it started on *without* inventing links between unrelated assets.
//! * [`profile`] — per-finding production/consumption, derived from the agent
//!   that found it, its CWE, its technique and its text, for **every** domain
//!   the agent library covers: web, API, network, host, Active Directory,
//!   cloud, SaaS identity, containers, mobile, AI/LLM, CI/CD and supply chain.
//!
//! The graph that comes out carries the same node kinds an operator expects to
//! see on an attack-path diagram — exploited weakness, discovered credential,
//! compromised credential, accessed resource, loaded implant, established
//! session, and the impact a path terminates in — ordered on the run's own
//! timeline.
//!
//! Every edge is derived and says so, carries the artifact that justifies it,
//! and is dropped when the artifact could not have travelled that far.

use crate::types::Finding;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

/// The plane a step operates on. Used for grouping and for deciding when a
/// crossing is a pivot worth calling out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Domain {
    Web,
    Api,
    Network,
    Host,
    ActiveDirectory,
    Cloud,
    Identity,
    Container,
    Mobile,
    Binary,
    Firmware,
    Ai,
    SupplyChain,
    Wireless,
    Social,
    Physical,
    Ot,
}

impl Domain {
    pub fn as_str(self) -> &'static str {
        match self {
            Domain::Web => "web",
            Domain::Api => "api",
            Domain::Network => "network",
            Domain::Host => "host",
            Domain::ActiveDirectory => "active-directory",
            Domain::Cloud => "cloud",
            Domain::Identity => "identity",
            Domain::Container => "container",
            Domain::Mobile => "mobile",
            Domain::Binary => "binary",
            Domain::Firmware => "firmware",
            Domain::Ai => "ai",
            Domain::SupplyChain => "supply-chain",
            Domain::Wireless => "wireless",
            Domain::Social => "social",
            Domain::Physical => "physical",
            Domain::Ot => "ot-ics",
        }
    }
}

/// What one step hands the attacker, or needs from an earlier one.
///
/// This is deliberately about *material and access*, not about weakness
/// classes: two findings chain when one produces what the other consumes, and
/// that is true whether the producer is an SSRF or a Kerberoast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Artifact {
    // --- knowledge ---------------------------------------------------------
    /// Which accounts, objects or hosts exist.
    ValidIdentities,
    /// Versions, paths, stack traces, internal names, config.
    InternalKnowledge,
    /// A map of who can reach what (ACLs, group membership, trust edges).
    PrivilegeMap,
    /// Source code or build definitions.
    SourceCode,
    /// A config/secret-bearing file pulled off a host or share.
    SecretsFile,

    // --- credential material ----------------------------------------------
    /// A password or secret in the clear.
    PlaintextCredential,
    /// A password hash, NTLM hash or crackable blob.
    PasswordHash,
    /// A Kerberos TGT/TGS, including one minted from a certificate.
    KerberosTicket,
    /// A keytab or machine-account secret.
    MachineAccount,
    /// An API key, long-lived token, or webhook secret.
    ApiKey,
    /// A user session: cookie, bearer token, SAML/OIDC assertion.
    SessionToken,
    /// A cloud credential: STS/instance-metadata token, SAS, service-account key.
    CloudToken,
    /// A private key or certificate that can be used to authenticate.
    CertificateOrKey,
    /// Guessable or reused credentials (a policy weakness, not a secret).
    WeakCredentials,
    /// Attempts against a control are not limited.
    UnlimitedAttempts,
    /// A second factor can be skipped or replayed.
    MfaBypass,

    // --- access ------------------------------------------------------------
    /// Code or queries run on the target.
    CodeExecution,
    /// An interactive or semi-interactive foothold on a host.
    ShellOnHost,
    /// Administrator/root on one host.
    HostAdmin,
    /// A persistent implant/agent/webshell left on a host.
    Implant,
    /// Any authenticated directory identity.
    DomainUser,
    /// Directory-wide administrative control.
    DomainAdmin,
    /// A cloud IAM role, principal or service account the attacker can assume.
    CloudRole,
    /// Tenant-level administrative control of a cloud or SaaS identity plane.
    TenantAdmin,
    /// Database access as a normal principal.
    DatabaseAccess,
    /// Database access with command-execution rights (sysadmin/superuser).
    DatabaseAdmin,
    /// Acting as another application user.
    ApplicationIdentity,
    /// Application-level administrative rights.
    ApplicationAdmin,
    /// Reach into networks or services behind the edge.
    InternalReach,
    /// Write access to something others consume (package, pipeline, image).
    SupplyChainWrite,
    /// Read of data the attacker should not have.
    DataAccess,
    /// Read of regulated or business-critical data.
    SensitiveData,
    /// Control of an unmanaged/offline device or its storage.
    DeviceAccess,
    /// Influence over an agent/model's instructions or tools.
    AgentControl,
    /// A victim can be made to act (click, approve, authenticate).
    UserInteraction,
}

impl Artifact {
    pub fn as_str(self) -> &'static str {
        match self {
            Artifact::ValidIdentities => "valid identities",
            Artifact::InternalKnowledge => "internal knowledge",
            Artifact::PrivilegeMap => "privilege map",
            Artifact::SourceCode => "source code",
            Artifact::SecretsFile => "secrets file",
            Artifact::PlaintextCredential => "cleartext credential",
            Artifact::PasswordHash => "password hash",
            Artifact::KerberosTicket => "Kerberos ticket",
            Artifact::MachineAccount => "machine-account secret",
            Artifact::ApiKey => "API key",
            Artifact::SessionToken => "session token",
            Artifact::CloudToken => "cloud access token",
            Artifact::CertificateOrKey => "certificate / private key",
            Artifact::WeakCredentials => "weak credentials",
            Artifact::UnlimitedAttempts => "unlimited attempts",
            Artifact::MfaBypass => "MFA bypass",
            Artifact::CodeExecution => "code execution",
            Artifact::ShellOnHost => "shell on host",
            Artifact::HostAdmin => "administrator on host",
            Artifact::Implant => "loaded implant",
            Artifact::DomainUser => "domain user",
            Artifact::DomainAdmin => "domain administrator",
            Artifact::CloudRole => "cloud role",
            Artifact::TenantAdmin => "tenant administrator",
            Artifact::DatabaseAccess => "database access",
            Artifact::DatabaseAdmin => "database sysadmin",
            Artifact::ApplicationIdentity => "another user's application identity",
            Artifact::ApplicationAdmin => "application administrator",
            Artifact::InternalReach => "internal network reach",
            Artifact::SupplyChainWrite => "write into a consumed artifact",
            Artifact::DataAccess => "data access",
            Artifact::SensitiveData => "sensitive data",
            Artifact::DeviceAccess => "device access",
            Artifact::AgentControl => "control of an agent",
            Artifact::UserInteraction => "a victim's action",
        }
    }
}

/// How far an artifact travels from where it was obtained.
///
/// This is the whole reason a path may leave its host. `chain::derive_links`
/// refuses every cross-host edge, which is correct for a cookie flag and wrong
/// for a domain hash — and refusing both is what kept real engagements
/// reporting a dozen disconnected Mediums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reach {
    /// Only where it was obtained (a writable service, a local file read).
    HostLocal,
    /// Anywhere in the same realm: AD domain, cloud tenant, SaaS directory,
    /// or — for internal addresses with no name — the internal network.
    Realm,
    /// Anywhere. People reuse passwords and keys across boundaries, which is
    /// why credential reuse is the most reliable move in any engagement.
    Portable,
}

/// How far each artifact carries.
pub fn reach(a: Artifact) -> Reach {
    use Artifact::*;
    match a {
        // Bound to the thing that produced them.
        UnlimitedAttempts | CodeExecution | ShellOnHost | HostAdmin | Implant | DatabaseAccess
        | DatabaseAdmin | ApplicationIdentity | ApplicationAdmin | InternalKnowledge | DeviceAccess
        | AgentControl => Reach::HostLocal,
        // Good across the directory / tenant / internal network.
        DomainUser | DomainAdmin | KerberosTicket | MachineAccount | CloudRole | TenantAdmin
        | ValidIdentities | InternalReach | PrivilegeMap | MfaBypass => Reach::Realm,
        // Material an attacker carries anywhere and simply tries. Bearer
        // tokens belong here and not in `Realm`: a token lifted out of a
        // workstation's process memory is presented to a cloud endpoint that
        // shares no realm with the host it came from, and that crossing is the
        // step a report most needs to show.
        SessionToken | CloudToken | PlaintextCredential | PasswordHash | ApiKey | CertificateOrKey | WeakCredentials
        | SourceCode | SecretsFile | SupplyChainWrite | DataAccess | SensitiveData
        | UserInteraction => Reach::Portable,
    }
}

/// What a path ends in — the sentence a reader needs, not a severity word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Impact {
    HostCompromise,
    CriticalInfrastructureCompromise,
    DomainUserCompromise,
    DomainCompromise,
    CloudAccountCompromise,
    TenantCompromise,
    DatabaseCompromise,
    ApplicationTakeover,
    AccountTakeover,
    DataBreach,
    SourceCodeCompromise,
    SupplyChainCompromise,
    DeviceCompromise,
    AgentCompromise,
}

impl Impact {
    pub fn as_str(self) -> &'static str {
        match self {
            Impact::HostCompromise => "HOST COMPROMISE",
            Impact::CriticalInfrastructureCompromise => "CRITICAL INFRASTRUCTURE COMPROMISE",
            Impact::DomainUserCompromise => "DOMAIN USER COMPROMISE",
            Impact::DomainCompromise => "DOMAIN COMPROMISE",
            Impact::CloudAccountCompromise => "CLOUD ACCOUNT COMPROMISE",
            Impact::TenantCompromise => "IDENTITY TENANT COMPROMISE",
            Impact::DatabaseCompromise => "DATABASE COMPROMISE",
            Impact::ApplicationTakeover => "APPLICATION TAKEOVER",
            Impact::AccountTakeover => "ACCOUNT TAKEOVER",
            Impact::DataBreach => "SENSITIVE DATA COMPROMISE",
            Impact::SourceCodeCompromise => "SOURCE CODE COMPROMISE",
            Impact::SupplyChainCompromise => "SUPPLY CHAIN COMPROMISE",
            Impact::DeviceCompromise => "DEVICE COMPROMISE",
            Impact::AgentCompromise => "AI AGENT COMPROMISE",
        }
    }

    /// How much reaching this is worth when ranking paths.
    fn weight(self) -> f64 {
        match self {
            Impact::TenantCompromise | Impact::DomainCompromise => 10.0,
            Impact::CriticalInfrastructureCompromise | Impact::SupplyChainCompromise => 8.0,
            Impact::CloudAccountCompromise | Impact::DataBreach => 7.0,
            Impact::DatabaseCompromise | Impact::HostCompromise => 5.0,
            Impact::DomainUserCompromise | Impact::SourceCodeCompromise => 4.0,
            Impact::ApplicationTakeover | Impact::AgentCompromise => 3.0,
            Impact::AccountTakeover | Impact::DeviceCompromise => 2.0,
        }
    }
}

/// What an artifact, once held, means on its own.
fn impacts_of(a: Artifact) -> Option<Impact> {
    use Artifact::*;
    match a {
        TenantAdmin => Some(Impact::TenantCompromise),
        DomainAdmin => Some(Impact::DomainCompromise),
        DomainUser => Some(Impact::DomainUserCompromise),
        CloudRole => Some(Impact::CloudAccountCompromise),
        HostAdmin | Implant => Some(Impact::HostCompromise),
        DatabaseAdmin => Some(Impact::DatabaseCompromise),
        ApplicationAdmin => Some(Impact::ApplicationTakeover),
        ApplicationIdentity => Some(Impact::AccountTakeover),
        SensitiveData => Some(Impact::DataBreach),
        SourceCode => Some(Impact::SourceCodeCompromise),
        SupplyChainWrite => Some(Impact::SupplyChainCompromise),
        DeviceAccess => Some(Impact::DeviceCompromise),
        AgentControl => Some(Impact::AgentCompromise),
        _ => None,
    }
}

/// The node kinds an attack-path diagram is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    /// Where the path starts (the tester, or an assumed position).
    Entry,
    /// A weakness that was exploited.
    ExploitedWeakness,
    /// Credential material found lying around.
    DiscoveredCredential,
    /// Credential material that was successfully used to authenticate.
    CompromisedCredential,
    /// A share, file, database, bucket or endpoint that was read.
    AccessedResource,
    /// An implant/webshell/agent left running.
    LoadedImplant,
    /// A shell or administrative session on a host.
    EstablishedSession,
    /// A terminal consequence.
    Impact,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Entry => "entry",
            NodeKind::ExploitedWeakness => "Exploited Weakness",
            NodeKind::DiscoveredCredential => "Discovered Credential",
            NodeKind::CompromisedCredential => "Compromised Credential",
            NodeKind::AccessedResource => "Accessed Resource",
            NodeKind::LoadedImplant => "Loaded Implant",
            NodeKind::EstablishedSession => "Established Session",
            NodeKind::Impact => "Impact",
        }
    }

    /// Which node an artifact materializes as, when it materializes at all.
    fn for_artifact(a: Artifact) -> Option<NodeKind> {
        use Artifact::*;
        match a {
            PlaintextCredential | PasswordHash | ApiKey | CertificateOrKey | MachineAccount
            | SecretsFile => Some(NodeKind::DiscoveredCredential),
            KerberosTicket | SessionToken | CloudToken | DomainUser | DomainAdmin | CloudRole
            | TenantAdmin | DatabaseAdmin | ApplicationIdentity | ApplicationAdmin => {
                Some(NodeKind::CompromisedCredential)
            }
            Implant => Some(NodeKind::LoadedImplant),
            ShellOnHost | HostAdmin | CodeExecution => Some(NodeKind::EstablishedSession),
            DataAccess | SensitiveData | SourceCode | DatabaseAccess | InternalReach => {
                Some(NodeKind::AccessedResource)
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Where a step happened: host and realm
// ---------------------------------------------------------------------------

/// Where a step stands. `realm` is what makes a cross-host link legitimate: an
/// AD domain, a cloud account, an identity tenant, an app's registrable domain,
/// or `internal` for RFC1918 space with no name attached.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loc {
    pub host: String,
    pub realm: String,
}

fn private_ip(h: &str) -> bool {
    let o: Vec<u32> = h.split('.').filter_map(|p| p.parse().ok()).collect();
    if o.len() != 4 || h.split('.').count() != 4 {
        return h.starts_with("fe80:") || h.starts_with("fc") || h.starts_with("fd");
    }
    matches!(o[0], 10) || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254) || o[0] == 127
}

fn is_ip(h: &str) -> bool {
    !h.is_empty() && h.chars().all(|c| c.is_ascii_digit() || c == '.') && h.split('.').count() == 4
}

/// The registrable-ish name: the last two labels of a hostname.
fn registrable(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return host.to_string();
    }
    parts[parts.len() - 2..].join(".")
}

/// Infer the host and realm a finding sits in.
pub fn loc_of(f: &Finding) -> Loc {
    let host = crate::scope::host_of(&f.endpoint);
    let text = format!("{} {} {} {}", f.title, f.evidence, f.location, f.impact);
    let realm = realm_from_text(&text).unwrap_or_else(|| {
        if host.is_empty() {
            String::new()
        } else if is_ip(&host) {
            if private_ip(&host) { "internal".into() } else { host.clone() }
        } else {
            registrable(&host)
        }
    });
    Loc { host, realm }
}

/// Pull an explicit realm out of evidence text: an AD domain, a NetBIOS
/// prefix, an AWS account, an Entra tenant, a GCP project.
fn realm_from_text(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    // AWS account out of an ARN or an explicit account id.
    if let Some(c) = regex_once(r"arn:aws:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):", &lower) {
        return Some(format!("aws:{c}"));
    }
    if let Some(c) = regex_once(r"(?:aws\s+account|account\s+id)[^0-9]{0,12}(\d{12})", &lower) {
        return Some(format!("aws:{c}"));
    }
    // Entra / Azure tenant id (a GUID next to the word tenant).
    if let Some(c) = regex_once(
        r"tenant[^0-9a-f]{0,12}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        &lower,
    ) {
        return Some(format!("entra:{c}"));
    }
    if let Some(c) = regex_once(r"(?:gcp|google)\s+project[^a-z0-9]{0,8}([a-z0-9][a-z0-9-]{4,29})", &lower) {
        return Some(format!("gcp:{c}"));
    }
    // An AD domain name. `.local`/`.corp`/`.lan`/`.ad`/`.internal` are the
    // conventional internal suffixes; a bare `DOMAIN\user` gives the NetBIOS
    // name, which is the same realm under another spelling.
    if let Some(c) = regex_once(r"\b([a-z0-9][a-z0-9-]{1,30}\.(?:local|corp|lan|ad|internal|intranet))\b", &lower) {
        return Some(format!("ad:{c}"));
    }
    if let Some(c) = regex_once(r"\b([a-z0-9][a-z0-9-]{1,20})\\\\[a-z0-9._$-]+", &lower) {
        if !c.is_empty() && c != "c" && c != "d" {
            return Some(format!("ad:{c}"));
        }
    }
    None
}

fn regex_once(pattern: &str, hay: &str) -> Option<String> {
    let re = regex::Regex::new(pattern).ok()?;
    let c = re.captures(hay)?;
    Some(c.get(1)?.as_str().to_string())
}

/// The comparable core of a realm name.
///
/// The same realm is spelled several ways in one engagement: evidence says
/// `CORP\\svc_sql`, an endpoint says `dc01.corp.local`, a ticket says
/// `CORP.LOCAL`. Comparing the raw strings would call those three different
/// realms and refuse every link between them, so the first label — the part
/// that actually names the organization — is what is compared.
fn realm_key(realm: &str) -> String {
    let r = realm.to_lowercase();
    let r = r.split_once(':').map(|(_, rest)| rest.to_string()).unwrap_or(r);
    r.split('.').next().unwrap_or(&r).to_string()
}

/// Can an artifact obtained at `from` be used at `to`?
pub fn carries(a: Artifact, from: &Loc, to: &Loc) -> bool {
    match reach(a) {
        Reach::HostLocal => !from.host.is_empty() && from.host == to.host,
        Reach::Realm => {
            if from.host == to.host && !from.host.is_empty() {
                return true;
            }
            let (a, b) = (realm_key(&from.realm), realm_key(&to.realm));
            !a.is_empty() && a == b
        }
        Reach::Portable => true,
    }
}

// ---------------------------------------------------------------------------
// Per-finding profile: what this step gives, needs, and means
// ---------------------------------------------------------------------------

/// One finding's role in a path.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub domain: Domain,
    pub provides: Vec<Artifact>,
    pub requires: Vec<Artifact>,
    pub impacts: Vec<Impact>,
}

impl Default for Domain {
    fn default() -> Self {
        Domain::Web
    }
}

fn cwe_num(cwe: &str) -> u32 {
    cwe.chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// Everything the matcher reads, lowercased once.
struct Sig {
    agent: String,
    text: String,
    cwe: u32,
    mitre: String,
    endpoint: String,
}

impl Sig {
    fn of(f: &Finding) -> Sig {
        Sig {
            // Agent names are snake_case (`llm_tool_invocation_abuse`); the
            // needles below are written both ways, so both spellings are
            // offered to the matcher rather than making every rule guess.
            agent: format!("{} {}", f.agent.to_lowercase(), f.agent.to_lowercase().replace('_', " ")),
            text: format!("{} {} {} {} {}", f.title, f.evidence, f.impact, f.location, f.payload).to_lowercase(),
            cwe: cwe_num(&f.cwe),
            mitre: f.mitre.to_uppercase(),
            endpoint: f.endpoint.to_lowercase(),
        }
    }
    /// The agent that produced the finding names its technique; that is the
    /// strongest signal available and it exists for every domain in the
    /// library, including the ones with no meaningful CWE.
    fn agent_has(&self, needles: &[&str]) -> bool {
        needles.iter().any(|n| self.agent.contains(n))
    }
    fn says(&self, needles: &[&str]) -> bool {
        needles.iter().any(|n| self.text.contains(n))
    }
    fn any(&self, needles: &[&str]) -> bool {
        self.agent_has(needles) || self.says(needles)
    }
}

/// Which plane the finding belongs to.
pub fn domain_of(f: &Finding) -> Domain {
    let s = Sig::of(f);
    if s.agent_has(&["ad_", "bloodhound", "kerberoast", "asreproast", "dcsync", "ntlm_relay", "adcs", "llmnr", "smb_", "gpo_", "laps", "dpapi", "kerberos"])
        || s.says(&["active directory", "domain controller", "kerberos", "ntlm", "lsass", "keytab", "sysvol", "netlogon"])
    {
        return Domain::ActiveDirectory;
    }
    if s.agent_has(&["apk", "ipa", "mobile", "frida", "pinning", "jailbreak", "root_", "rasp", "anti_debug"])
        || s.says(&["apk", ".ipa", "smali", ".dex", "android manifest", "androidmanifest", "mobile app", "keystore", "objection", "jadx"])
    {
        return Domain::Mobile;
    }
    if s.agent_has(&["aws_", "azure_", "gcp_", "cloud_", "s3_", "gcs_", "ecr_", "imds", "serverless", "terraform", "presigned"])
        || s.says(&["169.254.169.254", "metadata.google", "imds", "sts:assumerole", "arn:aws", "storage account", "service account key"])
    {
        return Domain::Cloud;
    }
    if s.agent_has(&["entra", "oauth", "oidc", "saml", "okta", "passkey", "webauthn", "sso"])
        || s.says(&["microsoft graph", "entra id", "azure ad", "global administrator", "identity provider"])
    {
        return Domain::Identity;
    }
    if s.agent_has(&["k8s", "kube", "docker", "container", "helm", "ecr"]) {
        return Domain::Container;
    }
    if s.agent_has(&["firmware", "uboot", "bootloader", "spi_flash", "jtag", "uart"]) {
        return Domain::Firmware;
    }
    if s.agent_has(&["binary", "reverse", "exploit_dev", "rop", "heap", "stack_overflow", "fuzz", "deobfusc"])
        || matches!(s.cwe, 121 | 122 | 125 | 134 | 190 | 415 | 416 | 476 | 787 | 788 | 822 | 843)
    {
        return Domain::Binary;
    }
    if s.agent_has(&["llm_", "prompt_", "rag", "ml_", "vector_db", "agent_", "mcp_"]) {
        return Domain::Ai;
    }
    if s.agent_has(&["ci_cd", "dependency_confusion", "typosquat", "supply", "pipeline", "artifact_"]) {
        return Domain::SupplyChain;
    }
    if s.agent_has(&["wifi", "wireless", "wpa", "bluetooth", "zigbee", "rfid", "nfc"]) {
        return Domain::Wireless;
    }
    if s.agent_has(&["phish", "social", "pretext", "vishing", "smishing"]) {
        return Domain::Social;
    }
    if s.agent_has(&["modbus", "s7comm", "dnp3", "scada", "plc", "bacnet"]) {
        return Domain::Ot;
    }
    if s.agent_has(&["linux_", "windows_", "infra_", "ssh", "winrm", "smb", "port_service", "eol_os"]) {
        return Domain::Host;
    }
    if s.agent_has(&["api_", "graphql", "grpc", "rest_", "bola", "bfla", "jwt", "websocket", "soap"])
        || s.endpoint.contains("/api/")
        || s.endpoint.contains("/graphql")
    {
        return Domain::Api;
    }
    if s.says(&["port ", "tcp/", "udp/", "service banner"]) && s.endpoint.is_empty() {
        return Domain::Network;
    }
    Domain::Web
}

fn add(v: &mut Vec<Artifact>, items: &[Artifact]) {
    for a in items {
        if !v.contains(a) {
            v.push(*a);
        }
    }
}

/// What this finding produces, consumes and means — for every domain.
///
/// The agent that produced the finding names its technique, and that name is
/// the only signal that exists across the whole library: a Kerberoast, an IMDS
/// token steal and an APK secret dump have no useful CWE in common. CWE is
/// read too, because the web and API agents do set it, and the evidence text is
/// read last because an operator describing "dumped LSASS" has told us exactly
/// what the step yielded regardless of which agent ran.
pub fn profile(f: &Finding) -> Profile {
    let s = Sig::of(f);
    let mut p = Profile { domain: domain_of(f), ..Default::default() };
    match p.domain {
        Domain::ActiveDirectory => ad_rules(&s, &mut p),
        Domain::Cloud => cloud_rules(&s, &mut p),
        Domain::Identity => identity_rules(&s, &mut p),
        Domain::Container => container_rules(&s, &mut p),
        Domain::Mobile => mobile_rules(&s, &mut p),
        Domain::Binary => binary_rules(&s, &mut p),
        Domain::Firmware => firmware_rules(&s, &mut p),
        Domain::Ai => ai_rules(&s, &mut p),
        Domain::SupplyChain => supply_chain_rules(&s, &mut p),
        Domain::Wireless => wireless_rules(&s, &mut p),
        Domain::Social => social_rules(&s, &mut p),
        Domain::Ot => ot_rules(&s, &mut p),
        Domain::Host | Domain::Network => host_rules(&s, &mut p),
        Domain::Web | Domain::Api | Domain::Physical => {}
    }
    // CWE rules run for every domain: an AD finding that still carries CWE-287
    // is telling us something true about what it bypassed.
    cwe_rules(&s, &mut p);
    // What the evidence literally says happened.
    text_rules(&s, &mut p);

    for a in p.provides.clone() {
        if let Some(i) = impacts_of(a) {
            if !p.impacts.contains(&i) {
                p.impacts.push(i);
            }
        }
    }
    if s.says(&["vcenter", "esxi", "hypervisor", "domain controller", "backup server", "veeam", "san ", "ipmi", "idrac", "ilo "])
        && p.provides.iter().any(|a| matches!(a, Artifact::HostAdmin | Artifact::CodeExecution | Artifact::Implant | Artifact::ShellOnHost))
        && !p.impacts.contains(&Impact::CriticalInfrastructureCompromise)
    {
        p.impacts.push(Impact::CriticalInfrastructureCompromise);
    }
    p.impacts.sort();
    p.impacts.dedup();
    p
}

// --- Active Directory -------------------------------------------------------

fn ad_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["recon_enum", "ldap enum", "rpc enum", "user enumeration"]) {
        add(&mut p.provides, &[ValidIdentities, InternalKnowledge]);
    }
    if s.any(&["bloodhound", "sharphound", "attack path", "acl path"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[PrivilegeMap, InternalKnowledge]);
    }
    if s.any(&["kerberoast", "spn roast"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[PasswordHash]);
    }
    if s.any(&["asreproast", "as-rep", "preauth"]) {
        add(&mut p.requires, &[ValidIdentities]);
        add(&mut p.provides, &[PasswordHash]);
    }
    if s.any(&["password_spray", "password spray", "spraying"]) {
        add(&mut p.requires, &[ValidIdentities]);
        add(&mut p.provides, &[PlaintextCredential, DomainUser]);
    }
    if s.any(&["llmnr", "nbt-ns", "mdns", "responder", "poison"]) {
        add(&mut p.requires, &[InternalReach]);
        add(&mut p.provides, &[PasswordHash, ValidIdentities]);
    }
    if s.any(&["coerce", "petitpotam", "printerbug", "dfscoerce", "shadowcoerce"]) {
        add(&mut p.requires, &[InternalReach]);
        add(&mut p.provides, &[PasswordHash, MachineAccount]);
    }
    if s.any(&["ntlm_relay", "ntlm relay", "relay to", "smb relay", "ldap relay"]) {
        add(&mut p.requires, &[InternalReach]);
        add(&mut p.provides, &[DomainUser, HostAdmin, CertificateOrKey]);
    }
    if s.any(&["adcs", "esc1", "esc2", "esc3", "esc4", "esc6", "esc8", "certifried", "certificate template"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[CertificateOrKey, KerberosTicket, DomainAdmin]);
    }
    if s.any(&["dcsync", "drsuapi", "replicating directory"]) {
        add(&mut p.requires, &[DomainAdmin]);
        add(&mut p.provides, &[PasswordHash, DomainAdmin]);
    }
    if s.any(&["pass-the-hash", "pass the hash", "pth", "pass-the-ticket", "ptt", "overpass"]) {
        add(&mut p.requires, &[PasswordHash]);
        add(&mut p.provides, &[DomainUser, ShellOnHost, HostAdmin]);
    }
    if s.any(&["delegation", "rbcd", "s4u", "constrained", "unconstrained"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[KerberosTicket, DomainAdmin]);
    }
    if s.any(&["acl_privesc", "genericall", "writedacl", "writeowner", "addmember", "forcechangepassword"]) {
        add(&mut p.requires, &[DomainUser, PrivilegeMap]);
        add(&mut p.provides, &[DomainAdmin, PlaintextCredential]);
    }
    if s.any(&["gpo", "group policy"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[CodeExecution, HostAdmin]);
    }
    if s.any(&["laps", "gmsa"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[PlaintextCredential, HostAdmin]);
    }
    if s.any(&["dpapi", "credential manager", "vault blob", "masterkey"]) {
        add(&mut p.requires, &[HostAdmin]);
        add(&mut p.provides, &[PlaintextCredential, SessionToken]);
    }
    if s.any(&["share_hunt", "smb share", "sysvol", "netlogon", "share crawl", "open share"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[SecretsFile, PlaintextCredential, InternalKnowledge]);
    }
    if s.any(&["mssql", "sql server", "linked server", "xp_cmdshell"]) {
        add(&mut p.requires, &[DomainUser]);
        add(&mut p.provides, &[DatabaseAdmin, CodeExecution]);
    }
    if s.any(&["trust", "forest", "sid history", "golden ticket", "cross-forest"]) {
        add(&mut p.requires, &[DomainAdmin]);
        add(&mut p.provides, &[DomainAdmin, KerberosTicket]);
    }
    if s.any(&["zerologon", "printnightmare", "noPac", "nopac", "samaccountname", "ms14-068", "critical_cve"]) {
        add(&mut p.requires, &[InternalReach]);
        add(&mut p.provides, &[DomainAdmin, CodeExecution]);
    }
    if s.any(&["ad_default_creds", "default domain", "default credential"]) {
        add(&mut p.provides, &[PlaintextCredential, DomainUser]);
    }
    if s.any(&["persistence", "skeleton key", "adminsdholder", "dsrm"]) {
        add(&mut p.requires, &[DomainAdmin]);
        add(&mut p.provides, &[Implant, DomainAdmin]);
    }
}

// --- Cloud ------------------------------------------------------------------

fn cloud_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["imds", "169.254.169.254", "metadata", "instance metadata"]) {
        add(&mut p.requires, &[InternalReach]);
        add(&mut p.provides, &[CloudToken, CloudRole]);
    }
    if s.any(&["iam_privesc", "iam privilege", "assumerole", "passrole", "role chaining", "rbac_privesc", "privilege escalation path"]) {
        add(&mut p.requires, &[CloudToken]);
        add(&mut p.provides, &[CloudRole, TenantAdmin]);
    }
    if s.any(&["s3", "bucket", "gcs", "blob container", "storage account", "object storage"]) {
        add(&mut p.provides, &[DataAccess, SensitiveData, SecretsFile]);
    }
    if s.any(&["secrets manager", "keyvault", "key vault", "parameter store", "secret manager", "secrets_exposure"]) {
        add(&mut p.requires, &[CloudToken]);
        add(&mut p.provides, &[PlaintextCredential, ApiKey, CertificateOrKey]);
    }
    if s.any(&["service account key", "serviceaccount", "sa key", "json key"]) {
        add(&mut p.provides, &[CloudToken, CertificateOrKey, CloudRole]);
    }
    if s.any(&["lambda", "cloud function", "functions", "serverless"]) {
        add(&mut p.requires, &[CloudToken]);
        add(&mut p.provides, &[CodeExecution, CloudRole]);
    }
    if s.any(&["compute_exposure", "ec2", "vm exposed", "instance exposed", "ssh exposed"]) {
        add(&mut p.provides, &[InternalReach, ShellOnHost]);
    }
    if s.any(&["terraform", "state file", "tfstate", "pulumi"]) {
        add(&mut p.provides, &[CloudToken, SecretsFile, InternalKnowledge]);
    }
    if s.any(&["ecr", "registry public", "container registry"]) {
        add(&mut p.provides, &[SourceCode, SecretsFile]);
    }
    if s.any(&["presigned", "sas token", "signed url"]) {
        add(&mut p.provides, &[DataAccess, SensitiveData]);
    }
    if s.any(&["cloud_recon", "footprint", "asset discovery"]) {
        add(&mut p.provides, &[InternalKnowledge, ValidIdentities]);
    }
}

// --- SaaS / identity plane --------------------------------------------------

fn identity_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["entra_enum", "tenant enum", "user enumeration", "directory enumeration"]) {
        add(&mut p.provides, &[ValidIdentities, InternalKnowledge]);
    }
    if s.any(&["oauth", "oidc", "openid", "saml", "sso"]) {
        add(&mut p.provides, &[SessionToken, ApplicationIdentity]);
    }
    if s.any(&["signature wrapping", "alg confusion", "jku", "x5u", "jwk injection", "kid injection", "none algorithm", "forged token"]) {
        add(&mut p.provides, &[SessionToken, ApplicationAdmin]);
    }
    if s.any(&["mfa", "2fa", "two factor", "second factor", "otp bypass"]) {
        add(&mut p.requires, &[PlaintextCredential]);
        add(&mut p.provides, &[MfaBypass, ApplicationIdentity]);
    }
    if s.any(&["refresh token", "access token", "primary refresh token", "prt", "graph api", "microsoft graph"]) {
        if s.says(&["stolen", "extracted", "replay", "escalat", "reused", "lifted", "captured"]) {
            add(&mut p.requires, &[CloudToken]);
        }
        add(&mut p.provides, &[CloudToken, SessionToken]);
    }
    if s.any(&["global administrator", "global admin", "tenant admin", "privileged role"]) {
        add(&mut p.provides, &[TenantAdmin]);
    }
    if s.any(&["consent", "illicit grant", "app registration", "service principal"]) {
        add(&mut p.requires, &[SessionToken]);
        add(&mut p.provides, &[CloudRole, Implant]);
    }
}

// --- Containers & orchestration ---------------------------------------------

fn container_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["docker socket", "docker.sock", "docker api"]) {
        add(&mut p.requires, &[InternalReach]);
        add(&mut p.provides, &[HostAdmin, ShellOnHost, Implant]);
    }
    if s.any(&["escape", "privileged container", "hostpid", "hostpath", "cgroup release_agent"]) {
        add(&mut p.requires, &[ShellOnHost]);
        add(&mut p.provides, &[HostAdmin]);
    }
    if s.any(&["rbac", "cluster-admin", "clusterrole", "service account token"]) {
        add(&mut p.requires, &[SessionToken]);
        add(&mut p.provides, &[CloudRole, CodeExecution, TenantAdmin]);
    }
    if s.any(&["kubelet", "10250", "exec api"]) {
        add(&mut p.requires, &[InternalReach]);
        add(&mut p.provides, &[CodeExecution, SensitiveData]);
    }
    if s.any(&["dashboard", "kubeconfig"]) {
        add(&mut p.provides, &[CodeExecution, CloudToken]);
    }
    if s.any(&["helm", "chart secret", "image secret", "imagepullsecret"]) {
        add(&mut p.provides, &[PlaintextCredential, ApiKey]);
    }
}

// --- Mobile ------------------------------------------------------------------

fn mobile_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["apk_static", "ipa_static", "static_binary", "decompil", "manifest"]) {
        add(&mut p.provides, &[SourceCode, InternalKnowledge]);
    }
    if s.any(&["hardcoded", "embedded secret", "api key", "firebase", "keystore password"]) {
        add(&mut p.provides, &[ApiKey, PlaintextCredential, CloudToken]);
    }
    if s.any(&["insecure_data_storage", "shared preferences", "sqlite", "keychain", "plist", "external storage"]) {
        add(&mut p.requires, &[DeviceAccess]);
        add(&mut p.provides, &[SessionToken, PlaintextCredential, SensitiveData]);
    }
    if s.any(&["pinning", "mitm proxy", "traffic analysis", "intercept"]) {
        add(&mut p.provides, &[InternalKnowledge, ApiKey, SessionToken]);
    }
    if s.any(&["root detection", "jailbreak", "anti_debug", "rasp", "tamper", "integrity check"]) {
        add(&mut p.provides, &[DeviceAccess, CodeExecution]);
    }
    if s.any(&["obfuscation", "deobfusc"]) {
        add(&mut p.provides, &[SourceCode, InternalKnowledge]);
    }
    if s.any(&["exported activity", "deeplink", "content provider", "broadcast receiver", "intent"]) {
        add(&mut p.requires, &[DeviceAccess]);
        add(&mut p.provides, &[ApplicationIdentity, DataAccess]);
    }
}

// --- Binaries ----------------------------------------------------------------

fn binary_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["buffer overflow", "stack overflow", "heap overflow", "use-after-free", "uaf", "double free",
               "out-of-bounds write", "oob write", "format string", "type confusion", "integer overflow", "rop", "memory corruption"])
        || matches!(s.cwe, 121 | 122 | 124 | 125 | 134 | 190 | 415 | 416 | 476 | 787 | 788 | 822 | 843)
    {
        add(&mut p.provides, &[CodeExecution, ShellOnHost]);
    }
    if s.any(&["reverse engineer", "disassembl", "decompil", "symbol", "deobfusc", "unpack"]) {
        add(&mut p.provides, &[SourceCode, InternalKnowledge]);
    }
    if s.any(&["hardcoded key", "embedded credential", "xor key", "license key", "crypto key"]) {
        add(&mut p.provides, &[CertificateOrKey, PlaintextCredential, ApiKey]);
    }
    if s.any(&["setuid", "suid", "privileged binary", "dll hijack", "dll side-load", "service binary"]) {
        add(&mut p.requires, &[ShellOnHost]);
        add(&mut p.provides, &[HostAdmin]);
    }
    if s.any(&["signature bypass", "code signing", "sign check"]) {
        add(&mut p.provides, &[CodeExecution, SupplyChainWrite]);
    }
}

// --- Firmware / embedded ------------------------------------------------------

fn firmware_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["firmware image", "squashfs", "extract", "binwalk", "flash dump", "spi"]) {
        add(&mut p.requires, &[DeviceAccess]);
        add(&mut p.provides, &[SourceCode, PlaintextCredential, CertificateOrKey, InternalKnowledge]);
    }
    if s.any(&["uart", "jtag", "swd", "serial console", "debug port"]) {
        add(&mut p.requires, &[DeviceAccess]);
        add(&mut p.provides, &[ShellOnHost, HostAdmin]);
    }
    if s.any(&["secure boot", "bootloader", "u-boot", "signed image", "rollback"]) {
        add(&mut p.requires, &[DeviceAccess]);
        add(&mut p.provides, &[CodeExecution, Implant, SupplyChainWrite]);
    }
    if s.any(&["backdoor account", "hardcoded telnet", "default root", "busybox shell"]) {
        add(&mut p.provides, &[PlaintextCredential, ShellOnHost, HostAdmin]);
    }
    if s.any(&["ota", "update channel", "unsigned update"]) {
        add(&mut p.provides, &[SupplyChainWrite, CodeExecution]);
    }
}

// --- AI / LLM / agents --------------------------------------------------------

fn ai_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["prompt injection", "jailbreak", "system prompt override", "indirect injection", "rag poison", "vector db", "poisoned document"]) {
        add(&mut p.provides, &[AgentControl]);
    }
    if s.any(&["system prompt leak", "prompt disclosure", "instruction leak"]) {
        add(&mut p.provides, &[InternalKnowledge]);
    }
    if s.any(&["tool invocation", "function calling", "excessive agency", "insecure output handling", "mcp tool", "skill abuse"]) {
        add(&mut p.requires, &[AgentControl]);
        add(&mut p.provides, &[CodeExecution, DataAccess]);
    }
    if s.any(&["api key exfil", "key exfiltration", "credential exfil"]) {
        add(&mut p.requires, &[AgentControl]);
        add(&mut p.provides, &[ApiKey, CloudToken]);
    }
    if s.any(&["pii leak", "training data extraction", "model inversion", "memorized"]) {
        add(&mut p.provides, &[SensitiveData]);
    }
    if s.any(&["plugin", "supply chain", "model weights", "unsigned model"]) {
        add(&mut p.provides, &[SupplyChainWrite, CodeExecution]);
    }
}

// --- CI/CD & supply chain -----------------------------------------------------

fn supply_chain_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["ci_cd", "pipeline secret", "build log", "workflow secret", "runner"]) {
        add(&mut p.provides, &[ApiKey, CloudToken, PlaintextCredential]);
    }
    if s.any(&["dependency confusion", "typosquat", "package takeover", "unclaimed package", "registry push"]) {
        add(&mut p.provides, &[SupplyChainWrite, CodeExecution]);
    }
    if s.any(&["artifact signing", "unsigned artifact", "poisoned image", "base image"]) {
        add(&mut p.provides, &[SupplyChainWrite, Implant]);
    }
}

// --- Wireless -----------------------------------------------------------------

fn wireless_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["handshake", "pmkid", "wpa", "wep", "deauth"]) {
        add(&mut p.provides, &[PasswordHash, InternalReach]);
    }
    if s.any(&["evil twin", "rogue ap", "karma", "captive portal"]) {
        add(&mut p.provides, &[PlaintextCredential, SessionToken, InternalReach]);
    }
    if s.any(&["guest network", "vlan hop", "wps"]) {
        add(&mut p.provides, &[InternalReach]);
    }
    if s.any(&["ble", "bluetooth", "zigbee", "rfid", "nfc", "badge clone"]) {
        add(&mut p.provides, &[DeviceAccess, InternalReach]);
    }
}

// --- Social -------------------------------------------------------------------

fn social_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    add(&mut p.provides, &[UserInteraction]);
    if s.any(&["credential harvest", "fake login", "phish"]) {
        add(&mut p.provides, &[PlaintextCredential, SessionToken]);
    }
    if s.any(&["mfa fatigue", "push bombing", "device code", "consent phishing"]) {
        add(&mut p.provides, &[MfaBypass, SessionToken, CloudToken]);
    }
    if s.any(&["payload", "macro", "attachment", "lnk", "iso"]) {
        add(&mut p.provides, &[CodeExecution, Implant]);
    }
}

// --- OT / ICS -------------------------------------------------------------------

fn ot_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    add(&mut p.requires, &[InternalReach]);
    if s.any(&["modbus", "s7comm", "dnp3", "bacnet", "plc", "hmi", "scada", "historian"]) {
        add(&mut p.provides, &[CodeExecution, SensitiveData]);
        if !p.impacts.contains(&Impact::CriticalInfrastructureCompromise) {
            p.impacts.push(Impact::CriticalInfrastructureCompromise);
        }
    }
}

// --- Hosts & internal network ----------------------------------------------------

fn host_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.any(&["port_service", "port scan", "service scan", "banner"]) {
        add(&mut p.provides, &[InternalKnowledge]);
    }
    if s.any(&["smb_enum", "null session", "share enumeration", "rpc null"]) {
        add(&mut p.provides, &[ValidIdentities, InternalKnowledge, SecretsFile]);
    }
    if s.any(&["ssh_weak", "weak ssh", "ssh key", "authorized_keys", "password authentication"]) {
        add(&mut p.requires, &[ValidIdentities]);
        add(&mut p.provides, &[ShellOnHost, PlaintextCredential]);
    }
    if s.any(&["sudo", "cron", "writable", "priv_esc", "privilege escalation", "capabilities", "kernel exploit", "unquoted service"]) {
        add(&mut p.requires, &[ShellOnHost]);
        add(&mut p.provides, &[HostAdmin]);
    }
    if s.any(&["winrm", "psexec", "wmiexec", "smbexec", "remote execution"]) {
        add(&mut p.requires, &[PlaintextCredential]);
        add(&mut p.provides, &[ShellOnHost, HostAdmin]);
    }
    if s.any(&["smb signing", "signing not required"]) {
        add(&mut p.provides, &[InternalKnowledge, InternalReach]);
    }
    if s.any(&["default credential", "default password", "admin:admin"]) {
        add(&mut p.provides, &[PlaintextCredential, HostAdmin, ApplicationAdmin]);
    }
    if s.any(&["eol", "end-of-life", "unsupported version", "unpatched"]) {
        add(&mut p.provides, &[CodeExecution, ShellOnHost]);
    }
    if s.any(&["exposed datastore", "mongodb", "redis", "elasticsearch", "memcached", "database exposed"]) {
        add(&mut p.provides, &[DataAccess, SensitiveData, PlaintextCredential, DatabaseAccess]);
    }
}

// --- Web / API, by weakness class -------------------------------------------

fn cwe_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    match s.cwe {
        // Injection into a data store.
        89 | 943 | 90 | 564 => {
            add(&mut p.provides, &[DataAccess, SensitiveData, DatabaseAccess, PasswordHash]);
            if s.says(&["xp_cmdshell", "stacked", "into outfile", "copy to program", "sp_oacreate", "lo_import"]) {
                add(&mut p.provides, &[CodeExecution, DatabaseAdmin]);
            }
            if s.cwe == 564 {
                add(&mut p.requires, &[ApplicationIdentity]);
            }
        }
        // Command / template / expression / code injection and deserialization.
        77 | 78 | 94 | 95 | 502 | 917 | 1336 | 1321 | 470 => {
            add(&mut p.provides, &[CodeExecution, ShellOnHost, InternalReach]);
        }
        // Upload leading to a shell.
        434 => add(&mut p.provides, &[CodeExecution, Implant]),
        // SSRF and XML entity expansion reach inward.
        918 => {
            add(&mut p.provides, &[InternalReach, InternalKnowledge]);
            if s.says(&["169.254.169.254", "metadata", "imds", "computemetadata"]) {
                add(&mut p.provides, &[CloudToken, CloudRole]);
            }
        }
        611 | 776 | 827 => add(&mut p.provides, &[DataAccess, SecretsFile, InternalReach]),
        // Path traversal / file read / inclusion.
        22 | 23 | 35 | 73 | 98 => {
            add(&mut p.provides, &[DataAccess, SecretsFile, InternalKnowledge, SourceCode]);
            if s.cwe == 98 && s.says(&["remote", "http://", "rfi"]) {
                add(&mut p.provides, &[CodeExecution]);
            }
        }
        // Cross-site scripting runs in someone else's session.
        79 | 80 | 83 | 87 | 116 => {
            add(&mut p.provides, &[SessionToken, ApplicationIdentity]);
            if s.says(&["reflected", "requires a victim", "user must"]) {
                add(&mut p.requires, &[UserInteraction]);
            }
            if s.says(&["admin", "administrator panel", "privileged user"]) {
                add(&mut p.provides, &[ApplicationAdmin]);
            }
        }
        // Request forgery needs a victim and acts as them.
        352 => {
            add(&mut p.requires, &[UserInteraction]);
            add(&mut p.provides, &[ApplicationIdentity]);
        }
        // Broken access control.
        639 | 862 | 863 | 284 | 285 | 566 | 425 | 668 => {
            add(&mut p.requires, &[ValidIdentities]);
            add(&mut p.provides, &[ApplicationIdentity, DataAccess, SensitiveData]);
        }
        // Authentication bypass / missing authentication.
        287 | 288 | 290 | 306 | 305 | 603 | 645 => {
            add(&mut p.provides, &[ApplicationIdentity, ApplicationAdmin, SessionToken]);
        }
        // Credentials at rest, in code, in transit.
        798 | 522 | 312 | 256 | 257 | 321 | 260 | 555 => {
            add(&mut p.provides, &[PlaintextCredential, ApiKey, CertificateOrKey]);
        }
        319 | 311 => add(&mut p.provides, &[SessionToken, PlaintextCredential]),
        // Session handling.
        384 | 613 | 614 | 1004 | 539 | 488 => {
            add(&mut p.provides, &[SessionToken]);
            if matches!(s.cwe, 614 | 1004 | 539) {
                add(&mut p.requires, &[SessionToken]);
            }
        }
        // Rate limiting and resource control.
        307 | 770 | 799 | 400 | 1333 => {
            add(&mut p.provides, &[UnlimitedAttempts]);
            add(&mut p.requires, &[ValidIdentities]);
        }
        // Password policy.
        521 | 261 | 262 | 263 | 549 => {
            add(&mut p.provides, &[WeakCredentials]);
            add(&mut p.requires, &[ValidIdentities, UnlimitedAttempts]);
        }
        // Enumeration and observable discrepancies.
        200 | 203 | 204 | 208 => {
            if s.says(&["account", "user", "email", "username", "enumerat"]) {
                add(&mut p.provides, &[ValidIdentities]);
            }
            add(&mut p.provides, &[InternalKnowledge]);
        }
        // Information leakage.
        209 | 532 | 538 | 540 | 548 | 215 | 497 => {
            add(&mut p.provides, &[InternalKnowledge, SecretsFile, SourceCode]);
        }
        // Mass assignment / improper state write.
        915 | 913 | 1287 => add(&mut p.provides, &[ApplicationAdmin, ApplicationIdentity]),
        // Redirects and victim-driven flows.
        601 | 1021 => {
            add(&mut p.requires, &[UserInteraction]);
            add(&mut p.provides, &[SessionToken]);
        }
        // Privilege management.
        269 | 250 | 271 | 272 => {
            add(&mut p.requires, &[ApplicationIdentity]);
            add(&mut p.provides, &[ApplicationAdmin, HostAdmin]);
        }
        // Capture-replay / relay / certificate validation / signature checks.
        294 => add(&mut p.provides, &[PasswordHash, SessionToken]),
        295 | 297 | 299 => add(&mut p.provides, &[SessionToken, InternalKnowledge]),
        347 | 345 | 1270 => add(&mut p.provides, &[SessionToken, ApplicationIdentity]),
        // Weak crypto / randomness: predictable tokens are session material.
        327 | 328 | 330 | 338 | 326 | 916 => add(&mut p.provides, &[SessionToken, WeakCredentials]),
        // Default credentials.
        1392 | 1393 => add(&mut p.provides, &[PlaintextCredential, ApplicationAdmin, HostAdmin]),
        // Request smuggling / cache poisoning / header injection: other users'
        // requests and responses become attacker-controlled.
        444 | 113 | 93 | 644 => add(&mut p.provides, &[SessionToken, UserInteraction, ApplicationIdentity]),
        // CORS and origin trust.
        942 | 346 | 1385 => add(&mut p.provides, &[DataAccess, SessionToken]),
        _ => {}
    }
}

// --- What the evidence literally says ----------------------------------------

fn text_rules(s: &Sig, p: &mut Profile) {
    use Artifact::*;
    if s.says(&["lsass", "mimikatz", "procdump", "comsvcs", "credential dump", "sam hive", "ntds.dit"]) {
        add(&mut p.requires, &[HostAdmin]);
        add(&mut p.provides, &[PasswordHash, PlaintextCredential]);
    }
    if s.says(&["keytab", "machine account", "computer account", "$ account"]) {
        add(&mut p.requires, &[HostAdmin]);
        add(&mut p.provides, &[MachineAccount, PasswordHash]);
    }
    if s.says(&["xp_cmdshell", "sp_oacreate", "ole automation", "clr assembly"]) {
        add(&mut p.requires, &[DatabaseAdmin]);
        add(&mut p.provides, &[CodeExecution, ShellOnHost]);
    }
    if s.says(&["seimpersonate", "potato", "juicypotato", "printspoofer", "setokenprivilege", "sedebugprivilege"]) {
        add(&mut p.requires, &[ShellOnHost]);
        add(&mut p.provides, &[HostAdmin]);
    }
    if s.says(&["webshell", "implant", "beacon", " rat ", "c2 agent", "reverse shell", "meterpreter", "payload loaded", "nodezero"]) {
        add(&mut p.provides, &[Implant, ShellOnHost]);
    }
    if s.says(&["nt authority\\system", "uid=0", "root shell", "administrators group", "local administrator"]) {
        add(&mut p.provides, &[HostAdmin]);
    }
    if s.says(&["domain admin", "enterprise admin", "domain administrator"]) {
        add(&mut p.provides, &[DomainAdmin]);
    }
    if s.says(&["global administrator", "global admin", "tenant administrator"]) {
        add(&mut p.provides, &[TenantAdmin]);
    }
    if s.says(&["process memory", "token theft", "stolen token", "access token extracted", "office process"]) {
        add(&mut p.requires, &[HostAdmin]);
        add(&mut p.provides, &[SessionToken, CloudToken]);
    }
    if s.says(&["pass-the-hash", "pass the hash", "pass-the-ticket", "kerberos authentication with", "ntlm authentication with"]) {
        add(&mut p.requires, &[PasswordHash]);
        add(&mut p.provides, &[DomainUser]);
    }
    if s.says(&["credential reuse", "same password", "password reuse", "reused credential",
                "recovered credential", "discovered credential", "found credential",
                "leaked credential", "stolen credential", "harvested credential",
                "with the recovered", "with the discovered", "with the leaked"]) {
        add(&mut p.requires, &[PlaintextCredential]);
        add(&mut p.provides, &[ApplicationIdentity, ShellOnHost]);
    }
    if s.mitre.starts_with("T1557") || s.mitre.starts_with("T1110") {
        add(&mut p.requires, &[ValidIdentities]);
    }
}

// ---------------------------------------------------------------------------
// The graph
// ---------------------------------------------------------------------------

/// One node on the path: a weakness that was exploited, a piece of material it
/// produced, a session it opened, or the consequence a branch ends in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    /// The headline, e.g. `CVE-2026-59310 vCenter Syslog Traversal`.
    pub label: String,
    /// The second line: host, account, artifact detail.
    pub detail: String,
    pub domain: Domain,
    pub host: String,
    pub realm: String,
    /// The finding this node came from (empty for artifact/impact nodes that
    /// several findings share).
    pub finding_id: String,
    pub severity: String,
    pub artifact: Option<Artifact>,
    /// Epoch seconds; 0 when the run did not record one.
    pub at: u64,
    /// Position on the rendered timeline.
    pub step: usize,
    /// Whether the step was validated rather than asserted.
    pub proven: bool,
    pub impacts: Vec<Impact>,
}

/// A dependency between two nodes, always carrying why it holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub via: Option<Artifact>,
    pub reason: String,
    /// Derived by these rules rather than asserted by an agent.
    pub inferred: bool,
}

/// The engagement as a graph of steps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackPathGraph {
    pub target: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

/// One route through the graph, start to consequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Path {
    /// Node ids in order.
    pub nodes: Vec<String>,
    /// How many exploited weaknesses it strings together.
    pub steps: usize,
    pub score: f64,
    pub impacts: Vec<Impact>,
    /// Domains it crosses, in order of first appearance — the pivots.
    pub domains: Vec<Domain>,
    /// Hosts it touches.
    pub hosts: Vec<String>,
    pub narrative: String,
}

const ENTRY: &str = "entry";

fn sev_weight(sev: &str) -> f64 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 5.0,
        "high" => 4.0,
        "medium" => 2.0,
        "low" => 1.0,
        _ => 0.5,
    }
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn short(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n { format!("{t}…") } else { t }
}

/// Where an artifact lives, for node identity: a host-local artifact is a
/// different thing on each host, a realm artifact is one thing per realm, and a
/// portable one is a single thing the attacker carries.
fn artifact_scope_key(a: Artifact, loc: &Loc) -> String {
    match reach(a) {
        Reach::HostLocal => loc.host.clone(),
        Reach::Realm => {
            if loc.realm.is_empty() { loc.host.clone() } else { loc.realm.clone() }
        }
        Reach::Portable => String::new(),
    }
}

/// Build the path graph for a finished engagement.
///
/// `loot` is the typed material the chaining rounds collected
/// (`cred:…`, `token:…`, `host:…`, `endpoint:…`); it is folded in so the
/// credentials an operator actually carried forward appear as nodes even when
/// no single finding reported them.
pub fn build(target: &str, findings: &[Finding], loot: &[String]) -> AttackPathGraph {
    let mut g = AttackPathGraph { target: target.to_string(), nodes: Vec::new(), edges: Vec::new() };
    if findings.is_empty() {
        return g;
    }
    let profiles: Vec<Profile> = findings.iter().map(profile).collect();
    let locs: Vec<Loc> = findings.iter().map(loc_of).collect();

    // Order on the clock when the run recorded one, otherwise on discovery
    // order. `order[i]` is the position of finding i in time.
    let mut idx: Vec<usize> = (0..findings.len()).collect();
    idx.sort_by_key(|&i| (findings[i].observed_at, i));
    let mut order = vec![0usize; findings.len()];
    for (slot, &i) in idx.iter().enumerate() {
        order[i] = slot;
    }

    // 1. A node per exploited weakness.
    for (i, f) in findings.iter().enumerate() {
        let p = &profiles[i];
        let loc = &locs[i];
        g.nodes.push(Node {
            id: format!("w{i}"),
            kind: NodeKind::ExploitedWeakness,
            label: short(if f.title.is_empty() { f.cwe.as_str() } else { f.title.as_str() }, 90),
            detail: [f.cwe.as_str(), loc.host.as_str()].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" · "),
            domain: p.domain,
            host: loc.host.clone(),
            realm: loc.realm.clone(),
            finding_id: f.id.clone(),
            severity: f.severity.clone(),
            artifact: None,
            at: f.observed_at,
            step: order[i],
            proven: f.validated && f.review_status != "needs-review",
            impacts: p.impacts.clone(),
        });
    }

    // 2. A node per distinct artifact a weakness produced, keyed by how far
    //    that artifact travels: one shell per host, one domain-admin hash per
    //    realm, one carried password everywhere.
    let mut artifact_node: HashMap<String, String> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        let loc = &locs[i];
        for a in &profiles[i].provides {
            let Some(kind) = NodeKind::for_artifact(*a) else { continue };
            let key = format!("{:?}|{}|{i}", a, artifact_scope_key(*a, loc));
            let id = artifact_node.entry(key).or_insert_with(|| {
                let id = format!("a{}", g.nodes.len());
                let scope = artifact_scope_key(*a, loc);
                g.nodes.push(Node {
                    id: id.clone(),
                    kind,
                    label: title_case(a.as_str()),
                    detail: if scope.is_empty() { "carried by the attacker".into() } else { scope },
                    domain: profiles[i].domain,
                    host: loc.host.clone(),
                    realm: loc.realm.clone(),
                    finding_id: String::new(),
                    severity: f.severity.clone(),
                    artifact: Some(*a),
                    at: f.observed_at,
                    step: order[i],
                    proven: f.validated,
                    impacts: impacts_of(*a).into_iter().collect(),
                });
                id
            }).clone();
            g.edges.push(Edge {
                from: format!("w{i}"),
                to: id,
                via: Some(*a),
                reason: format!("yields {}", a.as_str()),
                inferred: true,
            });
        }
    }

    // 3. Consumption: a step that needs an artifact is linked to whatever
    //    produced one that could have reached it.
    for (j, consumer) in findings.iter().enumerate() {
        for need in &profiles[j].requires {
            let mut linked = false;
            for (i, producer) in findings.iter().enumerate() {
                if i == j || !profiles[i].provides.contains(need) {
                    continue;
                }
                if !carries(*need, &locs[i], &locs[j]) {
                    continue;
                }
                // A weakness does not enable itself, and one instance of a
                // class does not enable another instance of the same class.
                if cwe_num(&producer.cwe) != 0 && cwe_num(&producer.cwe) == cwe_num(&consumer.cwe) {
                    continue;
                }
                // Time, when the run recorded it: a step cannot be enabled by
                // one that happened later.
                if producer.observed_at > 0 && consumer.observed_at > 0 && producer.observed_at > consumer.observed_at {
                    continue;
                }
                let from = match NodeKind::for_artifact(*need) {
                    Some(_) => artifact_node
                        .get(&format!("{:?}|{}|{i}", need, artifact_scope_key(*need, &locs[i])))
                        .cloned()
                        .unwrap_or_else(|| format!("w{i}")),
                    None => format!("w{i}"),
                };
                let to = format!("w{j}");
                if from == to || g.edges.iter().any(|e| e.from == from && e.to == to && e.via == Some(*need)) {
                    continue;
                }
                let pivot = locs[i].host != locs[j].host && !locs[i].host.is_empty() && !locs[j].host.is_empty();
                g.edges.push(Edge {
                    from,
                    to,
                    via: Some(*need),
                    reason: if pivot {
                        format!("{} carried from {} to {}", need.as_str(), locs[i].host, locs[j].host)
                    } else {
                        format!("{} used against {}", need.as_str(), short(&consumer.title, 48))
                    },
                    inferred: true,
                });
                linked = true;
            }
            let _ = linked;
        }
    }

    // 4. Loot the chaining rounds carried forward but no finding reported.
    fold_loot(&mut g, loot, &mut artifact_node);

    // 5. Impact terminals.
    let mut impact_node: BTreeMap<Impact, String> = BTreeMap::new();
    let sources: Vec<(String, Vec<Impact>, usize)> =
        g.nodes.iter().map(|n| (n.id.clone(), n.impacts.clone(), n.step)).collect();
    for (id, impacts, step) in sources {
        for im in impacts {
            let node_id = impact_node.entry(im).or_insert_with(|| {
                let nid = format!("i{}", slug(im.as_str()));
                g.nodes.push(Node {
                    id: nid.clone(),
                    kind: NodeKind::Impact,
                    label: im.as_str().to_string(),
                    detail: String::new(),
                    domain: Domain::Web,
                    host: String::new(),
                    realm: String::new(),
                    finding_id: String::new(),
                    severity: "Critical".into(),
                    artifact: None,
                    at: 0,
                    step,
                    proven: true,
                    impacts: vec![im],
                });
                nid
            }).clone();
            if !g.edges.iter().any(|e| e.from == id && e.to == node_id) {
                g.edges.push(Edge { from: id.clone(), to: node_id, via: None, reason: im.as_str().to_string(), inferred: true });
            }
        }
    }

    // 6. An entry node, so every path has a start to be read from.
    let has_incoming: BTreeSet<String> = g.edges.iter().map(|e| e.to.clone()).collect();
    let roots: Vec<String> = g
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::ExploitedWeakness && !has_incoming.contains(&n.id))
        .map(|n| n.id.clone())
        .collect();
    if !roots.is_empty() {
        g.nodes.insert(0, Node {
            id: ENTRY.into(),
            kind: NodeKind::Entry,
            label: "Attacker".into(),
            detail: target.to_string(),
            domain: Domain::Web,
            host: String::new(),
            realm: String::new(),
            finding_id: String::new(),
            severity: "Info".into(),
            artifact: None,
            at: 0,
            step: 0,
            proven: true,
            impacts: Vec::new(),
        });
        for r in roots {
            g.edges.push(Edge { from: ENTRY.into(), to: r, via: None, reason: "starting position".into(), inferred: true });
        }
    }
    g.renumber_steps();
    g
}

fn title_case(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Fold the chain rounds' loot (`cred:…`, `token:…`, `host:…`, `endpoint:…`)
/// into the graph as material the attacker carried.
fn fold_loot(g: &mut AttackPathGraph, loot: &[String], artifact_node: &mut HashMap<String, String>) {
    for item in loot {
        let (prefix, rest) = item.split_once(':').unwrap_or(("", item.as_str()));
        let (artifact, kind) = match prefix.trim().to_lowercase().as_str() {
            "cred" | "credential" | "password" => (Artifact::PlaintextCredential, NodeKind::DiscoveredCredential),
            "hash" | "ntlm" => (Artifact::PasswordHash, NodeKind::DiscoveredCredential),
            "token" | "jwt" | "session" => (Artifact::SessionToken, NodeKind::CompromisedCredential),
            "key" | "apikey" | "api_key" => (Artifact::ApiKey, NodeKind::DiscoveredCredential),
            "host" => (Artifact::InternalReach, NodeKind::AccessedResource),
            "endpoint" | "url" | "share" | "file" => (Artifact::DataAccess, NodeKind::AccessedResource),
            _ => continue,
        };
        let key = format!("loot|{:?}|{}", artifact, rest.trim());
        if artifact_node.contains_key(&key) {
            continue;
        }
        let id = format!("l{}", g.nodes.len());
        artifact_node.insert(key, id.clone());
        g.nodes.push(Node {
            id,
            kind,
            label: title_case(artifact.as_str()),
            detail: short(rest.trim(), 60),
            domain: Domain::Network,
            host: String::new(),
            realm: String::new(),
            finding_id: String::new(),
            severity: "Info".into(),
            artifact: Some(artifact),
            at: 0,
            step: 0,
            proven: true,
            impacts: impacts_of(artifact).into_iter().collect(),
        });
    }
}

impl AttackPathGraph {
    /// Lay the nodes out in dependency order so the timeline reads left to
    /// right even when the run recorded no clock: a node sits one slot after
    /// the latest thing that feeds it.
    fn renumber_steps(&mut self) {
        let ids: Vec<String> = self.nodes.iter().map(|n| n.id.clone()).collect();
        let pos: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, s)| (s.as_str(), i)).collect();
        let mut incoming: Vec<Vec<usize>> = vec![Vec::new(); self.nodes.len()];
        for e in &self.edges {
            if let (Some(&a), Some(&b)) = (pos.get(e.from.as_str()), pos.get(e.to.as_str())) {
                incoming[b].push(a);
            }
        }
        // Longest-path layering, with a bounded number of relaxation rounds so
        // a cycle introduced by contradictory evidence cannot hang the run.
        let mut depth = vec![0usize; self.nodes.len()];
        for _ in 0..self.nodes.len().min(64) {
            let mut changed = false;
            for i in 0..self.nodes.len() {
                let want = incoming[i].iter().map(|&a| depth[a] + 1).max().unwrap_or(0);
                if want > depth[i] && want < 256 {
                    depth[i] = want;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for (i, n) in self.nodes.iter_mut().enumerate() {
            n.step = depth[i];
        }
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    fn out_edges(&self, id: &str) -> Vec<&Edge> {
        self.edges.iter().filter(|e| e.from == id).collect()
    }

    /// Every maximal route through the graph, best first.
    ///
    /// "Best" is what an operator briefs: how far it gets (the impact it ends
    /// in), how much it proves on the way, and how many planes it crosses — a
    /// path that starts on a web form and ends in a directory is worth more
    /// than a longer one that never leaves the application.
    pub fn paths(&self, top: usize) -> Vec<Path> {
        let starts: Vec<&Node> = if self.nodes.iter().any(|n| n.id == ENTRY) {
            self.nodes.iter().filter(|n| n.id == ENTRY).collect()
        } else {
            let has_in: BTreeSet<&str> = self.edges.iter().map(|e| e.to.as_str()).collect();
            self.nodes.iter().filter(|n| !has_in.contains(n.id.as_str())).collect()
        };
        let mut out: Vec<Path> = Vec::new();
        let mut budget = 20_000usize;
        for s in starts {
            let mut trail: Vec<String> = vec![s.id.clone()];
            let mut seen: BTreeSet<String> = BTreeSet::new();
            seen.insert(s.id.clone());
            self.walk(&s.id, &mut trail, &mut seen, &mut out, &mut budget);
        }
        // Drop a path that is a prefix of another: only maximal routes are
        // worth printing, and the prefixes are already inside them.
        out.sort_by(|a, b| b.nodes.len().cmp(&a.nodes.len()));
        let mut kept: Vec<Path> = Vec::new();
        for p in out {
            if kept.iter().any(|k: &Path| k.nodes.len() >= p.nodes.len() && k.nodes.starts_with(&p.nodes)) {
                continue;
            }
            kept.push(p);
        }
        kept.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        // One weakness that yields four kinds of material is one path, not
        // four. Routes that exploit the same sequence of weaknesses collapse
        // into the highest-scoring one, so the top of the list is different
        // attacks rather than the same attack's branches.
        let mut by_weaknesses: Vec<(String, Path)> = Vec::new();
        for p in kept {
            let sig = p
                .nodes
                .iter()
                .filter_map(|id| self.node(id))
                .filter(|n| n.kind == NodeKind::ExploitedWeakness)
                .map(|n| n.id.as_str())
                .collect::<Vec<_>>()
                .join(">");
            if by_weaknesses.iter().any(|(s, _)| *s == sig) {
                continue;
            }
            by_weaknesses.push((sig, p));
        }
        // Diversity: a list whose first three entries are the same attack
        // missing one hop tells an operator nothing they did not learn from
        // the first. A path is only added when it exploits a materially
        // different set of weaknesses than everything already chosen; if that
        // leaves room, the near-duplicates fill it.
        let ranked: Vec<Path> = by_weaknesses.into_iter().map(|(_, p)| p).collect();
        let weaknesses = |p: &Path| -> BTreeSet<String> {
            p.nodes
                .iter()
                .filter_map(|id| self.node(id))
                .filter(|n| n.kind == NodeKind::ExploitedWeakness)
                .map(|n| n.id.clone())
                .collect()
        };
        let mut out: Vec<Path> = Vec::new();
        let mut chosen: Vec<BTreeSet<String>> = Vec::new();
        for p in &ranked {
            if out.len() >= top {
                break;
            }
            let w = weaknesses(p);
            let overlaps = chosen.iter().any(|c| {
                let inter = w.intersection(c).count() as f64;
                let union = w.union(c).count().max(1) as f64;
                inter / union > 0.6
            });
            if overlaps {
                continue;
            }
            chosen.push(w);
            out.push(p.clone());
        }
        for p in ranked {
            if out.len() >= top {
                break;
            }
            if !out.iter().any(|k| k.nodes == p.nodes) {
                out.push(p);
            }
        }
        out
    }

    fn walk(&self, at: &str, trail: &mut Vec<String>, seen: &mut BTreeSet<String>, out: &mut Vec<Path>, budget: &mut usize) {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let next: Vec<&Edge> = self.out_edges(at).into_iter().filter(|e| !seen.contains(&e.to)).collect();
        if next.is_empty() {
            if trail.len() > 1 {
                out.push(self.describe(trail));
            }
            return;
        }
        for e in next {
            trail.push(e.to.clone());
            seen.insert(e.to.clone());
            self.walk(&e.to, trail, seen, out, budget);
            seen.remove(&e.to);
            trail.pop();
        }
    }

    fn describe(&self, trail: &[String]) -> Path {
        let nodes: Vec<&Node> = trail.iter().filter_map(|id| self.node(id)).collect();
        let steps = nodes.iter().filter(|n| n.kind == NodeKind::ExploitedWeakness).count();
        let mut impacts: Vec<Impact> = nodes.iter().flat_map(|n| n.impacts.clone()).collect();
        impacts.sort();
        impacts.dedup();
        let mut domains: Vec<Domain> = Vec::new();
        for n in &nodes {
            if n.kind == NodeKind::ExploitedWeakness && !domains.contains(&n.domain) {
                domains.push(n.domain);
            }
        }
        let mut hosts: Vec<String> = Vec::new();
        for n in &nodes {
            if !n.host.is_empty() && !hosts.contains(&n.host) {
                hosts.push(n.host.clone());
            }
        }
        let proven = nodes.iter().filter(|n| n.kind == NodeKind::ExploitedWeakness && n.proven).count() as f64;
        let score = nodes.iter().filter(|n| n.kind == NodeKind::ExploitedWeakness).map(|n| sev_weight(&n.severity)).sum::<f64>()
            + impacts.iter().map(|i| i.weight()).sum::<f64>()
            + (domains.len().saturating_sub(1) as f64) * 3.0
            + (hosts.len().saturating_sub(1) as f64) * 2.0
            + proven;
        Path {
            nodes: trail.to_vec(),
            steps,
            score,
            impacts,
            domains,
            hosts,
            narrative: narrate(&nodes, self),
        }
    }

    /// Mermaid, laid out on the run's timeline: one column per step, node
    /// shapes and classes per kind, impacts in red at the ends.
    pub fn mermaid(&self) -> String {
        let mut s = String::from("flowchart LR\n");
        let mut by_step: BTreeMap<usize, Vec<&Node>> = BTreeMap::new();
        for n in &self.nodes {
            by_step.entry(n.step).or_default().push(n);
        }
        let t0 = self.nodes.iter().map(|n| n.at).filter(|a| *a > 0).min().unwrap_or(0);
        for (step, nodes) in &by_step {
            let label = match nodes.iter().map(|n| n.at).filter(|a| *a > 0).min() {
                Some(at) if t0 > 0 => format!("T+{}", hhmmss(at.saturating_sub(t0))),
                _ => format!("step {step}"),
            };
            s.push_str(&format!("  subgraph s{step}[\"{label}\"]\n"));
            for n in nodes {
                let text = if n.detail.is_empty() {
                    mm(&n.label)
                } else {
                    format!("{}<br/><i>{}</i>", mm(&n.label), mm(&n.detail))
                };
                let body = match n.kind {
                    NodeKind::Entry => format!("{}((\"{}\"))", n.id, text),
                    NodeKind::Impact => format!("{}[[\"{}\"]]", n.id, text),
                    NodeKind::DiscoveredCredential | NodeKind::CompromisedCredential => format!("{}[/\"{}\"/]", n.id, text),
                    NodeKind::LoadedImplant => format!("{}{{{{\"{}\"}}}}", n.id, text),
                    NodeKind::EstablishedSession => format!("{}([\"{}\"])", n.id, text),
                    NodeKind::AccessedResource => format!("{}[(\"{}\")]", n.id, text),
                    NodeKind::ExploitedWeakness => format!("{}[\"{}\"]", n.id, text),
                };
                s.push_str(&format!("    {body}\n"));
            }
            s.push_str("  end\n");
        }
        for e in &self.edges {
            match &e.via {
                Some(a) => s.push_str(&format!("  {} -->|{}| {}\n", e.from, mm(a.as_str()), e.to)),
                None => s.push_str(&format!("  {} --> {}\n", e.from, e.to)),
            }
        }
        s.push_str("  classDef weakness fill:#2a1a1a,stroke:#b33,color:#eee;\n");
        s.push_str("  classDef cred fill:#1a1f2a,stroke:#59f,color:#eee;\n");
        s.push_str("  classDef impact fill:#3a0d0d,stroke:#f55,color:#fff,font-weight:bold;\n");
        s.push_str("  classDef implant fill:#2a1a2a,stroke:#b5f,color:#eee;\n");
        for n in &self.nodes {
            let class = match n.kind {
                NodeKind::ExploitedWeakness => "weakness",
                NodeKind::DiscoveredCredential | NodeKind::CompromisedCredential => "cred",
                NodeKind::Impact => "impact",
                NodeKind::LoadedImplant => "implant",
                _ => continue,
            };
            s.push_str(&format!("  class {} {};\n", n.id, class));
        }
        s
    }

    /// The same thing for a terminal.
    pub fn ascii(&self, top: usize) -> String {
        let paths = self.paths(top);
        if paths.is_empty() {
            return "no chained attack path: every finding stands on its own\n".into();
        }
        let mut s = String::new();
        for (i, p) in paths.iter().enumerate() {
            s.push_str(&format!(
                "\nPATH {} — {} step(s), {} domain(s), {} host(s), score {:.1}\n",
                i + 1,
                p.steps,
                p.domains.len(),
                p.hosts.len().max(1),
                p.score
            ));
            if !p.impacts.is_empty() {
                s.push_str(&format!("  ends in: {}\n", p.impacts.iter().map(|i| i.as_str()).collect::<Vec<_>>().join(" · ")));
            }
            for (k, id) in p.nodes.iter().enumerate() {
                let Some(n) = self.node(id) else { continue };
                let arm = if k == 0 { "  ┌─" } else { "  ├─" };
                let tag = match n.kind {
                    NodeKind::Entry => "start",
                    NodeKind::ExploitedWeakness => "exploit",
                    NodeKind::DiscoveredCredential => "cred found",
                    NodeKind::CompromisedCredential => "cred used",
                    NodeKind::AccessedResource => "resource",
                    NodeKind::LoadedImplant => "implant",
                    NodeKind::EstablishedSession => "session",
                    NodeKind::Impact => "IMPACT",
                };
                let detail = if n.detail.is_empty() { String::new() } else { format!("  ({})", n.detail) };
                s.push_str(&format!("{arm} [{tag}] {}{detail}\n", short(&n.label, 78)));
            }
        }
        s
    }

    pub fn json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// A Markdown section for the report: the ranked paths, their narratives,
    /// and the graph.
    pub fn markdown(&self, top: usize) -> String {
        let paths = self.paths(top);
        let mut s = String::from("## Attack paths\n\n");
        if paths.is_empty() {
            s.push_str("No finding in this engagement enabled another: each one stands alone.\n\n");
            return s;
        }
        s.push_str(
            "Each path below is a sequence that was proven step by step: a weakness yields material \
             (a credential, a token, a session, a foothold), and the next step consumes it. A link is \
             drawn only when the material could actually travel that far — host-local access stays on \
             its host, directory and tenant material moves inside its realm, and credentials move \
             anywhere, because people reuse them.\n\n",
        );
        for (i, p) in paths.iter().enumerate() {
            s.push_str(&format!("### Path {} — {}\n\n", i + 1,
                if p.impacts.is_empty() { "chained impact".to_string() } else { p.impacts.iter().map(|i| i.as_str()).collect::<Vec<_>>().join(" + ") }));
            s.push_str(&format!(
                "*{} exploited weakness(es) · {} domain(s): {} · {} host(s)*\n\n",
                p.steps,
                p.domains.len(),
                p.domains.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", "),
                p.hosts.len().max(1)
            ));
            s.push_str(&p.narrative);
            s.push_str("\n\n");
            for (k, id) in p.nodes.iter().enumerate() {
                let Some(n) = self.node(id) else { continue };
                if n.kind == NodeKind::Entry {
                    continue;
                }
                let fid = if n.finding_id.is_empty() { String::new() } else { format!(" `{}`", n.finding_id) };
                s.push_str(&format!("{}. **{}** — {}{}\n", k, n.kind.as_str(), n.label, fid));
            }
            s.push('\n');
        }
        s.push_str("### Graph\n\n```mermaid\n");
        s.push_str(&self.mermaid());
        s.push_str("```\n\n");
        s
    }
}

fn hhmmss(secs: u64) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Mermaid label escaping: quotes and pipes end a label early.
fn mm(s: &str) -> String {
    s.replace('"', "'").replace('|', "/").replace('[', "(").replace(']', ")")
}

/// The path as a sentence an operator can read aloud.
fn narrate(nodes: &[&Node], g: &AttackPathGraph) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        if n.kind == NodeKind::Entry {
            continue;
        }
        let via = if i > 0 {
            g.edges
                .iter()
                .find(|e| e.from == nodes[i - 1].id && e.to == n.id)
                .and_then(|e| e.via)
                .map(|a| format!(" using {}", a.as_str()))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let where_ = if n.host.is_empty() { String::new() } else { format!(" on {}", n.host) };
        parts.push(match n.kind {
            NodeKind::ExploitedWeakness => format!("{}{}{}", short(&n.label, 70), where_, via),
            NodeKind::Impact => format!("which is {}", n.label),
            _ => format!("{}{}", n.label.to_lowercase(), where_),
        });
    }
    parts.join(" → ")
}

// ---------------------------------------------------------------------------
// Writing the result back onto the findings
// ---------------------------------------------------------------------------

/// A derived producer→consumer link between two findings, with the artifact
/// that justifies it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FindingLink {
    pub from: usize,
    pub to: usize,
    pub via: Artifact,
    /// The link leaves the host it started on, carried by portable or
    /// realm-wide material.
    pub pivot: bool,
}

/// Derive every enablement link across a finding set, across all domains.
pub fn links(findings: &[Finding]) -> Vec<FindingLink> {
    let profiles: Vec<Profile> = findings.iter().map(profile).collect();
    let locs: Vec<Loc> = findings.iter().map(loc_of).collect();
    let mut out: Vec<FindingLink> = Vec::new();
    for (j, consumer) in findings.iter().enumerate() {
        for need in &profiles[j].requires {
            for (i, producer) in findings.iter().enumerate() {
                if i == j || !profiles[i].provides.contains(need) {
                    continue;
                }
                if !carries(*need, &locs[i], &locs[j]) {
                    continue;
                }
                if cwe_num(&producer.cwe) != 0 && cwe_num(&producer.cwe) == cwe_num(&consumer.cwe) {
                    continue;
                }
                if !producer.id.is_empty() && producer.id == consumer.id {
                    continue;
                }
                if producer.observed_at > 0 && consumer.observed_at > 0 && producer.observed_at > consumer.observed_at {
                    continue;
                }
                let pivot = locs[i].host != locs[j].host;
                if out.iter().any(|l| l.from == i && l.to == j && l.via == *need) {
                    continue;
                }
                out.push(FindingLink { from: i, to: j, via: *need, pivot });
            }
        }
    }
    out
}

/// Could material produced by `src` legitimately have reached `dst`?
///
/// `chain::repair` deletes any link whose two findings sit on different hosts,
/// which is right for an application-local condition and wrong for a stolen
/// hash — this is the exception it consults before dropping one.
pub fn portable_link(src: &Finding, dst: &Finding) -> bool {
    let (ps, pd) = (profile(src), profile(dst));
    let (ls, ld) = (loc_of(src), loc_of(dst));
    pd.requires.iter().any(|need| ps.provides.contains(need) && carries(*need, &ls, &ld))
}

/// Write derived links into `chains_from`, keeping what agents asserted.
///
/// `chain::apply_links` fills the same field from the web-local rules and runs
/// first; this adds the links those rules cannot see — the ones that cross a
/// host, a protocol or an identity plane, which is where an engagement's real
/// paths live. Each finding keeps at most `MAX_SOURCES` causes so a report
/// stays readable: the nearest and most severe are kept.
pub fn apply(findings: &mut [Finding]) -> usize {
    const MAX_SOURCES: usize = 4;
    let derived = links(findings);
    let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
    let sev: Vec<f64> = findings.iter().map(|f| sev_weight(&f.severity)).collect();
    let mut written = 0usize;
    for (j, f) in findings.iter_mut().enumerate() {
        let mut candidates: Vec<(usize, f64)> = derived
            .iter()
            .filter(|l| l.to == j)
            .map(|l| (l.from, sev[l.from] + if l.pivot { 2.0 } else { 0.0 }))
            .collect();
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let mut added = false;
        for (i, _) in candidates {
            let Some(id) = ids.get(i).filter(|s| !s.is_empty()) else { continue };
            if f.chains_from.len() >= MAX_SOURCES {
                break;
            }
            if f.chains_from.iter().any(|s| s == id) || *id == f.id {
                continue;
            }
            f.chains_from.push(id.clone());
            added = true;
        }
        if added {
            written += 1;
        }
    }
    written
}

/// A one-line summary for the run log.
pub fn summary(g: &AttackPathGraph) -> String {
    let paths = g.paths(3);
    let weaknesses = g.nodes.iter().filter(|n| n.kind == NodeKind::ExploitedWeakness).count();
    let creds = g
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, NodeKind::DiscoveredCredential | NodeKind::CompromisedCredential))
        .count();
    let impacts: BTreeSet<&str> = g.nodes.iter().filter(|n| n.kind == NodeKind::Impact).map(|n| n.label.as_str()).collect();
    match paths.first() {
        Some(best) => format!(
            "{} step(s) · {} credential node(s) · {} path(s) · longest {} step(s) across {} domain(s){}",
            weaknesses,
            creds,
            paths.len(),
            best.steps,
            best.domains.len(),
            if impacts.is_empty() { String::new() } else { format!(" — {}", impacts.into_iter().collect::<Vec<_>>().join(", ")) }
        ),
        None => format!("{weaknesses} step(s), no chained path"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, agent: &str, title: &str, endpoint: &str, evidence: &str, cwe: &str, sev: &str, at: u64) -> Finding {
        Finding {
            id: id.into(),
            agent: agent.into(),
            title: title.into(),
            endpoint: endpoint.into(),
            evidence: evidence.into(),
            cwe: cwe.into(),
            severity: sev.into(),
            validated: true,
            observed_at: at,
            ..Default::default()
        }
    }

    /// The published vCenter → Entra path, step for step: one CVE on a
    /// hypervisor ends in a cloud identity tenant. Every hop is a different
    /// plane, and the point of the module is that the sequence survives those
    /// crossings.
    fn vcenter_to_entra() -> Vec<Finding> {
        vec![
            f("VC-01", "cve_known_exploitation", "CVE-2026-59310 — vCenter syslog directory traversal to RCE",
              "https://vcenter.corp.local", "unauthenticated traversal in the vCenter syslog service; wrote a payload and got a root shell, then loaded an implant",
              "CWE-22", "Critical", 1000),
            f("VC-02", "post_exploitation", "Machine-account keytab extracted from vCenter",
              "https://vcenter.corp.local", "root on the appliance; extracted the keytab for the machine account CORP\\VC01$",
              "", "High", 1100),
            f("AD-01", "ad_pth_ptt", "Machine-account hash authenticated to Active Directory",
              "ldap://dc01.corp.local", "pass-the-hash with the VC01$ machine account hash authenticated to the domain as a domain user",
              "", "High", 1200),
            f("AD-02", "ad_smb_share_hunt", "SQL administrator password found in a log file on an open share",
              "smb://fs01.corp.local/logs", "domain user could read \\\\fs01\\logs; install log contained the sa password in cleartext",
              "", "High", 1300),
            f("SQL-01", "ad_mssql_abuse", "SQL Server authentication as sysadmin with the discovered password",
              "mssql://sql01.corp.local", "authenticated to SQL Server with the recovered credential; the login holds the sysadmin role",
              "", "High", 1400),
            f("SQL-02", "post_exploitation", "xp_cmdshell used to drop a second implant",
              "mssql://sql01.corp.local", "xp_cmdshell enabled and used to write and start an implant as the SQL service account",
              "", "Critical", 1500),
            f("LPE-01", "windows_priv_esc", "SeImpersonatePrivilege abused to become SYSTEM",
              "https://sql01.corp.local", "printspoofer against the SQL service account token returned NT AUTHORITY\\SYSTEM",
              "", "High", 1600),
            f("CRED-01", "ad_dpapi_looting", "LSASS dumped; domain administrator hash recovered",
              "https://sql01.corp.local", "comsvcs LSASS dump as SYSTEM; recovered the NTLM hash of the domain admin CORP\\da-adm",
              "", "Critical", 1700),
            f("AD-03", "ad_pth_ptt", "Domain administrator hash replayed to a workstation",
              "https://ws10.corp.local", "pass-the-hash with the domain admin hash authenticated to the workstation as local administrator",
              "", "Critical", 1800),
            f("IMP-01", "post_exploitation", "Implant deployed on the workstation",
              "https://ws10.corp.local", "beacon loaded and calling back from the workstation",
              "", "High", 1900),
            f("TOK-01", "post_exploitation", "Entra access token extracted from Office process memory",
              "https://ws10.corp.local", "dumped the process memory of a signed-in Office process and extracted an access token",
              "", "Critical", 2000),
            f("ENT-01", "entra_graph_escalation", "Stolen token replayed to Microsoft Graph and escalated to Global Administrator",
              "https://graph.microsoft.com", "the stolen access token authenticated to Microsoft Graph; role assignment escalated to Global Administrator in tenant 8f1c2a44-1111-2222-3333-444455556666",
              "", "Critical", 2100),
        ]
    }

    #[test]
    fn one_cve_on_a_hypervisor_reaches_a_cloud_identity_tenant() {
        let fs = vcenter_to_entra();
        let g = build("corp.local", &fs, &[]);
        let paths = g.paths(5);
        assert!(!paths.is_empty(), "the chain produced no path at all");
        let best = &paths[0];
        assert!(best.steps >= 8, "expected the whole sequence, got {} steps: {}", best.steps, best.narrative);
        assert!(
            best.impacts.contains(&Impact::TenantCompromise),
            "the path must terminate in the tenant it reached, got {:?}",
            best.impacts
        );
        assert!(best.impacts.contains(&Impact::DomainCompromise), "{:?}", best.impacts);
        assert!(best.hosts.len() >= 4, "a path that never leaves one host is not this path: {:?}", best.hosts);
        assert!(best.domains.len() >= 3, "it crosses planes: {:?}", best.domains);
    }

    #[test]
    fn the_keytab_links_the_hypervisor_to_the_directory() {
        let fs = vcenter_to_entra();
        let ls = links(&fs);
        let has = |from: &str, to: &str| {
            ls.iter().any(|l| fs[l.from].id == from && fs[l.to].id == to)
        };
        assert!(has("VC-01", "VC-02"), "root on the host is what allows the keytab to be taken");
        assert!(has("VC-02", "AD-01"), "the machine-account hash is what authenticates to the directory");
        assert!(has("AD-01", "AD-02"), "a domain user is what reads the share");
        assert!(has("SQL-01", "SQL-02"), "sysadmin is what makes xp_cmdshell available");
        assert!(has("SQL-02", "LPE-01"), "a shell is what SeImpersonate escalates from");
        assert!(has("LPE-01", "CRED-01"), "SYSTEM is what allows the LSASS dump");
        assert!(has("CRED-01", "AD-03"), "the domain admin hash is what moves laterally");
        assert!(has("TOK-01", "ENT-01"), "the stolen token is what reaches the tenant");
    }

    #[test]
    fn a_stolen_token_crosses_from_an_internal_host_to_a_cloud_endpoint() {
        let fs = vcenter_to_entra();
        let (tok, ent) = (&fs[10], &fs[11]);
        assert_ne!(loc_of(tok).host, loc_of(ent).host);
        assert!(portable_link(tok, ent), "bearer material travels with the attacker, not with the host");
    }

    #[test]
    fn host_local_access_does_not_jump_to_an_unrelated_host() {
        let mut fs = vec![
            f("A", "windows_priv_esc", "SeImpersonate to SYSTEM", "https://a.example.com", "printspoofer returned NT AUTHORITY\\SYSTEM", "", "High", 10),
            f("B", "ad_dpapi_looting", "LSASS dump", "https://b.other-company.net", "comsvcs LSASS dump recovered hashes", "", "High", 20),
        ];
        assert!(links(&fs).is_empty(), "administrator on one host is not administrator on another");
        // Same host: the link is real.
        fs[1].endpoint = "https://a.example.com".into();
        assert!(!links(&fs).is_empty());
    }

    #[test]
    fn a_step_cannot_be_enabled_by_one_that_happened_later() {
        let mut fs = vcenter_to_entra();
        fs[0].observed_at = 9_000; // the vCenter RCE "happens" after everything
        let ls = links(&fs);
        assert!(
            !ls.iter().any(|l| fs[l.from].id == "VC-01" && fs[l.to].id == "VC-02"),
            "the clock is part of the evidence"
        );
    }

    #[test]
    fn the_classic_web_sequence_still_chains() {
        let fs = vec![
            f("enum", "account_registration_and_forms", "Account enumeration on /Account/Register", "https://app.example.com/Account/Register",
              "the response distinguishes an existing account from a new one", "CWE-204", "Medium", 10),
            f("rate", "rate_limit_abuse", "No rate limiting or lockout on /Account/Login", "https://app.example.com/Account/Login",
              "500 login attempts in 60s, none throttled", "CWE-307", "Medium", 20),
            f("pw", "weak_password", "Weak password policy — breached passwords accepted", "https://app.example.com/Account/Register",
              "registration accepted Password123", "CWE-521", "Medium", 30),
        ];
        let ls = links(&fs);
        assert!(ls.iter().any(|l| l.from == 0 && l.to == 1), "enumeration feeds the guessing");
        assert!(ls.iter().any(|l| l.from == 1 && l.to == 2), "no throttling is what makes a weak password land");
    }

    #[test]
    fn ssrf_to_instance_metadata_to_iam_is_one_path() {
        let fs = vec![
            f("SSRF", "ssrf_cloud", "SSRF in the PDF renderer reaches instance metadata", "https://app.example.com/render",
              "fetched http://169.254.169.254/latest/meta-data/iam/security-credentials/ and received a session token", "CWE-918", "High", 10),
            f("IAM", "aws_iam_privesc", "iam:PassRole plus lambda:CreateFunction escalates the role", "https://iam.amazonaws.com",
              "the instance role could pass a privileged role to a new function in account 123456789012", "", "Critical", 20),
        ];
        let g = build("app.example.com", &fs, &[]);
        let best = &g.paths(3)[0];
        assert!(best.impacts.contains(&Impact::CloudAccountCompromise), "{:?}", best.impacts);
        assert!(links(&fs).iter().any(|l| l.from == 0 && l.to == 1), "the metadata token is what the escalation consumes");
    }

    #[test]
    fn a_key_hardcoded_in_a_mobile_build_chains_into_the_cloud_account() {
        let fs = vec![
            f("APK", "hardcoded_secrets_extraction", "Service-account key hardcoded in the Android build", "",
              "strings on the APK yielded a Google service account JSON key", "", "High", 10),
            f("GCP", "gcp_iam_privesc", "Service account can impersonate a project owner", "https://iam.googleapis.com",
              "the leaked key could mint tokens for a project owner in gcp project acme-prod", "", "Critical", 20),
        ];
        let ls = links(&fs);
        assert!(ls.iter().any(|l| l.from == 0 && l.to == 1), "a key extracted from a binary is carried anywhere");
        assert_eq!(domain_of(&fs[0]), Domain::Mobile);
        assert_eq!(domain_of(&fs[1]), Domain::Cloud);
    }

    #[test]
    fn a_memory_corruption_bug_chains_into_local_privilege_escalation() {
        let fs = vec![
            f("BIN", "reverse_binary_exploit_dev", "Heap overflow in the update service yields code execution", "https://host1.internal",
              "controlled chunk metadata, ROP chain gave a shell as the service user", "CWE-122", "Critical", 10),
            f("LPE", "linux_sudo_misconfig", "sudo NOPASSWD on a writable script", "https://host1.internal",
              "the service user could run a writable script as root via sudo", "", "High", 20),
        ];
        assert_eq!(domain_of(&fs[0]), Domain::Binary);
        assert!(links(&fs).iter().any(|l| l.from == 0 && l.to == 1));
        let g = build("host1.internal", &fs, &[]);
        assert!(g.paths(3)[0].impacts.contains(&Impact::HostCompromise));
    }

    #[test]
    fn an_indirect_prompt_injection_chains_into_the_tools_the_agent_holds() {
        let fs = vec![
            f("AI-1", "prompt_injection_indirect", "Indirect prompt injection via an ingested document", "https://assistant.example.com",
              "a poisoned document in the RAG corpus changed the agent's instructions", "", "High", 10),
            f("AI-2", "llm_tool_invocation_abuse", "The agent can be made to call its shell tool", "https://assistant.example.com",
              "the injected instruction made the agent invoke its tool with attacker-chosen arguments", "", "Critical", 20),
        ];
        assert_eq!(domain_of(&fs[0]), Domain::Ai);
        assert!(links(&fs).iter().any(|l| l.from == 0 && l.to == 1));
    }

    #[test]
    fn apply_writes_the_cross_domain_causes_onto_the_findings() {
        let mut fs = vcenter_to_entra();
        let written = apply(&mut fs);
        assert!(written >= 6, "most steps have a cause, wrote {written}");
        let ent = fs.iter().find(|f| f.id == "ENT-01").unwrap();
        assert!(ent.chains_from.contains(&"TOK-01".to_string()), "{:?}", ent.chains_from);
        assert!(ent.chains_from.len() <= 4, "a report stays readable");
    }

    #[test]
    fn asserted_chains_are_kept() {
        let mut fs = vcenter_to_entra();
        fs[2].chains_from = vec!["asserted-by-an-agent".into()];
        apply(&mut fs);
        assert!(fs[2].chains_from.contains(&"asserted-by-an-agent".to_string()));
    }

    #[test]
    fn the_graph_renders_with_a_timeline_and_impact_terminals() {
        let g = build("corp.local", &vcenter_to_entra(), &["cred:svc_sql:Summer2026!@sql01".into()]);
        let m = g.mermaid();
        assert!(m.starts_with("flowchart LR"));
        assert!(m.contains("T+00:"), "the timeline is drawn from the run's own clock:\n{m}");
        assert!(m.contains("IDENTITY TENANT COMPROMISE"));
        let a = g.ascii(2);
        assert!(a.contains("PATH 1"));
        assert!(a.contains("[IMPACT]"));
        assert!(g.nodes.iter().any(|n| n.kind == NodeKind::LoadedImplant), "an implant is a node, not a sentence");
        assert!(g.nodes.iter().any(|n| n.detail.contains("svc_sql")), "loot carried forward becomes a node");
        let md = g.markdown(2);
        assert!(md.contains("## Attack paths") && md.contains("```mermaid"));
    }

    #[test]
    fn an_engagement_with_nothing_connected_says_so() {
        let fs = vec![f("x", "security_headers", "Missing HSTS", "https://a.example.com", "no Strict-Transport-Security", "CWE-319", "Low", 10)];
        let g = build("a.example.com", &fs, &[]);
        assert!(g.paths(3).iter().all(|p| p.steps <= 1));
        assert!(g.markdown(3).contains("Attack paths"));
    }

    #[test]
    fn realms_spelled_differently_are_still_one_realm() {
        let netbios = Loc { host: "vcenter.corp.local".into(), realm: "ad:corp".into() };
        let dns = Loc { host: "dc01.corp.local".into(), realm: "corp.local".into() };
        assert!(carries(Artifact::DomainUser, &netbios, &dns));
        let other = Loc { host: "x.contoso.com".into(), realm: "contoso.com".into() };
        assert!(!carries(Artifact::DomainUser, &netbios, &other));
    }
}
