//! Credential loading for authenticated testing (`creds.yaml`).
//!
//! Dependency-free parser for a small YAML subset: flat `key: value` pairs plus
//! one nested `login:` block (2-space indent). Lets the operator hand the
//! harness a JWT / header / cookie, or a login flow the agents should perform so
//! they test the target as an authenticated user.
//!
//! Example `creds.yaml`:
//! ```yaml
//! jwt: eyJhbGciOi...                 # → Authorization: Bearer <jwt>
//! # header: "X-Api-Key: abc123"      # raw header (alternative)
//! # cookie: "session=deadbeef"       # → Cookie: session=deadbeef
//! login:
//!   url: http://app/login
//!   method: POST
//!   username_field: uid
//!   password_field: passw
//!   username: admin
//!   password: admin
//!   success: Logout
//! ```
//!
//! Multi-identity block for the authorization matrix (each identity is a named
//! block; `tier` is `high|readonly|tenant|none`, and an explicit `none` keeps a
//! credential-less anonymous context the matrix needs):
//! ```yaml
//! admin:
//!   header: "Authorization: Bearer AAA"
//!   tier: high
//! readonly:
//!   header: "Authorization: Bearer BBB"
//!   tier: readonly
//! tenantB:
//!   cookie: "session=ccc"
//!   known_id: "6531bb"            # a real object this identity owns (BOLA baseline)
//! anonymous:
//!   tier: none
//! sample_values:                   # valid domain values to pass format gates
//!   nfe_key: "3520...0017"
//!   cnpj: "11222333000181"
//!   known_ids: "6531aa, 6531bb"
//! ```

#[derive(Default, Debug, Clone)]
pub struct Login {
    pub url: String,
    pub method: String,
    pub username_field: String,
    pub password_field: String,
    pub username: String,
    pub password: String,
    pub success: String,
}

/// SSH credentials for Linux host testing.
#[derive(Default, Debug, Clone)]
pub struct Ssh {
    pub host: String,
    pub port: String,   // default 22
    pub user: String,
    pub password: String,
    pub key: String,    // path to a private key
}

/// Windows / Active Directory credentials.
#[derive(Default, Debug, Clone)]
pub struct Win {
    pub host: String,
    pub user: String,
    pub password: String,
    pub domain: String,
    pub hash: String,   // NTLM hash for pass-the-hash (LM:NT or NT)
}

/// Cloud provider credentials for cloud-infra testing (AWS / GCP / Azure).
/// Secrets are read from `creds.yaml` and exported to the process environment so
/// the `aws` / `gcloud` / `az` CLIs the agents use pick them up automatically.
#[derive(Default, Debug, Clone)]
pub struct Cloud {
    // AWS — static keys (access key + secret [+ session token]) OR a named profile.
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_session_token: String,
    pub aws_region: String,
    pub aws_profile: String,
    // GCP — a service-account JSON (path, recommended) or inline single-line JSON.
    pub gcp_sa_json: String,
    pub gcp_project: String,
    // Azure — a service principal (recommended for non-interactive automation).
    pub azure_tenant_id: String,
    pub azure_client_id: String,
    pub azure_client_secret: String,
    pub azure_subscription_id: String,
}

impl Cloud {
    fn is_empty(&self) -> bool {
        self.aws_access_key_id.is_empty() && self.aws_profile.is_empty()
            && self.gcp_sa_json.is_empty()
            && self.azure_client_id.is_empty()
    }
}

/// A named identity/role for multi-user access-control testing (IDOR / BOLA /
/// BFLA / privilege escalation). Each carries ONE way to authenticate.
#[derive(Default, Debug, Clone)]
pub struct Identity {
    pub name: String,             // e.g. "admin", "user", "victim"
    pub jwt: String,              // → Authorization: Bearer <jwt>
    pub header: String,           // raw header, e.g. "X-Api-Key: abc"
    pub cookie: String,           // → Cookie: <cookie>
    pub apikey: String,           // → X-Api-Key: <apikey> (unless it contains ':')
    pub login_url: String,        // login endpoint (agent authenticates itself)
    pub username: String,
    pub password: String,
    /// Privilege tier for the authorization matrix: "high"|"readonly"|"tenant"|
    /// "none"/"anonymous". Empty → derived from the name.
    pub tier: String,
    /// A real object id this identity legitimately owns (for BOLA baselines).
    pub known_id: String,
}

/// Privilege tier an identity holds, for deriving the access-control prior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    High,
    ReadOnly,
    Tenant,
    None,
}

/// Valid domain values the matrix engine uses to get a request past input/format
/// validation so it actually reaches the authorization check and the handler.
#[derive(Default, Debug, Clone)]
pub struct SampleValues {
    pub nfe_key: String,
    pub cnpj: String,
    /// Comma-separated real ids, per the friendly YAML (`known_ids: a,b,c`).
    pub known_ids: Vec<String>,
}

impl Identity {
    /// The ready-to-send auth header for this identity, if it has direct material.
    pub fn header_line(&self) -> Option<String> {
        if !self.header.is_empty() { return Some(self.header.clone()); }
        if !self.jwt.is_empty() { return Some(format!("Authorization: Bearer {}", self.jwt)); }
        if !self.apikey.is_empty() {
            return Some(if self.apikey.contains(':') { self.apikey.clone() } else { format!("X-Api-Key: {}", self.apikey) });
        }
        if !self.cookie.is_empty() { return Some(format!("Cookie: {}", self.cookie)); }
        None
    }
    fn describe(&self) -> String {
        if let Some(h) = self.header_line() { format!("{} → send `{}`", self.name, h) }
        else if !self.login_url.is_empty() { format!("{} → log in at {} as {}:{} and reuse the session", self.name, self.login_url, self.username, self.password) }
        else { format!("{} → (no usable credential)", self.name) }
    }

    /// Explicitly declared as the no-credential anonymous context (so a
    /// credential-less block is kept only when it is meant to be anonymous,
    /// never a typo'd empty one).
    pub fn is_explicit_anonymous(&self) -> bool {
        let t = self.tier.to_lowercase();
        t == "none" || t == "anonymous" || t == "anon" || self.name.to_lowercase().contains("anon")
    }

    /// Resolve the privilege tier from the explicit `tier` or, failing that,
    /// the name. A credential-less, tier-less block is treated as anonymous.
    pub fn tier_kind(&self) -> Tier {
        let t = self.tier.to_lowercase();
        let hay = format!("{t} {}", self.name.to_lowercase());
        match t.as_str() {
            "high" | "admin" | "superuser" | "super" => return Tier::High,
            "readonly" | "read-only" | "read only" | "ro" | "viewer" => return Tier::ReadOnly,
            "tenant" | "user" | "customer" => return Tier::Tenant,
            "none" | "anonymous" | "anon" => return Tier::None,
            _ => {}
        }
        if self.header_line().is_none() && self.login_url.is_empty() {
            return Tier::None; // no credential, no tier → anonymous
        }
        if hay.contains("admin") || hay.contains("super") || hay.contains("root") {
            Tier::High
        } else if hay.contains("readonly") || hay.contains("read-only") || hay.contains("read only") || hay.contains("viewer") {
            Tier::ReadOnly
        } else if hay.contains("anon") {
            Tier::None
        } else {
            Tier::Tenant
        }
    }

    /// The access-control prior: what SHOULD happen for this identity on a
    /// route. `write` = the route changes state (POST/PUT/PATCH/DELETE or a
    /// decision verb). The matrix flags any observed Allow where Deny was
    /// expected. Cross-tenant object access is left to the BOLA validator.
    pub fn expected(&self, write: bool) -> crate::validation::Expect {
        use crate::validation::Expect;
        match self.tier_kind() {
            Tier::High => Expect::Allow,
            Tier::None => Expect::Deny,
            Tier::ReadOnly => if write { Expect::Deny } else { Expect::Allow },
            Tier::Tenant => if write { Expect::Deny } else { Expect::Allow },
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Creds {
    pub jwt: Option<String>,
    pub header: Option<String>,
    pub cookie: Option<String>,
    pub login: Option<Login>,
    pub ssh: Option<Ssh>,
    pub win: Option<Win>,
    pub cloud: Option<Cloud>,
    /// Named identities for multi-role access-control testing.
    pub roles: Vec<Identity>,
    /// Valid domain values for the authorization matrix engine.
    pub samples: SampleValues,
}

impl Creds {
    pub fn load(path: &std::path::Path) -> Option<Creds> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut c = Creds::default();
        let mut login = Login { method: "POST".into(), ..Default::default() };
        let mut ssh = Ssh { port: "22".into(), ..Default::default() };
        let mut win = Win::default();
        let mut cloud = Cloud::default();
        let mut samples = SampleValues::default();
        let (mut have_login, mut have_ssh, mut have_win) = (false, false, false);
        let mut roles: Vec<Identity> = Vec::new();
        let mut cur_role = 0usize;
        let mut block = ""; // "", "login", "ssh", "windows", "aws", "gcp", "azure", "role"
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("");
            if line.trim().is_empty() {
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let (k, v) = match line.split_once(':') {
                Some((k, v)) => (k.trim().to_string(), unquote(v.trim())),
                None => continue,
            };
            // Enter a nested block (header line with empty value).
            if v.is_empty() && !indented {
                block = match k.as_str() {
                    "login" => { have_login = true; "login" }
                    "ssh" => { have_ssh = true; "ssh" }
                    "windows" | "win" | "ad" => { have_win = true; "windows" }
                    "aws" => "aws",
                    "gcp" | "google" | "gcloud" => "gcp",
                    "azure" | "az" => "azure",
                    "roles" | "identities" | "users" => "", // optional wrapper — ignore
                    "sample_values" | "samples" | "fixtures" => "samples",
                    // Any other named block is a role/identity for access-control testing.
                    other => { roles.push(Identity { name: other.to_string(), ..Default::default() }); cur_role = roles.len() - 1; "role" }
                };
                continue;
            }
            if indented {
                match block {
                    "login" => match k.as_str() {
                        "url" => login.url = v,
                        "method" => login.method = v.to_uppercase(),
                        "username_field" => login.username_field = v,
                        "password_field" => login.password_field = v,
                        "username" | "user" => login.username = v,
                        "password" | "pass" => login.password = v,
                        "success" => login.success = v,
                        _ => {}
                    },
                    "ssh" => match k.as_str() {
                        "host" | "ip" => ssh.host = v,
                        "port" => ssh.port = v,
                        "user" | "username" => ssh.user = v,
                        "password" | "pass" => ssh.password = v,
                        "key" | "keyfile" | "identity" => ssh.key = v,
                        _ => {}
                    },
                    "windows" => match k.as_str() {
                        "host" | "ip" => win.host = v,
                        "user" | "username" => win.user = v,
                        "password" | "pass" => win.password = v,
                        "domain" => win.domain = v,
                        "hash" | "ntlm" => win.hash = v,
                        _ => {}
                    },
                    "aws" => match k.as_str() {
                        "access_key_id" | "access_key" | "key" => cloud.aws_access_key_id = v,
                        "secret_access_key" | "secret" => cloud.aws_secret_access_key = v,
                        "session_token" | "token" => cloud.aws_session_token = v,
                        "region" => cloud.aws_region = v,
                        "profile" => cloud.aws_profile = v,
                        _ => {}
                    },
                    "gcp" => match k.as_str() {
                        "service_account_json" | "sa_json" | "key" | "keyfile" | "credentials" => cloud.gcp_sa_json = v,
                        "project" | "project_id" => cloud.gcp_project = v,
                        _ => {}
                    },
                    "azure" => match k.as_str() {
                        "tenant_id" | "tenant" => cloud.azure_tenant_id = v,
                        "client_id" | "app_id" => cloud.azure_client_id = v,
                        "client_secret" | "secret" | "password" => cloud.azure_client_secret = v,
                        "subscription_id" | "subscription" => cloud.azure_subscription_id = v,
                        _ => {}
                    },
                    "role" => if let Some(r) = roles.get_mut(cur_role) {
                        match k.as_str() {
                            "jwt" | "token" => r.jwt = v,
                            "header" => r.header = v,
                            "cookie" => r.cookie = v,
                            "apikey" | "api_key" | "key" => r.apikey = v,
                            "login" | "url" | "login_url" => r.login_url = v,
                            "username" | "user" => r.username = v,
                            "password" | "pass" => r.password = v,
                            "tier" | "level" | "privilege" => r.tier = v,
                            "known_id" | "id" => r.known_id = v,
                            _ => {}
                        }
                    },
                    "samples" => match k.as_str() {
                        "nfe_key" | "nfekey" | "access_key" | "chave" => samples.nfe_key = v,
                        "cnpj" => samples.cnpj = v,
                        "known_ids" | "ids" => {
                            samples.known_ids = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                        }
                        _ => {}
                    },
                    _ => {}
                }
                continue;
            }
            block = "";
            match k.as_str() {
                "jwt" | "token" => c.jwt = Some(v),
                "header" => c.header = Some(v),
                "cookie" => c.cookie = Some(v),
                _ => {}
            }
        }
        if have_login && !login.url.is_empty() { c.login = Some(login); }
        if have_ssh && !ssh.host.is_empty() { c.ssh = Some(ssh); }
        if have_win && !win.host.is_empty() { c.win = Some(win); }
        if !cloud.is_empty() { c.cloud = Some(cloud); }
        // Keep an identity with real credentials, a self-login, or one that is
        // EXPLICITLY the anonymous context (the matrix needs anonymous), but
        // drop a typo'd empty block.
        roles.retain(|r| r.header_line().is_some() || !r.login_url.is_empty() || r.is_explicit_anonymous());
        c.roles = roles;
        c.samples = samples;
        if c.jwt.is_none() && c.header.is_none() && c.cookie.is_none()
            && c.login.is_none() && c.ssh.is_none() && c.win.is_none() && c.cloud.is_none()
            && c.roles.is_empty() {
            return None;
        }
        Some(c)
    }

    /// True when the authorization matrix can run: at least two identities
    /// spanning at least two distinct privilege tiers (so there is a
    /// should-be-denied context to differentiate against a privileged one).
    pub fn authz_matrix_ready(&self) -> bool {
        let tiers: std::collections::HashSet<Tier> = self.roles.iter().map(|r| r.tier_kind()).collect();
        self.roles.len() >= 2 && tiers.len() >= 2
    }

    /// The highest-privilege identity, used as the matrix's privileged baseline.
    pub fn highest_identity(&self) -> Option<&Identity> {
        self.roles.iter().find(|r| r.tier_kind() == Tier::High)
            .or_else(|| self.roles.iter().max_by_key(|r| match r.tier_kind() {
                Tier::High => 3, Tier::Tenant => 2, Tier::ReadOnly => 1, Tier::None => 0,
            }))
    }

    /// Multi-role access-control testing directive: lists every identity and
    /// instructs the agent to test cross-role access (IDOR/BOLA, BFLA, privesc)
    /// by acting as each role against the others' objects and functions.
    pub fn roles_instruction(&self) -> Option<String> {
        if self.roles.len() < 2 { return None; }
        let list = self.roles.iter().map(|r| format!("  - {}", r.describe())).collect::<Vec<_>>().join("\n");
        Some(format!(
            "MULTI-ROLE ACCESS CONTROL — you have {} identities:\n{list}\n\
             Authenticate as EACH identity (use its header on every request, or log in first for a login: role and \
             reuse the session). Then test broken access control across roles:\n\
             - BOLA/IDOR: as a low-privilege role, capture your own object IDs, then try to READ/UPDATE another \
               role's objects by their IDs; a low-priv role reaching a high-priv/other-user object is a finding.\n\
             - BFLA: call admin-only functions/endpoints/HTTP methods with a low-privilege role's session.\n\
             - Privilege escalation: mass-assignment of role/permission fields, or reaching admin routes.\n\
             Always compare against the control (the authorized role should succeed; the unauthorized role should be \
             denied). Prove each with the two requests (authorized vs unauthorized) and their responses. Respect data \
             safety — read-only proof, mask any PII.\n",
            self.roles.len()))
    }

    /// Environment variables to export so the `aws`/`gcloud`/`az` CLIs the agents
    /// run pick up the cloud credentials automatically. For inline GCP JSON the
    /// content is written to a temp file and that path is returned.
    pub fn cloud_env(&self) -> Vec<(String, String)> {
        let mut e: Vec<(String, String)> = Vec::new();
        let Some(c) = &self.cloud else { return e };
        // AWS
        if !c.aws_access_key_id.is_empty() {
            e.push(("AWS_ACCESS_KEY_ID".into(), c.aws_access_key_id.clone()));
            e.push(("AWS_SECRET_ACCESS_KEY".into(), c.aws_secret_access_key.clone()));
            if !c.aws_session_token.is_empty() {
                e.push(("AWS_SESSION_TOKEN".into(), c.aws_session_token.clone()));
            }
        }
        if !c.aws_profile.is_empty() { e.push(("AWS_PROFILE".into(), c.aws_profile.clone())); }
        if !c.aws_region.is_empty() {
            e.push(("AWS_DEFAULT_REGION".into(), c.aws_region.clone()));
            e.push(("AWS_REGION".into(), c.aws_region.clone()));
        }
        // GCP — path (recommended) or inline JSON written to a temp file.
        if !c.gcp_sa_json.is_empty() {
            let path = if c.gcp_sa_json.trim_start().starts_with('{') {
                let p = std::env::temp_dir().join("neurosploit-gcp-sa.json");
                let _ = std::fs::write(&p, c.gcp_sa_json.as_bytes());
                p.display().to_string()
            } else {
                c.gcp_sa_json.clone()
            };
            e.push(("GOOGLE_APPLICATION_CREDENTIALS".into(), path));
        }
        if !c.gcp_project.is_empty() {
            e.push(("GOOGLE_CLOUD_PROJECT".into(), c.gcp_project.clone()));
            e.push(("CLOUDSDK_CORE_PROJECT".into(), c.gcp_project.clone()));
        }
        // Azure — service principal env (consumed by `az login --service-principal`).
        if !c.azure_tenant_id.is_empty() { e.push(("AZURE_TENANT_ID".into(), c.azure_tenant_id.clone())); }
        if !c.azure_client_id.is_empty() { e.push(("AZURE_CLIENT_ID".into(), c.azure_client_id.clone())); }
        if !c.azure_client_secret.is_empty() { e.push(("AZURE_CLIENT_SECRET".into(), c.azure_client_secret.clone())); }
        if !c.azure_subscription_id.is_empty() {
            e.push(("AZURE_SUBSCRIPTION_ID".into(), c.azure_subscription_id.clone()));
            e.push(("ARM_SUBSCRIPTION_ID".into(), c.azure_subscription_id.clone()));
        }
        e
    }

    /// A directive telling the agents which cloud creds are available and how to
    /// authenticate the provider CLI, so they enumerate/test the cloud account.
    pub fn cloud_instruction(&self) -> Option<String> {
        let c = self.cloud.as_ref()?;
        let mut s = String::new();
        if !c.aws_access_key_id.is_empty() || !c.aws_profile.is_empty() {
            s.push_str(&format!(
                "AWS ACCESS: credentials are set in the environment{}. Use the `aws` CLI to enumerate and test the account — start with `aws sts get-caller-identity`, then IAM (users/roles/policies, privilege escalation paths), S3 (public/misconfigured buckets), EC2/SG, Lambda, Secrets Manager. Read-only enumeration first; never destructive.\n",
                if c.aws_region.is_empty() { String::new() } else { format!(" (region {})", c.aws_region) }));
        }
        if !c.gcp_sa_json.is_empty() {
            s.push_str(&format!(
                "GCP ACCESS: a service account is available via $GOOGLE_APPLICATION_CREDENTIALS{}. Run `gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS` first, then enumerate with `gcloud`/`gsutil` — IAM bindings & privilege escalation, buckets, compute, service accounts/keys, Cloud Functions.\n",
                if c.gcp_project.is_empty() { String::new() } else { format!(" (project {})", c.gcp_project) }));
        }
        if !c.azure_client_id.is_empty() {
            s.push_str(
                "AZURE ACCESS: a service principal is set in the environment. Authenticate with `az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID`, then enumerate with `az` — role assignments (RBAC) & escalation, storage accounts/containers, VMs, Key Vaults, managed identities.\n");
        }
        if s.is_empty() { None } else { Some(s) }
    }

    /// A directive describing the host credentials available to the agents, so
    /// they can authenticate to Linux (SSH) / Windows (AD) hosts.
    pub fn host_instruction(&self) -> Option<String> {
        let mut s = String::new();
        if let Some(h) = &self.ssh {
            let auth = if !h.key.is_empty() { format!("private key {}", h.key) } else { "password (provided)".into() };
            s.push_str(&format!(
                "SSH ACCESS (Linux): host {}:{} as user '{}' via {}. Use `ssh`/`sshpass` to run \
                 enumeration and privilege-escalation checks on the host.\n",
                h.host, h.port, h.user, auth));
        }
        if let Some(w) = &self.win {
            let auth = if !w.hash.is_empty() { "NTLM hash (pass-the-hash)".to_string() } else { "password".into() };
            s.push_str(&format!(
                "WINDOWS/AD ACCESS: host {} domain '{}' as user '{}' via {}. Use tools like \
                 crackmapexec/netexec, impacket, evil-winrm, bloodhound-python for host and AD checks.\n",
                w.host, if w.domain.is_empty() { "(workgroup)" } else { &w.domain }, w.user, auth));
        }
        if s.is_empty() { None } else { Some(s) }
    }

    /// The auth material to send with each request, as a header line.
    pub fn auth_header(&self) -> Option<String> {
        if let Some(h) = &self.header {
            return Some(h.clone());
        }
        if let Some(j) = &self.jwt {
            return Some(format!("Authorization: Bearer {j}"));
        }
        if let Some(ck) = &self.cookie {
            return Some(format!("Cookie: {ck}"));
        }
        None
    }

    /// A directive instructing the agent to authenticate first via curl.
    pub fn login_instruction(&self) -> Option<String> {
        let l = self.login.as_ref()?;
        Some(format!(
            "AUTHENTICATE FIRST: {} {} with {}={} and {}={}; capture the session cookie/token \
             from the response (success indicator: \"{}\") and reuse it on every subsequent request.",
            l.method, l.url, l.username_field, l.username, l.password_field, l.password, l.success
        ))
    }
}

/// Perform the login flow now (real HTTP POST) and return an auth header to
/// reuse on every subsequent request: a `Cookie:` from Set-Cookie, or an
/// `Authorization: Bearer` from a token in the JSON response. Returns
/// (auth_header, note). Redirects are not followed so the login response's
/// Set-Cookie is visible.
pub async fn login(l: &Login) -> anyhow::Result<(String, String)> {
    use reqwest::header::SET_COOKIE;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let form: Vec<(String, String)> = vec![
        (l.username_field.clone(), l.username.clone()),
        (l.password_field.clone(), l.password.clone()),
    ];
    let req = if l.method == "GET" {
        client.get(&l.url).query(&form)
    } else {
        client.post(&l.url).form(&form)
    };
    let resp = req.send().await?;
    let status = resp.status();

    // 1) session cookies from Set-Cookie on the login response
    let mut cookie_pairs = Vec::new();
    for hv in resp.headers().get_all(SET_COOKIE) {
        if let Ok(s) = hv.to_str() {
            if let Some(pair) = s.split(';').next() {
                let p = pair.trim();
                if !p.is_empty() {
                    cookie_pairs.push(p.to_string());
                }
            }
        }
    }
    let body = resp.text().await.unwrap_or_default();

    // 2) bearer token from a JSON response body
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        for k in ["access_token", "token", "jwt", "id_token", "accessToken"] {
            if let Some(t) = v.get(k).and_then(|x| x.as_str()).filter(|t| !t.is_empty()) {
                return Ok((format!("Authorization: Bearer {t}"), format!("bearer token from JSON `{k}` (HTTP {status})")));
            }
        }
    }
    if !cookie_pairs.is_empty() {
        let cookie = cookie_pairs.join("; ");
        // Soft success check (don't fail hard — many apps 302 on success).
        let ok = l.success.is_empty() || body.contains(&l.success) || status.is_redirection() || status.is_success();
        let note = format!("session cookie captured (HTTP {status}{})", if ok { "" } else { ", success marker not seen" });
        return Ok((format!("Cookie: {cookie}"), note));
    }
    anyhow::bail!("login returned no Set-Cookie or token (HTTP {status})")
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ns_creds_{}_{}.yaml", name, std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn parses_identities_tiers_and_samples() {
        let yaml = r#"
admin:
  header: "Authorization: Bearer AAA"
  tier: high
readonly:
  header: "Authorization: Bearer BBB"
  tier: readonly
tenantB:
  cookie: "session=ccc"
  known_id: "6531bb"
anonymous:
  tier: none
sample_values:
  nfe_key: "35200114200166000187550010000000071000000017"
  cnpj: "11222333000181"
  known_ids: "6531aa, 6531bb, 6531cc"
"#;
        let p = write_tmp("matrix", yaml);
        let c = Creds::load(&p).expect("should parse");
        std::fs::remove_file(&p).ok();

        // Anonymous (credential-less) is KEPT because it is explicit.
        assert_eq!(c.roles.len(), 4, "roles: {:?}", c.roles.iter().map(|r| &r.name).collect::<Vec<_>>());

        let tier = |name: &str| c.roles.iter().find(|r| r.name == name).unwrap().tier_kind();
        assert_eq!(tier("admin"), Tier::High);
        assert_eq!(tier("readonly"), Tier::ReadOnly);
        assert_eq!(tier("tenantB"), Tier::Tenant);
        assert_eq!(tier("anonymous"), Tier::None);

        // Samples parsed.
        assert_eq!(c.samples.cnpj, "11222333000181");
        assert_eq!(c.samples.known_ids.len(), 3);
        assert!(!c.samples.nfe_key.is_empty());

        assert!(c.authz_matrix_ready());
        assert_eq!(c.highest_identity().unwrap().name, "admin");
    }

    #[test]
    fn expected_prior_matches_policy() {
        use crate::validation::Expect;
        let admin = Identity { name: "admin".into(), header: "Authorization: Bearer x".into(), tier: "high".into(), ..Default::default() };
        let ro = Identity { name: "ro".into(), header: "Authorization: Bearer x".into(), tier: "readonly".into(), ..Default::default() };
        let anon = Identity { name: "anon".into(), tier: "none".into(), ..Default::default() };

        // Admin allowed everywhere.
        assert_eq!(admin.expected(true), Expect::Allow);
        assert_eq!(admin.expected(false), Expect::Allow);
        // Read-only may read, must not write.
        assert_eq!(ro.expected(false), Expect::Allow);
        assert_eq!(ro.expected(true), Expect::Deny);
        // Anonymous denied on any protected route.
        assert_eq!(anon.expected(false), Expect::Deny);
        assert_eq!(anon.expected(true), Expect::Deny);
    }

    #[test]
    fn typoed_empty_block_is_dropped_but_not_anonymous() {
        // A credential-less block with no tier and a non-anon name is a typo,
        // not an identity — it must be dropped.
        let yaml = "ghost:\n  note: nothing\nadmin:\n  header: \"Authorization: Bearer A\"\n  tier: high\n";
        let p = write_tmp("typo", yaml);
        let c = Creds::load(&p).expect("should parse");
        std::fs::remove_file(&p).ok();
        assert_eq!(c.roles.len(), 1);
        assert_eq!(c.roles[0].name, "admin");
        assert!(!c.authz_matrix_ready(), "one identity, one tier → not ready");
    }
}
