# NeuroSploit — Staged Upgrades (APPLY ONLY AFTER CURRENT RUN CLOSES)

## PROGRESS (2026-11-21)
- Run 1 `ns-1795270602` CLOSED at round 4/6, ~$36 — Forest01 owned (APP-DMZ01 local admin, SQL01 RCE/SeImpersonate, S4U Administrator→FS01, AS-REP/kerberoast, constrained delegation) + DMZ root. **VANGUARD NOT reached** — DCSync blocked by double-forward tunnel mangling DRSUAPI. Neo4j 1214 nodes. 44 findings.
- Run 2 (relaunch) `ns-1795288108` RUNNING — opus-4-8, seeded creds (svc_deploy+svc_web via /scratchpad/creds.yaml), proxychains installed, focus = DCSync native-from-APP-DMZ01 OR single proxychains SOCKS (NOT double-forward), chain-depth 8. Log: scratchpad/engage2.log. Monitor: bbne0n7bc.
- Branch `feat/validator-chain-graph-stealth-multimodel`, commit `5a3fe4a`, **PR #69** (origin). cargo check 0 errors.
- DONE (#1 chain-expands-needs-review via graph_memory, #2 validator optional + loot-never-rejected, #6 --stealth, #7 --planner-model). Backend only; **NOT yet built into the running binary** — build + merge AFTER run 2 closes.
- REMAINING: #3 graph UI extra filters, #4 goal-path-to-objective graph highlight, #5 neo4j consumed by planner (BloodHound shortestPath). Largely partial already (graph_checkpoint feeds next-moves from the graph; Chains tab shows ordered steps+vulns). Best iterated with the user's visual review.
- Disk reclaimed to 11Gi (docker build cache + brew). ~40GB stopped containers + 49GB images still reclaimable with user OK.

---


**Status:** staged. Do NOT rebuild/restart the engine while the live run is active.
**Live run:** `ns-1795270602-10_0_0_4` · model `claude-opus-4-8 --subscription` · scope `10.0.0.0/8` · neo4j · c2 lateral+persist · chain-depth 6 · log: `/private/tmp/claude-0/-opt-neurosploit-rs/863aed78-9c0f-4bc7-95a7-b9b99c021b04/scratchpad/engage.log`
**Goal (Stop hook):** reach DC01-VANGUARD (10.0.3.4), compromise all DCs, 100% via neurosploit.

## Lab topology (from user image)
- VPN 10.0.4.0/24 — entry 10.0.4.4
- DMZ 10.0.0.0/24: WEB-PUBLIC01 10.0.0.4 (Ubuntu, ROOTED), APP-DMZ01 10.0.0.5 (Win2016 domain-joined, LOCAL ADMIN owned)
- Forest01 10.0.1.0/24: FS01-AUREON .1.4, SQL01-AUREON .1.5, **DC01-AUREON .1.6**
- Forest02 10.0.2.0/24: **DC01-HELIX 10.0.2.4**
- Forest Root 10.0.3.0/24: **DC01-VANGUARD 10.0.3.4** (final objective)
- domains: aureon.local (Forest01), + helix, vanguard.local (forest root)

## Loot so far (run ns-1795270602)
- `svc_web:W3bS3rvic3!` = LOCAL ADMIN APP-DMZ01 (nxc Pwn3d!)
- `svc_deploy:D3pl0y#Svc!` (SSH 10.0.0.4) / `aureon\svc_deploy:D3pl0ySvc#2024` (WinRM)
- `jmartinez_id_rsa` (looted key, used for pivot)
- APP-DMZ01$ machine account NTLM + AES keys; local Administrator NTLM; SAM (svc_iis/backup_admin/dev_deploy)
- DAs aureon: adm.roberts, adm.chen, adm.martinez, Administrator
- **d.kim@vanguard.local = forest-root Domain Admin (target identity)**
- Kerberoastable SPNs: svc_sql, svc_backup, svc_sccm, svc_monitor
- .env secrets: MSSQL sa, INTERNAL_API, mail creds
- Pivot: chisel reverse SOCKS 127.0.0.1:1080 + reverse port-forwards to DC ports. APP-DMZ01 reaches DC01-AUREON/FS01/SQL01.

## Environment fixes already applied (support, not attack)
- VPN: `openvpn --config /Users/joas/Downloads/cadp_laboratory.ovpn` (bg). Endpoint host DNS broken via getaddrinfo (mDNSResponder); fixed with `/etc/hosts`: `3.220.78.132 6c0292d5621b.network.coursestack.com`.
- `proxychains-ng` installed for user joas: `sudo -u joas -H env HOME=/Users/joas brew install proxychains-ng`.

---

# STAGED CHANGES (implement, then build + push)

## 1. Chain must expand NON-CONFIRMED footholds (needs-review), not only Confirmed
- File: `crates/harness/src/pipeline.rs`
- `attack_chain()` def @2959, called @2505/2788/5875/6708 with `&findings` (already ALL findings — confirmed+needs-review+rejected, see "Keep ALL" @3699). Param named `confirmed` is misleading.
- VERIFY + FIX: the frontier (@2983 `frontier=confirmed.to_vec()`) and the `ready`/`prio` from `graph_checkpoint()` (@2977) — ensure graph_checkpoint and seed selection do NOT silently drop non-Confirmed status nodes. If `graph_checkpoint`/graph only treats `gm::Status::Confirmed` as a valid foothold (@2943 filters Confirmed), make needs-review-with-receipt also seed chains.
- Rule: a foothold with a concrete receipt (looted cred/key, command output) seeds chain expansion regardless of vote quorum.

## 2. Validator optional + receipt-bearing never `rejected`; useful key/secret keeps value
- File: `crates/harness/src/pipeline.rs` verdict logic @3636-3708; `main.rs` host flags.
- Add `--no-validate` host flag → skip vote, all findings status `unvalidated`, keep agent severity. Wire into RunConfig.
- In validate(): a finding with `grounded_receipt(&f) || has_http_receipt(&f)` OR a looted credential/key/secret that was REUSED (proven downstream) must become at worst `needs-review`, NEVER `rejected`. Secret/key disclosure + proven reuse = `confirmed` Critical/High.
- Do NOT delete anything (already "Keep ALL" @3699 — good). Fix the CAPPING (@3670-3681) so proven-reused secrets aren't severity-capped to Low.
- VOTE_SYS/REFUTE_SYS @1259/1263: add explicit line — a leaked long-lived credential/private key/API key that AUTHENTICATES or is REUSED downstream is a confirmed High/Critical finding, not "just a cat on an owned host".

## 3. Graph UI improvements (frontend)
- Files: `web/public/app.js` (renderGraphMemory ~4440, finding detail ~4480), `web/public/style.css`.
- Better filtering (by entity kind, severity, status, subnet/host), edge-type legend (HAS_* structural vs ESCALATES_TO/IMPACTS/PROVES/CAN_ACCESS attack edges), node/edge path highlighting.

## 4. FINAL graph shows FULL attack path + all vulns traversed to objective
- The end-of-run graph must render the kill chain: entry (VPN/WEB-PUBLIC01) → every pivot/host → vulns used at each hop → DC01-VANGUARD.
- Backend: `graph_memory.rs` — ensure ESCALATES_TO/PROVES/CAN_ACCESS edges link the ordered path; emit a "goal path" (shortestPath/explicit chain) from entry to the objective host.
- Frontend: highlight/overlay that path distinctly (the "road to VANGUARD"), listing the vuln/finding used on each edge.

## 5. Neo4j graph must be USEFUL for the tests (not just visualization)
- Engine should QUERY the graph to drive decisions (BloodHound-style): shortestPath from owned principals to high-value targets (DCs, DA d.kim), suggest next moves from graph edges.
- Files: `graph_memory.rs` (push + query), planner (`crates/harness/src/planner.rs`, `reactive.rs`) — feed graph-derived paths into planner intents.
- Make the graph queryable/actionable: expose "owned → target" path queries the chain phase consumes.

## 6. Stealth / OPSEC mode (`--stealth`)
- New host flag `--stealth`. When on:
  - recon: slow timing (nmap -T2/-T1, no -T4; no rustscan mass-scan), fewer probes, jitter/throttle between actions.
  - prefer LOLBins / native tooling over noisy uploads (chisel.exe tripped Defender this run — prefer SSH tunnels, native PowerShell, WMI, built-in). Avoid AV-tripping binaries.
  - no aggressive brute/spray bursts; lockout-safe, spaced.
  - inject an OPSEC preamble into agent system prompts (minimize footprint, avoid detection, clean up).
  - MUST NOT reduce test coverage/quality — same objectives, quieter path.
- Touch: `main.rs` flag + RunConfig; `pipeline.rs` recon intensity + agent preamble; chain/C2 tool selection.

## 8. Engagement identifier / marker (`--engagement <id>`)  [requested, do later]
- Internal IPs (e.g. 10.0.0.4) collide across different engagements/clients, so grouping/merging runs by IP suffix is unreliable.
- Add `--engagement <id>` (alias `--test-id`): stamped into RunConfig + each run's metadata (status.json / a tag file in the run dir).
- Used as the GROUP KEY: `merge_runs.py` groups by engagement id, not IP.
- Namespaces Neo4j: set property `engagement=<id>` on every node/edge the run pushes, so separate engagements never mix in the graph even with the same IP. Graph/attack-path queries filter by it.
- Runs stay separate on disk; the marker is what says "same test".
- Files: main.rs flag + RunConfig field; graph_memory.rs push (add the property); merge script group key.

## 7. `--planner-model` (multi-model role routing)
- Already: `--model a,b,c` builds a multi-model `ModelPool` (pool.rs) + cross-model vote (vote_n). DeepSeek etc. usable now via `--model claude-opus-4-8,deepseek-v4.1`.
- NEW: `--planner-model <model>` to route the planner/strategist role to a specific model (e.g. deepseek proposes alternative approaches) while executor/validator use others. Wire into planner.rs/reactive.rs model selection.
- TTP customization already via `agents_md/*.md` (editable) + runtime planner synthesis.

---

# APPLY PROCEDURE (after run closes)
1. Confirm run ended: `pgrep -f "neurosploit host"` empty; report final findings + VANGUARD status.
2. `cd /opt/neurosploit-rs/neurosploit-rs && cargo build --release` (binary target/release/neurosploit). Frontend changes are static (no build).
3. Smoke test: `./target/release/neurosploit host --help` lists new flags; quick lab re-run if lab up.
4. Git: branch `feat/validator-chain-graph-stealth-multimodel`, commit per-area. **NO Claude attribution lines** (user memory rule overrides). Push to origin, open PR, merge.
5. Re-launch engagement with new flags if goal (VANGUARD) not yet met: add `--stealth` + `--model claude-opus-4-8,deepseek-v4.1` + `--no-validate` optional.

# KEY CODE LOCATIONS
- pipeline.rs: attack_chain @2959 (calls 2505/2788/5875/6708); validate verdict @3636-3708 (Keep ALL @3699, cap @3670, receipt path @3659); VOTE_SYS @1259, REFUTE_SYS @1263; graph confirmed-count @2943.
- main.rs: host flags session_environment@51 session_policy@54 transport@61; host cfg build @970-1000; apply_authorization call added ~1187.
- graph_memory.rs: neo4j push, reads NEO4J_PASSWORD ~1976.
- app.js: renderGraphMemory ~4440, finding detail panel ~4480. style.css: .fd-pre, .moves clamp.
- NEO4J creds: user neo4j / pass b6gF1AmPHpuNdTpsd2Z7RFoe / bolt://127.0.0.1:7687 (container neurosploit-neo4j).
