#!/usr/bin/env python3
"""
NeuroSploit v3.5.1 — application-stack & CVE-hunting agents.
Adds IIS/.NET, CMS (WordPress/Drupal/Joomla/etc.), app-server and known-CVE
exploitation agents to agents_md/vulns/. Credits: Joas A Santos & Red Team Leaders.
"""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "agents_md", "vulns")


def render(a):
    L = [f"# {a['title']} Agent\n", "## User Prompt",
         f"You are testing **{{target}}** for {a['for']}.\n",
         "**Recon Context:**\n{recon_json}\n", "**METHODOLOGY:**\n"]
    for i, (s, bs) in enumerate(a["steps"], 1):
        L.append(f"### {i}. {s}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["steps"]) + 1
    L += [f"### {n}. Report Format", "For each CONFIRMED finding:", "```", "FINDING:",
          f"- Title: {a['title']} at [endpoint]", f"- Severity: {a['sev']}", f"- CWE: {a['cwe']}",
          "- Endpoint: [full URL]", "- Vector: [what/where]", "- Payload: [exact payload/command]",
          "- Evidence: [raw tool output proving it]", f"- Impact: {a['impact']}",
          f"- Remediation: {a['fix']}", "```\n", "## System Prompt", a["system"]]
    return "\n".join(L) + "\n"


def A(name, title, vc, cwe, sev, steps, fix, impact):
    return {"name": name, "title": title, "for": vc, "sev": sev, "cwe": cwe, "impact": impact,
            "fix": fix, "steps": steps,
            "system": (f"You are a specialist in {vc}. AUTHORIZED engagement. Report ONLY what you "
                       "proved with a real tool receipt (raw output) — never a paraphrase or assumption. "
                       "Confirm the component/version before claiming a version-specific CVE is exploitable; "
                       "if you cannot reach a working PoC, report it as a lower-confidence exposure, not a "
                       "confirmed exploit. No destructive/DoS actions. Credits: Joas A Santos and Red Team Leaders.")}


AGENTS = [
 # ---- IIS / ASP.NET ----
 A("iis_tilde_shortname", "IIS Tilde (~) Short-Name Enumeration", "IIS 8.3 short-name disclosure",
   "CWE-200", "Medium",
   [("Detect", ["Probe `GET /*~1*/.aspx` style requests; a 404-vs-error differential reveals 8.3 short names",
                "Confirm IIS version from Server header"]),
    ("Enumerate", ["Brute the short names char by char to reveal hidden files/dirs"]),
    ("Confirm", ["Show recovered short names mapping to real sensitive files"])],
   "Disable 8.3 name creation; patch IIS", "Discovery of hidden files/backups/configs"),
 A("iis_webdav", "IIS WebDAV Misconfiguration", "exposed/unsafe WebDAV on IIS",
   "CWE-650", "High",
   [("Detect", ["`OPTIONS /` — look for DAV header / PUT/MOVE/COPY allowed"]),
    ("Test write", ["Attempt PUT of a benign file; if blocked, try `.txt`→MOVE→`.asp` trick"]),
    ("Confirm", ["Show an uploaded file is served (and if executable → RCE)"])],
   "Disable WebDAV or restrict methods/authn", "Arbitrary upload, potential RCE"),
 A("aspnet_viewstate", "ASP.NET ViewState Deserialization", "unprotected/known-key __VIEWSTATE deserialization",
   "CWE-502", "Critical",
   [("Inspect", ["Capture __VIEWSTATE; check if MAC is disabled (enableViewStateMac=false) or a known/leaked machineKey is in play"]),
    ("Weaponize", ["With a known/guessed machineKey, craft a ysoserial.net ViewState gadget"]),
    ("Confirm", ["Prove code execution via OOB callback or command output tied to a unique marker"])],
   "Enable ViewState MAC; rotate machineKey; patch", "Remote code execution"),
 A("aspnet_debug_trace", "ASP.NET Debug/Trace Exposure", "debug/trace enabled in production ASP.NET",
   "CWE-489", "Medium",
   [("Probe", ["Request `trace.axd`; send `DEBUG` verb; check `<compilation debug=...>` leakage via errors"]),
    ("Assess", ["Harvest request/session data, stack traces, app internals from trace output"]),
    ("Confirm", ["Show sensitive runtime data exposed"])],
   "Disable debug/trace; custom errors", "Information disclosure"),
 A("iis_handler_bypass", "IIS Handler/Extension Bypass", "auth or filter bypass via IIS handler quirks",
   "CWE-288", "High",
   [("Probe", ["Test path/extension tricks: `;.asp`, `::$DATA`, trailing dot, `%20`, case, `/admin/.`/`..%2f`"]),
    ("Bypass", ["Reach a protected handler/endpoint via a normalization or handler-mapping quirk"]),
    ("Confirm", ["Show access to a resource that should be blocked"])],
   "Consistent normalization; patch; tighten ACLs", "Auth/control bypass"),
 # ---- CMS general & specific ----
 A("cms_fingerprint", "CMS Fingerprint & Version", "CMS identification and version disclosure",
   "CWE-200", "Info",
   [("Identify", ["Detect CMS via meta generator, paths (`/wp-`, `/sites/`, `/administrator/`), headers, favicon hash",
                  "Run whatweb/wpscan-style detection without auth"]),
    ("Version", ["Pin exact version from readme/changelog/asset hashes"]),
    ("Map", ["List plugins/themes/modules and their versions for CVE correlation"])],
   "Hide version/generator; keep components updated", "Targeted exploitation surface"),
 A("wordpress_audit", "WordPress Security Audit", "WordPress core/plugin/theme weaknesses",
   "CWE-1395", "High",
   [("Enumerate", ["Users (`/?author=`, REST `/wp-json/wp/v2/users`), plugins/themes + versions, `xmlrpc.php`"]),
    ("Correlate CVEs", ["Map plugin/theme versions to known vulns (arbitrary upload, SQLi, auth bypass, LFI)"]),
    ("Confirm", ["Reproduce one concrete issue (e.g. unauth arbitrary file upload) with proof"])],
   "Update core/plugins/themes; harden; disable xmlrpc", "Site takeover / RCE"),
 A("joomla_audit", "Joomla Security Audit", "Joomla core/extension weaknesses",
   "CWE-1395", "High",
   [("Enumerate", ["Version (`administrator/manifests/files/joomla.xml`), components/extensions + versions"]),
    ("Correlate CVEs", ["Map to known Joomla/extension CVEs (SQLi, LFI, object injection)"]),
    ("Confirm", ["Reproduce one with proof"])],
   "Update core/extensions; harden admin", "Site takeover / data breach"),
 A("drupal_audit", "Drupal Security Audit", "Drupal core/module weaknesses (e.g. Drupalgeddon class)",
   "CWE-1395", "Critical",
   [("Enumerate", ["Version (CHANGELOG, headers), enabled modules"]),
    ("Correlate CVEs", ["Map to known Drupal RCE/SQLi (e.g. SA-CORE highly-critical classes)"]),
    ("Confirm", ["Reproduce with an OOB/output proof where applicable"])],
   "Patch core/modules promptly", "Remote code execution"),
 A("cms_default_admin", "CMS Admin Panel & Default Creds", "exposed CMS admin with weak/default credentials",
   "CWE-1392", "High",
   [("Locate", ["Find admin (`/wp-admin`, `/administrator`, `/user/login`, `/admin`)"]),
    ("Test (in scope)", ["Try supplied/default credentials; respect lockout/ROE — no out-of-scope brute force"]),
    ("Confirm", ["Show authenticated admin access"])],
   "Remove defaults; strong creds + MFA; restrict admin", "Full CMS compromise"),
 # ---- app servers / panels ----
 A("appserver_exposure", "App-Server Console Exposure", "exposed Tomcat/JBoss/Jenkins/Actuator consoles",
   "CWE-1188", "High",
   [("Discover", ["Probe `/manager/html`, `/jmx-console`, `/jenkins`, `/actuator`, `/console`, `/admin`"]),
    ("Assess", ["Test default/weak creds (in scope); check unauth-exposed management endpoints"]),
    ("Confirm", ["Demonstrate a management action / deploy / info-leak proving exposure (→ often RCE)"])],
   "Authenticate & network-restrict consoles; remove defaults", "Remote code execution / takeover"),
 A("git_svn_exposure_app", "Exposed VCS / Build Artifacts", "exposed .git/.svn/CI artifacts on the app host",
   "CWE-527", "High",
   [("Probe", ["Request `/.git/HEAD`, `/.svn/entries`, `/.env`, build/CI artifact paths"]),
    ("Recover", ["Dump source (git-dumper) / read secrets"]),
    ("Confirm", ["Show recovered source or live secret"])],
   "Block VCS/dotfiles from web; rotate secrets", "Source/secret disclosure → RCE"),
 # ---- CVE hunting ----
 A("cve_known_exploitation", "Known-CVE Exploitation Specialist", "exploiting known CVEs for the detected stack",
   "CWE-1395", "Critical",
   [("Identify versions", ["From recon, list each component + exact version (server, framework, CMS, plugins, libs)"]),
    ("Map to CVEs", ["Match versions to known CVEs; prioritise unauth RCE/SQLi/auth-bypass; note CVE id + CVSS",
                     "Prefer issues with a reliable, non-destructive PoC"]),
    ("Reproduce safely", ["Run a benign PoC (e.g. a version/echo check or OOB callback) to confirm the CVE is actually present and exploitable — never a destructive payload"]),
    ("Confirm", ["Report the CVE only when the PoC produced concrete proof (output/OOB); otherwise report it as 'potentially vulnerable (version match, unconfirmed)'"])],
   "Patch/upgrade the affected components; apply vendor advisories", "Depends on CVE — up to full compromise"),
 A("outdated_dependency_cve", "Outdated Component CVE Specialist", "outdated front-end/back-end components with known CVEs",
   "CWE-1104", "High",
   [("Inventory", ["Extract JS libs (jQuery, Angular, etc.), server modules, framework versions from responses/JS/headers"]),
    ("Correlate", ["Map each to known CVEs; flag the exploitable, reachable ones"]),
    ("Confirm", ["Prove exploitability where a safe PoC exists; else report as version-based exposure"])],
   "Upgrade components; dependency scanning in CI", "Varies — XSS/RCE/info-leak"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for a in AGENTS:
        open(os.path.join(OUT, a["name"] + ".md"), "w").write(render(a))
    print(f"wrote {len(AGENTS)} app-stack/CVE agents to {OUT}")


if __name__ == "__main__":
    main()
