#!/usr/bin/env python3
"""
NeuroSploit v3.5.5 — End-of-Life (EOL) / End-of-Support exploitation agents.

Detect components past their vendor support window (runtime, framework, CMS,
web/app server, DB, OS, client libraries, TLS/protocols) and exploit the CVEs
that accumulate once security patches stop. EOL software is high-value: known,
unpatched, and often reachable. Web agents → agents_md/vulns/, host/OS → infra/.
Read-only-first, safe PoCs only, non-destructive, authorized only.
Credits: Joas A Santos & Red Team Leaders.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULNS = os.path.join(ROOT, "agents_md", "vulns")
INFRA = os.path.join(ROOT, "agents_md", "infra")

EOL_NOTE = ("EOL = past the vendor's end-of-life / end-of-support date, so it no longer receives security patches. "
            "Pin the EXACT version, check it against public EOL data (endoflife.date) and the CVE feeds, and exploit the "
            "known, unpatched issues with a SAFE proof — EOL software is high-value because the bugs are public and unfixed.")


def render(a):
    L = [f"# {a['title']} Agent\n", "## User Prompt",
         f"You are testing **{{target}}** for {a['for']}.\n",
         f"> {EOL_NOTE}\n",
         "**Recon Context:**\n{recon_json}\n", "**METHODOLOGY:**\n"]
    for i, (s, bs) in enumerate(a["steps"], 1):
        L.append(f"### {i}. {s}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["steps"]) + 1
    L += [f"### {n}. Report Format", "For each CONFIRMED finding:", "```", "FINDING:",
          f"- Title: {a['title']} - [component vX.Y (EOL)]", f"- Severity: {a['sev']}", f"- CWE: {a['cwe']}",
          "- Endpoint: [URL/host/resource]", "- Vector: [component, version, EOL date, CVE id(s)]",
          "- Payload: [exact request/command/PoC]", "- Evidence: [version proof + safe exploit receipt]",
          f"- Impact: {a['impact']}", f"- Remediation: {a['fix']}", "```\n", "## System Prompt", a["system"]]
    return "\n".join(L) + "\n"


def A(name, title, vc, cwe, sev, steps, fix, impact):
    return {"name": name, "title": title, "for": vc, "sev": sev, "cwe": cwe, "impact": impact, "fix": fix,
            "steps": steps,
            "system": (f"You are a specialist in exploiting {vc}. AUTHORIZED engagement. Confirm the EXACT version and its "
                       "EOL/end-of-support status before claiming a version-specific CVE; correlate with endoflife.date and "
                       "NVD/exploit feeds. Prove exploitability with a SAFE, non-destructive PoC (version/echo/OOB) — if you "
                       "can't reach a working PoC, report it as 'EOL, potentially vulnerable (unconfirmed)'. Report ONLY with "
                       "a real receipt. No destructive/DoS. Credits: Joas A Santos and Red Team Leaders.")}


VULN_AGENTS = [
 A("eol_stack_detection", "EOL Stack Detection", "components that are past end-of-life / end-of-support",
   "CWE-1104", "Medium",
   [("Fingerprint versions", ["From headers (Server, X-Powered-By, X-AspNet-Version), assets, error pages, cookies, JS "
                              "bundles and /*version* endpoints, pin the EXACT version of every component: web/app server, "
                              "language runtime, framework, CMS, DB, TLS lib, JS libraries"]),
    ("Classify EOL", ["Check each version against public EOL data (endoflife.date) — flag anything past its end-of-life or "
                      "end-of-support date; note how far past and the last supported version"]),
    ("Prioritise", ["Rank EOL components by reachability and CVE weight (unauth RCE/SQLi/auth-bypass first) and hand off to "
                    "the specialist EOL agents"])],
   "Upgrade to a supported release; add SBOM + EOL monitoring in CI; virtual-patch/WAF until upgraded",
   "Expanded, unpatched attack surface across the stack"),

 A("eol_runtime_exploitation", "EOL Language Runtime Exploitation", "end-of-life language runtimes (PHP/Python/Node/Java/.NET/Ruby)",
   "CWE-1104", "Critical",
   [("Identify runtime + version", ["Pin the runtime and exact version (e.g. PHP 5.x/7.x EOL, Python 2.7, Node 12/14, "
                                    "Java 6/7/8u-old, .NET Framework legacy, Ruby 2.x EOL) from banners/errors/behaviour"]),
    ("Map runtime CVEs", ["Correlate the EOL version with known runtime CVEs (deserialization, memory, parser, type-juggling) "
                          "and any bundled-extension CVEs"]),
    ("Safe PoC", ["Trigger a benign proof (version echo, OOB callback, type-juggling auth bypass on old PHP, etc.) — never a "
                  "destructive payload"])],
   "Migrate to a supported runtime version promptly; apply vendor advisories",
   "RCE / auth bypass / memory disclosure depending on runtime"),

 A("eol_framework_exploitation", "EOL Framework Exploitation", "end-of-life web frameworks (Struts/Spring-legacy/Rails/Django/Laravel/Symfony/AngularJS)",
   "CWE-1104", "Critical",
   [("Detect framework + version", ["Fingerprint the framework and version (cookies, headers, routes, error pages, asset "
                                     "hashes) — e.g. Struts2 old, Spring legacy, Rails <5, Django <2, AngularJS 1.x, jQuery <3"]),
    ("Correlate CVEs", ["Map to known framework RCE/SSTI/deser/mass-assignment CVEs (e.g. Struts OGNL, Spring4Shell-class, "
                        "Rails deserialization, AngularJS sandbox escape)"]),
    ("Reproduce safely", ["Prove with an OOB/echo PoC; for client-side framework issues confirm in the browser"])],
   "Upgrade the framework to a supported major; refactor deprecated APIs",
   "RCE / SSTI / template & client-side compromise"),

 A("eol_cms_exploitation", "EOL CMS Exploitation", "end-of-life CMS core & plugins (WordPress/Drupal/Joomla/Magento)",
   "CWE-1104", "Critical",
   [("Detect CMS + version", ["Pin CMS core version and enumerate plugins/themes/modules + versions (readme, changelog, "
                              "asset hashes, REST endpoints)"]),
    ("Flag EOL & correlate CVEs", ["Flag EOL core (e.g. Drupal 7/8, Magento 1, old WP branches) and EOL/abandoned plugins; "
                                   "map to known unauth RCE/SQLi/file-upload/auth-bypass CVEs"]),
    ("Confirm", ["Reproduce one concrete issue with a safe proof (version-gated echo / unauth read)"])],
   "Upgrade CMS core to a supported branch; remove abandoned plugins/themes; keep everything patched",
   "Site takeover / RCE / data breach"),

 A("eol_client_library", "EOL Client-Side Library Exploitation", "end-of-life front-end libraries with known CVEs",
   "CWE-1104", "High",
   [("Inventory JS libs", ["From responses/JS/source maps, list client libraries + exact versions (jQuery, AngularJS, "
                           "Bootstrap, Lodash, Moment, old React/Vue, Swiper, DOMPurify)"]),
    ("Flag EOL & CVEs", ["Flag EOL/abandoned versions (jQuery <3.5 XSS, AngularJS EOL, Lodash prototype pollution, etc.) and "
                         "map to CVEs"]),
    ("Confirm reachability", ["Where a sink is reachable, prove exploitability (e.g. DOM XSS via the vulnerable lib) in the "
                              "browser; else report as version-based exposure"])],
   "Upgrade/replace EOL front-end libraries; add SCA in CI",
   "XSS / prototype pollution / client-side compromise"),
]

INFRA_AGENTS = [
 A("eol_webserver_exploitation", "EOL Web/App Server Exploitation", "end-of-life web & app servers (Apache/nginx/IIS/Tomcat/JBoss/WebLogic)",
   "CWE-1104", "Critical",
   [("Fingerprint server + version", ["Pin the exact server/app-server version from banners, error pages, default files, and "
                                       "behaviour (Apache httpd old, nginx old, IIS 6/7, Tomcat/JBoss/WebLogic legacy)"]),
    ("Flag EOL & correlate", ["Flag EOL versions and map to known CVEs (Tomcat AJP Ghostcat, WebLogic deser/T3, IIS WebDAV, "
                              "Apache path traversal/mod CVEs)"]),
    ("Safe PoC", ["Reproduce with a non-destructive PoC (version-gated read / OOB) proving the CVE is present"])],
   "Upgrade to a supported server release; disable legacy modules/connectors; WAF/virtual-patch meanwhile",
   "RCE / file read / deserialization compromise"),

 A("eol_os_service", "EOL OS & Service Exploitation", "end-of-life operating systems and network services",
   "CWE-1104", "Critical",
   [("Enumerate versions", ["From service banners / SSH / SMB / TLS / uname (with creds), pin OS and service versions "
                            "(EOL Windows/Ubuntu/CentOS, old OpenSSH/OpenSSL/Samba, SMBv1)"]),
    ("Flag EOL & correlate", ["Flag EOL OS/services and map to known CVEs (EternalBlue-class SMBv1, old OpenSSL Heartbleed-"
                              "class, unsupported OpenSSH auth issues)"]),
    ("Confirm safely", ["Prove the vulnerable version/config is present with a safe check — never run a destructive exploit"])],
   "Upgrade/replace EOL OS & services; disable SMBv1/legacy TLS; segment until remediated",
   "RCE / host compromise / lateral movement"),

 A("eol_tls_protocol", "EOL TLS & Protocol Exploitation", "deprecated TLS versions and legacy protocols",
   "CWE-327", "Medium",
   [("Enumerate protocols/ciphers", ["Test supported TLS versions and cipher suites (SSLv3, TLS 1.0/1.1 EOL, weak/CBC/RC4/"
                                      "export ciphers) and legacy protocols (SMBv1, FTP, Telnet, old SNMP)"]),
    ("Flag deprecated", ["Flag anything past deprecation (RFC 8996 TLS1.0/1.1, SSLv3 POODLE, weak ciphers) and note "
                         "downgrade/MITM feasibility"]),
    ("Confirm", ["Complete a handshake proving the deprecated protocol/cipher is accepted"])],
   "Require TLS 1.2+ (prefer 1.3); disable SSLv3/TLS1.0/1.1, weak ciphers and legacy protocols",
   "Downgrade / MITM / weakened transport security"),
]


def main():
    os.makedirs(VULNS, exist_ok=True); os.makedirs(INFRA, exist_ok=True)
    for a in VULN_AGENTS:
        open(os.path.join(VULNS, a["name"] + ".md"), "w").write(render(a))
    for a in INFRA_AGENTS:
        open(os.path.join(INFRA, a["name"] + ".md"), "w").write(render(a))
    print(f"wrote {len(VULN_AGENTS)} EOL agents to {VULNS} and {len(INFRA_AGENTS)} to {INFRA}")


if __name__ == "__main__":
    main()
