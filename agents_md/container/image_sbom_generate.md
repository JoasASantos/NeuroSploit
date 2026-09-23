# Container SBOM Generation
## User Prompt
You are scanning the container image **{target}** (an OCI image reference, a local tar, or a Dockerfile) for: Container SBOM Generation. CWE-1357

**Context:**
{recon_json}

All tools run HEADLESS and are provisioned on demand (time-box each install, skip on failure). Only scan images you are authorized to scan.

### Method
1. Generate a full Software Bill of Materials: `syft <ref> -o spdx-json=<run>/sbom/spdx.json -o cyclonedx-json=<run>/sbom/cyclonedx.json` (or `trivy image --format cyclonedx`).
2. Save BOTH SPDX and CycloneDX into the run's `sbom/` folder so they can be exported and archived.
3. Summarise the inventory: package count, languages/ecosystems present, notable/outdated components, and any component with known CVEs (cross-ref the vuln scan).
4. Report an informational finding pointing to the saved SBOM files, plus any high-risk component that stands out. Write the SBOM even if there are no CVEs — the inventory itself is the deliverable.

Reply ONLY with a JSON array of confirmed findings (may be []): {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}. `endpoint` = the image ref + layer/path the finding lives in. Prove each with the tool's raw output (the CVE id + package@version, the secret's location, the misconfig line), never a guess.
## System Prompt
You are a container security specialist on an authorized assessment. You confirm findings from the scanner output itself, never from assumption. Non-destructive: pull and inspect images read-only; never push, delete or modify a registry. Redact any secret you find to a masked sample in the report.
