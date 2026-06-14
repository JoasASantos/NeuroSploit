# NeuroSploit v3.3.0 — Agent Registry

Curated markdown agent library: **213 agents** (196 vulnerability specialists + 17 meta-agents).

Each agent is a self-contained playbook with `## User Prompt` (methodology) and `## System Prompt` (strict anti-false-positive rules). The orchestrator selects and ranks them per target using recon signals and reinforcement-learning weights.

## Meta-agents (`agents_md/meta/`)

| Agent | Role |
|-------|------|
| `exploit_validator` | Independently re-exploits candidates for hard proof |
| `false_positive_filter` | Adversarial skeptic; drops anything unproven |
| `impact_evaluator` | Business/risk impact + exploit-chain mapping |
| `orchestrator` | Master loop: recon → select → exploit → validate → score → report → learn |
| `recon` | Attack-surface mapping; emits recon_json |
| `reporter` | Emits findings.json + report.md |
| `rl_feedback` | Per-agent reward signals → data/rl_state.json |
| `role_Pentestfull` | PROMPT FINAL COMPLETO - RIGOR TÉCNICO + INTELIGÊNCIA CONTEXTUAL |
| `role_bug_bounty_hunter` | Bug Bounty Hunter Prompt |
| `role_cwe_expert` | CWE Top 25 Prompt |
| `role_exploit_expert` | Exploit Expert Prompt |
| `role_owasp_expert` | OWASP Top 10 Expert Prompt |
| `role_pentest_generalist` | Penetration Test Generalist Prompt |
| `role_recon_deep` | Deep Reconnaissance Specialist Agent |
| `role_red_team_agent` | Red Team Agent Prompt |
| `role_replay_attack_specialist` | Replay Attack Prompt |
| `severity_assessor` | Assigns defensible CVSS 3.1 vector + band |

## Vulnerability specialists (`agents_md/vulns/`)

| Agent | Title | CWE |
|-------|-------|-----|
| `account_takeover_chain` | Account Takeover Chain Specialist | CWE-640 |
| `ai_api_key_exfiltration` | AI Provider Secret Exfiltration Specialist | CWE-522 |
| `api_bola_chained` | Chained BOLA Specialist | CWE-639 |
| `api_excessive_data` | Excessive Data Exposure Specialist | CWE-213 |
| `api_key_exposure` | API Key Exposure Specialist | CWE-798 |
| `api_rate_limiting` | Missing API Rate Limiting Specialist | CWE-770 |
| `arbitrary_file_delete` | Arbitrary File Delete Specialist | CWE-22 |
| `arbitrary_file_read` | Arbitrary File Read Specialist | CWE-22 |
| `auth_bypass` | Authentication Bypass Specialist | CWE-287 |
| `aws_imds_v2_bypass` | AWS IMDSv2 SSRF Specialist | CWE-918 |
| `azure_blob_public` | Azure Blob Public Exposure Specialist | CWE-284 |
| `azure_imds_exposure` | Azure IMDS SSRF Specialist | CWE-918 |
| `backup_file_exposure` | Backup File Exposure Specialist | CWE-530 |
| `bfla` | BFLA Specialist | CWE-285 |
| `blind_xss` | Blind XSS Specialist | CWE-79 |
| `bola` | BOLA Specialist | CWE-639 |
| `brute_force` | Brute Force Vulnerability Specialist | CWE-307 |
| `business_logic` | Business Logic Specialist | CWE-840 |
| `byte_range_cache` | Byte-Range Cache Poisoning Specialist | CWE-444 |
| `cache_poisoning` | Web Cache Poisoning Specialist | CWE-444 |
| `captcha_bypass` | CAPTCHA Bypass Specialist | CWE-804 |
| `cdn_cache_key_poisoning` | Unkeyed Header Cache Poisoning Specialist | CWE-444 |
| `ci_cd_secret_leak` | CI/CD Secret Leak Specialist | CWE-532 |
| `cleartext_transmission` | Cleartext Transmission Specialist | CWE-319 |
| `clickjacking` | Clickjacking Specialist | CWE-1021 |
| `client_side_template_injection` | Client-Side Template Injection Specialist | CWE-94 |
| `cloud_iam_privesc` | Cloud IAM Privilege-Escalation Specialist | CWE-269 |
| `cloud_metadata_exposure` | Cloud Metadata Exposure Specialist | CWE-918 |
| `command_injection` | OS Command Injection Specialist | CWE-78 |
| `container_escape` | Container Escape Specialist | CWE-250 |
| `container_escape_advanced` | Container Escape Specialist | CWE-269 |
| `cors_misconfig` | CORS Misconfiguration Specialist | CWE-942 |
| `coupon_logic_abuse` | Coupon/Discount Logic Specialist | CWE-840 |
| `crlf_injection` | CRLF Injection Specialist | CWE-93 |
| `csrf` | CSRF Specialist | CWE-352 |
| `css_injection` | CSS Injection Specialist | CWE-79 |
| `csv_injection` | CSV/Formula Injection Specialist | CWE-1236 |
| `dangling_markup_injection` | Dangling Markup Injection Specialist | CWE-79 |
| `debug_mode` | Debug Mode Detection Specialist | CWE-489 |
| `default_credentials` | Default Credentials Specialist | CWE-798 |
| `dependency_confusion` | Dependency Confusion Specialist | CWE-427 |
| `directory_listing` | Directory Listing Specialist | CWE-548 |
| `docker_socket_exposure` | Docker Socket Exposure Specialist | CWE-284 |
| `dom_clobbering` | DOM Clobbering Specialist | CWE-79 |
| `ecb_pattern_leak` | ECB Pattern Leakage Specialist | CWE-327 |
| `ecr_public_exposure` | Public Container Registry Exposure Specialist | CWE-200 |
| `edge_side_includes` | ESI Injection Specialist | CWE-94 |
| `email_injection` | Email Injection Specialist | CWE-93 |
| `env_file_exposure` | Exposed .env / Config Specialist | CWE-200 |
| `excessive_data_exposure` | Excessive Data Exposure Specialist | CWE-213 |
| `exposed_admin_panel` | Exposed Admin Panel Specialist | CWE-200 |
| `exposed_api_docs` | Exposed API Documentation Specialist | CWE-200 |
| `expression_language_injection` | Expression Language Injection Specialist | CWE-917 |
| `file_upload` | File Upload Vulnerability Specialist | CWE-434 |
| `forced_browsing` | Forced Browsing Specialist | CWE-425 |
| `formula_injection_excel` | CSV/Formula Injection Specialist | CWE-1236 |
| `gcp_metadata_ssrf` | GCP Metadata SSRF Specialist | CWE-918 |
| `gcs_bucket_misconfig` | GCS Bucket Misconfiguration Specialist | CWE-284 |
| `git_exposed_repo` | Exposed .git Repository Specialist | CWE-527 |
| `graphql_batching_attack` | GraphQL Batching Attack Specialist | CWE-799 |
| `graphql_dos` | GraphQL Denial of Service Specialist | CWE-400 |
| `graphql_dos_alias_overload` | GraphQL Alias/Field Overload DoS Specialist | CWE-770 |
| `graphql_field_suggestion` | GraphQL Field-Suggestion Leak Specialist | CWE-200 |
| `graphql_injection` | GraphQL Injection Specialist | CWE-89 |
| `graphql_introspection` | GraphQL Introspection Specialist | CWE-200 |
| `grpc_reflection_exposure` | gRPC Reflection Exposure Specialist | CWE-200 |
| `h2c_smuggling` | h2c Smuggling Specialist | CWE-444 |
| `header_injection` | HTTP Header Injection Specialist | CWE-113 |
| `helm_secret_exposure` | Helm Secret Exposure Specialist | CWE-312 |
| `hop_by_hop_abuse` | Hop-by-Hop Header Abuse Specialist | CWE-444 |
| `host_header_injection` | Host Header Injection Specialist | CWE-644 |
| `html_injection` | HTML Injection Specialist | CWE-79 |
| `http2_request_smuggling` | HTTP/2 Request Smuggling Specialist | CWE-444 |
| `http_desync_cl_te` | CL.TE Request Smuggling Specialist | CWE-444 |
| `http_desync_te_cl` | TE.CL Request Smuggling Specialist | CWE-444 |
| `http_methods` | HTTP Methods Testing Specialist | CWE-749 |
| `http_smuggling` | HTTP Request Smuggling Specialist | CWE-444 |
| `idempotency_key_abuse` | Idempotency Key Abuse Specialist | CWE-362 |
| `idor` | IDOR Specialist | CWE-639 |
| `improper_error_handling` | Improper Error Handling Specialist | CWE-209 |
| `information_disclosure` | Information Disclosure Specialist | CWE-200 |
| `insecure_cdn` | Insecure CDN Resource Loading Specialist | CWE-829 |
| `insecure_cookie_flags` | Insecure Cookie Configuration Specialist | CWE-614 |
| `insecure_deserialization` | Insecure Deserialization Specialist | CWE-502 |
| `jwt_alg_confusion` | JWT Algorithm Confusion Specialist | CWE-347 |
| `jwt_jwk_injection` | JWT Embedded-JWK Injection Specialist | CWE-347 |
| `jwt_kid_injection` | JWT kid Injection Specialist | CWE-22 |
| `jwt_manipulation` | JWT Token Manipulation Specialist | CWE-347 |
| `k8s_exposed_dashboard` | Exposed Kubernetes Dashboard Specialist | CWE-306 |
| `k8s_exposed_kubelet` | Exposed Kubelet API Specialist | CWE-306 |
| `k8s_rbac_misconfig` | Kubernetes RBAC Misconfiguration Specialist | CWE-285 |
| `ldap_injection` | LDAP Injection Specialist | CWE-90 |
| `lfi` | Local File Inclusion Specialist | CWE-98 |
| `llm_excessive_agency` | Excessive Agency Specialist | CWE-285 |
| `llm_function_calling_abuse` | Function-Calling Argument-Injection Specialist | CWE-77 |
| `llm_insecure_output_handling` | Insecure LLM Output Handling Specialist | CWE-79 |
| `llm_jailbreak` | LLM Jailbreak Specialist | CWE-1427 |
| `llm_model_dos` | LLM Resource-Exhaustion (DoS) Specialist | CWE-400 |
| `llm_pii_leakage` | Cross-Tenant LLM PII Leakage Specialist | CWE-200 |
| `llm_rag_poisoning` | RAG / Vector-Store Poisoning Specialist | CWE-1427 |
| `llm_supply_chain_plugin` | LLM Plugin/MCP Supply-Chain Specialist | CWE-829 |
| `llm_system_prompt_leak` | System Prompt Leak Specialist | CWE-200 |
| `llm_tool_invocation_abuse` | LLM Tool-Invocation Abuse Specialist | CWE-918 |
| `llm_training_data_extraction` | Training/Context Data Extraction Specialist | CWE-200 |
| `log4shell_jndi` | JNDI Lookup Injection Specialist | CWE-917 |
| `log_injection` | Log Injection / Log4Shell Specialist | CWE-117 |
| `mass_assignment` | Mass Assignment Specialist | CWE-915 |
| `mfa_bypass_response` | MFA Bypass (Response Manipulation) Specialist | CWE-287 |
| `ml_model_inversion` | Model Inversion / Attribute Inference Specialist | CWE-200 |
| `mutation_xss` | Mutation XSS Specialist | CWE-79 |
| `nosql_injection` | NoSQL Injection Specialist | CWE-943 |
| `oauth_misconfiguration` | OAuth Misconfiguration Specialist | CWE-601 |
| `oauth_open_redirect_chain` | OAuth Open-Redirect Token-Theft Specialist | CWE-601 |
| `oauth_pkce_downgrade` | OAuth PKCE Downgrade Specialist | CWE-287 |
| `oidc_misconfig` | OIDC Misconfiguration Specialist | CWE-347 |
| `open_redirect` | Open Redirect Specialist | CWE-601 |
| `orm_injection` | ORM Injection Specialist | CWE-89 |
| `outdated_component` | Outdated Component Specialist | CWE-1104 |
| `padding_oracle` | Padding Oracle Specialist | CWE-696 |
| `parameter_pollution` | HTTP Parameter Pollution Specialist | CWE-235 |
| `password_reset_poisoning` | Password Reset Poisoning Specialist | CWE-640 |
| `path_traversal` | Path Traversal Specialist | CWE-22 |
| `pickle_deserialization` | Python Pickle Deserialization Specialist | CWE-502 |
| `postmessage_vulnerability` | postMessage Vulnerability Specialist | CWE-346 |
| `price_manipulation` | Price/Quantity Tampering Specialist | CWE-602 |
| `privilege_escalation` | Privilege Escalation Specialist | CWE-269 |
| `prompt_injection_direct` | Direct Prompt Injection Specialist | CWE-1427 |
| `prompt_injection_indirect` | Indirect Prompt Injection Specialist | CWE-1427 |
| `prototype_pollution` | Prototype Pollution Specialist | CWE-1321 |
| `race_condition` | Race Condition Specialist | CWE-362 |
| `range_header_dos` | Range Header Amplification Specialist | CWE-400 |
| `rate_limit_bypass` | Rate Limit Bypass Specialist | CWE-770 |
| `refresh_token_abuse` | Refresh Token Abuse Specialist | CWE-613 |
| `regex_dos` | ReDoS Specialist | CWE-1333 |
| `response_splitting` | HTTP Response Splitting Specialist | CWE-113 |
| `rest_api_versioning` | Insecure API Version Exposure Specialist | CWE-284 |
| `reverse_proxy_path_confusion` | Reverse-Proxy Path Confusion Specialist | CWE-22 |
| `rfi` | Remote File Inclusion Specialist | CWE-98 |
| `s3_bucket_misconfiguration` | S3 Bucket Misconfiguration Specialist | CWE-284 |
| `s3_bucket_takeover` | S3 Bucket Takeover Specialist | CWE-284 |
| `saml_signature_wrapping` | SAML Signature Wrapping Specialist | CWE-347 |
| `second_order_redirect` | Second-Order Open Redirect Specialist | CWE-601 |
| `security_headers` | Security Headers Specialist | CWE-693 |
| `sensitive_data_exposure` | Sensitive Data Exposure Specialist | CWE-200 |
| `server_side_includes` | SSI Injection Specialist | CWE-97 |
| `server_side_prototype_pollution` | Server-Side Prototype Pollution Specialist | CWE-1321 |
| `serverless_event_injection` | Serverless Event-Injection Specialist | CWE-94 |
| `serverless_misconfiguration` | Serverless Misconfiguration Specialist | CWE-284 |
| `session_fixation` | Session Fixation Specialist | CWE-384 |
| `smtp_injection` | SMTP Header Injection Specialist | CWE-93 |
| `soap_injection` | SOAP/XML Web Service Injection Specialist | CWE-91 |
| `source_code_disclosure` | Source Code Disclosure Specialist | CWE-540 |
| `sqli_blind` | Blind SQL Injection (Boolean) Specialist | CWE-89 |
| `sqli_error` | Error-Based SQL Injection Specialist | CWE-89 |
| `sqli_time` | Time-Based Blind SQL Injection Specialist | CWE-89 |
| `sqli_union` | Union-Based SQL Injection Specialist | CWE-89 |
| `ssl_issues` | SSL/TLS Issues Specialist | CWE-326 |
| `ssrf` | SSRF Specialist | CWE-918 |
| `ssrf_cloud` | Cloud SSRF / Metadata Specialist | CWE-918 |
| `ssti` | Server-Side Template Injection Specialist | CWE-94 |
| `ssti_freemarker` | FreeMarker SSTI Specialist | CWE-1336 |
| `ssti_jinja2` | Jinja2 SSTI Specialist | CWE-1336 |
| `ssti_thymeleaf` | Thymeleaf SSTI Specialist | CWE-1336 |
| `ssti_velocity` | Velocity SSTI Specialist | CWE-1336 |
| `subdomain_takeover` | Subdomain Takeover Specialist | CWE-284 |
| `tabnabbing` | Reverse Tabnabbing Specialist | CWE-1022 |
| `terraform_state_exposure` | Terraform State Exposure Specialist | CWE-200 |
| `timing_attack` | Timing Attack Specialist | CWE-208 |
| `timing_side_channel_auth` | Auth Timing Side-Channel Specialist | CWE-208 |
| `two_factor_bypass` | 2FA Bypass Specialist | CWE-287 |
| `type_juggling` | Type Juggling Specialist | CWE-843 |
| `typosquatting_package` | Typosquatting Detection Specialist | CWE-1357 |
| `vector_db_injection` | Vector DB Metadata-Filter Injection Specialist | CWE-74 |
| `version_disclosure` | Version Disclosure Specialist | CWE-200 |
| `vulnerable_dependency` | Vulnerable Dependency Specialist | CWE-1104 |
| `weak_encryption` | Weak Encryption Specialist | CWE-327 |
| `weak_hashing` | Weak Hashing Specialist | CWE-328 |
| `weak_jwt_secret_bruteforce` | Weak JWT Secret Specialist | CWE-326 |
| `weak_password` | Weak Password Policy Specialist | CWE-521 |
| `weak_random` | Weak Random Number Generation Specialist | CWE-330 |
| `web_cache_deception` | Web Cache Deception Specialist | CWE-525 |
| `web_cache_poisoning_dos` | Cache Poisoning DoS Specialist | CWE-444 |
| `websocket_csrf` | Cross-Site WebSocket Hijacking Specialist | CWE-352 |
| `websocket_hijacking` | WebSocket Hijacking Specialist | CWE-1385 |
| `websocket_smuggling` | WebSocket Smuggling Specialist | CWE-444 |
| `workflow_step_skip` | Workflow Step-Skipping Specialist | CWE-841 |
| `xpath_injection` | XPath Injection Specialist | CWE-643 |
| `xslt_injection` | XSLT Injection Specialist | CWE-91 |
| `xss_dom` | DOM XSS Specialist | CWE-79 |
| `xss_reflected` | Reflected XSS Specialist | CWE-79 |
| `xss_stored` | Stored XSS Specialist | CWE-79 |
| `xxe` | XXE Injection Specialist | CWE-611 |
| `xxe_billion_laughs` | XML Entity-Expansion DoS Specialist | CWE-776 |
| `xxe_oob_exfiltration` | OOB XXE Exfiltration Specialist | CWE-611 |
| `yaml_deserialization` | Unsafe YAML Deserialization Specialist | CWE-502 |
| `zip_slip` | Zip Slip Specialist | CWE-22 |
