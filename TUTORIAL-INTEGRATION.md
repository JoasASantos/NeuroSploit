# NeuroSploit — Integrations Setup Guide

Connect NeuroSploit to **GitHub**, **GitLab** and **Jira** so it can review private
repositories and Pull Requests, **gate merges** on severe findings, watch branches
for new code, run from a **`@neurosploit`** comment, and file a Jira
**card per vulnerability**.

> ⚠️ **Authorized testing only.** Use integrations against code/projects you own or
> are explicitly permitted to test.

---

## Table of contents
1. [How it works (config & secrets)](#1-how-it-works)
2. [The `/integrations` command](#2-the-integrations-command)
3. [GitHub](#3-github)
4. [GitLab](#4-gitlab)
5. [Jira](#5-jira)
6. [Recipes](#6-recipes)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. How it works

- Integration config is **per project**, stored at
  `<cwd>/.neurosploit/integrations.json`.
- **Secrets are never written to disk.** The config only stores the **name** of
  the environment variable that holds each token (e.g. `GITHUB_TOKEN`). The real
  value is read from your environment at use time. Keep tokens in your shell /
  secret manager, not in the repo.
- Enable/disable per integration; each is independent.

Default env-var names (configurable):

| Integration | Token env var(s) |
|-------------|------------------|
| GitHub | `GITHUB_TOKEN` |
| GitLab | `GITLAB_TOKEN` |
| Jira | `JIRA_EMAIL` + `JIRA_API_TOKEN` |

---

## 2. The `/integrations` command

In the **REPL** (`neurosploit` with no args):

```
/integrations                      # show status of all three
/integrations enable github        # toggle on   (also: gitlab | jira)
/integrations disable jira         # toggle off
/integrations setup jira           # interactive: base URL, project key, issue type
/integrations setup gitlab         # set the GitLab base (gitlab.com or self-hosted)
/integrations setup github         # set the API base (change only for GitHub Enterprise)
```

From the **CLI**:

```bash
neurosploit integrations                       # show status
neurosploit integrations enable github         # enable / disable <github|gitlab|jira>
```

`show` prints whether each is on and whether the token env var is currently set
(`✓ token` / `⚠ token env not set`).

---

## 3. GitHub

**a. Create a token.** GitHub → *Settings → Developer settings → Personal access
tokens*. A classic PAT with the **`repo`** scope (read access to the private repos
you'll test) is enough. Fine-grained tokens also work (grant *Contents: Read* and,
for PR comments, *Pull requests: Read & write*).

**b. Export it and enable:**
```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
neurosploit integrations enable github
```

**c. What you can now do:**

- **Clone & review a private repo** (token is injected into the clone URL,
  never printed):
  ```bash
  neurosploit whitebox https://github.com/myorg/private-app \
    --subscription --model anthropic:claude-opus-4-8 -v
  ```
- **Review a Pull Request's code** — clones the PR head (`refs/pull/N/head`):
  ```bash
  neurosploit pr myorg/private-app 128 \
    --subscription --model anthropic:claude-opus-4-8 --comment
  ```
  - `--comment` posts a Markdown findings summary back on the PR.
  - `--jira` also opens a card per finding (needs Jira configured).
- **Watch a branch** and re-review on every new commit:
  ```bash
  neurosploit watch myorg/private-app --branch main --interval 300 \
    --subscription --model anthropic:claude-opus-4-8
  ```
  It polls the branch tip via the GitHub API and runs a white-box review whenever
  the SHA changes (Ctrl-C to stop).
- **Gate a Pull Request** — block the merge when a confirmed finding is severe:
  ```bash
  neurosploit pr myorg/private-app 128 \
    --model anthropic:claude-opus-4-8 --comment --fail-on critical
  ```
  `--fail-on <critical|high|medium|low>` does three things when a **confirmed**
  finding is at/above the threshold: the CLI **exits non-zero** (so a CI check
  fails), it sets a **`neurosploit/security` commit status** of `failure` on the
  PR head, and it submits a **REQUEST_CHANGES** review. `needs-review` findings
  never trip the gate — only confirmed ones do.

**GitHub Enterprise:** `/integrations setup github` and set the API base to your
GHE URL (e.g. `https://ghe.mycorp.com/api/v3`).

### 3.1 Automations — GitHub Actions

Two workflows ship in [`examples/github-actions/`](examples/github-actions). Copy them into
your repo and add an `ANTHROPIC_API_KEY` Actions secret (or swap `MODEL` for a
provider you have a key for). The built-in `GITHUB_TOKEN` already covers commit
statuses, reviews and comments.

**PR gate — `neurosploit-pr-gate.yml`**
Runs on every pull request, reviews the code, and enforces the gate:
```bash
neurosploit pr "$REPO" "$PR_NUMBER" --model "$MODEL" --comment --fail-on critical -v
```
To make it actually block merges: *repo Settings → Branches → Branch protection
rule* on your default branch → **Require status checks to pass** → select
**`neurosploit-pr-gate`**. Add **Require a pull request review** to also honor the
REQUEST_CHANGES review it posts.

**`@neurosploit` mention bot — `neurosploit-mention.yml`**
Comment `@neurosploit` on a PR or issue to trigger a scan. Only users with
**write** access can trigger it (a permission check guards the model budget).
Everything after the mention is the instruction, in **any language**:

| Comment | Effect |
|---------|--------|
| `@neurosploit` | white-box review of this PR (blocks on critical) |
| `@neurosploit focus SQLi and IDOR` | same, steered by the focus |
| `@neurosploit scan https://staging.app` | black-box test of that URL |
| `@neurosploit foco em IDOR, fora de escopo /admin` | steered review (Portuguese) |

The bot reacts 👀 to acknowledge, then posts results back as a comment.

---

## 4. GitLab

**a. Create a token.** GitLab → *Preferences → Access Tokens* (or a project/group
token) with the **`read_repository`** scope (add `api` if you want more later).

**b. Export it and enable:**
```bash
export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
neurosploit integrations enable gitlab
# self-hosted? set the base:
#   /integrations setup gitlab   →  https://gitlab.mycorp.com
```

**c. Review a private GitLab repo** (token-injected clone, works in whitebox &
greybox):
```bash
neurosploit whitebox https://gitlab.com/myorg/private-svc \
  --subscription --model anthropic:claude-opus-4-8 -v
```

> To review a specific Merge Request, check out its source branch and point
> `whitebox` at that clone, or pass the MR source branch URL.

---

## 5. Jira

**a. Create an API token.** https://id.atlassian.com/manage-profile/security/api-tokens
→ *Create API token*. Note the email of the Atlassian account that owns it.

**b. Export credentials:**
```bash
export JIRA_EMAIL=you@yourorg.com
export JIRA_API_TOKEN=xxxxxxxxxxxxxxxxxxxx
```

**c. Configure base URL + project (once):**
```
# in the REPL:
/integrations setup jira
  Jira base URL (https://your-org.atlassian.net):  https://yourorg.atlassian.net
  Jira project key (e.g. SEC):                     SEC
  Issue type [Bug]:                                Bug
```
This enables Jira and saves the base URL / project key / issue type to
`.neurosploit/integrations.json` (no secrets).

**d. Open cards.** Add `--jira` to any engagement (or `pr` / `watch`). One card is
created per **validated** finding, with severity, CVSS, CWE, location, PoC,
evidence and remediation:
```bash
neurosploit whitebox https://github.com/myorg/app --jira \
  --subscription --model anthropic:claude-opus-4-8 -v
```
The created issue keys are printed (e.g. `🪪 Jira cards opened: SEC-481, SEC-482`).

> Uses the Jira REST API (`POST /rest/api/2/issue`) with Basic auth
> (`JIRA_EMAIL` : `JIRA_API_TOKEN`). The `issuetype` must exist in your project
> (use `Vulnerability` if your project defines it).

---

## 6. Recipes

**PR gate in CI** (block a PR if Critical/High findings appear):
```bash
export GITHUB_TOKEN=...   # CI secret
neurosploit integrations enable github
neurosploit pr "$REPO" "$PR_NUMBER" --model anthropic:claude-opus-4-8 --comment --jira
```

**Nightly drift review** of a private app, filing Jira cards:
```bash
neurosploit integrations enable github
neurosploit integrations enable jira
neurosploit watch myorg/app --branch main --interval 3600 --jira \
  --model anthropic:claude-opus-4-8
```

**Local private-repo audit** (no PR), cards to Jira:
```bash
neurosploit whitebox https://github.com/myorg/app --jira \
  --subscription --model anthropic:claude-opus-4-8 -v
```

---

## 7. Troubleshooting

- **`⚠ token env not set`** — the integration is enabled but the env var isn't
  exported in this shell. Export it (`export GITHUB_TOKEN=...`) and re-run.
- **`git clone failed` on a private repo** — confirm the token scope (`repo` /
  `read_repository`) and that the integration is enabled (`neurosploit
  integrations`). The token is only injected when the matching integration is on.
- **`jira create failed: 400`** — the `issuetype` name doesn't exist in the
  project, or a required field is enforced. Try `Bug`, or set your project's type
  via `/integrations setup jira`.
- **`jira ... not set`** — export `JIRA_EMAIL` and `JIRA_API_TOKEN`.
- **GitHub comment fails (403/404)** — the token needs *Pull requests: write*
  (fine-grained) or `repo` (classic), and you must have access to the repo.
- **Tokens in CI** — pass them as masked secrets; NeuroSploit never logs or
  stores token values.
