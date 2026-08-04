# NeuroSploit — GitHub Actions templates

Copy either file into your repository's `.github/workflows/` directory to enable
the automation. Add an `ANTHROPIC_API_KEY` secret (Settings → Secrets and
variables → Actions), or swap the `MODEL`/key for a provider you use. The built-in
`GITHUB_TOKEN` already covers commit statuses, PR reviews and comments.

| Template | What it does |
|----------|--------------|
| `neurosploit-pr-gate.yml` | Reviews every pull request and **blocks the merge** on a confirmed critical (fails the check + sets a `neurosploit/security` commit status + posts a REQUEST_CHANGES review). |
| `neurosploit-mention.yml` | Comment **`@neurosploit`** on a PR/issue (writers only) to trigger a scan. Text after the mention steers it, in any language; a URL runs a black-box test, otherwise it reviews the PR. |
| `ci.yml` | Rust CI for the `neurosploit-rs/` workspace — `cargo build` / `test` / `clippy -D warnings` on every push & PR. |

## Enforce the PR gate as a merge block

1. Add `neurosploit-pr-gate.yml` to `.github/workflows/` and let it run once on a PR.
2. Repo **Settings → Branches → Branch protection rule** on your default branch.
3. Enable **Require status checks to pass** and select **`neurosploit-pr-gate`**.
4. (Optional) Enable **Require a pull request review** so the REQUEST_CHANGES
   review it posts must be resolved/overridden before merge.

These live here (not in `.github/workflows/`) so this repo doesn't run them on
itself — they're templates for **your** repo.
