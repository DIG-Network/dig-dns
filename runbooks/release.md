# Runbook — releasing dig-dns (nightly cron + manual dispatch)

How this repo's `dig-dns` binary + native OS packages (.msi/.pkg/.deb) are built and released. The
shape is copied from the ecosystem's **reference nightlies system** (`dig-updater`, dig_ecosystem
#590/#592); the normative contract is `SPEC.md` §16. (General ops live in `runbooks/dig-dns.md`.)

## TL;DR

- Releases are **NOT cut on merge to `main`**, and **NOT cut at midnight either** — the nightly cron
  drives the nightly channel only. They are batched to **manual dispatch** for stable, plus the
  **nightly cron at midnight UTC** for the nightly pre-release.
- **Stable** (`vX.Y.Z`): cut ONLY by a manual `workflow_dispatch` — never by the cron (CLAUDE.md
  §3.6-A). The run detects a bump as "the `vX.Y.Z` tag doesn't exist yet" and cuts it.
  `prerelease: false`, marked `latest`. Builds the binary + `digd` alias + native
  `.msi`/`.pkg`/`.deb`.
- **Nightly**: built every night from `main` HEAD as a **pre-release** under a dated tag
  `nightly-YYYYMMDD` + a rolling `nightly` tag. `prerelease: true`, never `latest`. Keeps 14.

## Prerequisites / credentials

- **`RELEASE_TOKEN`** — an org-level classic PAT (the ecosystem release token). Both channels no-op
  with a warning if it is absent. Used to push the changelog commit past branch protection and to
  push tags that trigger downstream workflows (`GITHUB_TOKEN` cannot do either).

## If nightlies silently stop — check for the 60-day cron auto-disable

GitHub disables a `schedule:` trigger after **60 days of no repo activity** on a public repo, with
**no automatic re-enable** — and since this cron is the *only* automatic release trigger of any kind
(stable is dispatch-only, always), a quiet repo's **nightly** channel can go dark with no error.
Stable is unaffected either way — it never ran off the cron. If nightlies stop appearing:

```bash
gh api repos/DIG-Network/dig-dns/actions/workflows/nightly-release.yml --jq .state
# "disabled_inactivity" means GitHub turned it off — re-enable it:
gh workflow enable nightly-release.yml --repo DIG-Network/dig-dns
```

Any repo activity (a merged PR, a manual dispatch) resets the 60-day counter.

## Cut a STABLE release (manual dispatch — the ONLY path)

**Nothing releases on merge, and nothing releases at midnight either.** A stable `vX.Y.Z` is cut
ONLY by a manual dispatch (CLAUDE.md §3.6-A) — the midnight cron runs the nightly channel alone and
can never cut a stable release, bumped version or not.

1. In your feature PR, bump `version` in `Cargo.toml` per SemVer and run `cargo update -p dig-dns`
   so `Cargo.lock` matches. Merge the PR (squash) as usual.
2. Dispatch the release: Actions → **Nightly + stable release** → **Run workflow** →
   `channel: stable` (or `both`) → Run. It sees the new version has no `vX.Y.Z` tag, regenerates
   `CHANGELOG.md`, commits `chore(release): vX.Y.Z` to `main`, tags it, and pushes with
   `RELEASE_TOKEN`.
3. The pushed `v*` tag fires `release.yml`, which builds every OS/arch + native package and
   publishes the stable GitHub Release. The Ubuntu `.deb` is then ingested + GPG-signed by
   apt.dig.net (#425).

### Re-cut / re-release the current version (e.g. after a failed build)

Actions → **Nightly + stable release** → **Run workflow** → `channel: stable`, **`force: true`** →
Run. `force` REFUSES (non-zero exit) when the tag already has a PUBLISHED release AND points at a
different commit than this run would build — it only proceeds for a same-commit retry or a tag with
no published release. To ship new code, bump `Cargo.toml` instead.

## Cut a NIGHTLY on demand

Actions → **Nightly + stable release** → **Run workflow** → `channel: nightly` (or `both`) → Run.

## Verify a release went live

- **Stable:** `gh release view vX.Y.Z --repo DIG-Network/dig-dns` — raw binaries + `digd` + native
  `.msi`/`.pkg`/`.deb`, `prerelease: false`, marked latest. Watch: `gh run watch <id>`.
- **Nightly:** `gh release view nightly --repo DIG-Network/dig-dns` (rolling) or
  `gh release view nightly-YYYYMMDD` — `prerelease: true`.

## Workflows

| File | Trigger | Role |
|---|---|---|
| `nightly-release.yml` | `workflow_dispatch` only (stable) · midnight-UTC cron or `workflow_dispatch` (nightly) | Orchestrator: stable (changelog + tag, dispatch-only) + nightly (build + pre-release + prune). |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release for a `vX.Y.Z` tag. |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS build + native packages (both channels call it). |
| `ci.yml` | PR + push to main | fmt/clippy/test/coverage + the cross-OS service-smoke matrix (pre-merge). |

## Local build (dev)

```bash
cargo build --release --locked
cargo test  --locked        # includes the workflow-shape guard tests
```
