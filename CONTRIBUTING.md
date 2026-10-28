# Contributing to AEGIS

Read [AGENTS.md](AGENTS.md), [the four roles](docs/TEAM_WORKSTREAMS.md), and your module's README before editing. Roles are independent of people; no GitHub username is implied by this map.

## Branch map

| Branch | Purpose | Tracking issue |
|---|---|---|
| `dev/integration` | Accepted work and the default checkout | All roles |
| `feat/core-shield` | A — Core Platform, Shield & Integration | #9 |
| `feat/lab-mirage` | B — Adversarial AI Lab & Mirage | #10 |
| `feat/frontend` | C — Frontend & Product Experience | #11 |
| `feat/signature-sentinel` | D — Signature, Sentinel & Verification | #12 |

The four feature branches are working branches, not separate products or releases. PRs target `dev/integration`; workstreams exchange changes through that branch. No release branch is defined yet. `docs/*` branches are temporary review branches and are not extra engineering roles. Historical branches recorded in old ADRs do not need to be recreated.

## Start or resume work

These commands work in Bash and Fish. First inspect local changes; commit or otherwise preserve your work before switching. For role B, for example:

```sh
git status --short
git fetch origin --prune
git switch feat/lab-mirage
git merge --ff-only origin/feat/lab-mirage
git merge origin/dev/integration
```

In a fresh clone, `git switch` creates a local tracking branch when exactly one matching remote branch exists. If the fast-forward fails, inspect the divergent commits before proceeding; never use reset or force-push as a synchronization shortcut. Resolve any integration merge conflicts, run affected tests, and include the merge in the next push.

For independent work within a role, create a task branch from current integration instead:

```sh
git switch -c feat/lab-trial-manifest origin/dev/integration
```

Use `feat/`, `fix/` or `docs/` with a specific task name. Coordinate simultaneous edits on a shared role branch. Avoid squash-merging a long-lived role branch: a normal merge preserves ancestry for subsequent PRs. Squash is suitable for disposable task branches.

## Review and merge

Keep each PR focused and target `dev/integration`. Use the PR template to record the role, issue, behavior, affected interfaces, exact test commands and results. Report missing tools as **not run**. Never replace actual outcomes with a planned acceptance criterion.

Root/documentation changes follow the validation rules in AGENTS.md. Shared schemas, API, storage and security controls require review across the affected roles. Tests and review expectations are repository policy; they are not evidence that GitHub branch protection or CI has been enabled.

After merging, synchronize affected role branches through integration. Remove a temporary branch only after confirming its changes are merged and nobody is using it. Never delete an active role branch or rewrite another contributor's history.

## Documentation

The PDF User Guide is the short introduction; the Technical Documentation expands it. Both use roles A–D and issues #9–#12. [TEAM_WORKSTREAMS.md](docs/TEAM_WORKSTREAMS.md) tracks boundaries and [PROJECT_STATUS.md](docs/PROJECT_STATUS.md) tracks evidence and pending work. Keep these aligned when responsibilities change. Older PDFs remain recoverable in Git history.

The four-role PDF revision is reproducible with `python docs/tools/revise_four_roles.py` using PyMuPDF; it reads the original PDFs from commit `7752d39` and preserves unaffected pages. Render and inspect revised pages before committing generated PDFs.
