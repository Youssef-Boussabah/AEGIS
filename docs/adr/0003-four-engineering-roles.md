# ADR 0003: Four engineering roles and shared integration

- **Status:** Accepted
- **Date:** 2026-10-28
- **Scope:** Role boundaries, branches and onboarding documentation

## Context

The original onboarding documents split work into six assignments. The current
team plan combines them into four roles. Branches, issues and documentation must
describe the same structure without assuming who will fill a role.

## Decision

Use A Core Platform/Shield/Integration (#9), B Adversarial AI Lab/Mirage (#10),
C Frontend/Product Experience (#11), and D Signature/Sentinel/Verification (#12).
The canonical paths and branch map live in TEAM_WORKSTREAMS.md and CONTRIBUTING.md.
All roles integrate through reviewed PRs to dev/integration. Existing protocol,
package and security boundaries remain unchanged. Role branches are synchronized
without rewriting work. No new release branch or person assignment is introduced.

Revise the role sections of both PDFs and retain the historical implementation
evidence at c995857. Original documents remain available in Git history. ADR 0001
remains a historical record of the initial two-branch implementation; its old
branch names are not current onboarding instructions.

## Consequences

Shield and integration share one role; Lab and Mirage share another. Their
technical components remain separate. Shared contracts still need cross-role
review. CI and branch protection are separate pending implementation tasks;
documenting this workflow does not enable either service.
