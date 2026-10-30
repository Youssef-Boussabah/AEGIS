# Final dashboard handoff

The workspace now connects Protect → Verify → Evaluate → Results while retaining
the existing pages and real job lifecycle. Both supported protection profiles use
actual health registrations and documented adapter options. Artifact downloads
check the exact bytes in the browser after the API's own integrity/policy checks.

Provenance and Sentinel use [Agent 1's contract](../../docs/release/FINAL_API_CONTRACT.md).
The UI distinguishes verified/unsigned/failed signatures, configured/unconfigured
services, invalid policies, current permitted/denied decisions and request failures.
Results retain the timestamp of the last verification, never a permanent trust claim.

The Lab uses [Agent 2's public contract](../../attack_lab/docs/public-summary.md),
with an exact schema snapshot, recursive extra-field rejection and semantic checks.
Provider identity and usage are reported observations. Billing remains unknown;
reservations and estimates are labeled separately. Synthetic fixtures are visible
as synthetic. Comparisons never claim behavioral reconstruction or protection.

All source edits for this assignment are within `platform/dashboard/`. Other agents'
existing edits were preserved. No commit, push, reset, installation or live provider
request was performed. Root architecture and release synchronization remain with
Agent 1, as required by this assignment's exclusive ownership.

See [README](README.md) for setup/contracts and [validation](VALIDATION.md) for exact
commands, results, limitations and changed files.

The optional post-hoc parser review extension is also consumed through the public
schema. Original generation/candidate states stay unchanged; revalidation has its
own parser, status, envelope validity and safe hashes. Reviews remain text-only
and behaviorally unscored. Private nested review data fails import.
