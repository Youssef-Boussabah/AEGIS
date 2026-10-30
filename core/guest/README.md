# Firecracker candidate guest: provisioning and containment validation

**Status (2026-10-29):** implemented and unit-tested; nothing below has been run. No VM, canary, package fetch or build has been executed. Real candidate execution stays disabled until a passing candidate-guest report is pinned **and** ADR 0004 is accepted in a reviewed change (`ADR_0004_ACCEPTED`).

## Provisioning without host package changes

Yes, provisioning can proceed without installing or upgrading host packages. Network access for the fetch steps needs approval.

| Need | Provided by | On this host |
|---|---|---|
| Debian packages | `debpack.py` (stdlib): verified fetch, dependency closure, unpack-only (no maintainer scripts), deterministic tar | python3 3.14 (`lzma`, `compression.zstd`) |
| archive signature | `gpgv` with an operator-supplied keyring; the signing-key fingerprint must be confirmed out of band | gpgv present; **no Debian keyring on the host**, so the operator supplies and confirms one |
| ext4 image | `mkfs.ext4 -d rootfs.tar` | e2fsprogs 1.47.4, loads `libarchive.so.13` (present) |
| kernel build | a pinned Debian toolchain tree from `debpack.py` (`builder-packages.json`), run inside rootless `bwrap` | the host lacks `bc`; this avoids needing it and pins the compiler |
| `mmdebstrap`, `debootstrap` | not used | absent; not needed |

## Guest image (`build-guest-image.sh`, `guest-packages.json`)

- **Packages:** `gcc`, `libc6-dev` and full `python3`, plus their dependency closure, from a pinned `snapshot.debian.org` timestamp. The minimal Python package split does not supply all of the agent's modules (`ctypes`, `socket`, `hmac`, `select`, `resource`). The script refuses to fetch until a snapshot is pinned. Actual guest imports/startup remain unvalidated until C0 boots the built image.
- **Excluded:** shells, `util-linux`/`mount`, login and `passwd`, `sudo`, `dpkg`/`debconf` and network tools.
- **No shell, no mount binary:** `/sbin/aegis-init` is a Python PID 1 that mounts with `mount(2)`. Every setuid/setgid bit is stripped, and the build lists what it stripped.
- **Agent and identities:** `/opt/aegis/lab_guest_agent.py` and `lab_vm_protocol.py` (stdlib only); `/etc/aegis/guest.json` holds the compiler's real path, version and SHA-256, which the agent re-hashes at start; `/etc/passwd` has `root` and `runner` (uid 1000) only.
- **Image format:** ext4 with a fixed UUID and hash seed, no journal, `SOURCE_DATE_EPOCH` clamping and sorted members, mode 0444. Firecracker attaches it `is_read_only`, the kernel mounts it `ro`, and bwrap binds it read-only.
- **Output:** `guest-manifest.json` with the image, agent and compiler digests to pin.

## Guest kernel (`build-guest-kernel.sh`, `aegis-kernel.fragment`)

- **Source:** latest 6.1.y LTS from kernel.org; the SHA-256 comes from the signed `sha256sums.asc`, verified against a key confirmed at kernel.org.
- **Base config:** Firecracker v1.17.0's `microvm-kernel-ci-x86_64-6.1.config`, pinned by SHA-256.
- **Fragment** (enforced by `kernel_config_check.py`):
  - required: virtio-mmio and virtio-blk, ext4, vsock, cgroups (memory, pids, sched), tmpfs, devtmpfs;
  - **forbidden:** `INET` (no IP stack at all), `PACKET`, `VIRTIO_NET`, `MODULES`, `USER_NS`, `BPF_SYSCALL`, `USERFAULTFD`, `IO_URING`, `KEXEC`, `DEVMEM`, 9p, virtio-fs, FUSE and balloon.
- **Build:** `make vmlinux` inside rootless `bwrap` with the pinned Debian toolchain and fixed `KBUILD_BUILD_*`.

## Containment validation (`aegis_core.lab_containment`, `canaries/`)

- **Canaries:** trusted, deterministic C programs written by Role A. Each prints one `AEGIS-CANARY <name> k=v ...` line, or is judged by the observed limit.
- **Runtime:** the driver uses a **validation-mode** runtime. It cannot serve a session, compiles only sources whose digests are in `canaries/manifest.json`, executes only binaries it compiled, and is the only mode allowed to change boot arguments (the smoke fixture boots its own init).
- **Report:** `aegis.core.containment-report.v1`. Check verdicts and the overall verdict are recomputed from the case results on load, so a hand-edited report is invalid.

| Check | Cases (VM) | Proves |
|---|---|---|
| C0 | control | a trusted canary compiles and runs (positive control) |
| V1 | net | IPv4/IPv6 TCP and UDP, AF_PACKET and vsock to the host and to the agent all fail |
| V2 | fs | no `/home` or host files, no `/dev/kvm`; `/dev/vda`, `/proc/1`, `mount`, `chroot` and user namespaces are denied; no setid files |
| V3 | fs, rootfs_unchanged | writes to `/`, `/usr` and `/etc` fail; the image digest is unchanged after all runs |
| V4 | forkbomb | `limit_exceeded: processes` |
| V5 | memory, scratch | `limit_exceeded: memory`; scratch writes stop at the bound (ENOSPC or EFBIG) |
| V6 | spin, sleeper | `limit_exceeded: cpu`; `timeout` even after the program closes its outputs |
| V7 | flood_stdout, flood_stderr, bigbinary | output cut at limit + 1; `limit_exceeded: binary` at compile |
| V8 | identity | uid/gid 1000, no groups, `CapEff 0`, `NoNewPrivs 1` |
| V9 | teardown_verified, backstop, no_leftovers | the VMM is gone and the scope empty after kill; `RuntimeMaxSec` stops an abandoned VM; no `aegis-fc-*` scopes and an empty state dir at the end |
| V10 | readback_mismatch, pin_mismatch, report_enforcement | a wrong cgroup read-back, a wrong kernel pin, and a missing, failed, foreign, smoke or mismatched report all refuse |
| V11 | orphan (+ teardown_verified) | a detached daemon does not outlive the job or VM |
| F1 | jail_view | the VMM root holds only `dev proc run tmp vm`; mounts are exactly the jail's |
| F2 | host_sockets_and_netns, net | one vsock socket and no API socket; the VMM network namespace has only `lo`; the guest has only `lo` |
| F3 | vmm_seccomp | `Seccomp: 2`, `NoNewPrivs: 1`, `CapEff: 0` on every VMM thread |
| F4 | memory | the guest cgroup handles the overrun; host scope peak ≤ `MemoryMax`, no host OOM kill |
| F5 | 5 fuzz cases | garbage, a bad-tag HELLO, an oversized header, a truncated HELLO and a bad-tag JOB get no answer, and the guest powers off by itself |

## First trusted containment test: smoke fixture, host-observable checks

This test boots the approved Ubuntu smoke fixture, with its drive **read-only**, three times in sequence. No canary and no candidate runs, and the agent is not involved. It covers F1, F2 (host side), F3, V9, V10 and V3 (image unchanged).

**Privileges:**
- the operator's uid only; no sudo;
- the systemd **user** manager (transient scopes);
- unprivileged user namespaces (bwrap);
- read-write `/dev/kvm`.

There is no network access, and the VMs have no network device.

**Resources:**
- 3 VMs, one at a time;
- each VM: 321 MiB guest RAM, scope `MemoryMax` 385 MiB, no swap, `TasksMax` 16, `CPUQuota` 100% (one vCPU);
- worst-case wall time 179 s;
- block reads ≤ 64 MiB/s;
- no disk writes besides the report.

Preflight additionally holds sealed, hashed copies of the four pinned assets in
host memory (combined maximum 2 GiB), outside the VM's scope. The plan reports
this bound separately. Launch uses held `/proc/<Core pid>/fd` aliases so path
replacement and in-place modification cannot change a verified asset. Existing
smoke assets total about 343 MiB; no copies were made during the read-only
prerequisite review. Namespace access to these aliases and actual launch are
part of the still-pending live checks. The updated report identity invalidates
reports from the earlier path-based launch design.

**Files created:**
- `~/.local/share/aegis-vm/validation/smoke.toml` (config copy);
- `/run/user/<uid>/aegis-fc/` (0700, tmpfs), holding per-VM `config.json` and `sock/vsock.sock`, each removed after its VM;
- transient units `aegis-fc-<id>.scope`, collected automatically and capped by `RuntimeMaxSec`;
- the report file (0600, never overwritten).

```sh
cd /home/youss/Projects/aegis-core-lab-execution
export PYTHONPATH=$PWD/core/src PYTHONDONTWRITEBYTECODE=1
PY=/home/youss/Projects/aegis/.venv/bin/python
V=$HOME/.local/share/aegis-vm/validation
mkdir -p "$V"
sed "s|/home/OPERATOR|$HOME|g; s|/run/user/OPERATOR_UID|/run/user/$(id -u)|g" \
  core/guest/validation-smoke.toml.example > "$V/smoke.toml"

# No VM: static checks and the plan.
$PY -m aegis_core.lab_host --runtime firecracker
$PY -m aegis_core.lab_containment plan --config "$V/smoke.toml" --target smoke_fixture
sha256sum "$HOME/.local/share/aegis-vm/boot-test/smoke-rootfs.ext4"     # expect a7df8e91...44e5

# Boots 3 VMs (APPROVAL REQUIRED).
$PY -m aegis_core.lab_containment run --config "$V/smoke.toml" --target smoke_fixture \
  --report "$V/smoke-report-$(date -u +%Y%m%dT%H%M%SZ).json" --approve-vm-launch
echo "exit=$?"   # 3 = incomplete (expected for smoke), 1 = a check failed, 0 is impossible for smoke

# Afterwards.
sha256sum "$HOME/.local/share/aegis-vm/boot-test/smoke-rootfs.ext4"     # unchanged
systemctl --user list-units 'aegis-fc-*' --all --no-legend               # nothing
ls -A "/run/user/$(id -u)/aegis-fc"                                      # empty
```

**Expected result:** `overall: "incomplete"` (exit 3). These cases pass: `jail_view`, `vmm_seccomp`, `host_sockets_and_netns`, `teardown_verified`, `backstop`, `readback_mismatch`, `pin_mismatch`, `report_enforcement`, `no_leftovers` and `rootfs_unchanged`. The guest cases stay `not_run`. Any `failed` or `error` case is a finding: candidate execution remains disabled, and the case's `observed` and `failures` say why.

**Rollback** (nothing persistent is changed; use this only if a run is interrupted):

```sh
for u in $(systemctl --user list-units 'aegis-fc-*' --all --no-legend --plain | awk '{print $1}'); do
  systemctl --user kill --signal=SIGKILL "$u"; systemctl --user stop "$u"
done
pkill -KILL -f '^/vm/firecracker --no-api' || true     # only jailed AEGIS VMMs have this argv[0]
rm -rf "/run/user/$(id -u)/aegis-fc"
sha256sum "$HOME/.local/share/aegis-vm/boot-test/smoke-rootfs.ext4"   # still a7df8e91...44e5
```

No packages, system settings, persistent units or host files outside the paths above are touched. A VM can never outlive its `RuntimeMaxSec`: 53 s at most here (20 s for the backstop VM).

## Later: candidate-guest validation (after the image and kernel exist)

```sh
$PY -m aegis_core.lab_containment plan --config "$V/candidate.toml" --target candidate_guest   # 33 VMs
$PY -m aegis_core.lab_containment run  --config "$V/candidate.toml" --target candidate_guest \
  --report "$V/candidate-report.json" --approve-vm-launch                                     # exit 0 only if all pass
```

`candidate.toml` pins the new kernel, image, agent and compiler digests from the build manifests. Each VM uses at most 704 MiB of guest RAM (768 MiB scope) for the compile stages and runs one at a time.

Only a report with exit 0 may be pinned, by setting `containment_report_path` and `containment_verification_sha256` (its SHA-256). Changing any pinned artifact or host control later invalidates it. Even then, execution stays refused until ADR 0004 is accepted in a reviewed change.

## Real-VM failure paths reviewed (not observable with the fake VMM)

| Path | Handling |
|---|---|
| `cgroup.kill` not writable or failing | teardown falls back to killing bwrap's process group (only while the child is unreaped, so the id cannot be reused); `--die-with-parent` and the PID namespace stop Firecracker; the cleanup is still marked failed |
| systemd-run fails (no user bus) | detected at once as `sandbox_start_failed`, not after the boot timeout |
| Core killed mid-run | `RuntimeMaxSec` stops the scope (V9 backstop); stale per-VM directories without a scope are swept at the next preflight (only when older than max(60 s, 2 × boot timeout)) |
| Firecracker non-dumpable | jail view, mounts and netns are read through its bwrap parent, which shares those namespaces; task status files stay world-readable |
| Firecracker renames threads | the VMM is identified by argv[0] `/vm/firecracker`, not by `comm` |
| a candidate keeps running after closing stdout/stderr | supervision continues until exit or the deadline (it used to report `signaled`); now `timeout` |
| setuid binaries in the image (Debian's `mount`, `su`) | not in the image (excluded), and the builder strips setid bits; `PR_SET_NO_NEW_PRIVS` is set before exec; scratch is `nosuid,nodev` |
| compiler temporaries in the shared 8 MiB `/tmp` | `TMPDIR` points to the bounded per-job scratch |
| guest kernel attack surface | no IP stack, no user namespaces, no BPF, io_uring, userfaultfd or modules (kernel fragment) |
| a guest closing a connection with host bytes unread | an `ECONNRESET` on the host counts as a refusal (F5), not an answer |
| reaped child with output still in pipes | drain to EOF after killing descendants; each stream retains at most cap + 1 bytes |
| many children each below `RLIMIT_CPU` | poll aggregate job cgroup CPU usage during execution every 10 ms; kill at the budget, with possible polling overshoot; missing accounting fails closed |
| teardown/verification/removal fails | retain tracking and state, refuse further runs, retry on `close()`; keep sealed asset descriptors until teardown verifies |
| guest success alongside a host OOM/deadline | host observation takes precedence; discard any claimed compile binary |
| mutable pinned paths | launch sealed asset copies, hashed while copied and held through teardown; real launch still unvalidated |
| glibc without `ld.so.cache` (unpack-only image) | relies on Debian's built-in multiarch search paths; if the agent does not start, READY times out and the run fails closed (`sandbox_start_failed`). Verified by C0 once the image exists |
| host page cache from reading the image | charged to the VM's scope; reclaimable, so not an OOM risk |
