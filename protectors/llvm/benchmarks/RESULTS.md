# Measured baseline versus transformed executable

The raw measurement is in
[results/llvm22-linux-x86_64.json](results/llvm22-linux-x86_64.json).
It was collected on 2026-10-28 UTC (2026-10-27 in America/Toronto), using the
installed LLVM/Clang 22.1.8 on Linux x86-64, Intel Core Ultra 9 185H.

The command, from the repository root, was:

```sh
python3 protectors/llvm/benchmarks/benchmark.py \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --output protectors/llvm/benchmarks/results/llvm22-linux-x86_64.json
```

Clang O1 generated input IR for one annotated integer dependency-chain kernel.
The plugin expanded three adds with seed 42. Both baseline and transformed IR
were compiled to objects with Clang O2 and linked to the same C runner. Each
executable received one warmup followed by nine alternating samples, each
containing 20,000,000 calls. Timing uses the runner's monotonic wall clock and
excludes compilation and process launch.

| Measurement | Baseline | Transformed |
| --- | ---: | ---: |
| Median seconds | 0.073364098 | 0.091700455 |
| Min–max seconds | 0.065757773–0.083706625 | 0.081079862–0.102784737 |
| Kernel `.text` bytes | 51 | 60 |
| Executable bytes | 16,256 | 16,256 |
| IR bytes | 1,838 | 2,795 |
| Result checksum | `3ee3ed446eb83a2d` | `3ee3ed446eb83a2d` |

The transformed/baseline median ratio was **1.24994**, about **25% slower** for
this kernel on this run. Kernel `.text` hashes differ, so these expansions
changed optimized machine code as well as IR in this particular benchmark.
Whole executable size stayed equal because file layout/alignment obscured the
nine extra kernel bytes. Machine-code differences are not guaranteed elsewhere.

This is one small workload on an unpinned shared host. Scheduling, CPU frequency,
and thermal variation affect wall time; the sample ranges show substantial
noise. There is no statistical confidence claim or application-level overhead
estimate. A rerun can differ. No compile-time or memory benchmark is included.
Matching checksums complement the broader runtime tests and the arithmetic
identities; they do not prove all-program equivalence. Changed IR, changed code,
and measured overhead do not demonstrate resistance to reverse engineering or
any other security property.
