# Reconstruction benchmark results

Generated from actual final binaries and owned oracle runs.
No reverse-engineering resistance or general security property is established.

Measured at: 2026-10-30T12:42:42.356567Z. CPU: Intel(R) Core(TM) Ultra 9 185H. Platform: Linux-7.2.3-1-cachyos-x86_64-with-glibc2.44.
LLVM: 22.1.8; Python: 3.14.7; seed: 42.
Timing: 9 samples per variant, 1 warmup, 2,000,000 iterations/sample; both target functions per iteration. Process wall time, shared host, no CPU pinning.

| Variant | ELF bytes | .text bytes | Target symbols / dynamic exports | Target bytes vs baseline | Mirage retained | Oracle cases | Wall median [min, max] ms | Behavioral evidence |
| --- | ---: | ---: | --- | --- | --- | --- | --- | --- |
| baseline | 16240 | 777 | 2/2 / 0 | identical | 0/0 | passed 24 | 7.588 [7.332, 9.431] | absent; scoring unavailable |
| shield | 16240 | 809 | 2/2 / 0 | different_not_attributed | 0/0 | passed 24 | 10.374 [9.782, 12.597] | absent; scoring unavailable |
| shield_mirage | 16416 | 953 | 2/2 / 0 | different_not_attributed | 3/3 | passed 24 | 10.071 [9.535, 11.151] | absent; scoring unavailable |

Exact final artifact SHA-256:

- `baseline`: `39904cead0d859e79cb2f1207d566647b5f3842ad424143c5fcae50b6f51f00b`
- `shield`: `1607e36c12900af4e34ecc01a4a4ac4fd183a8aabbd12b102424789c8730b1c7`
- `shield_mirage`: `b0e25b4d3793f87b00bde40d831450e93914c28f494686f593d7635417c22176`

Imported analysis and reconstruction evidence:

Absent. No attack was scored. Behavioral scoring is unavailable without validated isolation.

Comparison identity (canonical JSON SHA-256): `b769899ebc28ccbdc50ca94cf0f82637d0e1786b4759174470062b210da0ba1f`.
Frozen oracle SHA-256: `2b333ba0e867b91684d73d19cae732c4443aa6499616a88a75bcf92c3aa0b6b4`.

Shield IR sites reported (module / selected targets): baseline=0/0, shield=5/5, shield_mirage=5/5.
Function byte comparisons measure structural differences. They do not attribute a particular retained Shield transformation, and they do not establish attack resistance. Mirage retention counts show defined executable function bodies in the final ELF, not whether an analyst was misled.

Limitations:

- Single owned fixture, 2 selected uint32 functions, 24 public cases; finite regression evidence only.
- Unpinned shared host; process wall timings include startup, scheduling and frequency noise.
- Symbol and machine-byte observations are structural, not reverse-engineering resistance.
- Shield site counts are plugin claims; final target bytes are independently read from the ELF.
- The owned measurement run performed no Ghidra, REA, model request or candidate compilation/execution.
- Build metadata and evidence files are unsigned; hashes check consistency, not origin.

Reproduce using the commands in [README.md](README.md). `measured-results.json` retains all raw timing samples, commands, compiler/tool hashes, source hashes, build flags and the comparison manifest. Full binary/IR/report archives stay outside the repository.
