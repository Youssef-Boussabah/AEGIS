#!/usr/bin/env python3
"""Generate the small, deterministic ImageLab test fixtures.

    make_fixtures.py --write DIR   write every fixture into DIR
    make_fixtures.py --check DIR   fail if DIR's fixtures differ from a fresh run

The fixtures are tiny (at most 33x17 pixels) and exercise: odd sizes, 1x1,
single rows and columns, hard edges, saturated values, varied alpha, P6 PPM
input and three-channel PAM input. Generation uses SplitMix64 with fixed
seeds and only integer arithmetic, so output is byte-identical everywhere.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

MASK64 = (1 << 64) - 1


class SplitMix64:
    def __init__(self, seed: int) -> None:
        self.state = seed & MASK64

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return z ^ (z >> 31)


def pam(width: int, height: int, pixels: list[tuple[int, ...]], depth: int = 4) -> bytes:
    tupltype = "RGB_ALPHA" if depth == 4 else "RGB"
    header = (f"P7\nWIDTH {width}\nHEIGHT {height}\nDEPTH {depth}\nMAXVAL 255\n"
              f"TUPLTYPE {tupltype}\nENDHDR\n").encode("ascii")
    return header + bytes(v for px in pixels for v in px[:depth])


def ppm(width: int, height: int, pixels: list[tuple[int, ...]]) -> bytes:
    header = f"P6\n# ImageLab fixture\n{width} {height}\n255\n".encode("ascii")
    return header + bytes(v for px in pixels for v in px[:3])


def gradient(w: int, h: int) -> list[tuple[int, ...]]:
    return [((x * 255) // (w - 1), (y * 255) // (h - 1), ((x + y) * 255) // (w + h - 2),
             255 - (x * 255) // (w - 1)) for y in range(h) for x in range(w)]


def checker(w: int, h: int) -> list[tuple[int, ...]]:
    return [((240, 16)[((x // 2) + (y // 2)) & 1],) * 3 + (255,)
            for y in range(h) for x in range(w)]


def noise(w: int, h: int, seed: int) -> list[tuple[int, ...]]:
    rng = SplitMix64(seed)
    out = []
    for _ in range(w * h):
        r = rng.next()
        out.append(tuple((r >> (8 * i)) & 0xFF for i in range(4)))
    return out


def extremes() -> list[tuple[int, ...]]:
    values = [0, 1, 127, 128, 254, 255]
    out = []
    for y in range(4):
        for x in range(6):
            out.append((values[x], values[(x + y) % 6], values[(5 - x + 2 * y) % 6],
                        values[(x * y) % 6]))
    return out


def edges(w: int, h: int, seed: int) -> list[tuple[int, ...]]:
    rng = SplitMix64(seed)
    out = []
    for y in range(h):
        for x in range(w):
            r = rng.next()
            step = 180 if x >= w // 2 else 40
            ramp = (y * 200) // (h - 1)
            n = [((r >> (8 * i)) & 7) - 3 for i in range(3)]
            out.append((min(255, max(0, step + n[0])), min(255, max(0, ramp + n[1])),
                        min(255, max(0, (step + ramp) // 2 + n[2])), (r >> 32) & 0xFF))
    return out


def fixtures() -> dict[str, bytes]:
    return {
        "gradient_17x9.pam": pam(17, 9, gradient(17, 9)),
        "checker_8x8.pam": pam(8, 8, checker(8, 8)),
        "noise_13x7.pam": pam(13, 7, noise(13, 7, 0x1A6E)),
        "extremes_6x4.pam": pam(6, 4, extremes()),
        "single_1x1.pam": pam(1, 1, [(200, 30, 90, 128)]),
        "row_9x1.pam": pam(9, 1, noise(9, 1, 0x50)),
        "column_1x6.pam": pam(1, 6, noise(1, 6, 0x60)),
        "edges_33x17.pam": pam(33, 17, edges(33, 17, 0xED6E)),
        "rgb_5x3.ppm": ppm(5, 3, noise(5, 3, 0x56)),
        "rgb_4x2.pam": pam(4, 2, noise(4, 2, 0x42), depth=3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", type=Path, metavar="DIR")
    mode.add_argument("--check", type=Path, metavar="DIR")
    args = parser.parse_args()

    generated = fixtures()
    if args.write:
        args.write.mkdir(parents=True, exist_ok=True)
        for name, data in generated.items():
            (args.write / name).write_bytes(data)
        print(f"wrote {len(generated)} fixtures to {args.write}")
        return 0

    failures = 0
    for name, data in generated.items():
        path = args.check / name
        if not path.is_file() or path.read_bytes() != data:
            print(f"FAIL {name}: missing or different from a fresh generation")
            failures += 1
    extra = sorted(p.name for p in args.check.iterdir()
                   if p.suffix in (".pam", ".ppm") and p.name not in generated)
    for name in extra:
        print(f"FAIL {name}: not produced by the generator")
        failures += 1
    print(f"{len(generated)} fixtures checked; {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
