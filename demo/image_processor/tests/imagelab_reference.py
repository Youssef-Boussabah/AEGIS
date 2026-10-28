"""Independent reference model of AEGIS ImageLab (Python standard library only).

This module re-implements the README "Numeric semantics" directly, using
exact rational arithmetic (fractions.Fraction) and Python's unbounded signed
integers. It shares no code with the C++ library: no bias tricks, no fixed
integer widths, its own Netpbm codec. Tests compare the C++ CLI against it
byte for byte.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction

MAX_DIMENSION = 32768
MAX_PIXELS = 1 << 26

# Parameter sets used by the reference test and the variant comparison.
# Each entry: (operation, {option: value}). Values are CLI option values.
PARAMETER_SETS: list[tuple[str, dict[str, int]]] = [
    ("tone", {}),
    ("tone", {"exposure-q8": 512, "knee": 16384}),
    ("tone", {"exposure-q8": 64, "knee": 1 << 20}),
    ("tone", {"exposure-q8": 4096, "knee": 1}),
    ("tone", {"exposure-q8": 1, "knee": 1}),
    ("color", {}),
    ("color", {"saturation-q8": 0}),
    ("color", {"saturation-q8": 1024, "contrast-q8": 1024, "brightness": 255}),
    ("color", {"saturation-q8": 512, "contrast-q8": 128, "brightness": -40}),
    ("color", {"saturation-q8": 300, "contrast-q8": 900, "brightness": -255}),
    ("enhance", {}),
    ("enhance", {"amount-q8": 0, "threshold": 0}),
    ("enhance", {"amount-q8": 1024, "threshold": 0}),
    ("enhance", {"amount-q8": 512, "threshold": 255}),
    ("enhance", {"amount-q8": 777, "threshold": 3}),
]

DEFAULTS = {
    "tone": {"exposure-q8": 256, "knee": 65280},
    "color": {"saturation-q8": 256, "contrast-q8": 256, "brightness": 0},
    "enhance": {"amount-q8": 256, "threshold": 8},
}


def case_id(op: str, params: dict[str, int]) -> str:
    """Stable identifier, e.g. 'tone:exposure-q8=512,knee=16384'."""
    full = dict(DEFAULTS[op])
    full.update(params)
    return op + ":" + ",".join(f"{k}={full[k]}" for k in sorted(full))


@dataclass
class Image:
    width: int
    height: int
    pixels: list[tuple[int, int, int, int]]  # row-major RGBA

    def at(self, x: int, y: int) -> tuple[int, int, int, int]:
        x = min(max(x, 0), self.width - 1)
        y = min(max(y, 0), self.height - 1)
        return self.pixels[y * self.width + x]


def clamp255(v: int) -> int:
    return 0 if v < 0 else 255 if v > 255 else v


def round_half_up(q: Fraction) -> int:
    return math.floor(q + Fraction(1, 2))


# ---- Operations -----------------------------------------------------------

def tone_channel(c: int, exposure_q8: int, knee: int) -> int:
    m = 255 * 256
    e = c * exposure_q8
    y = Fraction(255 * e * (m + knee), m * (e + knee))
    return min(255, round_half_up(y))


def color_channel(c: int, luma: int, sat: int, con: int, bri: int) -> int:
    s1 = clamp255(math.floor(Fraction((c - luma) * sat, 256) + luma + Fraction(1, 2)))
    s2 = clamp255(math.floor(Fraction((s1 - 128) * con, 256) + 128 + Fraction(1, 2)))
    return clamp255(s2 + bri)


def enhance_channel(c: int, n: int, s: int, w: int, e: int, amount: int, t: int) -> int:
    blur = math.floor(Fraction(4 * c + n + s + w + e, 8) + Fraction(1, 2))
    rng = max(c, n, s, w, e) - min(c, n, s, w, e)
    gate = 0 if rng <= t else min(16 * (rng - t), 256)
    delta = Fraction((c - blur) * amount * gate, 65536)
    return clamp255(math.floor(c + delta + Fraction(1, 2)))


def apply(op: str, params: dict[str, int], img: Image) -> Image:
    p = dict(DEFAULTS[op])
    p.update(params)
    out: list[tuple[int, int, int, int]] = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b, a = img.at(x, y)
            if op == "tone":
                g_, k = p["exposure-q8"], p["knee"]
                out.append((tone_channel(r, g_, k), tone_channel(g, g_, k),
                            tone_channel(b, g_, k), a))
            elif op == "color":
                luma = math.floor(Fraction(77 * r + 150 * g + 29 * b, 256) + Fraction(1, 2))
                args = (luma, p["saturation-q8"], p["contrast-q8"], p["brightness"])
                out.append((color_channel(r, *args), color_channel(g, *args),
                            color_channel(b, *args), a))
            elif op == "enhance":
                nb = [img.at(x, y), img.at(x, y - 1), img.at(x, y + 1),
                      img.at(x - 1, y), img.at(x + 1, y)]
                out.append(tuple(
                    enhance_channel(*(px[i] for px in nb), p["amount-q8"], p["threshold"])
                    for i in range(3)) + (a,))
            else:
                raise ValueError(f"unknown operation {op}")
    return Image(img.width, img.height, out)


# ---- Netpbm codec ---------------------------------------------------------

class FormatError(ValueError):
    pass


def _p7_header(data: bytes) -> tuple[dict[str, str], int]:
    pos = 3
    fields: dict[str, str] = {}
    while True:
        end = data.find(b"\n", pos)
        if end < 0 or end > 4096:
            raise FormatError("no ENDHDR")
        line = data[pos:end].decode("ascii").strip(" \t\r")
        pos = end + 1
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        if key == "ENDHDR":
            return fields, pos
        if key in fields:
            raise FormatError("duplicate key")
        fields[key] = value.strip()


def decode(data: bytes) -> Image:
    if data.startswith(b"P7\n"):
        fields, pos = _p7_header(data)
        width, height, depth = (int(fields["WIDTH"]), int(fields["HEIGHT"]),
                                int(fields["DEPTH"]))
        if fields.get("MAXVAL") != "255" or depth not in (3, 4):
            raise FormatError("unsupported PAM")
    elif data.startswith(b"P6"):
        tokens: list[int] = []
        pos = 2
        while len(tokens) < 3:
            while data[pos:pos + 1].isspace() or data[pos:pos + 1] == b"#":
                if data[pos:pos + 1] == b"#":
                    pos = data.index(b"\n", pos)
                pos += 1
            start = pos
            while data[pos:pos + 1].isdigit():
                pos += 1
            tokens.append(int(data[start:pos]))
        pos += 1
        width, height, maxval = tokens
        depth = 3
        if maxval != 255:
            raise FormatError("unsupported PPM")
    else:
        raise FormatError("unsupported magic")
    payload = data[pos:]
    if len(payload) != width * height * depth:
        raise FormatError("payload size")
    pixels = []
    for i in range(width * height):
        px = payload[i * depth:(i + 1) * depth]
        pixels.append((px[0], px[1], px[2], px[3] if depth == 4 else 255))
    return Image(width, height, pixels)


def encode_pam(img: Image) -> bytes:
    header = (f"P7\nWIDTH {img.width}\nHEIGHT {img.height}\nDEPTH 4\n"
              "MAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n").encode("ascii")
    return header + bytes(v for px in img.pixels for v in px)


def fnv1a64(data: bytes) -> int:
    h = 14695981039346656037
    for b in data:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def fingerprint(img: Image) -> int:
    return fnv1a64(bytes(v for px in img.pixels for v in px))
