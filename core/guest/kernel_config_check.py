#!/usr/bin/env python3
"""Check a kernel .config against aegis-kernel.fragment: required =y, forbidden unset (stdlib only).

    python3 -I kernel_config_check.py linux/.config aegis-kernel.fragment
Exit 0 when every requirement holds; otherwise prints each violation and exits 1.
"""
from __future__ import annotations

import re
import sys

_SET = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.+)$")
_UNSET = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")


def parse(text: str) -> tuple[dict[str, str], set[str]]:
    values, unset = {}, set()
    for line in text.splitlines():
        if m := _SET.match(line.strip()):
            values[m.group(1)] = m.group(2)
        elif m := _UNSET.match(line.strip()):
            unset.add(m.group(1))
    return values, unset


def violations(config_text: str, fragment_text: str) -> list[str]:
    config, _ = parse(config_text)
    required, forbidden = parse(fragment_text)
    out = [f"{k} must be {v}, is {config.get(k, 'unset')}" for k, v in sorted(required.items())
           if config.get(k) != v]
    out += [f"{k} must not be set, is {config[k]}" for k in sorted(forbidden) if config.get(k) not in (None, "n")]
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: kernel_config_check.py CONFIG FRAGMENT\n")
        return 2
    with open(argv[0]) as c, open(argv[1]) as f:
        problems = violations(c.read(), f.read())
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
