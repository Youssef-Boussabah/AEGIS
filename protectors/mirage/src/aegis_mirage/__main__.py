import argparse
from pathlib import Path

from .transform import MirageConfig, MirageError, transform


def main():
    parser = argparse.ArgumentParser(description="Insert deterministic retained LLVM decoys; never executes artifacts")
    parser.add_argument("input_ir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--disabled", action="store_true")
    args = parser.parse_args()
    try:
        report = transform(args.input_ir, args.output_dir, MirageConfig(args.seed, not args.disabled, args.count))
    except (MirageError, OSError):
        print("mirage_failed: invalid_input_toolchain_or_publication")
        return 2
    print(f"inserted={report['inserted_count']} output_sha256={report['output_sha256']}")
    return 0


raise SystemExit(main())
