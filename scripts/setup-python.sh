#!/usr/bin/env sh
# Reproducible clean-clone Python setup for AEGIS.
#
# Creates a uv-managed virtual environment and installs the three Python
# packages (aegis-core, aegis-api, aegis-cli) together in editable mode,
# constrained by core/requirements-dev.lock. This is the scripted form of the
# sequence documented in README.md#setup; CI and humans run the same thing.
#
# It does NOT install LLVM/Clang, CMake or Ninja. The LLVM Shield and its
# adapter suite need LLVM >= 22 separately (see protectors/llvm/README.md).
#
# Usage:
#   scripts/setup-python.sh            # creates .venv at the repository root
#   VENV=/path/to/venv scripts/setup-python.sh
#
# Requires: uv (https://docs.astral.sh/uv/). Run from any directory.

set -eu

# Resolve the repository root from this script's location, so the script works
# regardless of the caller's working directory.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENV=${VENV:-"$ROOT/.venv"}

if ! command -v uv >/dev/null 2>&1; then
  echo "error: uv not found on PATH. Install it from https://docs.astral.sh/uv/" >&2
  exit 1
fi

echo "Creating virtual environment at $VENV"
uv venv "$VENV"

echo "Installing aegis-core, aegis-api, aegis-cli, aegis-provenance and aegis-sentinel (editable, lock-constrained)"
uv pip install --python "$VENV/bin/python" \
  -c "$ROOT/core/requirements-dev.lock" \
  -e "$ROOT/core[dev]" \
  -e "$ROOT/platform/api[dev]" \
  -e "$ROOT/platform/cli[dev]" \
  -e "$ROOT/provenance[dev]" \
  -e "$ROOT/sentinel[dev]"

echo "Done. Activate with: . $VENV/bin/activate"
echo "Run the default suite with: $VENV/bin/python -m pytest"
