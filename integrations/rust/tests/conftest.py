from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def pytest_addoption(parser):
    parser.addoption("--rust-shield-plugin", default=None,
                     help="Built AegisShield.so; required for explicitly selected real Rust tests")


@pytest.fixture(scope="session")
def rust_shield_plugin(request):
    value = request.config.getoption("--rust-shield-plugin")
    if not value or not Path(value).is_file():
        pytest.fail("Real Rust integration suite NOT RUN: provide --rust-shield-plugin /absolute/AegisShield.so")
    return Path(value).absolute()
