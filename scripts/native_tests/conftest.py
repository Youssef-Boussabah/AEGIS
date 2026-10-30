"""Native product tests: real LLVM 22 tools and a real Shield plugin. Missing tools fail."""
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--shield-plugin", default=None,
                     help="AegisShield.so built from this checkout (required by Shield+Mirage tests)")


@pytest.fixture(scope="session")
def shield_plugin(request):
    raw = request.config.getoption("--shield-plugin")
    if not raw or not Path(raw).is_file():
        pytest.fail("Native Shield+Mirage tests need --shield-plugin /absolute/AegisShield.so "
                    "(build it with scripts/product.py build); this suite is NOT RUN without it")
    return str(Path(raw).absolute())
