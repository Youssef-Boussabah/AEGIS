from pathlib import Path
import sys

import pytest

MODULE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE))


def pytest_addoption(parser):
    parser.addoption("--native-plugin", help="existing LLVM 22 AegisShield.so; required for native integration tests")


@pytest.fixture(scope="session")
def plugin(request):
    path = request.config.getoption("--native-plugin")
    if not path:
        pytest.skip("Native integration not run: pass --native-plugin and install matching LLVM 22 tools")
    assert Path(path).is_file(), "Requested native plugin is unavailable"
    return Path(path).absolute()
