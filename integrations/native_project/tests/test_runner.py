import json
import os
from pathlib import Path
import signal
import sys
import time

import pytest

from runner import Failure, Runner, regular


def make_runner(tmp_path, **kwargs):
    root = tmp_path / "output"
    root.mkdir()
    return Runner(root, **kwargs)


def dead(pid):
    proc = Path(f"/proc/{pid}/stat")
    try:
        return proc.read_text().split()[2] == "Z"
    except (FileNotFoundError, ProcessLookupError):
        return True


@pytest.mark.parametrize("error", [FileNotFoundError, ProcessLookupError])
def test_process_disappearance_during_proc_read(monkeypatch, error):
    def disappeared(path):
        raise error("Process disappeared during /proc read")

    monkeypatch.setattr(Path, "read_text", disappeared)
    assert dead(12345)


def test_environment_and_literal_arguments(tmp_path, monkeypatch):
    runner = make_runner(tmp_path)
    monkeypatch.setenv("AEGIS_NATIVE_TEST_SECRET", "must-not-inherit")
    monkeypatch.setenv("PYTHONPATH", "/nonexistent")
    code = "import os,sys,json; print(json.dumps({'env':dict(os.environ),'argv':sys.argv[1:]}))"
    arg = "$(touch accidental); 'literal' && true"
    out, err, status = runner.run([sys.executable, "-c", code, arg], tmp_path)
    value = json.loads(out)
    assert "AEGIS_NATIVE_TEST_SECRET" not in value["env"] and "PYTHONPATH" not in value["env"]
    assert value["argv"] == [arg] and status == 0 and err == b""
    assert set(value["env"]) <= {"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR"}


@pytest.mark.parametrize("leader_exits", [False, True])
def test_process_group_cleanup_including_descendants(tmp_path, leader_exits):
    runner = make_runner(tmp_path, timeout=0.2)
    pidfile = tmp_path / "child.pid"
    code = ("import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "open(sys.argv[1],'w').write(str(p.pid)); " + ("" if leader_exits else "time.sleep(30)"))
    if leader_exits:
        runner.run([sys.executable, "-c", code, pidfile], tmp_path)
    else:
        with pytest.raises(Failure) as info:
            runner.run([sys.executable, "-c", code, pidfile], tmp_path, stage="adapter")
        assert info.value.code == "ADAPTER_TIMEOUT"
    pid = int(pidfile.read_text())
    for _ in range(100):
        if dead(pid):
            break
        time.sleep(0.01)
    assert dead(pid), "Process-group cleanup left a live descendant"


def test_bounded_diagnostics(tmp_path):
    runner = make_runner(tmp_path, log_limit=1024, file_limit=8192)
    with pytest.raises(Failure) as info:
        runner.run([sys.executable, "-c", "import os; os.write(1,b'x'*4096)"], tmp_path)
    assert info.value.code == "OUTPUT_TOO_LARGE"


def test_hard_file_cap(tmp_path):
    runner = make_runner(tmp_path, file_limit=8192)
    target = runner.root / "huge"
    with pytest.raises(Failure):
        runner.run([sys.executable, "-c", "import os,sys; f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT); "
                    "os.write(f,b'x'*8192); os.write(f,b'y'*8192)", target], tmp_path)
    assert target.stat().st_size <= 8192


def test_regular_rejects_symlinks_hardlinks_and_oversize(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"1234")
    with pytest.raises(Failure) as info:
        regular(source, 3)
    assert info.value.code == "OUTPUT_TOO_LARGE"
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(Failure) as info:
        regular(link, 10)
    assert info.value.code == "UNSAFE_PATH"
    hardlink = tmp_path / "hardlink"
    os.link(source, hardlink)
    with pytest.raises(Failure) as info:
        regular(source, 10)
    assert info.value.code == "UNSAFE_PATH"
