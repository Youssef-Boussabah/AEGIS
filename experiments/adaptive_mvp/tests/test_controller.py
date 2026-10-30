import json
from pathlib import Path
import sys

import pytest

from experiments.adaptive_mvp.controller import (
    Budget, BudgetExhausted, Budgets, ExperimentError, NativeEngine, ROOT, Runner,
    TARGET_SHA256, artifact, elf_function_bytes, main, reference_checksum, run_experiment, sha256_file,
)
from experiments.adaptive_mvp.policy import Constraints
from experiments.adaptive_mvp.tests.test_policy import measured


class MeasurementDouble:
    """Non-executing measurements for controller failure tests only."""
    def __init__(self, failure=None):
        self.failure = failure
        self.calls = 0

    def snapshot(self):
        return {"test_double": True}

    def baseline(self):
        return {"test_double": True, "status": "VERIFIED", "artifact": {"sha256": "0" * 64}}

    def candidate(self, config, candidate_id, baseline, *, progress):
        self.calls += 1
        if self.failure:
            progress["job_id"] = "synthetic-test-job"
            raise self.failure
        return measured(candidate_id, config, retained=self.calls > 1)


def experiment(engine, **budgets):
    report, saves = {}, []
    result = run_experiment(engine, Budget(Budgets(**budgets)), Constraints(), [], report,
                            lambda: saves.append(json.dumps(report)))
    return result, saves


def test_controller_completes_real_feedback_logic_without_claiming_double_evidence():
    result, saves = experiment(MeasurementDouble())
    assert result["stop_reason"] == "FEEDBACK_PLAN_COMPLETE"
    assert len(result["candidates"]) == 4
    assert result["inputs"]["test_double"] is True
    assert result["selection"]["resistance"] == "UNMEASURED"
    assert result["candidates"][0]["parent_candidate_id"] == "baseline"
    assert result["candidates"][3]["parent_candidate_id"] == "c003"
    assert len(saves) >= 10


@pytest.mark.parametrize("count", [0, 1, 2, 3])
def test_candidate_budget_never_starts_extra_builds(count):
    engine = MeasurementDouble()
    result, _ = experiment(engine, max_candidates=count)
    assert engine.calls == count
    assert result["stop_reason"] == "CANDIDATE_BUDGET_EXHAUSTED"
    assert len(result["candidates"]) == count
    if count < 2:
        assert result["selection"]["selected_candidate_id"] is None
    else:
        assert result["selection"]["selected_candidate_id"] is not None
    assert "deferred_decision" in result


def test_build_failures_preserve_lineage_and_never_select():
    result, _ = experiment(MeasurementDouble(ExperimentError("COMMAND_FAILED")))
    assert result["selection"]["selected_candidate_id"] is None
    assert len(result["candidates"]) == 2  # bounded fallback, then no repeat
    assert all(item["error"]["code"] == "COMMAND_FAILED" for item in result["candidates"])
    assert all(item["job_id"] == "synthetic-test-job" for item in result["candidates"])


def test_budget_exhaustion_during_candidate_is_failed_and_not_retried():
    engine = MeasurementDouble(BudgetExhausted("NATIVE_RUN_BUDGET_EXHAUSTED"))
    result, saves = experiment(engine)
    assert result["stop_reason"] == "NATIVE_RUN_BUDGET_EXHAUSTED"
    assert result["candidates"][0]["verification_status"] == "incomplete"
    assert result["selection"]["selected_candidate_id"] is None
    assert engine.calls == 1
    assert json.loads(saves[-1])["stop_reason"] == result["stop_reason"]


def test_exhaustion_keeps_an_already_verified_incumbent():
    class AfterIncumbent(MeasurementDouble):
        def candidate(self, *args, **kwargs):
            if self.calls == 2:
                raise BudgetExhausted("WALL_BUDGET_EXHAUSTED")
            return super().candidate(*args, **kwargs)
    result, _ = experiment(AfterIncumbent())
    assert result["selection"]["selected_candidate_id"] == "c002"
    assert result["stop_reason"] == "WALL_BUDGET_EXHAUSTED"
    assert result["candidates"][2]["status"] == "FAILED"


def test_wall_budget_is_monotonic_and_exhaustion_stops_before_snapshot():
    now = [0.0]
    budget = Budget(Budgets(wall_seconds=1), clock=lambda: now[0])
    now[0] = 1.0
    engine = MeasurementDouble()
    report = {}
    run_experiment(engine, budget, Constraints(), [], report, lambda: None)
    assert report["stop_reason"] == "WALL_BUDGET_EXHAUSTED"
    assert engine.calls == 0
    assert report["baseline"] is None


def test_native_run_counter_reserves_before_launch_and_has_a_hard_limit():
    budget = Budget(Budgets(max_native_runs=1))
    budget.native()
    with pytest.raises(BudgetExhausted, match="NATIVE_RUN_BUDGET_EXHAUSTED"):
        budget.native()
    assert budget.native_runs == 1


def test_baseline_failure_is_explicit():
    class BadBaseline(MeasurementDouble):
        def baseline(self):
            raise ExperimentError("CORRECTNESS_FAILED")
    result, _ = experiment(BadBaseline())
    assert result["stop_reason"] == "EXPERIMENT_FAILED"
    assert result["error"]["code"] == "CORRECTNESS_FAILED"
    assert result["candidates"] == []


def test_unexpected_errors_do_not_look_like_a_completed_experiment():
    class Bug(MeasurementDouble):
        def candidate(self, *args, **kwargs):
            raise KeyError("synthetic internal error")
    result, _ = experiment(Bug())
    assert result["stop_reason"] == "EXPERIMENT_FAILED"
    assert result["error"]["code"] == "INTERNAL_ERROR"
    assert result["candidates"][0]["status"] == "FAILED"


def test_interruption_marks_the_in_progress_candidate():
    result, _ = experiment(MeasurementDouble(KeyboardInterrupt()))
    assert result["stop_reason"] == "INTERRUPTED"
    assert result["selection"]["selected_candidate_id"] is None
    assert result["candidates"][0]["status"] == "FAILED"


@pytest.mark.parametrize("kwargs", [
    {"wall_seconds": float("nan")}, {"command_seconds": 0}, {"max_candidates": 7},
    {"max_candidates": True}, {"samples": 0}, {"samples": 32}, {"max_native_runs": -1},
])
def test_budget_validation(kwargs):
    with pytest.raises(ValueError):
        Budgets(**kwargs)


def test_target_is_a_byte_exact_copy_of_the_existing_trusted_fixture():
    path = ROOT / "experiments/adaptive_mvp/target/signal.c"
    assert sha256_file(path) == TARGET_SHA256
    assert path.read_bytes() == (ROOT / "protectors/mirage/tests/fixtures/signal.c").read_bytes()
    assert reference_checksum() == "bf283ea0\n"


def test_command_timeout_has_a_killed_group_and_a_record(tmp_path):
    runner = Runner(tmp_path, Budget(Budgets(command_seconds=0.05)))
    with pytest.raises(ExperimentError, match="COMMAND_TIMEOUT"):
        runner.run(["/usr/bin/sleep", "3"])
    assert runner.commands[0]["timed_out"] is True
    assert runner.commands[0]["exit_code"] == -9
    assert runner.commands[0]["duration_seconds"] < 1


@pytest.mark.parametrize("parent_waits", [False, True])
def test_descendants_are_killed_on_success_and_timeout(tmp_path, parent_waits):
    runner = Runner(tmp_path, Budget(Budgets(command_seconds=0.25)))
    script = ("import subprocess,time; from pathlib import Path; "
              "p=subprocess.Popen(['/usr/bin/sleep','10']); "
              "Path('child.pid').write_text(str(p.pid)); "
              + ("time.sleep(10)" if parent_waits else ""))
    if parent_waits:
        with pytest.raises(ExperimentError, match="COMMAND_TIMEOUT"):
            runner.run([sys.executable, "-c", script])
    else:
        runner.run([sys.executable, "-c", script])
    pid = int((tmp_path / "child.pid").read_text())
    status = Path(f"/proc/{pid}/stat")
    # A killed orphan may remain a zombie until its adopting process reaps it.
    assert not status.exists() or status.read_text().split()[2] in ("Z", "X")


def test_runner_does_not_inherit_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("ADAPTIVE_TEST_SECRET", "must-not-be-inherited")
    runner = Runner(tmp_path, Budget(Budgets()))
    output = runner.run([sys.executable, "-c", "import os; print('ADAPTIVE_TEST_SECRET' in os.environ)"])
    assert output == b"False\n"


def test_missing_tool_is_an_explicit_error(tmp_path):
    runner = Runner(tmp_path, Budget(Budgets()))
    with pytest.raises(ExperimentError, match="TOOL_UNAVAILABLE"):
        runner.run(["/nonexistent/aegis-adaptive-tool"])


def test_symlink_or_escape_is_never_accepted_as_an_artifact(tmp_path):
    link = tmp_path / "link"
    link.symlink_to("/usr/bin/true")
    with pytest.raises(ExperimentError, match="UNSAFE_PATH"):
        artifact(tmp_path, link)
    with pytest.raises(ExperimentError, match="UNSAFE_PATH"):
        artifact(tmp_path, Path("/usr/bin/true"))


def test_invalid_elf_cannot_provide_retention(tmp_path):
    path = tmp_path / "bad.elf"
    path.write_bytes(b"fake ELF")
    with pytest.raises(ExperimentError, match="INVALID_ELF"):
        elf_function_bytes(path, ["signal_mix"])


def test_artifact_hash_change_is_refused_before_native_execution(tmp_path):
    path = tmp_path / "target.elf"
    path.write_bytes(b"never executed")
    runner = Runner(tmp_path, Budget(Budgets()))
    engine = NativeEngine(tmp_path, runner, {}, tmp_path / "plugin")
    with pytest.raises(ExperimentError, match="ARTIFACT_INTEGRITY_ERROR"):
        engine.execute_owned(path, "0" * 64)
    assert runner.budget.native_runs == 0


def test_source_tree_outputs_are_refused():
    assert main(["--output-dir", str(ROOT / "experiments/adaptive_mvp/refused-output"),
                 "--plugin", "/tmp/unused-plugin"]) == 2
    assert not (ROOT / "experiments/adaptive_mvp/refused-output").exists()
