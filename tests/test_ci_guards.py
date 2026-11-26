"""Guards that keep a stuck CI job from hanging for hours with no logs."""

import re
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
WORKFLOWS = sorted((TESTS.parent / ".github" / "workflows").glob("*.y*ml"))


def _jobs_missing_timeout(text):
    """Return the names of jobs under ``jobs:`` that lack ``timeout-minutes``."""
    missing, in_jobs, job, has_timeout = [], False, None, False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if re.match(r"^\S", line):
            if job and not has_timeout:
                missing.append(job)
            job = None
            in_jobs = line.startswith("jobs:")
            continue
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            if job and not has_timeout:
                missing.append(job)
            job, has_timeout = m.group(1), False
        elif re.match(r"^    timeout-minutes:\s*\S", line):
            has_timeout = True
    if job and not has_timeout:
        missing.append(job)
    return missing


def test_workflows_found():
    assert WORKFLOWS


@pytest.mark.parametrize("wf", WORKFLOWS, ids=[w.name for w in WORKFLOWS])
def test_every_ci_job_sets_timeout_minutes(wf):
    # Without a cap a hung job runs for GitHub's 6-hour default and is then
    # cancelled with its logs cut off.
    assert _jobs_missing_timeout(wf.read_text(encoding="utf-8")) == []


def test_timeout_check_catches_a_missing_cap():
    text = "on: push\njobs:\n  a:\n    runs-on: x\n    timeout-minutes: 5\n  b:\n    runs-on: x\n"
    assert _jobs_missing_timeout(text) == ["b"]


class _Item:
    def __init__(self, nodeid):
        self.nodeid = nodeid


def test_long_test_ids_fail_collection():
    import importlib.util

    spec = importlib.util.spec_from_file_location("_root_conftest", TESTS / "conftest.py")
    conftest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(conftest)
    conftest._check_test_id_lengths([_Item("t.py::ok[short]")])
    with pytest.raises(pytest.UsageError, match="ids="):
        conftest._check_test_id_lengths([_Item("t.py::big[" + "x" * 2000 + "]")])
