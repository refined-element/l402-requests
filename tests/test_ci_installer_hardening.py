"""Pins the installer-bootstrap hardening of this repository's CI/CD (2026-10-22).

Stdlib only (no PyYAML): the workflows use consistent two-space indentation, which is
enough to split jobs and steps. Every job that installs anything with pip must first run
the `trusted-pip` composite action, which replaces the runner's pip/certifi with pinned,
SHA256-verified wheels. The action itself must carry matching pins. When a Dockerfile is
present (lightning-enable-mcp) that repository's copy of this file adds the Dockerfile rules.

Set LE_CI_HARDENING_ROOT to check a different tree (used to prove the test fails on the
unpatched workflows).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

PIN_PIP = "26.2.2"
PIN_PIP_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
PIN_CERTIFI = "2026.10.19"
PIN_CERTIFI_SHA256 = "42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b"
ACTION_USE = "./.github/actions/trusted-pip"
# `pip install ...`, `pip3 install`, `python -m pip install`; group 1 is set only for the -m form.
PIP_INSTALL = re.compile(r"(?<![\w./-])(python(?:3(?:\.\d+)?)?\s+-m\s+)?pip(?:3)?\s+install\b")


def repo_root() -> Path:
    override = os.environ.get("LE_CI_HARDENING_ROOT")
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".github").is_dir():
            return parent
    # An sdist ships tests/ without .github: nothing to check there, and a collection
    # error here would abort the whole suite for downstream packagers.
    pytest.skip("not a repository checkout (no .github directory above the test)", allow_module_level=True)


ROOT = repo_root()
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ACTION = ROOT / ".github" / "actions" / "trusted-pip" / "action.yml"


def split_jobs(text: str) -> dict[str, list[str]]:
    """Return {job_name: lines} for a GitHub workflow using two-space indentation."""
    jobs: dict[str, list[str]] = {}
    in_jobs, current = False, None
    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs, current = True, None
            continue
        if line.lstrip().startswith("#") or not line.strip():
            if current:
                jobs[current].append(line)
            continue  # comments and blank lines never open or close a job
        if in_jobs and re.match(r"^\S", line):  # another top-level key ends the jobs map
            in_jobs = False
        if not in_jobs:
            continue
        m = re.match(r"^  ['\"]?([A-Za-z0-9_.-]+)['\"]?:\s*$", line)
        if m:
            current = m.group(1)
            jobs[current] = []
            continue
        assert re.match(r"^\s{3,}", line), f"unexpected job-level line (two-space indentation expected): {line!r}"
        if current:
            jobs[current].append(line)
    return jobs


def is_command(line: str) -> bool:
    """A shell line that could actually run pip: not a YAML/shell comment, not an echo."""
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#") and not stripped.startswith("echo ")


def first_index(lines: list[str], pattern) -> int | None:
    for i, line in enumerate(lines):
        if not is_command(line):
            continue
        if isinstance(pattern, str):
            if pattern in line:
                return i
        elif pattern.search(line):
            return i
    return None


def _pip_jobs():
    for wf in WORKFLOWS:
        for name, lines in split_jobs(wf.read_text(encoding="utf-8")).items():
            if any(PIP_INSTALL.search(l) for l in lines if is_command(l)):
                yield wf, name, lines


PIP_JOBS = list(_pip_jobs())
PIP_JOB_IDS = [f"{w.name}:{j}" for w, j, _ in PIP_JOBS]


def test_workflows_exist():
    assert WORKFLOWS, f"no workflows under {ROOT}"


def test_pip_jobs_were_found():
    assert PIP_JOBS, "expected at least one job installing with pip"


def test_trusted_pip_action_exists_with_expected_pins():
    assert ACTION.is_file(), f"missing {ACTION}"
    text = ACTION.read_text(encoding="utf-8")
    assert f"PIN_PIP_VERSION: '{PIN_PIP}'" in text
    assert f"PIN_PIP_SHA256: {PIN_PIP_SHA256}" in text
    assert f"PIN_CERTIFI_VERSION: '{PIN_CERTIFI}'" in text
    assert f"PIN_CERTIFI_SHA256: {PIN_CERTIFI_SHA256}" in text
    assert f"/pip-{PIN_PIP}-py3-none-any.whl" in text
    assert f"/certifi-{PIN_CERTIFI}-py3-none-any.whl" in text
    assert "--no-index" in text and "--isolated" in text, "bootstrap must not touch an index"
    assert "pip._vendor import certifi" in text, "must verify pip's vendored CA bundle, not only certifi"
    assert "https://files.pythonhosted.org/" in text
    assert "http://" not in text, "plain-http URL in the bootstrap"
    assert "--proto-redir '=https'" in text, "redirects must stay on https"
    assert 'if [ "$actual" != "$2" ]' in text and "SHA256 mismatch" in text, "the hash check itself is gone"
    # The pins appear in both steps (composite actions have no action-wide env); both copies must agree.
    assert text.count(f"PIN_PIP_VERSION: '{PIN_PIP}'") == 2
    assert text.count(f"PIN_CERTIFI_VERSION: '{PIN_CERTIFI}'") == 2
    assert not re.search(r"PIN_PIP_VERSION: '(?!" + re.escape(PIN_PIP) + ")", text)
    assert not re.search(r"PIN_CERTIFI_VERSION: '(?!" + re.escape(PIN_CERTIFI) + ")", text)


@pytest.mark.parametrize("wf,job,lines", PIP_JOBS, ids=PIP_JOB_IDS)
def test_every_pip_installing_job_bootstraps_first(wf, job, lines):
    boot = first_index(lines, f"uses: {ACTION_USE}")
    install = first_index(lines, PIP_INSTALL)
    assert boot is not None, f"{wf.name} job '{job}' installs with pip but never runs {ACTION_USE}"
    assert boot < install, (
        f"{wf.name} job '{job}' runs pip install (line {install}) before the bootstrap (line {boot})")
    setup = first_index(lines, "actions/setup-python@")
    if setup is not None:
        assert setup < boot, f"{wf.name} job '{job}': bootstrap must run after setup-python"
    # The bootstrap step must be unconditional: an `if:` or `continue-on-error` on it would let
    # the job fall through to the runner's pip. Inspect the whole step block around the uses line.
    start = boot
    while start > 0 and not re.match(r"^\s*- ", lines[start]):
        start -= 1
    end = boot + 1
    while end < len(lines) and not re.match(r"^\s*- ", lines[end]):
        end += 1
    block = "\n".join(lines[start:end])
    assert not re.search(r"^\s*(if|continue-on-error):", block, re.M), (
        f"{wf.name} job '{job}': the bootstrap step must not be conditional")


@pytest.mark.parametrize("wf,job,lines", PIP_JOBS, ids=PIP_JOB_IDS)
def test_pip_is_invoked_through_the_bootstrapped_interpreter(wf, job, lines):
    for line in filter(is_command, lines):
        m = PIP_INSTALL.search(line)
        if m:
            assert m.group(1), (
                f"{wf.name} job '{job}': use `python -m pip install` so the pinned pip runs: {line.strip()}")


@pytest.mark.parametrize("wf,job,lines", PIP_JOBS, ids=PIP_JOB_IDS)
def test_no_floating_pip_self_upgrade(wf, job, lines):
    for line in filter(is_command, lines):
        m = PIP_INSTALL.search(line)
        if not m:
            continue
        args = line[m.end():]
        assert not re.search(r"(^|\s)[\"']?pip[\"']?(\s|$|[=<>~!])", args), (
            f"{wf.name} job '{job}': a floating pip self-upgrade undoes the pin: {line.strip()}")
