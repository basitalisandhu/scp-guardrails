"""End-to-end: build the wheel, install it in a fresh venv and run the README quick start.

The three-line quick start at the top of README.md is run as written, with `pipx install` replaced by
installing the freshly built wheel and `curl` replaced by copying examples/spec.yaml (the file it
fetches). The combined output must match the README's output block exactly. Building needs the network
for the build backend, so this runs only when SCP_GUARDRAILS_E2E=1; CI sets it in the quickstart job.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest
from conftest import ROOT

pytestmark = pytest.mark.skipif(os.environ.get("SCP_GUARDRAILS_E2E") != "1", reason="set SCP_GUARDRAILS_E2E=1")

README = (ROOT / "README.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def bin_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("e2e")
    dist = base / "dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist), str(ROOT)], check=True, capture_output=True
    )
    venv.create(base / "venv", with_pip=True)
    bin_dir = base / "venv" / ("Scripts" if os.name == "nt" else "bin")
    wheel = next(dist.glob("scp_guardrails-*.whl"))
    subprocess.run([str(bin_dir / "python"), "-m", "pip", "install", "-q", str(wheel)], check=True, capture_output=True)
    return bin_dir


def test_readme_quick_start(bin_dir: Path, tmp_path: Path) -> None:
    match = re.search(r"Quick start .*?```bash\n(.*?)```.*?Output of those commands.*?```text\n(.*?)```", README, re.S)
    assert match, "README quick start or its output block not found"
    commands, expected = match.group(1).splitlines(), match.group(2)
    assert commands[0].startswith("pipx install ") and commands[1].startswith("curl ")
    assert commands[1].endswith("/main/examples/spec.yaml")
    shutil.copy(ROOT / "examples" / "spec.yaml", tmp_path / "spec.yaml")
    env = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    out = subprocess.run(
        ["bash", "-c", commands[2] + " 2>&1"], cwd=tmp_path, env=env, capture_output=True, text=True, check=True
    )
    assert out.stdout == expected
    assert (tmp_path / "scps" / "scp-01.json").is_file() and (tmp_path / "scps" / "SUMMARY.md").is_file()


def test_installed_command_lints_stdin(bin_dir: Path) -> None:
    policy = (ROOT / "tests" / "fixtures" / "action" / "fixture-bad-policy.json").read_bytes()
    out = subprocess.run([str(bin_dir / "scp-guardrails"), "lint", "-"], input=policy, capture_output=True)
    assert out.returncode == 1 and b"<stdin>" in out.stdout and b"SCP-REGION-BLOCKS-GLOBAL" in out.stdout
