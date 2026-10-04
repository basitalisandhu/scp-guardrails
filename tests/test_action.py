"""Action metadata and workflow hygiene. YAML is read with the package's own standard-library reader."""

import re

import pytest
from conftest import ROOT

from scp_guardrails import _miniyaml

ACTION_TEXT = (ROOT / "action.yml").read_text()
ACTION = _miniyaml.load(ACTION_TEXT)
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _uses(doc):
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "uses" and isinstance(v, str):
                yield v
            else:
                yield from _uses(v)
    elif isinstance(doc, list):
        for item in doc:
            yield from _uses(item)


def test_action_is_composite_with_metadata():
    assert ACTION["runs"]["using"] == "composite"
    assert ACTION["name"] and ACTION["description"] and ACTION["branding"]["icon"]
    assert len(ACTION["description"]) <= 200


def test_action_has_required_inputs_with_defaults():
    inputs = ACTION["inputs"]
    for name in ("path", "fail-on", "sarif", "upload-sarif"):
        assert name in inputs, name
        assert "default" in inputs[name] and inputs[name]["description"]
    assert inputs["fail-on"]["default"] == "high"
    assert inputs["sarif"]["default"] in ("true", "false")
    assert inputs["upload-sarif"]["default"] in ("true", "false")


def test_every_input_is_referenced_in_steps():
    body = ACTION_TEXT.split("runs:", 1)[1]
    for name in ACTION["inputs"]:
        assert f"inputs.{name}" in body, name


def test_outputs_map_to_lint_step():
    steps = {s.get("id") for s in ACTION["runs"]["steps"]}
    assert "lint" in steps
    for name, spec in ACTION["outputs"].items():
        assert spec["value"] == f"${{{{ steps.lint.outputs.{name} }}}}"


def test_outputs_written_by_the_cli_match_the_action_outputs():
    from scp_guardrails.report import github_outputs

    written = set(github_outputs([], "pass")) | {"sarif-file"}
    assert written == set(ACTION["outputs"])


def test_action_runs_linter_from_its_own_path():
    lint = next(s for s in ACTION["runs"]["steps"] if s.get("id") == "lint")
    assert lint["env"]["ACTION_PATH"] == "${{ github.action_path }}"
    assert "$ACTION_PATH/src" in lint["run"] and "python3 -m scp_guardrails" in lint["run"]
    assert "set +e" in lint["run"] and "--github-output" in lint["run"]


def test_sarif_upload_is_conditional_and_pinned():
    upload = next(s for s in ACTION["runs"]["steps"] if "upload-sarif" in s.get("uses", ""))
    assert upload["uses"].startswith("github/codeql-action/upload-sarif@")
    assert SHA_PIN.match(upload["uses"])
    assert "inputs.upload-sarif == 'true'" in upload["if"] and "inputs.sarif == 'true'" in upload["if"]
    assert upload["with"]["sarif_file"] == "${{ inputs.sarif-file }}"


def test_gate_step_fails_last():
    last = ACTION["runs"]["steps"][-1]
    assert "steps.lint.outputs.gate == 'fail'" in last["if"]
    assert "exit 1" in last["run"]


def test_inputs_never_interpolated_into_run_scripts():
    for step in ACTION["runs"]["steps"]:
        assert "${{ inputs." not in step.get("run", ""), step.get("name")


@pytest.mark.parametrize("path", [*WORKFLOWS, ROOT / "action.yml"], ids=lambda p: p.name)
def test_every_action_reference_is_sha_pinned(path):
    doc = _miniyaml.load(path.read_text())
    refs = list(_uses(doc))
    for ref in refs:
        if ref.startswith("./"):
            continue
        assert SHA_PIN.match(ref), f"{path.name}: {ref}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_default_to_read_only_permissions(path):
    doc = _miniyaml.load(path.read_text())
    assert doc["permissions"] == {"contents": "read"}


def test_expected_workflows_exist():
    assert {p.name for p in WORKFLOWS} == {"ci.yml", "self-test.yml", "publish-github-packages.yml", "release.yml"}


def test_self_test_uses_the_local_action_on_planted_and_good_fixtures():
    doc = _miniyaml.load((ROOT / ".github" / "workflows" / "self-test.yml").read_text())
    steps = doc["jobs"]["self-test"]["steps"]
    local = [s for s in steps if s.get("uses") == "./"]
    paths = {s["with"]["path"] for s in local}
    assert "tests/fixtures/action/fixture-bad-policy.json" in paths
    assert "tests/fixtures/action/fixture-good-policy.json" in paths
    assert all(s["with"]["upload-sarif"] == "false" for s in local)
    bad = next(s for s in local if s["with"]["path"].endswith("fixture-bad-policy.json"))
    assert bad["continue-on-error"] is True


def test_release_is_guarded_by_pypi_publish_variable():
    doc = _miniyaml.load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    for job in doc["jobs"].values():
        assert job["if"] == "vars.PYPI_PUBLISH == 'true'"


def test_ci_has_a_container_build_job():
    doc = _miniyaml.load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    assert "container-build" in doc["jobs"]
