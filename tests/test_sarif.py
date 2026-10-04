"""SARIF 2.1.0 structure for code scanning."""

from conftest import fixture, run_json

from scp_guardrails.lint import RULES


def sarif(*paths):
    rc, doc = run_json(["lint", *map(str, paths), "--format", "sarif", "--fail-on", "none"])
    assert rc == 0
    return doc


def test_sarif_top_level():
    doc = sarif(fixture("fixture-mgmt-lockout.json"))
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_sarif_rules_cover_every_rule_with_help():
    driver = sarif(fixture("fixture-good.json"))["runs"][0]["tool"]["driver"]
    assert driver["name"] == "scp-guardrails"
    assert [r["id"] for r in driver["rules"]] == list(RULES)
    for r in driver["rules"]:
        assert r["helpUri"].endswith("#" + r["id"].lower())
        assert r["defaultConfiguration"]["level"] in ("error", "warning", "note")
        assert float(r["properties"]["security-severity"]) > 0


def test_sarif_results_have_locations_levels_and_fingerprints():
    run = sarif(fixture("fixture-never-true.json"), fixture("fixture-mgmt-lockout.json"))["runs"][0]
    rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert run["results"]
    for res in run["results"]:
        assert rules[res["ruleIndex"]] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].endswith(".json")
        assert loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["scpGuardrails/v1"]
        assert "Fix:" in res["message"]["text"]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["SCP-MGMT-LOCKOUT"] == "error" and levels["SCP-CONDITION-NEVER-TRUE"] == "warning"


def test_sarif_clean_run_has_no_results():
    run = sarif(fixture("fixture-good.json"))["runs"][0]
    assert run["results"] == [] and run["invocations"][0]["executionSuccessful"] is True


def test_sarif_fingerprints_are_stable():
    a = sarif(fixture("fixture-mgmt-lockout.json"))["runs"][0]["results"]
    b = sarif(fixture("fixture-mgmt-lockout.json"))["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in a] == [r["partialFingerprints"] for r in b]
