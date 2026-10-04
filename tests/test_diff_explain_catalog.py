"""diff, explain and catalog."""

import json

from conftest import ROOT, fixture, run, run_json

from scp_guardrails import catalog
from scp_guardrails.diff import diff_policies, normalise
from scp_guardrails.explain import describe_condition, describe_statement

A, B = fixture("fixture-diff-a.json"), fixture("fixture-diff-b.json")


def test_diff_reports_added_removed_and_changed_statements():
    rc, out = run_json(["diff", str(A), str(B), "--format", "json"])
    assert rc == 1 and out["changed"] is True
    status = {s["sid"]: s["status"] for s in out["statements"]}
    assert status == {
        "DenyLeaveOrganization": "removed",
        "ProtectCloudTrail": "changed",
        "DenyOutsideAllowedRegions": "changed",
        "DenyRootUser": "added",
    }


def test_diff_action_and_condition_sets():
    d = diff_policies(json.loads(A.read_text()), json.loads(B.read_text()))
    details = {s.sid: s.details for s in d.statements}
    assert "Action + cloudtrail:updatetrail" in details["ProtectCloudTrail"]
    assert any(
        "SecurityAutomation" in line and line.startswith("Condition ArnNotLike")
        for line in details["ProtectCloudTrail"]
    )
    assert details["DenyOutsideAllowedRegions"] == ["Condition StringNotEquals aws:requestedregion + us-east-1"]


def test_diff_ignores_order_case_and_string_vs_list(write):
    a = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "X", "Effect": "Deny", "Action": ["s3:GetObject", "IAM:*"], "Resource": "*"}],
    }
    b = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "X", "Effect": "Deny", "Action": ["iam:*", "s3:getobject"], "Resource": ["*"]}],
    }
    rc, out, _ = run(["diff", str(write("a.json", a)), str(write("b.json", b))])
    assert rc == 0 and "semantically identical" in out


def test_diff_effect_and_notaction_changes():
    a = {"Statement": [{"Sid": "X", "Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}
    b = {"Statement": [{"Sid": "X", "Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]}
    details = diff_policies(a, b).statements[0].details
    assert "Effect Deny -> Allow" in details
    assert any(line.startswith("Action removed") for line in details)
    assert any(line.startswith("NotAction added") for line in details)


def test_diff_matches_unnamed_statements_by_content():
    st = {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
    d = diff_policies({"Statement": [st]}, {"Statement": [dict(st)]})
    assert not d.changed
    d2 = diff_policies({"Statement": [st]}, {"Statement": [{**st, "Action": "ec2:*"}]})
    assert sorted(s.status for s in d2.statements) == ["added", "removed"]


def test_diff_text_output():
    rc, out, _ = run(["diff", str(A), str(B)])
    assert rc == 1
    assert "- DenyLeaveOrganization (removed)" in out and "+ DenyRootUser (added)" in out
    assert "~ ProtectCloudTrail (changed)" in out
    assert out.strip().endswith("1 added, 1 removed, 2 changed, 0 unchanged statement(s).")


def test_normalise_condition_keys_case_insensitive():
    a = normalise(
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"StringEquals": {"AWS:RequestedRegion": "eu-west-1"}},
        }
    )
    assert a["Condition"] == {"StringEquals": {"aws:requestedregion": ["eu-west-1"]}}


def test_explain_narrative():
    rc, out, _ = run(["explain", str(fixture("fixture-diff-b.json"))])
    assert rc == 0
    assert "does not apply to the management account" in out
    assert "DenyRootUser: Denies every action on any resource, when the caller is the root user." in out
    assert "unless the caller is arn:aws:iam::*:role/BreakGlassAdmin or arn:aws:iam::*:role/SecurityAutomation" in out
    assert "Purpose:" in out and "Watch for:" in out


def test_explain_markdown():
    rc, out, _ = run(["explain", str(fixture("fixture-good.json")), "--format", "markdown"])
    assert rc == 0 and out.startswith("# What ") and "- **DenyLeaveOrganization**:" in out


def test_explain_region_condition_phrase():
    text = describe_condition("StringNotEquals", "aws:RequestedRegion", ["eu-west-1", "us-east-1"])
    assert text == "the requested region is not eu-west-1 or us-east-1"


def test_explain_handles_qualifiers_null_and_notaction():
    assert describe_condition("ForAnyValue:StringLike", "sagemaker:InstanceTypes", ["ml.p*"]).startswith("any of")
    assert describe_condition("Null", "aws:RequestTag/Owner", ["true"]) == "the Owner tag in the request is missing"
    assert describe_condition("StringEqualsIfExists", "ec2:InstanceType", ["t3.micro"]).endswith(
        "(or the key is absent)"
    )
    st = {"Effect": "Deny", "NotAction": ["iam:*"], "NotResource": ["arn:aws:s3:::logs"]}
    assert (
        describe_statement(st)
        == "Denies every action except 1 listed (iam:*) on every resource except arn:aws:s3:::logs."
    )


def test_explain_allow_only_policy(write):
    rc, out, _ = run(
        ["explain", str(write("allow.json", {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))]
    )
    assert rc == 0 and "restricts nothing" in out


def test_explain_describe_policy_output():
    rc, out, _ = run(["explain", str(fixture("fixture-describe-policy-output.json"))])
    assert rc == 0 and "DenyLeave: Denies organizations:LeaveOrganization" in out


def test_catalog_table_lists_every_key():
    rc, out, _ = run(["catalog"])
    assert rc == 0
    for g in catalog.CATALOG:
        assert g.key in out


def test_catalog_json_structure():
    rc, data = run_json(["catalog", "--format", "json"])
    assert rc == 0
    assert len(data["guardrails"]) == len(catalog.CATALOG)
    for g in data["guardrails"]:
        assert set(g) >= {"key", "title", "category", "statements", "denies", "protects", "side_effects", "docs"}
        assert g["docs"] and all(d.startswith("https://") for d in g["docs"])
        assert g["category"] in ("baseline", "spend")


def test_catalog_one_key_and_unknown_key():
    rc, out, _ = run(["catalog", "--key", "require_imdsv2"])
    assert rc == 0 and "RequireImdsv2OnLaunch" in out and "docs:" in out
    rc, out = run_json(["catalog", "--key", "deny_root_user", "--format", "json"])
    assert out["statements"] == ["DenyRootUser"]
    rc, _, err = run(["catalog", "--key", "nope"])
    assert rc == 2 and "unknown guardrail" in err


def test_catalog_sids_are_unique():
    sids = [s for g in catalog.CATALOG for s in g.statements]
    assert len(sids) == len(set(sids))


def test_docs_catalog_md_is_generated_from_the_catalogue():
    rc, out, _ = run(["catalog", "--format", "markdown"])
    assert rc == 0
    assert (ROOT / "docs" / "catalog.md").read_text() == out
