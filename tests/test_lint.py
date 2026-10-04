"""Lint rule tests: the ported aws-security-skills cases plus one planted policy per new rule."""

import json

import pytest
from conftest import fixture, run, run_json

from scp_guardrails.catalog import GLOBAL_SERVICE_ACTIONS
from scp_guardrails.lint import RULES, LintOptions, lint_policy


def ids(path, *extra):
    _, out = run_json(["lint", str(path), "--format", "json", "--fail-on", "none", *extra])
    return {f["id"] for f in out[0]["findings"]}


def by_id(path, rule, *extra):
    _, out = run_json(["lint", str(path), "--format", "json", "--fail-on", "none", *extra])
    return [f for f in out[0]["findings"] if f["id"] == rule]


# Ported cases.


def test_allow_in_deny_list():
    assert ids(fixture("fixture-allow-in-deny-list.json")) == {"SCP-ALLOW-IN-DENY-LIST"}
    assert ids(fixture("fixture-allow-in-deny-list.json"), "--strategy", "allow-list") == set()


def test_region_deny_with_action_star_blocks_global_services():
    found = ids(fixture("fixture-region-action-star.json"))
    assert found == {"SCP-REGION-BLOCKS-GLOBAL", "SCP-NO-EXEMPTION"}
    rc, _, _ = run(["lint", str(fixture("fixture-region-action-star.json"))])
    assert rc == 1


def test_region_notaction_gaps():
    path = fixture("fixture-region-gaps.json")
    assert {"SCP-REGION-GLOBAL-GAPS", "SCP-REGION-DOC-GAPS", "SCP-NO-EXEMPTION"} == ids(path)
    assert run(["lint", str(path)])[0] == 0  # medium and low only; default --fail-on high
    assert run(["lint", str(path), "--fail-on", "medium"])[0] == 1


def test_notaction_principal_duplicate_and_deny_all():
    assert ids(fixture("fixture-notaction-and-principal.json")) == {
        "SCP-ALLOW-NOTACTION",
        "SCP-DENY-NOTACTION-BARE",
        "SCP-PRINCIPAL",
        "SCP-DUPLICATE-SID",
        "SCP-DENY-ALL",
        "SCP-MGMT-LOCKOUT",
    }


def test_size_limit(write):
    big = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": f"Deny{i}", "Effect": "Deny", "Action": [f"ec2:Action{j}" for j in range(20)], "Resource": "*"}
            for i in range(60)
        ],
    }
    assert "SCP-SIZE" in ids(write("big.json", big))
    small = {"Version": "2012-10-17", "Statement": [big["Statement"][0]]}
    assert lint_policy(small) == []
    assert [f.id for f in lint_policy(small, LintOptions(limit=100))] == ["SCP-SIZE"]
    assert "SCP-SIZE" in ids(write("small.json", small), "--limit", "100")


def test_size_is_measured_compact_not_as_written(write):
    st = {"Sid": "DenyLeave", "Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}
    padded = json.dumps({"Version": "2012-10-17", "Statement": [st]}, indent=40)
    assert len(padded) > 400
    assert ids(write("padded.json", padded), "--limit", "400") == set()


def test_structure_and_version(write):
    assert ids(write("a.json", '{"Version": "2008-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*"}]}')) == {
        "SCP-VERSION",
        "SCP-STRUCTURE",
    }
    assert ids(write("b.json", '{"Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]}')) >= {
        "SCP-STRUCTURE"
    }
    assert ids(write("c.json", "[]")) == {"SCP-STRUCTURE"}
    assert ids(write("d.json", '{"Version": "2012-10-17", "Statement": ["x"]}')) == {"SCP-STRUCTURE"}
    both = '{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*", "NotAction": "s3:Get*", "Resource": "*"}]}'
    assert ids(write("e.json", both)) == {"SCP-STRUCTURE"}


def test_describe_policy_output_and_full_allow_are_clean(write):
    assert ids(fixture("fixture-describe-policy-output.json")) == set()
    full = write(
        "full.json", '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    )
    assert ids(full) == set()


def test_bad_input_exit_2(write):
    rc, out, _ = run(["lint", str(write("x.json", "{oops"))])
    assert rc == 2 and "invalid JSON" in out
    rc, _, _ = run(["lint", str(write("y.json", '{"Policy": {"Content": "not json"}}'))])
    assert rc == 2


# New rules, each with a planted policy.


def test_mgmt_lockout():
    found = by_id(fixture("fixture-mgmt-lockout.json"), "SCP-MGMT-LOCKOUT")
    assert {f["sid"] for f in found} == {"DenyAllSts", "DenyRoleChanges"}
    assert all(f["severity"] == "high" for f in found)
    assert "OrganizationAccountAccessRole" in found[0]["message"]


def test_mgmt_lockout_not_raised_with_an_exemption(write):
    st = {
        "Sid": "DenyAllSts",
        "Effect": "Deny",
        "Action": "sts:*",
        "Resource": "*",
        "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/OrganizationAccountAccessRole"}},
    }
    assert "SCP-MGMT-LOCKOUT" not in ids(write("ok.json", {"Version": "2012-10-17", "Statement": [st]}))


def test_mgmt_lockout_names_custom_admin_role():
    found = by_id(fixture("fixture-mgmt-lockout.json"), "SCP-MGMT-LOCKOUT", "--admin-role", "LandingZoneAdmin")
    assert "LandingZoneAdmin" in found[0]["message"]


def test_mgmt_account_reference():
    path = fixture("fixture-mgmt-account-ref.json")
    assert "SCP-MGMT-ACCOUNT-REF" not in ids(path)
    found = by_id(path, "SCP-MGMT-ACCOUNT-REF", "--management-account", "999988887777")
    assert len(found) == 1 and found[0]["sid"] == "DenyIamUsersOutsideManagement"


def test_management_account_must_be_12_digits():
    rc, _, err = run(["lint", str(fixture("fixture-good.json")), "--management-account", "12"])
    assert rc == 2 and "12-digit" in err


def test_region_doc_gaps_compares_against_the_aws_example():
    found = by_id(fixture("fixture-region-doc-gaps.json"), "SCP-REGION-DOC-GAPS")
    assert len(found) == 1 and found[0]["severity"] == "low"
    assert "github.com/aws-samples/service-control-policy-examples" in found[0]["help"]
    assert f"of the {len(GLOBAL_SERVICE_ACTIONS)} entries" in found[0]["message"]
    assert ids(fixture("fixture-region-doc-gaps.json")) == {"SCP-REGION-DOC-GAPS"}


def test_region_deny_with_the_full_aws_list_is_clean(write):
    st = {
        "Sid": "DenyOtherRegions",
        "Effect": "Deny",
        "NotAction": list(GLOBAL_SERVICE_ACTIONS),
        "Resource": "*",
        "Condition": {
            "StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]},
            "ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::*:role/BreakGlassAdmin"]},
        },
    }
    assert ids(write("region.json", {"Version": "2012-10-17", "Statement": [st]})) == set()


def test_condition_operator_mismatches():
    found = by_id(fixture("fixture-condition-operator.json"), "SCP-CONDITION-OPERATOR")
    by_sid = {f["sid"]: f["message"] for f in found}
    assert "use ArnNotLike" in by_sid["ExemptAdminsWrongOperator"]
    assert "not ARNs" in by_sid["ArnOperatorOnRegion"]
    assert "non-numeric" in by_sid["NumericOnText"]
    assert "unknown condition operator" in by_sid["MadeUpOperator"]


def test_string_equals_wildcard_on_non_arn_suggests_string_like(write):
    st = {
        "Sid": "DenyBigTypes",
        "Effect": "Deny",
        "Action": "ec2:RunInstances",
        "Resource": "*",
        "Condition": {"StringEquals": {"ec2:InstanceType": ["p4d.*"]}},
    }
    found = by_id(write("w.json", {"Version": "2012-10-17", "Statement": [st]}), "SCP-CONDITION-OPERATOR")
    assert "use StringLike" in found[0]["message"]


def test_condition_never_true():
    found = by_id(fixture("fixture-never-true.json"), "SCP-CONDITION-NEVER-TRUE")
    assert {f["sid"] for f in found} == {
        "EmptyValueList",
        "Contradiction",
        "NullAndValue",
        "ExemptEveryone",
        "ExemptEveryRole",
        "BoolTypo",
    }
    every_role = next(f for f in found if f["sid"] == "ExemptEveryRole")
    assert "every IAM role" in every_role["message"]


def test_if_exists_with_null_is_not_a_contradiction(write):
    st = {
        "Sid": "RequireOwnerTag",
        "Effect": "Deny",
        "Action": "ec2:RunInstances",
        "Resource": "*",
        "Condition": {
            "Null": {"aws:RequestTag/Owner": "true"},
            "StringNotEqualsIfExists": {"aws:RequestTag/Owner": "x"},
        },
    }
    assert "SCP-CONDITION-NEVER-TRUE" not in ids(write("ie.json", {"Version": "2012-10-17", "Statement": [st]}))


def test_break_glass_role_not_exempt():
    path = fixture("fixture-break-glass.json")
    assert "SCP-BREAK-GLASS-NOT-EXEMPT" not in ids(path)
    found = by_id(path, "SCP-BREAK-GLASS-NOT-EXEMPT", "--break-glass-role", "BreakGlassAdmin")
    assert [f["sid"] for f in found] == ["ProtectCloudTrail"]  # ProtectGuardDuty covers it with BreakGlass*


def test_break_glass_literal_operator_does_not_count_as_wildcard_exemption():
    found = by_id(
        fixture("fixture-condition-operator.json"), "SCP-BREAK-GLASS-NOT-EXEMPT", "--break-glass-role", "AdminRole"
    )
    assert [f["sid"] for f in found] == ["ExemptAdminsWrongOperator"]


def test_sid_format():
    assert ids(fixture("fixture-sid-format.json")) == {"SCP-SID-FORMAT"}


def test_notaction_scope():
    found = by_id(fixture("fixture-notaction-scope.json"), "SCP-NOTACTION-SCOPE")
    assert found and "aws:MultiFactorAuthPresent" in found[0]["message"]


def test_security_guardrail_without_exemption_is_low(write):
    st = {"Sid": "ProtectCloudTrail", "Effect": "Deny", "Action": "cloudtrail:StopLogging", "Resource": "*"}
    found = by_id(write("p.json", {"Version": "2012-10-17", "Statement": [st]}), "SCP-NO-EXEMPTION")
    assert found[0]["severity"] == "low"


def test_good_fixture_is_clean_at_the_lowest_threshold():
    rc, out, _ = run(["lint", str(fixture("fixture-good.json")), "--fail-on", "low"])
    assert rc == 0 and "0 finding(s)" in out


def test_every_finding_has_id_severity_sid_explanation_and_fix():
    _, out = run_json(
        [
            "lint",
            str(fixture("fixture-never-true.json")),
            str(fixture("fixture-mgmt-lockout.json")),
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
    )
    for result in out:
        for f in result["findings"]:
            assert f["id"] in RULES
            assert f["severity"] in ("low", "medium", "high")
            assert f["sid"] and f["message"] and f["fix"]
            assert f["line"] >= 1


def test_findings_point_at_the_sid_line():
    _, out = run_json(["lint", str(fixture("fixture-good.json")), "--format", "json", "--break-glass-role", "Other"])
    finding = out[0]["findings"][0]
    lines = fixture("fixture-good.json").read_text().splitlines()
    assert '"ProtectCloudTrail"' in lines[finding["line"] - 1]


def test_rule_severities_are_valid_and_unique_ids():
    for rid, rule in RULES.items():
        assert rule.id == rid and rid.startswith("SCP-")
        assert rule.severity in ("low", "medium", "high")
        assert rule.fix and rule.title and rule.help.startswith("https://")


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [("high", 0), ("medium", 1), ("low", 1), ("none", 0)],
)
def test_fail_on_thresholds(threshold, expected):
    rc, _, _ = run(["lint", str(fixture("fixture-region-gaps.json")), "--fail-on", threshold])
    assert rc == expected
