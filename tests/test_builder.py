"""Builder tests, ported from the aws-security-skills scp-guardrails tests and extended."""

import json

import pytest
from conftest import fixture, run, run_json

from scp_guardrails import builder
from scp_guardrails.catalog import BY_KEY, CATALOG, GLOBAL_SERVICE_ACTIONS
from scp_guardrails.lint import lint_policy
from scp_guardrails.policy import SCP_MAX_ATTACHED, SCP_MAX_CHARS, compact

SPEC = fixture("fixture-full-spec.yaml")
EVERY_KEY = {
    "allowed_regions": ["eu-west-1", "us-east-1"],
    "protected_roles": ["OrganizationAccountAccessRole", "BreakGlassAdmin"],
    "deny_leave_organization": True,
    "deny_disable_security_services": True,
    "deny_root_user": True,
    "deny_iam_users_outside": ["111122223333"],
    "require_imdsv2": True,
    "deny_public_s3_acls": True,
    "require_instance_tag": "Owner",
    "deny_instance_types": True,
    "max_volume_iops": 3000,
    "deny_volume_types": ["io1", "io2"],
    "sagemaker_instance_types": True,
    "deny_bedrock_customization": True,
    "deny_services": ["redshift", "redshift-serverless"],
    "deny_commitments": True,
    "protect_budgets": True,
}


def statements(docs):
    return {s["Sid"]: s for d in docs for s in d["Statement"]}


def test_full_spec_builds_valid_documents_under_limit(tmp_path):
    rc, out = run_json(["build", "--spec", str(SPEC), "--format", "json", "--out", str(tmp_path)])
    assert rc == 0
    docs = out["documents"]
    for d in docs:
        assert d["Version"] == "2012-10-17"
        assert isinstance(d["Statement"], list) and d["Statement"]
        for st in d["Statement"]:
            assert st["Effect"] == "Deny"
            assert ("Action" in st) != ("NotAction" in st)
            assert "Resource" in st
        assert len(compact(d)) <= SCP_MAX_CHARS
        assert lint_policy(d) == []
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == ["SUMMARY.md", "manifest.json"] + [f"scp-{i:02d}.json" for i in range(1, len(docs) + 1)]
    assert json.loads((tmp_path / "scp-01.json").read_text()) == docs[0]
    assert out["manifest"]["lint"] == []


def test_guardrail_contents():
    _, out = run_json(["build", "--spec", str(SPEC), "--format", "json"])
    st = statements(out["documents"])
    assert set(st) >= {
        "DenyLeaveOrganization",
        "DenyRootUser",
        "ProtectCloudTrail",
        "ProtectGuardDuty",
        "ProtectSecurityHub",
        "ProtectConfig",
        "DenyOutsideAllowedRegions",
        "DenyIamUsersOutsideIdentityAccount",
        "RequireImdsv2OnLaunch",
        "DenyImdsv1RoleCredentials",
        "DenyPublicS3CannedAcls",
    }
    region = st["DenyOutsideAllowedRegions"]
    assert "iam:*" in region["NotAction"] and "sts:*" in region["NotAction"]
    assert region["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == ["ap-southeast-2", "us-east-1"]
    assert region["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == [
        "arn:aws:iam::*:role/OrganizationAccountAccessRole",
        "arn:aws:iam::*:role/BreakGlassAdmin",
    ]
    assert "ArnNotLike" in st["ProtectCloudTrail"]["Condition"]
    assert st["DenyIamUsersOutsideIdentityAccount"]["Condition"]["StringNotEquals"]["aws:PrincipalAccount"] == [
        "111122223333"
    ]
    assert st["RequireImdsv2OnLaunch"]["Condition"]["StringNotEquals"]["ec2:MetadataHttpTokens"] == "required"


def test_region_notaction_is_the_aws_example_list():
    docs = builder.build({"allowed_regions": ["eu-west-1"]}).documents
    assert statements(docs)["DenyOutsideAllowedRegions"]["NotAction"] == list(GLOBAL_SERVICE_ACTIONS)


def test_small_limit_splits_into_several_documents_and_warns():
    spec = {k: v for k, v in EVERY_KEY.items() if k != "allowed_regions"}
    result = builder.build({**spec, "max_policy_chars": 700, "max_documents": 40})
    assert len(result.documents) > SCP_MAX_ATTACHED - 1
    assert all(m["chars_compact"] <= 700 for m in result.manifest["documents"])
    assert any("directly attached" in w for w in result.manifest["warnings"])
    sids = [s for m in result.manifest["documents"] for s in m["statements"]]
    assert len(sids) == len(set(sids)) == len(builder.build_statements(spec))
    assert result.findings == []


def test_ported_split_at_1100_characters():
    spec = {**builder.load_spec(SPEC), "max_policy_chars": 1100}
    result = builder.build(spec)
    assert len(result.documents) == 5
    assert all(m["chars_compact"] <= 1100 for m in result.manifest["documents"])
    assert not any("directly attached" in w for w in result.manifest["warnings"])


def test_split_documents_each_lint_clean_and_keep_order():
    spec = {**builder.load_spec(SPEC), "max_policy_chars": 2000}
    result = builder.build(spec)
    assert len(result.documents) >= 2
    for doc in result.documents:
        assert len(compact(doc)) <= 2000
        assert lint_policy(doc) == []
    first = [s["Sid"] for s in result.documents[0]["Statement"]]
    assert first[0] == "DenyLeaveOrganization"


def test_more_documents_than_attachment_slots_is_a_spec_error():
    spec = {**builder.load_spec(SPEC), "max_policy_chars": 1100, "max_documents": 4}
    with pytest.raises(builder.SpecError, match="more than max_documents"):
        builder.build(spec)
    rc, _, err = run(["build", "--spec", str(SPEC), "--max-chars", "300"])
    assert rc == 2 and "error:" in err


def test_default_max_documents_leaves_a_slot_for_full_aws_access():
    assert builder.DEFAULT_MAX_DOCUMENTS == SCP_MAX_ATTACHED - 1


def test_pack_is_first_fit():
    a = ("x", {"Sid": "A", "Effect": "Deny", "Action": ["ec2:" + "A" * 300], "Resource": "*"})
    b = ("x", {"Sid": "B", "Effect": "Deny", "Action": ["ec2:" + "B" * 300], "Resource": "*"})
    c = ("x", {"Sid": "C", "Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"})
    packed = builder.pack([a, b, c], 480)
    assert [[s["Sid"] for _, s in d] for d in packed] == [["A", "C"], ["B"]]


def test_minimal_json_spec_and_missing_exemption_warning():
    rc, out = run_json(["build", "--spec", str(fixture("fixture-minimal-spec.json")), "--format", "json"])
    assert rc == 0
    assert set(statements(out["documents"])) == {"DenyLeaveOrganization", "DenyOutsideAllowedRegions"}
    assert any("protected_roles" in w for w in out["manifest"]["warnings"])
    assert any("us-east-1" in w for w in out["manifest"]["warnings"])
    assert [i["id"] for i in out["manifest"]["lint"]] == ["SCP-NO-EXEMPTION"]


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("unknown.json", '{"deny_everything": true}'),
        ("empty.json", "{}"),
        ("acct.json", '{"deny_iam_users_outside": ["12345"]}'),
        ("arn.json", '{"deny_root_user": true, "protected_roles": ["arn:aws:iam::123456789012:role/x"]}'),
        ("star.json", '{"deny_root_user": true, "protected_roles": ["*"]}'),
        ("regions.json", '{"allowed_regions": []}'),
        ("region-name.json", '{"allowed_regions": ["Europe"]}'),
        ("broken.json", '{"allowed_regions": '),
        ("list.json", "[1, 2]"),
        ("bool.json", '{"deny_root_user": "yes"}'),
        ("both.json", '{"deny_instance_types": true, "allowed_instance_types": ["t3.*"]}'),
        ("allow-star.json", '{"allowed_instance_types": ["*"]}'),
        ("iops.json", '{"max_volume_iops": -1}'),
        ("services.json", '{"deny_services": ["iam"]}'),
        ("service-name.json", '{"deny_services": ["Not A Service"]}'),
        ("tag.json", '{"require_instance_tag": "aws:reserved"}'),
        ("chars.json", '{"deny_root_user": true, "max_policy_chars": 50000}'),
        ("docs.json", '{"deny_root_user": true, "max_documents": 0}'),
        ("false-default.json", '{"deny_instance_types": false}'),
    ],
)
def test_bad_specs_exit_2(write, name, body):
    rc, _, err = run(["build", "--spec", str(write(name, body))])
    assert rc == 2, name
    assert err.startswith("error:"), name


def test_missing_spec_file_exit_2(tmp_path):
    rc, _, err = run(["build", "--spec", str(tmp_path / "nope.yaml")])
    assert rc == 2 and "cannot read" in err


def test_text_output():
    rc, out, _ = run(["build", "--spec", str(SPEC)])
    assert rc == 0 and "scp-01.json" in out and f"/{SCP_MAX_CHARS} chars" in out and "non-production OU" in out


def test_statement_larger_than_limit_is_a_spec_error(write):
    rc, _, err = run(
        ["build", "--spec", str(write("s.json", '{"allowed_regions": ["eu-west-1"], "max_policy_chars": 500}'))]
    )
    assert rc == 2 and "over the 500 limit" in err


def test_every_catalogue_key_is_buildable_and_emits_its_statements():
    result = builder.build(EVERY_KEY | {"deny_instance_types": True})
    sids = set(statements(result.documents))
    for g in CATALOG:
        if g.key == "allowed_instance_types":
            continue  # mutually exclusive with deny_instance_types
        assert set(g.statements) <= sids, g.key
    assert result.findings == []


def test_allowed_instance_types_guardrail():
    spec = {k: v for k, v in EVERY_KEY.items() if k != "deny_instance_types"} | {"allowed_instance_types": ["t3.*"]}
    st = statements(builder.build(spec).documents)
    assert st["DenyInstanceTypesNotAllowed"]["Condition"]["StringNotLike"]["ec2:InstanceType"] == ["t3.*"]
    assert "DenyExpensiveInstanceTypes" not in st


def test_each_catalogue_key_alone_builds():
    values = EVERY_KEY | {"allowed_instance_types": ["t3.*"]}
    for g in CATALOG:
        spec = {g.key: values[g.key]}
        result = builder.build(spec)
        assert {s["Sid"] for d in result.documents for s in d["Statement"]} == set(g.statements), g.key


def test_spend_statements_use_the_protected_role_exemption():
    st = statements(builder.build(EVERY_KEY).documents)
    for sid in (
        "DenyExpensiveInstanceTypes",
        "DenyHighIopsVolumes",
        "DenyExpensiveServices",
        "ProtectBudgetsAndAnomalyMonitors",
    ):
        assert st[sid]["Condition"]["ArnNotLike"]["aws:PrincipalArn"][1] == "arn:aws:iam::*:role/BreakGlassAdmin"
    assert st["DenyHighIopsVolumes"]["Condition"]["NumericGreaterThan"]["ec2:VolumeIops"] == "3000"
    assert st["DenyExpensiveServices"]["Action"] == ["redshift:*", "redshift-serverless:*"]
    assert st["RequireTagOnLaunch"]["Condition"] == {"Null": {"aws:RequestTag/Owner": "true"}}


def test_default_type_lists_are_used_for_true():
    st = statements(builder.build({"deny_instance_types": True, "sagemaker_instance_types": True}).documents)
    assert "p*" in st["DenyExpensiveInstanceTypes"]["Condition"]["StringLike"]["ec2:InstanceType"]
    assert st["DenySageMakerGpuInstanceTypes"]["Condition"]["ForAnyValue:StringLike"]["sagemaker:InstanceTypes"]


def test_summary_markdown_lists_every_statement_and_side_effects(tmp_path):
    rc, _, _ = run(["build", "--spec", str(SPEC), "--out", str(tmp_path)])
    assert rc == 0
    summary = (tmp_path / "SUMMARY.md").read_text()
    for sid in ("DenyLeaveOrganization", "DenyOutsideAllowedRegions", "RequireImdsv2OnLaunch"):
        assert f"`{sid}`" in summary
    assert BY_KEY["require_imdsv2"].side_effects in summary
    assert "## Before you attach" in summary


def test_markdown_format_prints_the_summary():
    rc, out, _ = run(["build", "--spec", str(SPEC), "--format", "markdown"])
    assert rc == 0 and out.startswith("# SCP build summary")


def test_pretty_output_is_indented_but_measured_compact(tmp_path):
    run(["build", "--spec", str(SPEC), "--out", str(tmp_path), "--pretty"])
    text = (tmp_path / "scp-01.json").read_text()
    assert "\n  " in text
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["documents"][0]["chars_compact"] == len(compact(json.loads(text)))


def test_build_is_deterministic():
    a = builder.build(builder.load_spec(SPEC))
    b = builder.build(builder.load_spec(SPEC))
    assert a.documents == b.documents and a.manifest == b.manifest


def test_example_specs_build_cleanly():
    from conftest import ROOT

    for name in ("spec.yaml", "sandbox-spec.yaml"):
        result = builder.build(builder.load_spec(ROOT / "examples" / name))
        assert result.findings == [], name
