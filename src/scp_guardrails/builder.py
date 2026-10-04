"""Build deny-list service control policies from a short YAML or JSON spec.

Every guardrail in the catalogue is enabled by one spec key (see `scp-guardrails catalog`). Statements are packed in
order into as few documents as fit under `max_policy_chars`, measured on the compact JSON form, which is what you
should upload. Every document is linted; a high-severity finding fails the build.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import _miniyaml
from .catalog import (
    BUDGET_PROTECT_ACTIONS,
    BY_KEY,
    BY_SID,
    COMMITMENT_ACTIONS,
    DEFAULT_DENY_INSTANCE_TYPES,
    DEFAULT_SAGEMAKER_TYPES,
    GLOBAL_SERVICE_ACTIONS,
    SAGEMAKER_CREATE,
    SECURITY_SERVICE_ACTIONS,
)
from .explain import describe_statement
from .lint import Finding, LintOptions, lint_policy
from .policy import POLICY_VERSION, SCP_MAX_ATTACHED, SCP_MAX_CHARS, compact

Statement = dict[str, Any]

GUARDRAIL_KEYS = set(BY_KEY)
OPTION_KEYS = {"protected_roles", "max_policy_chars", "max_documents"}
KNOWN_KEYS = GUARDRAIL_KEYS | OPTION_KEYS
BOOL_KEYS = {
    "deny_leave_organization",
    "deny_disable_security_services",
    "deny_root_user",
    "require_imdsv2",
    "deny_public_s3_acls",
    "deny_bedrock_customization",
    "deny_commitments",
    "protect_budgets",
}
LIST_KEYS = {
    "allowed_regions",
    "protected_roles",
    "deny_iam_users_outside",
    "allowed_instance_types",
    "deny_volume_types",
    "deny_services",
}
LIST_OR_DEFAULT_KEYS = {"deny_instance_types", "sagemaker_instance_types"}
MIN_POLICY_CHARS = 200
# FullAWSAccess (or your allow-list policy) stays attached, so it takes one of the attachment slots.
DEFAULT_MAX_DOCUMENTS = SCP_MAX_ATTACHED - 1

REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
ROLE_RE = re.compile(r"^[\w+=,.@*-]{1,64}$")
TYPE_PATTERN_RE = re.compile(r"^[a-z0-9.*-]{1,40}$")
SERVICE_RE = re.compile(r"^[a-z0-9-]{2,40}$")
TAG_RE = re.compile(r"^[\w.:/=+@ -]{1,128}$")
INSTANCE_ARN = "arn:aws:ec2:*:*:instance/*"
VOLUME_ARN = "arn:aws:ec2:*:*:volume/*"


class SpecError(Exception):
    """The spec cannot be read or does not validate."""


@dataclass
class BuildResult:
    documents: list[dict[str, Any]]
    manifest: dict[str, Any]
    placed: list[list[tuple[str, Statement]]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]


def load_spec(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecError(f"{path}: cannot read: {exc.strerror or exc}") from exc
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else _miniyaml.load(text)
    except (json.JSONDecodeError, _miniyaml.YAMLError) as exc:
        raise SpecError(f"{path}: cannot parse: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError(f"{path}: the spec must be a mapping")
    return data


def _need(cond: bool, message: str) -> None:
    if not cond:
        raise SpecError(message)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_spec(spec: dict[str, Any]) -> None:
    unknown = set(spec) - KNOWN_KEYS
    _need(not unknown, f"unknown spec keys: {', '.join(sorted(unknown))} (see `scp-guardrails catalog`)")
    for key in BOOL_KEYS & set(spec):
        _need(isinstance(spec[key], bool), f"{key} must be true or false")
    for key in LIST_KEYS & set(spec):
        _need(
            isinstance(spec[key], list) and all(isinstance(v, str) and v for v in spec[key]),
            f"{key} must be a list of non-empty strings",
        )
    for key in LIST_OR_DEFAULT_KEYS & set(spec):
        value = spec[key]
        if isinstance(value, bool):
            _need(value, f"{key}: false is not needed; leave the key out")
        else:
            _need(
                isinstance(value, list)
                and bool(value)
                and all(isinstance(v, str) and TYPE_PATTERN_RE.match(v) for v in value),
                f"{key} must be true (the default list) or a non-empty list of type names or patterns",
            )
    if "allowed_regions" in spec:
        _need(bool(spec["allowed_regions"]), "allowed_regions is empty, which would deny every regional service")
        for region in spec["allowed_regions"]:
            _need(bool(REGION_RE.match(region)), f"allowed_regions: {region!r} is not a region name like eu-west-1")
    for acct in spec.get("deny_iam_users_outside", []):
        _need(bool(ACCOUNT_RE.match(acct)), f"deny_iam_users_outside: {acct!r} is not a 12-digit account id")
    if "deny_iam_users_outside" in spec:
        _need(bool(spec["deny_iam_users_outside"]), "deny_iam_users_outside needs at least one account id")
    for role in spec.get("protected_roles", []):
        _need(
            "/" not in role and ":" not in role,
            f"protected_roles takes role names (optionally with a trailing *), not ARNs or paths: {role!r}",
        )
        _need(bool(ROLE_RE.match(role)), f"protected_roles: {role!r} is not a valid role name")
        _need(role.strip("*") != "", "protected_roles: '*' would exempt every role")
    _need(
        not ("deny_instance_types" in spec and "allowed_instance_types" in spec),
        "use deny_instance_types or allowed_instance_types, not both",
    )
    if "allowed_instance_types" in spec:
        _need(bool(spec["allowed_instance_types"]), "allowed_instance_types is empty, which denies every type")
        _need("*" not in spec["allowed_instance_types"], "allowed_instance_types: '*' allows everything")
        for t in spec["allowed_instance_types"]:
            _need(bool(TYPE_PATTERN_RE.match(t)), f"allowed_instance_types: {t!r} is not a type name or pattern")
    for t in spec.get("deny_volume_types", []):
        _need(bool(TYPE_PATTERN_RE.match(t)), f"deny_volume_types: {t!r} is not a volume type")
    for s in spec.get("deny_services", []):
        _need(bool(SERVICE_RE.match(s)), f"deny_services: {s!r} is not an IAM service prefix such as redshift")
        _need(s not in {"iam", "sts", "organizations"}, f"deny_services must not deny {s} entirely")
    if "max_volume_iops" in spec:
        _need(
            _is_int(spec["max_volume_iops"]) and spec["max_volume_iops"] > 0,
            "max_volume_iops must be a whole number above 0",
        )
    if "require_instance_tag" in spec:
        tag = spec["require_instance_tag"]
        _need(
            isinstance(tag, str) and bool(TAG_RE.match(tag)) and not tag.lower().startswith("aws:"),
            "require_instance_tag must be a tag key such as Owner",
        )
    if "max_policy_chars" in spec:
        v = spec["max_policy_chars"]
        _need(
            _is_int(v) and MIN_POLICY_CHARS <= v <= SCP_MAX_CHARS,
            f"max_policy_chars must be a whole number from {MIN_POLICY_CHARS} to {SCP_MAX_CHARS}",
        )
    if "max_documents" in spec:
        v = spec["max_documents"]
        _need(_is_int(v) and 1 <= v <= 50, "max_documents must be a whole number from 1 to 50")


def exemption(spec: dict[str, Any]) -> dict[str, Any]:
    roles = spec.get("protected_roles") or []
    if not roles:
        return {}
    return {"ArnNotLike": {"aws:PrincipalArn": [f"arn:aws:iam::*:role/{r}" for r in roles]}}


def with_condition(statement: Statement, condition: dict[str, Any]) -> Statement:
    if condition:
        merged = dict(statement.get("Condition", {}))
        for op, kv in condition.items():
            merged.setdefault(op, {}).update(kv)
        statement["Condition"] = merged
    return statement


def _types(spec: dict[str, Any], key: str, default: tuple[str, ...]) -> list[str]:
    value = spec[key]
    return list(default) if value is True else list(value)


def build_statements(spec: dict[str, Any]) -> list[tuple[str, Statement]]:
    """(guardrail key, statement) pairs in a stable order: baseline guardrails first, then spend denies."""
    ex = exemption(spec)
    out: list[tuple[str, Statement]] = []

    def add(key: str, st: Statement, exempt: bool = False) -> None:
        out.append((key, with_condition(st, ex) if exempt else st))

    if spec.get("deny_leave_organization"):
        add(
            "deny_leave_organization",
            {
                "Sid": "DenyLeaveOrganization",
                "Effect": "Deny",
                "Action": "organizations:LeaveOrganization",
                "Resource": "*",
            },
        )
    if spec.get("deny_root_user"):
        add(
            "deny_root_user",
            {
                "Sid": "DenyRootUser",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}},
            },
        )
    if spec.get("deny_disable_security_services"):
        for sid, actions in SECURITY_SERVICE_ACTIONS.items():
            add(
                "deny_disable_security_services",
                {"Sid": sid, "Effect": "Deny", "Action": list(actions), "Resource": "*"},
                exempt=True,
            )
    if spec.get("allowed_regions"):
        add(
            "allowed_regions",
            {
                "Sid": "DenyOutsideAllowedRegions",
                "Effect": "Deny",
                "NotAction": list(GLOBAL_SERVICE_ACTIONS),
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": list(spec["allowed_regions"])}},
            },
            exempt=True,
        )
    if spec.get("deny_iam_users_outside"):
        add(
            "deny_iam_users_outside",
            {
                "Sid": "DenyIamUsersOutsideIdentityAccount",
                "Effect": "Deny",
                "Action": ["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:CreateUser"],
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:PrincipalAccount": list(spec["deny_iam_users_outside"])}},
            },
        )
    if spec.get("require_imdsv2"):
        add(
            "require_imdsv2",
            {
                "Sid": "RequireImdsv2OnLaunch",
                "Effect": "Deny",
                "Action": "ec2:RunInstances",
                "Resource": INSTANCE_ARN,
                "Condition": {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}},
            },
        )
        add(
            "require_imdsv2",
            {
                "Sid": "DenyImdsOptionChanges",
                "Effect": "Deny",
                "Action": "ec2:ModifyInstanceMetadataOptions",
                "Resource": "*",
            },
            exempt=True,
        )
        add(
            "require_imdsv2",
            {
                "Sid": "DenyImdsv1RoleCredentials",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"NumericLessThan": {"ec2:RoleDelivery": "2.0"}},
            },
        )
    if spec.get("deny_public_s3_acls"):
        add(
            "deny_public_s3_acls",
            {
                "Sid": "DenyPublicS3CannedAcls",
                "Effect": "Deny",
                "Action": ["s3:CreateBucket", "s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": ["authenticated-read", "public-read", "public-read-write"]}
                },
            },
        )
        add(
            "deny_public_s3_acls",
            {
                "Sid": "ProtectAccountPublicAccessBlock",
                "Effect": "Deny",
                "Action": "s3:PutAccountPublicAccessBlock",
                "Resource": "*",
            },
            exempt=True,
        )
    if spec.get("require_instance_tag"):
        add(
            "require_instance_tag",
            {
                "Sid": "RequireTagOnLaunch",
                "Effect": "Deny",
                "Action": "ec2:RunInstances",
                "Resource": INSTANCE_ARN,
                "Condition": {"Null": {f"aws:RequestTag/{spec['require_instance_tag']}": "true"}},
            },
        )
    # Spend denies (lifted from the sandbox spend guardrails).
    if "allowed_instance_types" in spec:
        add(
            "allowed_instance_types",
            {
                "Sid": "DenyInstanceTypesNotAllowed",
                "Effect": "Deny",
                "Action": ["ec2:RunInstances", "ec2:StartInstances"],
                "Resource": INSTANCE_ARN,
                "Condition": {"StringNotLike": {"ec2:InstanceType": list(spec["allowed_instance_types"])}},
            },
            exempt=True,
        )
    elif spec.get("deny_instance_types"):
        add(
            "deny_instance_types",
            {
                "Sid": "DenyExpensiveInstanceTypes",
                "Effect": "Deny",
                "Action": ["ec2:RunInstances", "ec2:StartInstances"],
                "Resource": INSTANCE_ARN,
                "Condition": {
                    "StringLike": {"ec2:InstanceType": _types(spec, "deny_instance_types", DEFAULT_DENY_INSTANCE_TYPES)}
                },
            },
            exempt=True,
        )
    if "max_volume_iops" in spec:
        add(
            "max_volume_iops",
            {
                "Sid": "DenyHighIopsVolumes",
                "Effect": "Deny",
                "Action": ["ec2:CreateVolume", "ec2:RunInstances"],
                "Resource": VOLUME_ARN,
                "Condition": {"NumericGreaterThan": {"ec2:VolumeIops": str(spec["max_volume_iops"])}},
            },
            exempt=True,
        )
    if spec.get("deny_volume_types"):
        add(
            "deny_volume_types",
            {
                "Sid": "DenyProvisionedIopsVolumeTypes",
                "Effect": "Deny",
                "Action": ["ec2:CreateVolume", "ec2:RunInstances"],
                "Resource": VOLUME_ARN,
                "Condition": {"StringEquals": {"ec2:VolumeType": list(spec["deny_volume_types"])}},
            },
            exempt=True,
        )
    if spec.get("sagemaker_instance_types"):
        add(
            "sagemaker_instance_types",
            {
                "Sid": "DenySageMakerGpuInstanceTypes",
                "Effect": "Deny",
                "Action": list(SAGEMAKER_CREATE),
                "Resource": "*",
                "Condition": {
                    "ForAnyValue:StringLike": {
                        "sagemaker:InstanceTypes": _types(spec, "sagemaker_instance_types", DEFAULT_SAGEMAKER_TYPES)
                    }
                },
            },
            exempt=True,
        )
    if spec.get("deny_bedrock_customization"):
        add(
            "deny_bedrock_customization",
            {
                "Sid": "DenyBedrockCustomizationAndThroughput",
                "Effect": "Deny",
                "Action": ["bedrock:CreateModelCustomizationJob", "bedrock:CreateProvisionedModelThroughput"],
                "Resource": "*",
            },
            exempt=True,
        )
    if spec.get("deny_services"):
        add(
            "deny_services",
            {
                "Sid": "DenyExpensiveServices",
                "Effect": "Deny",
                "Action": [f"{s}:*" for s in sorted(set(spec["deny_services"]))],
                "Resource": "*",
            },
            exempt=True,
        )
    if spec.get("deny_commitments"):
        add(
            "deny_commitments",
            {
                "Sid": "DenyPurchaseCommitments",
                "Effect": "Deny",
                "Action": list(COMMITMENT_ACTIONS),
                "Resource": "*",
            },
            exempt=True,
        )
    if spec.get("protect_budgets"):
        add(
            "protect_budgets",
            {
                "Sid": "ProtectBudgetsAndAnomalyMonitors",
                "Effect": "Deny",
                "Action": list(BUDGET_PROTECT_ACTIONS),
                "Resource": "*",
            },
            exempt=True,
        )
    return out


def document(statements: list[Statement]) -> dict[str, Any]:
    return {"Version": POLICY_VERSION, "Statement": statements}


def pack(statements: list[tuple[str, Statement]], limit: int) -> list[list[tuple[str, Statement]]]:
    """First-fit packing in order: each statement goes into the first document it still fits in."""
    docs: list[list[tuple[str, Statement]]] = []
    for item in statements:
        single = len(compact(document([item[1]])))
        if single > limit:
            raise SpecError(f"statement {item[1].get('Sid')} alone is {single} characters, over the {limit} limit")
        for doc in docs:
            if len(compact(document([s for _, s in doc] + [item[1]]))) <= limit:
                doc.append(item)
                break
        else:
            docs.append([item])
    return docs


def build(spec: dict[str, Any]) -> BuildResult:
    validate_spec(spec)
    limit = int(spec.get("max_policy_chars", SCP_MAX_CHARS))
    max_docs = int(spec.get("max_documents", DEFAULT_MAX_DOCUMENTS))
    statements = build_statements(spec)
    if not statements:
        raise SpecError("the spec enables no guardrail (see `scp-guardrails catalog` for the keys)")
    packed = pack(statements, limit)
    if len(packed) > max_docs:
        raise SpecError(
            f"the guardrails need {len(packed)} documents of at most {limit} characters, more than max_documents "
            f"({max_docs}). Each root, OU and account takes at most {SCP_MAX_ATTACHED} directly attached SCPs "
            "including FullAWSAccess; attach some documents at the root and some at an OU (inheritance applies "
            "both), raise max_policy_chars, or raise max_documents if you will split them that way."
        )
    documents = [document([s for _, s in doc]) for doc in packed]
    manifest: dict[str, Any] = {
        "limit": limit,
        "max_documents": max_docs,
        "documents": [],
        "warnings": [],
        "lint": [],
    }
    findings: list[Finding] = []
    for i, (doc, items) in enumerate(zip(documents, packed, strict=True), 1):
        name = f"scp-{i:02d}.json"
        manifest["documents"].append(
            {
                "file": name,
                "chars_compact": len(compact(doc)),
                "guardrails": sorted({g for g, _ in items}),
                "statements": [s.get("Sid") for _, s in items],
            }
        )
        for f in lint_policy(doc, LintOptions(limit=limit)):
            f.file = name
            findings.append(f)
            manifest["lint"].append(f.as_dict())
    if len(documents) > SCP_MAX_ATTACHED - 1:
        manifest["warnings"].append(
            f"{len(documents)} documents: a root, OU or account takes at most {SCP_MAX_ATTACHED} directly attached "
            "SCPs including FullAWSAccess, so split them across the root and OUs"
        )
    if spec.get("allowed_regions") and not spec.get("protected_roles"):
        manifest["warnings"].append(
            "allowed_regions without protected_roles: no break-glass role can work outside the allowed regions"
        )
    if "us-east-1" not in spec.get("allowed_regions", ["us-east-1"]):
        manifest["warnings"].append(
            "us-east-1 is not in allowed_regions: services whose control plane is in us-east-1 and are not in the "
            "NotAction list will fail; test on a sandbox OU first"
        )
    return BuildResult(documents, manifest, packed, findings)


def summary_markdown(result: BuildResult) -> str:
    """What each statement denies and its known side effects, per document."""
    m = result.manifest
    out = [
        "# SCP build summary",
        "",
        f"{len(result.documents)} document(s), each at most {m['limit']} characters in compact form. "
        "Every statement is a Deny; none grants anything. SCPs do not affect the management account or "
        "service-linked roles.",
        "",
    ]
    for meta, items in zip(m["documents"], result.placed, strict=True):
        out += [
            f"## {meta['file']} ({meta['chars_compact']}/{m['limit']} characters)",
            "",
            "| Statement | Guardrail | What it denies | Known side effects |",
            "| --- | --- | --- | --- |",
        ]
        for key, st in items:
            g = BY_SID.get(str(st.get("Sid"))) or BY_KEY.get(key)
            side = g.side_effects if g else ""
            out.append(f"| `{st.get('Sid')}` | `{key}` | {describe_statement(st)} | {side} |")
        out.append("")
    if m["warnings"]:
        out += ["## Warnings", ""] + [f"- {w}" for w in m["warnings"]] + [""]
    if m["lint"]:
        out += ["## Lint findings", ""]
        out += [f"- {i['severity']} {i['id']} {i['file']} {i['sid'] or '-'}: {i['message']}" for i in m["lint"]]
        out.append("")
    out += [
        "## Before you attach",
        "",
        "- [ ] Every document reviewed by someone who did not write the spec.",
        "- [ ] Attached first to an OU holding one non-production account, and the workloads there tested.",
        "- [ ] The protected roles exist and the people who can assume them are known.",
        "- [ ] FullAWSAccess (or your allow statements) is still attached at every level.",
        "",
    ]
    return "\n".join(out)


def write_outputs(result: BuildResult, out: Path, pretty: bool = False) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for meta, doc in zip(result.manifest["documents"], result.documents, strict=True):
        path = out / meta["file"]
        path.write_text((json.dumps(doc, indent=2) if pretty else compact(doc)) + "\n", encoding="utf-8")
        written.append(path)
    (out / "manifest.json").write_text(json.dumps(result.manifest, indent=2) + "\n", encoding="utf-8")
    (out / "SUMMARY.md").write_text(summary_markdown(result), encoding="utf-8")
    return [*written, out / "manifest.json", out / "SUMMARY.md"]
