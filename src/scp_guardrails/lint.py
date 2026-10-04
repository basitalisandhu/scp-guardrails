"""Lint service control policies for the mistakes that lock you out or do nothing.

`lint_policy` takes one parsed SCP document and returns findings. Each rule has an id, a severity (low, medium or
high), a title, an explanation and a fix; docs/rules.md documents every rule with an example. Nothing here calls
AWS: the checks are static reads of the policy JSON.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .catalog import CORE_GLOBALS, GLOBAL_SERVICE_ACTIONS, SECURITY_PREFIXES
from .policy import (
    DOCS_CONDITION_OPERATORS,
    DOCS_EVALUATION,
    DOCS_QUOTAS,
    DOCS_REGION_EXAMPLE,
    DOCS_SCP,
    DOCS_SID,
    DOCS_SYNTAX,
    POLICY_VERSION,
    SCP_MAX_CHARS,
    as_list,
    compact,
    condition_keys,
    conditions,
    sid_of,
    split_operator,
    statement_covers,
    wildcard_match,
)

SEVERITIES = ("low", "medium", "high")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
DEFAULT_ADMIN_ROLES = ("OrganizationAccountAccessRole",)

# Actions the management account relies on inside member accounts: it administers them by assuming a role there.
ADMIN_PROBES = (
    "sts:AssumeRole",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:UpdateAssumeRolePolicy",
)

STRING_OPS = {"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"}
STRING_LIKE_OPS = {"StringLike", "StringNotLike"}
ARN_OPS = {"ArnEquals", "ArnNotEquals", "ArnLike", "ArnNotLike"}
NUMERIC_OPS = {
    "NumericEquals",
    "NumericNotEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
}
DATE_OPS = {
    "DateEquals",
    "DateNotEquals",
    "DateLessThan",
    "DateLessThanEquals",
    "DateGreaterThan",
    "DateGreaterThanEquals",
}
OTHER_OPS = {"Bool", "BinaryEquals", "IpAddress", "NotIpAddress", "Null"}
KNOWN_OPS = STRING_OPS | STRING_LIKE_OPS | ARN_OPS | NUMERIC_OPS | DATE_OPS | OTHER_OPS
NEGATED_OPS = {
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "StringNotLike",
    "ArnNotEquals",
    "ArnNotLike",
    "NumericNotEquals",
    "DateNotEquals",
    "NotIpAddress",
}
PRINCIPAL_KEYS = {
    "aws:principalarn",
    "aws:principalaccount",
    "aws:principalorgid",
    "aws:principaltag",
    "aws:userid",
    "aws:username",
}
ACCOUNT_KEYS = {"aws:principalaccount", "aws:sourceaccount", "aws:resourceaccount"}
SID_RE = re.compile(r"^[A-Za-z0-9]*$")
NUMBER_RE = re.compile(r"^-?\d+(\.\d+)?$")
ACCOUNT_RE = re.compile(r"^\d{12}$")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    fix: str
    help: str  # AWS documentation for the rule


RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule(
            "SCP-STRUCTURE",
            "high",
            "Policy or statement is malformed",
            "Give the policy a Statement list; give every statement Effect (Allow or Deny), exactly one of Action "
            "or NotAction, and Resource or NotResource.",
            DOCS_SYNTAX,
        ),
        Rule(
            "SCP-VERSION",
            "medium",
            'Version is not "2012-10-17"',
            'Set "Version": "2012-10-17"; older versions do not support policy variables.',
            DOCS_SYNTAX,
        ),
        Rule(
            "SCP-SIZE",
            "high",
            "Policy is over the size limit",
            "Split the statements across several documents (`scp-guardrails build` packs them for you) or remove "
            "whitespace; AWS counts every character.",
            DOCS_QUOTAS,
        ),
        Rule(
            "SCP-PRINCIPAL",
            "high",
            "Principal or NotPrincipal in an SCP",
            "SCPs do not support Principal or NotPrincipal. Scope the statement with a Condition on "
            "aws:PrincipalArn instead.",
            DOCS_SYNTAX,
        ),
        Rule(
            "SCP-ALLOW-IN-DENY-LIST",
            "medium",
            "Allow statement in a deny-list SCP",
            "Remove the Allow (FullAWSAccess already allows everything and IAM policies grant), or switch to an "
            "allow-list strategy deliberately and lint with --strategy allow-list.",
            DOCS_EVALUATION,
        ),
        Rule(
            "SCP-ALLOW-NOTACTION",
            "medium",
            "Allow with NotAction",
            "List the allowed actions with Action. In an allow-list strategy, Allow with NotAction allows every "
            "action not listed, including services launched later.",
            DOCS_SYNTAX,
        ),
        Rule(
            "SCP-DENY-ALL",
            "high",
            "Deny * on * with no condition",
            "Scope the statement with a Condition (and an aws:PrincipalArn exemption), or use a narrower Action "
            "list. As written it blocks every action in every attached account.",
            DOCS_EVALUATION,
        ),
        Rule(
            "SCP-DENY-NOTACTION-BARE",
            "medium",
            "Deny with NotAction and no condition",
            "Add the Condition that was meant to scope it (for example aws:RequestedRegion), or list the denied "
            "actions with Action instead.",
            DOCS_SYNTAX,
        ),
        Rule(
            "SCP-NOTACTION-SCOPE",
            "low",
            "Deny with NotAction scoped by something other than region",
            "Check that denying every action except the listed ones, whenever the condition holds, is the "
            "intent. If you meant to deny only the listed actions, use Action.",
            DOCS_SYNTAX,
        ),
        Rule(
            "SCP-REGION-BLOCKS-GLOBAL",
            "high",
            "Region deny that also denies global services",
            "Use NotAction with the global service list from the AWS region-deny example instead of Action, so "
            "IAM, STS, Organizations, Route 53, CloudFront and Support keep working.",
            DOCS_REGION_EXAMPLE,
        ),
        Rule(
            "SCP-REGION-GLOBAL-GAPS",
            "medium",
            "Region deny misses core global services",
            "Add the missing entries to the NotAction list; these services are served from us-east-1 and break "
            "outside it.",
            DOCS_REGION_EXAMPLE,
        ),
        Rule(
            "SCP-REGION-DOC-GAPS",
            "low",
            "Region deny differs from the AWS example list",
            "Compare the NotAction list with the AWS region-deny example and add the global services your "
            "accounts use. AWS notes the example might not include the latest global services.",
            DOCS_REGION_EXAMPLE,
        ),
        Rule(
            "SCP-NO-EXEMPTION",
            "low",
            "Guardrail without a break-glass exemption",
            "Add an ArnNotLike condition on aws:PrincipalArn for a break-glass or security role, for example "
            "arn:aws:iam::*:role/BreakGlassAdmin.",
            DOCS_SCP,
        ),
        Rule(
            "SCP-BREAK-GLASS-NOT-EXEMPT",
            "medium",
            "Named break-glass role is not exempt",
            "Add the role to the statement's aws:PrincipalArn exemption, for example arn:aws:iam::*:role/<name>.",
            DOCS_SCP,
        ),
        Rule(
            "SCP-MGMT-LOCKOUT",
            "high",
            "Deny cuts off the management account's access role",
            "Exempt the role the management account uses in member accounts (OrganizationAccountAccessRole by "
            "default) with an ArnNotLike condition on aws:PrincipalArn, or narrow the actions.",
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html",
        ),
        Rule(
            "SCP-MGMT-ACCOUNT-REF",
            "medium",
            "Condition names the management account",
            "Remove the management account from the condition: SCPs never apply to users or roles in the "
            "management account, so a condition about them has no effect there.",
            DOCS_SCP,
        ),
        Rule(
            "SCP-CONDITION-OPERATOR",
            "medium",
            "Condition operator does not fit its value",
            "Use StringLike or ArnLike for wildcards, Arn operators only with ARNs, Numeric operators with "
            "numbers and Bool with true or false.",
            DOCS_CONDITION_OPERATORS,
        ),
        Rule(
            "SCP-CONDITION-NEVER-TRUE",
            "medium",
            "Condition can never be true, so the statement denies nothing",
            "Fix the condition so it can match: remove the contradiction, the empty value list or the "
            "exemption that matches every principal.",
            DOCS_CONDITION_OPERATORS,
        ),
        Rule(
            "SCP-DUPLICATE-SID",
            "medium",
            "Duplicate statement Sid",
            "Give every statement a unique Sid so reviews, diffs and CloudTrail investigations can refer to it.",
            DOCS_SID,
        ),
        Rule(
            "SCP-SID-FORMAT",
            "low",
            "Sid has characters IAM does not accept",
            "Use only ASCII letters and digits in Sid values.",
            DOCS_SID,
        ),
    )
}


@dataclass
class Finding:
    id: str
    severity: str
    sid: str | None
    message: str
    fix: str
    file: str | None = None
    line: int = 1
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return RULES[self.id].title

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "sid": self.sid,
            "title": self.title,
            "message": self.message,
            "fix": self.fix,
            "help": RULES[self.id].help,
            "file": self.file,
            "line": self.line,
        }


@dataclass(frozen=True)
class LintOptions:
    limit: int = SCP_MAX_CHARS
    strategy: str = "deny-list"
    break_glass_roles: tuple[str, ...] = ()
    admin_roles: tuple[str, ...] = DEFAULT_ADMIN_ROLES
    management_account: str | None = None


def _finding(rule_id: str, message: str, sid: str | None = None) -> Finding:
    rule = RULES[rule_id]
    return Finding(rule_id, rule.severity, sid, message, rule.fix)


def _is_full_allow(st: dict[str, Any]) -> bool:
    return (
        st.get("Effect") == "Allow"
        and as_list(st.get("Action")) == ["*"]
        and as_list(st.get("Resource")) == ["*"]
        and "Condition" not in st
    )


def _principal_exemptions(st: dict[str, Any]) -> list[tuple[str, bool, bool]]:
    """(pattern, wildcards apply, ignore case) for negated aws:PrincipalArn conditions."""

    out: list[tuple[str, bool, bool]] = []
    for op, key, values in conditions(st):
        _, base, _ = split_operator(op)
        if key.lower() == "aws:principalarn" and base in NEGATED_OPS:
            wild = base in ("StringNotLike", "ArnNotLike", "ArnNotEquals")
            ignore_case = base == "StringNotEqualsIgnoreCase"
            out += [(v, wild, ignore_case) for v in values if isinstance(v, str)]
    return out


def _role_arn(name: str) -> str:
    return f"arn:aws:iam::123456789012:role/{name}"


def _exempts(patterns: list[tuple[str, bool, bool]], arn: str) -> bool:
    for pattern, wild, ignore_case in patterns:
        if wild and wildcard_match(pattern, arn, ignore_case=ignore_case):
            return True
        if not wild and (pattern.lower() == arn.lower() if ignore_case else pattern == arn):
            return True
    return False


def _check_conditions(st: dict[str, Any], sid: str, opts: LintOptions) -> list[Finding]:
    out: list[Finding] = []
    triples = conditions(st)
    cond = st.get("Condition")
    if cond is not None and not isinstance(cond, dict):
        out.append(_finding("SCP-STRUCTURE", "Condition must be an object of operators", sid))
        return out
    by_key: dict[str, list[tuple[str, list[Any], bool]]] = {}
    for op, key, values in triples:
        qualifier, base, if_exists = split_operator(op)
        by_key.setdefault(key.lower(), []).append((base, values, if_exists))
        strs = [v for v in values if isinstance(v, str)]
        if base not in KNOWN_OPS or qualifier not in ("", "ForAnyValue", "ForAllValues"):
            out.append(_finding("SCP-CONDITION-OPERATOR", f"unknown condition operator {op!r} on {key}", sid))
            continue
        if not values:
            out.append(
                _finding(
                    "SCP-CONDITION-NEVER-TRUE",
                    f"{op} on {key} has an empty value list, so it never matches and the statement never applies",
                    sid,
                )
            )
        if base in STRING_OPS:
            wild = [v for v in strs if "*" in v or "?" in v]
            if wild:
                better = "ArnLike" if any(v.lower().startswith("arn:") for v in wild) else "StringLike"
                if base.startswith("StringNot"):
                    better = better.replace("Like", "NotLike")
                out.append(
                    _finding(
                        "SCP-CONDITION-OPERATOR",
                        f"{op} on {key} matches wildcards literally: {', '.join(wild)} only matches a value "
                        f"with a real '*' or '?'; use {better}",
                        sid,
                    )
                )
        elif base in ARN_OPS:
            bad = [v for v in strs if v != "*" and not v.lower().startswith(("arn:", "${"))]
            if bad:
                out.append(
                    _finding(
                        "SCP-CONDITION-OPERATOR",
                        f"{op} on {key} compares values that are not ARNs ({', '.join(bad)}); use a String operator",
                        sid,
                    )
                )
        elif base in NUMERIC_OPS:
            bad = [str(v) for v in values if not NUMBER_RE.match(str(v))]
            if bad:
                out.append(
                    _finding(
                        "SCP-CONDITION-OPERATOR",
                        f"{op} on {key} has non-numeric values ({', '.join(bad)}), which never match",
                        sid,
                    )
                )
        elif base in ("Bool", "Null"):
            bad = [str(v) for v in values if str(v).lower() not in ("true", "false")]
            if bad:
                out.append(
                    _finding(
                        "SCP-CONDITION-NEVER-TRUE",
                        f"{op} on {key} takes true or false; {', '.join(bad)} never matches",
                        sid,
                    )
                )
        if opts.management_account and key.lower() in ACCOUNT_KEYS | {"aws:principalarn"}:
            hits = [v for v in strs if opts.management_account in v]
            if hits:
                out.append(
                    _finding(
                        "SCP-MGMT-ACCOUNT-REF",
                        f"{op} on {key} names the management account {opts.management_account}; SCPs never "
                        "apply to principals in the management account, so this condition has no effect there",
                        sid,
                    )
                )
    # Contradictions between operators on the same key.
    for key, entries in by_key.items():
        pos = {
            str(v).lower()
            for base, vals, ie in entries
            if base in ("StringEquals", "StringEqualsIgnoreCase", "ArnEquals") and not ie
            for v in vals
        }
        neg = {
            str(v).lower()
            for base, vals, _ in entries
            if base in ("StringNotEquals", "StringNotEqualsIgnoreCase", "ArnNotEquals")
            for v in vals
        }
        if pos and pos <= neg:
            out.append(
                _finding(
                    "SCP-CONDITION-NEVER-TRUE",
                    f"{key} must equal one of {', '.join(sorted(pos))} and must not equal any of them at the same time",
                    sid,
                )
            )
        null_true = any(base == "Null" and [str(v).lower() for v in vals] == ["true"] for base, vals, _ in entries)
        needs_value = [base for base, _, ie in entries if base != "Null" and not ie]
        if null_true and needs_value:
            out.append(
                _finding(
                    "SCP-CONDITION-NEVER-TRUE",
                    f"Null requires {key} to be absent while {needs_value[0]} requires it to have a value",
                    sid,
                )
            )
    exemptions = _principal_exemptions(st)
    if any(wild and p in ("*", "arn:aws:iam::*:*", "arn:*") for p, wild, _ in exemptions):
        out.append(
            _finding(
                "SCP-CONDITION-NEVER-TRUE",
                "the aws:PrincipalArn exemption matches every principal, so the statement never applies",
                sid,
            )
        )
    elif any(
        _exempts([e], _role_arn("ZzProbeRoleA")) and _exempts([e], _role_arn("team/QqProbeRoleB")) for e in exemptions
    ):
        out.append(
            _finding(
                "SCP-CONDITION-NEVER-TRUE",
                "the aws:PrincipalArn exemption matches every IAM role, so the statement only applies to IAM "
                "users and the root user",
                sid,
            )
        )
    return out


def lint_policy(doc: Any, opts: LintOptions | None = None) -> list[Finding]:
    """Lint one parsed SCP document."""
    opts = opts or LintOptions()
    if not isinstance(doc, dict) or "Statement" not in doc:
        return [_finding("SCP-STRUCTURE", "policy must be an object with a Statement element")]
    out: list[Finding] = []
    if doc.get("Version") != POLICY_VERSION:
        out.append(_finding("SCP-VERSION", f'Version is {doc.get("Version")!r}; use "{POLICY_VERSION}"'))
    size = len(compact(doc))
    if size > opts.limit:
        out.append(
            _finding("SCP-SIZE", f"{size} characters in compact form, over the {opts.limit} limit; split the policy")
        )
    seen: set[str] = set()
    for idx, st in enumerate(as_list(doc["Statement"])):
        if not isinstance(st, dict):
            out.append(_finding("SCP-STRUCTURE", f"statement {idx} is not an object"))
            continue
        sid = sid_of(st, idx)
        if "Sid" in st:
            if not isinstance(st["Sid"], str) or not SID_RE.match(st["Sid"]):
                out.append(
                    _finding("SCP-SID-FORMAT", f"Sid {st['Sid']!r} has characters other than letters and digits", sid)
                )
            if st["Sid"] in seen:
                out.append(_finding("SCP-DUPLICATE-SID", f"Sid {st['Sid']!r} is used more than once", sid))
            seen.add(str(st["Sid"]))
        effect = st.get("Effect")
        if effect not in {"Allow", "Deny"}:
            out.append(_finding("SCP-STRUCTURE", f"Effect must be Allow or Deny, got {effect!r}", sid))
            continue
        if ("Action" in st) == ("NotAction" in st):
            out.append(_finding("SCP-STRUCTURE", "exactly one of Action or NotAction is required", sid))
            continue
        if ("Resource" in st) == ("NotResource" in st):
            out.append(_finding("SCP-STRUCTURE", "exactly one of Resource or NotResource is required", sid))
        if "Principal" in st or "NotPrincipal" in st:
            out.append(
                _finding(
                    "SCP-PRINCIPAL",
                    "SCPs do not support Principal or NotPrincipal; use a Condition on aws:PrincipalArn",
                    sid,
                )
            )
        out += _check_conditions(st, sid, opts)
        has_cond = bool(st.get("Condition"))
        actions = [str(a).lower() for a in as_list(st.get("Action"))]
        not_actions = [str(a).lower() for a in as_list(st.get("NotAction"))]
        if effect == "Allow":
            if not_actions:
                out.append(
                    _finding(
                        "SCP-ALLOW-NOTACTION",
                        "Allow with NotAction allows every action not listed, including services added later",
                        sid,
                    )
                )
            elif opts.strategy == "deny-list" and not _is_full_allow(st):
                out.append(
                    _finding(
                        "SCP-ALLOW-IN-DENY-LIST",
                        "Allow statement in a deny-list SCP: it grants nothing by itself (IAM policies grant) and "
                        "restricts nothing while FullAWSAccess is attached (only Deny restricts)",
                        sid,
                    )
                )
            continue
        out += _check_deny(st, sid, actions, not_actions, has_cond, opts)
    return out


def _check_deny(
    st: dict[str, Any],
    sid: str,
    actions: list[str],
    not_actions: list[str],
    has_cond: bool,
    opts: LintOptions,
) -> list[Finding]:
    out: list[Finding] = []
    resources = as_list(st.get("Resource"))
    keys = condition_keys(st)
    deny_all = actions == ["*"] and resources == ["*"] and not has_cond
    if deny_all:
        out.append(
            _finding(
                "SCP-DENY-ALL", "Deny * on * without a Condition blocks every action in the attached accounts", sid
            )
        )
    if not_actions and not has_cond:
        out.append(
            _finding(
                "SCP-DENY-NOTACTION-BARE",
                "Deny with NotAction and no Condition denies every action not listed, in every region",
                sid,
            )
        )
    elif not_actions and "aws:requestedregion" not in keys:
        detail = " and NotResource" if "NotResource" in st else ""
        out.append(
            _finding(
                "SCP-NOTACTION-SCOPE",
                f"Deny with NotAction{detail} denies every action except {len(not_actions)} listed one(s) whenever "
                f"the condition on {', '.join(sorted({k for _, k, _ in conditions(st)}))} holds",
                sid,
            )
        )
    if not deny_all and not has_cond and "*" in resources:
        blocked = [a for a in ADMIN_PROBES if statement_covers(st, a)]
        if blocked:
            out.append(
                _finding(
                    "SCP-MGMT-LOCKOUT",
                    f"denies {', '.join(blocked)} for every principal with no exemption: the management account "
                    f"administers member accounts through a role there ({', '.join(opts.admin_roles)}), and this "
                    "statement applies to that role",
                    sid,
                )
            )
    if "aws:requestedregion" in keys:
        if actions:
            core_services = {g.split(":")[0] for g in CORE_GLOBALS}
            broad = [a for a in actions if a == "*" or (a.endswith(":*") and a.split(":")[0] in core_services)]
            if broad:
                out.append(
                    _finding(
                        "SCP-REGION-BLOCKS-GLOBAL",
                        f"region deny uses Action {', '.join(broad)}: global services (IAM, STS, Organizations, "
                        "Route 53, CloudFront, Support) are served from us-east-1 and will be denied outside it",
                        sid,
                    )
                )
        else:
            missing = [g for g in CORE_GLOBALS if g not in not_actions]
            if missing:
                out.append(
                    _finding(
                        "SCP-REGION-GLOBAL-GAPS",
                        f"region deny NotAction list misses {', '.join(missing)}",
                        sid,
                    )
                )
            doc_missing = [g for g in GLOBAL_SERVICE_ACTIONS if g.lower() not in not_actions and g not in CORE_GLOBALS]
            if doc_missing:
                shown = ", ".join(doc_missing[:6]) + (
                    f" and {len(doc_missing) - 6} more" if len(doc_missing) > 6 else ""
                )
                f = _finding(
                    "SCP-REGION-DOC-GAPS",
                    f"region deny NotAction list lacks {len(doc_missing)} of the {len(GLOBAL_SERVICE_ACTIONS)} "
                    f"entries in the AWS region-deny example: {shown}",
                    sid,
                )
                f.extra["missing"] = doc_missing
                out.append(f)
        if "aws:principalarn" not in keys:
            out.append(
                _finding(
                    "SCP-NO-EXEMPTION", "region deny has no aws:PrincipalArn exemption for a break-glass role", sid
                )
            )
    elif any(a.startswith(SECURITY_PREFIXES) for a in actions) and "aws:principalarn" not in keys:
        out.append(
            _finding(
                "SCP-NO-EXEMPTION",
                "security-service guardrail has no aws:PrincipalArn exemption; even the security team's role "
                "cannot change these settings",
                sid,
            )
        )
    exemptions = _principal_exemptions(st)
    if opts.break_glass_roles and exemptions:
        missing_roles = [r for r in opts.break_glass_roles if not _exempts(exemptions, _role_arn(r))]
        if missing_roles:
            out.append(
                _finding(
                    "SCP-BREAK-GLASS-NOT-EXEMPT",
                    f"the aws:PrincipalArn exemption does not cover the break-glass role(s) {', '.join(missing_roles)}",
                    sid,
                )
            )
    return out


def max_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: RANK[s])


def at_or_above(findings: list[Finding], threshold: str) -> list[Finding]:
    if threshold == "none":
        return []
    return [f for f in findings if RANK[f.severity] >= RANK[threshold]]


def valid_account(value: str) -> bool:
    return bool(ACCOUNT_RE.match(value))
