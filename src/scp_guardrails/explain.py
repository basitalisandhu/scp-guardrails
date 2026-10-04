"""Plain-English narrative of what an SCP denies, for reviewers who do not read policy JSON every day."""

from __future__ import annotations

from typing import Any

from .catalog import BY_SID
from .policy import as_list, compact, conditions, sid_of, split_operator

KEY_LABELS = {
    "aws:requestedregion": "the requested region",
    "aws:principalarn": "the caller's ARN",
    "aws:principalaccount": "the caller's account",
    "aws:principalorgid": "the caller's organization",
    "aws:sourceip": "the caller's IP address",
    "aws:securetransport": "the request uses TLS",
    "aws:multifactorauthpresent": "the caller signed in with MFA",
    "ec2:metadatahttptokens": "the instance metadata token setting",
    "ec2:roledelivery": "the instance metadata version that delivered the role credentials",
    "ec2:instancetype": "the instance type",
    "ec2:volumeiops": "the volume IOPS",
    "ec2:volumetype": "the volume type",
    "s3:x-amz-acl": "the S3 canned ACL",
    "sagemaker:instancetypes": "the SageMaker instance types",
}

OP_PHRASES = {
    "StringEquals": "is",
    "StringEqualsIgnoreCase": "is (ignoring case)",
    "StringNotEquals": "is not",
    "StringNotEqualsIgnoreCase": "is not (ignoring case)",
    "StringLike": "matches",
    "StringNotLike": "does not match",
    "ArnEquals": "is",
    "ArnLike": "matches",
    "ArnNotEquals": "is not",
    "ArnNotLike": "does not match",
    "NumericEquals": "equals",
    "NumericNotEquals": "does not equal",
    "NumericLessThan": "is less than",
    "NumericLessThanEquals": "is at most",
    "NumericGreaterThan": "is greater than",
    "NumericGreaterThanEquals": "is at least",
    "DateEquals": "is the date",
    "DateNotEquals": "is not the date",
    "DateLessThan": "is before",
    "DateLessThanEquals": "is on or before",
    "DateGreaterThan": "is after",
    "DateGreaterThanEquals": "is on or after",
    "Bool": "is",
    "IpAddress": "is in",
    "NotIpAddress": "is not in",
    "BinaryEquals": "equals",
}

MAX_LISTED = 8


def _join(values: list[Any], conj: str = "or") -> str:
    vals = [str(v) for v in values]
    if len(vals) > MAX_LISTED:
        vals = [*vals[:MAX_LISTED], f"{len(values) - MAX_LISTED} more"]
    if len(vals) <= 1:
        return "".join(vals)
    return ", ".join(vals[:-1]) + f" {conj} " + vals[-1]


def _label(key: str) -> str:
    low = key.lower()
    if low.startswith("aws:requesttag/"):
        return f"the {key.split('/', 1)[1]} tag in the request"
    return KEY_LABELS.get(low, key)


def describe_condition(op: str, key: str, values: list[Any]) -> str:
    qualifier, base, if_exists = split_operator(op)
    low = key.lower()
    label = _label(key)
    if base == "Null":
        absent = [str(v).lower() for v in values] == ["true"]
        text = f"{label} is {'missing' if absent else 'present'}"
    elif low == "aws:principalarn" and base in ("ArnNotLike", "StringNotLike", "ArnNotEquals", "StringNotEquals"):
        text = f"the caller is not {_join(values)}"
    elif low == "aws:principalarn" and [str(v) for v in values] == ["arn:aws:iam::*:root"]:
        text = "the caller is the root user"
    else:
        phrase = OP_PHRASES.get(base, base)
        if len(values) > 1 and phrase in ("is", "matches"):
            phrase = f"{phrase} one of"
        text = f"{label} {phrase} {_join(values)}"
    if qualifier == "ForAnyValue":
        text = f"any of {text}"
    elif qualifier == "ForAllValues":
        text = f"all of {text}"
    if if_exists:
        text += " (or the key is absent)"
    return text


def describe_actions(st: dict[str, Any]) -> str:
    if "NotAction" in st:
        nots = as_list(st.get("NotAction"))
        return f"every action except {len(nots)} listed ({_join(nots, 'and')})"
    acts = as_list(st.get("Action"))
    if acts == ["*"]:
        return "every action"
    return _join(acts, "and")


def describe_resources(st: dict[str, Any]) -> str:
    if "NotResource" in st:
        return f"every resource except {_join(as_list(st.get('NotResource')), 'and')}"
    res = as_list(st.get("Resource"))
    if res in (["*"], []):
        return "any resource"
    return _join(res)


def describe_statement(st: dict[str, Any]) -> str:
    """One sentence: what the statement does, on what, and when."""
    effect = st.get("Effect")
    verb = "Denies" if effect == "Deny" else "Allows" if effect == "Allow" else f"Has effect {effect!r} for"
    text = f"{verb} {describe_actions(st)} on {describe_resources(st)}"
    conds = [describe_condition(op, key, vals) for op, key, vals in conditions(st)]
    when = [c for c in conds if not c.startswith("the caller is not ")]
    unless = [c[len("the caller is not ") :] for c in conds if c.startswith("the caller is not ")]
    if when:
        text += ", when " + " and ".join(when)
    if unless:
        text += ", unless the caller is " + " or ".join(unless)
    return text + "."


def explain_policy(doc: Any, name: str = "policy") -> list[str]:
    """Narrative lines for a whole document."""
    if not isinstance(doc, dict) or "Statement" not in doc:
        return [f"{name} is not an SCP document (no Statement element)."]
    sts = [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]
    denies = [s for s in sts if s.get("Effect") == "Deny"]
    allows = [s for s in sts if s.get("Effect") == "Allow"]
    lines = [
        f"{name}: {len(sts)} statement(s), {len(denies)} deny and {len(allows)} allow, "
        f"{len(compact(doc))} characters in compact form.",
        "It applies to every IAM user and role, including the root user, in the member accounts it is attached "
        "to (directly or through an OU or the root). It does not apply to the management account or to "
        "service-linked roles, and it never grants anything.",
        "",
    ]
    for idx, st in enumerate(sts):
        sid = sid_of(st, idx)
        lines.append(f"{sid}: {describe_statement(st)}")
        guardrail = BY_SID.get(sid)
        if guardrail:
            lines.append(f"  Purpose: {guardrail.protects}")
            lines.append(f"  Watch for: {guardrail.side_effects}")
    if allows and not denies:
        lines += ["", "This policy only allows. Under a deny-list strategy it restricts nothing on its own."]
    return lines


def render_markdown(doc: Any, name: str) -> str:
    lines = explain_policy(doc, name)
    out = [f"# What `{name}` denies", ""]
    for line in lines:
        if ": " in line and not line.startswith((" ", name)) and line.split(": ", 1)[0].isidentifier():
            sid, rest = line.split(": ", 1)
            out.append(f"- **{sid}**: {rest}")
        elif line.startswith("  "):
            out.append(f"  - {line.strip()}")
        else:
            out.append(line)
    return "\n".join(out) + "\n"
