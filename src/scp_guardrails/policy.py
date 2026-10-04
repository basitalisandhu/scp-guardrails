"""Shared policy helpers: AWS limits, loading SCP documents, the compact form and element access."""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Any

POLICY_VERSION = "2012-10-17"

# AWS Organizations quotas for service control policies, as published on the quotas page (checked 2026-10-04):
# a policy document can be at most 10,240 characters, and a root, OU or account can have at most 10 SCPs attached
# directly. Earlier versions of the same page gave 5,120 characters and 5 policies; both are configurable.
SCP_MAX_CHARS = 10240
SCP_MAX_ATTACHED = 10
LEGACY_MAX_CHARS = 5120

DOCS_SCP = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html"
DOCS_SYNTAX = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html"
DOCS_EVALUATION = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html"
DOCS_QUOTAS = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html"
DOCS_EXAMPLES = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html"
DOCS_REGION_EXAMPLE = (
    "https://github.com/aws-samples/service-control-policy-examples/blob/main/Region-controls/"
    "Deny-access-to-AWS-based-on-the-requested-AWS-region.json"
)
DOCS_CONDITION_OPERATORS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html"
)
DOCS_SID = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_sid.html"


class PolicyError(ValueError):
    """A file that is not JSON, or describe-policy output whose Content is not JSON."""


def compact(doc: Any) -> str:
    """The compact JSON form (no whitespace outside strings), which is what AWS counts against the size limit."""
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_policy_text(text: str, name: str = "<policy>") -> Any:
    """Parse an SCP document, or the output of `aws organizations describe-policy` (its Content string)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{name}: invalid JSON: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("Policy"), dict) and "Content" in data["Policy"]:
        content = data["Policy"]["Content"]
        if not isinstance(content, str):
            return content
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{name}: Policy.Content is not JSON: {exc}") from exc
    return data


def load_policy(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"{path}: cannot read: {exc.strerror or exc}") from exc
    return parse_policy_text(text, str(path))


def looks_like_policy(doc: Any) -> bool:
    return isinstance(doc, dict) and "Statement" in doc


def statements(doc: Any) -> list[Any]:
    if not isinstance(doc, dict):
        return []
    return as_list(doc.get("Statement"))


def conditions(st: dict[str, Any]) -> list[tuple[str, str, list[Any]]]:
    """Every (operator, key, values) triple of a statement's Condition block, keys as written."""
    out: list[tuple[str, str, list[Any]]] = []
    cond = st.get("Condition")
    if not isinstance(cond, dict):
        return out
    for op, block in cond.items():
        if isinstance(block, dict):
            for key, values in block.items():
                out.append((str(op), str(key), as_list(values)))
    return out


def condition_keys(st: dict[str, Any]) -> set[str]:
    return {key.lower() for _, key, _ in conditions(st)}


def split_operator(op: str) -> tuple[str, str, bool]:
    """Split `ForAnyValue:StringLikeIfExists` into ("ForAnyValue", "StringLike", True)."""
    qualifier = ""
    if ":" in op:
        qualifier, op = op.split(":", 1)
    if_exists = op.endswith("IfExists")
    if if_exists:
        op = op[: -len("IfExists")]
    return qualifier, op, if_exists


def _pattern(value: str) -> str:
    # Policy variables such as ${aws:PrincipalAccount} can take any value, so treat them as a wildcard.
    return re.sub(r"\$\{[^}]*\}", "*", value).lower()


def wildcard_match(pattern: str, value: str) -> bool:
    """IAM-style match: `*` any run of characters, `?` one character, case-insensitive."""
    return fnmatch.fnmatchcase(value.lower(), _pattern(pattern).replace("[", "[[]"))


def action_covers(patterns: list[str], action: str) -> bool:
    return any(isinstance(p, str) and wildcard_match(p, action) for p in patterns)


def statement_covers(st: dict[str, Any], action: str) -> bool:
    """True when the statement's Action (or the complement of its NotAction) includes `action`."""
    if "NotAction" in st:
        return not action_covers(as_list(st.get("NotAction")), action)
    return action_covers(as_list(st.get("Action")), action)


def sid_of(st: Any, index: int) -> str:
    if isinstance(st, dict) and isinstance(st.get("Sid"), str) and st["Sid"]:
        return st["Sid"]
    return f"#{index}"


def find_line(text: str, sid: str | None) -> int:
    """1-based line of a statement's Sid in the source text, or 1 when it cannot be found."""
    if not sid or sid.startswith("#"):
        return 1
    needle = re.compile(r'"Sid"\s*:\s*"' + re.escape(sid) + '"')
    for no, line in enumerate(text.splitlines(), 1):
        if needle.search(line):
            return no
    return 1
