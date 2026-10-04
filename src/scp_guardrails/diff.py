"""Semantic diff of two SCPs: statements matched by Sid, compared by effect, action set, resources and conditions.

Order, case of actions, a single string versus a one-item list, and whitespace do not count as changes. Statements
without a Sid are matched by content.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .policy import as_list, compact

ADDED, REMOVED, CHANGED, UNCHANGED = "added", "removed", "changed", "unchanged"


@dataclass
class StatementDiff:
    sid: str
    status: str
    details: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"sid": self.sid, "status": self.status, "details": self.details}


@dataclass
class PolicyDiff:
    a_name: str
    b_name: str
    a_chars: int
    b_chars: int
    statements: list[StatementDiff]

    @property
    def changed(self) -> bool:
        return any(s.status != UNCHANGED for s in self.statements)

    def as_dict(self) -> dict[str, Any]:
        return {
            "a": self.a_name,
            "b": self.b_name,
            "a_chars_compact": self.a_chars,
            "b_chars_compact": self.b_chars,
            "changed": self.changed,
            "statements": [s.as_dict() for s in self.statements],
        }


def _norm_set(value: Any, fold: bool) -> set[str]:
    return {str(v).lower() if fold else str(v) for v in as_list(value)}


def normalise(st: dict[str, Any]) -> dict[str, Any]:
    """A canonical form: sets for actions and resources, condition values as sorted sets per operator and key."""
    cond: dict[str, dict[str, list[str]]] = {}
    raw = st.get("Condition")
    if isinstance(raw, dict):
        for op, block in raw.items():
            if isinstance(block, dict):
                for key, values in block.items():
                    cond.setdefault(op, {})[key.lower()] = sorted({str(v) for v in as_list(values)})
    return {
        "Effect": st.get("Effect"),
        "Action": sorted(_norm_set(st.get("Action"), True)) if "Action" in st else None,
        "NotAction": sorted(_norm_set(st.get("NotAction"), True)) if "NotAction" in st else None,
        "Resource": sorted(_norm_set(st.get("Resource"), False)) if "Resource" in st else None,
        "NotResource": sorted(_norm_set(st.get("NotResource"), False)) if "NotResource" in st else None,
        "Condition": cond,
    }


def _content_key(st: dict[str, Any]) -> str:
    return "#" + hashlib.sha256(compact(normalise(st)).encode()).hexdigest()[:10]


def _keyed(doc: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    sts = as_list(doc.get("Statement")) if isinstance(doc, dict) else []
    for st in sts:
        if not isinstance(st, dict):
            continue
        sid = st.get("Sid")
        key = sid if isinstance(sid, str) and sid else _content_key(st)
        while key in out:  # duplicate Sids: keep both, numbered
            key += "'"
        out[key] = st
    return out


def _set_change(label: str, old: list[str] | None, new: list[str] | None) -> list[str]:
    if old == new:
        return []
    if old is None:
        return [f"{label} added: {', '.join(new or [])}"]
    if new is None:
        return [f"{label} removed (was {', '.join(old)})"]
    lines = []
    plus = sorted(set(new) - set(old))
    minus = sorted(set(old) - set(new))
    if plus:
        lines.append(f"{label} + {', '.join(plus)}")
    if minus:
        lines.append(f"{label} - {', '.join(minus)}")
    return lines


def compare_statements(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    na, nb = normalise(a), normalise(b)
    details: list[str] = []
    if na["Effect"] != nb["Effect"]:
        details.append(f"Effect {na['Effect']} -> {nb['Effect']}")
    for label in ("Action", "NotAction", "Resource", "NotResource"):
        details += _set_change(label, na[label], nb[label])
    ca, cb = na["Condition"], nb["Condition"]
    pairs = sorted({(op, k) for op in ca for k in ca[op]} | {(op, k) for op in cb for k in cb[op]})
    for op, key in pairs:
        old = ca.get(op, {}).get(key)
        new = cb.get(op, {}).get(key)
        details += _set_change(f"Condition {op} {key}", old, new)
    return details


def diff_policies(a: Any, b: Any, a_name: str = "a", b_name: str = "b") -> PolicyDiff:
    ka, kb = _keyed(a), _keyed(b)
    out: list[StatementDiff] = []
    for key in ka:
        if key not in kb:
            out.append(StatementDiff(key, REMOVED, [_summary(ka[key])]))
        else:
            details = compare_statements(ka[key], kb[key])
            out.append(StatementDiff(key, CHANGED if details else UNCHANGED, details))
    for key in kb:
        if key not in ka:
            out.append(StatementDiff(key, ADDED, [_summary(kb[key])]))
    return PolicyDiff(a_name, b_name, len(compact(a)), len(compact(b)), out)


def _summary(st: dict[str, Any]) -> str:
    n = normalise(st)
    acts = n["Action"] if n["Action"] is not None else [f"all except {len(n['NotAction'] or [])}"]
    cond = ", ".join(f"{op} {k}" for op in n["Condition"] for k in n["Condition"][op])
    return f"{n['Effect']} {', '.join(acts)}" + (f" when {cond}" if cond else "")


def render_text(d: PolicyDiff) -> str:
    counts = {s: sum(1 for x in d.statements if x.status == s) for s in (ADDED, REMOVED, CHANGED, UNCHANGED)}
    lines = [f"--- {d.a_name} ({d.a_chars} chars)", f"+++ {d.b_name} ({d.b_chars} chars)"]
    marks = {ADDED: "+", REMOVED: "-", CHANGED: "~", UNCHANGED: " "}
    for s in d.statements:
        if s.status == UNCHANGED:
            continue
        lines.append(f"{marks[s.status]} {s.sid} ({s.status})")
        lines += [f"    {line}" for line in s.details]
    lines.append(
        f"{counts[ADDED]} added, {counts[REMOVED]} removed, {counts[CHANGED]} changed, "
        f"{counts[UNCHANGED]} unchanged statement(s)."
    )
    if not d.changed:
        lines.append("The policies are semantically identical.")
    return "\n".join(lines)
