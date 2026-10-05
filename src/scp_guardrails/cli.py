"""Command-line interface: build, lint, diff, explain and catalog."""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, catalog, report
from .builder import SpecError, build, load_spec, summary_markdown, write_outputs
from .diff import diff_policies, render_text
from .explain import explain_policy, explanation_data, render_markdown
from .lint import SEVERITIES, LintOptions, at_or_above, lint_policy, valid_account
from .policy import SCP_MAX_CHARS, PolicyError, find_line, load_policy, looks_like_policy, parse_policy_text

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DESCRIPTION = (
    "AWS service control policy builder and linter: build SCPs from a short spec, lint existing SCPs for the "
    "mistakes that lock you out or do nothing, diff two SCPs and explain one in plain English. It never calls AWS."
)
EPILOG = "Docs: https://github.com/basitalisandhu/scp-guardrails"


class _Formatter(argparse.RawDescriptionHelpFormatter):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scp-guardrails", description=DESCRIPTION, epilog=EPILOG, formatter_class=_Formatter
    )
    parser.add_argument("--version", action="version", version=f"scp-guardrails {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser(
        "build",
        help="build SCP documents from a YAML or JSON spec",
        description="Build deny-list SCPs from a spec. Every guardrail in `scp-guardrails catalog` is one spec "
        "key. Statements are packed into as few documents as fit under the size limit and every document is "
        "linted.",
        epilog="Writes scp-NN.json, manifest.json and SUMMARY.md to --out. Exit codes: 0 built, 1 a generated "
        "document has a high-severity lint finding (nothing is written), 2 bad spec.\n" + EPILOG,
        formatter_class=_Formatter,
    )
    p.add_argument("--spec", required=True, type=Path, help="YAML or JSON spec file")
    p.add_argument("--out", type=Path, help="directory for the documents, manifest.json and SUMMARY.md")
    p.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="what to print: a short text report, the documents and manifest as JSON, or the Markdown summary",
    )
    p.add_argument("--pretty", action="store_true", help="indent the written documents (size is measured compact)")
    p.add_argument(
        "--max-chars",
        type=int,
        help=f"override max_policy_chars from the spec (default {SCP_MAX_CHARS}, the documented SCP quota)",
    )

    p = sub.add_parser(
        "lint",
        help="lint SCP JSON files for lockouts, dead statements and size",
        description="Lint SCP documents (plain JSON or `aws organizations describe-policy` output). Arguments "
        "can be files, directories (every *.json below them) or quoted glob patterns.",
        epilog="Exit codes: 0 no finding at or above --fail-on, 1 findings at or above it, 2 bad input.\n"
        "Rules: docs/rules.md. " + EPILOG,
        formatter_class=_Formatter,
    )
    p.add_argument("paths", nargs="+", help="policy files, directories or glob patterns")
    p.add_argument("--format", choices=["table", "json", "sarif"], default="table", help="output format")
    p.add_argument("--output", type=Path, help="write the report here instead of standard output")
    p.add_argument("--sarif", type=Path, help="also write a SARIF 2.1.0 report to this file")
    p.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "none"],
        default="high",
        help="exit 1 when a finding is at or above this severity (default high; none never fails)",
    )
    p.add_argument(
        "--limit", type=int, default=SCP_MAX_CHARS, help=f"size limit in characters (default {SCP_MAX_CHARS})"
    )
    p.add_argument("--strategy", choices=["deny-list", "allow-list"], default="deny-list", help="SCP strategy in use")
    p.add_argument(
        "--break-glass-role",
        action="append",
        default=[],
        metavar="NAME",
        help="role name that every exemption must cover (repeatable)",
    )
    p.add_argument(
        "--admin-role",
        action="append",
        default=[],
        metavar="NAME",
        help="role the management account uses in member accounts (default OrganizationAccountAccessRole)",
    )
    p.add_argument(
        "--management-account", metavar="ID", help="12-digit management account id to look for in conditions"
    )
    p.add_argument("--summary", type=Path, help="append a Markdown summary (for $GITHUB_STEP_SUMMARY)")
    p.add_argument("--github-output", type=Path, help="append step outputs (for $GITHUB_OUTPUT)")

    p = sub.add_parser(
        "diff",
        help="semantic diff of two SCPs by statement and action set",
        description="Compare two SCPs statement by statement (matched by Sid). Order, action case and "
        "whitespace are not changes.",
        epilog="Exit codes: 0 identical, 1 different, 2 bad input.\n" + EPILOG,
        formatter_class=_Formatter,
    )
    p.add_argument("a", type=Path, help="the old policy")
    p.add_argument("b", type=Path, help="the new policy")
    p.add_argument("--format", choices=["text", "json"], default="text", help="output format")

    p = sub.add_parser(
        "explain",
        help="plain-English narrative of what a policy denies",
        description="Explain what an SCP denies, statement by statement, for reviewers.",
        epilog="Exit codes: 0, 2 bad input.\n" + EPILOG,
        formatter_class=_Formatter,
    )
    p.add_argument("policy", type=Path, help="policy JSON file")
    p.add_argument("--format", choices=["text", "markdown", "json"], default="text", help="output format")

    p = sub.add_parser(
        "catalog",
        help="print the guardrail catalogue with AWS documentation links",
        description="Print every guardrail `build` can emit: spec key, statements, what it denies and its side "
        "effects.",
        epilog="Exit codes: 0, 2 unknown --key.\n" + EPILOG,
        formatter_class=_Formatter,
    )
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table", help="output format")
    p.add_argument("--key", help="show one guardrail in full")
    return parser


def _err(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _display(path: Path) -> str:
    try:
        rel = os.path.relpath(path)
    except ValueError:
        return str(path)
    return str(path) if rel.startswith("..") else rel


def expand_paths(args: Sequence[str]) -> tuple[list[Path], list[Path], list[str]]:
    """(explicit files, discovered files, errors). Discovered files that are not SCPs are skipped later."""
    explicit: list[Path] = []
    found: list[Path] = []
    errors: list[str] = []
    for arg in args:
        p = Path(arg)
        if p.is_dir():
            found += sorted(x for x in p.rglob("*.json") if x.is_file())
        elif p.is_file():
            explicit.append(p)
        elif any(c in arg for c in "*?["):
            matches = sorted(Path(m) for m in glob.glob(arg, recursive=True) if Path(m).is_file())
            if not matches:
                errors.append(f"{arg}: no files match")
            found += matches
        else:
            errors.append(f"{arg}: no such file or directory")
    return explicit, found, errors


def cmd_build(args: argparse.Namespace) -> int:
    try:
        spec = load_spec(args.spec)
        if args.max_chars is not None:
            spec = {**spec, "max_policy_chars": args.max_chars}
        result = build(spec)
    except SpecError as exc:
        _err(str(exc))
        return EXIT_ERROR
    failed = bool(result.high_findings)
    written = []
    if args.out and not failed:
        written = write_outputs(result, args.out, pretty=args.pretty)
    if args.format == "json":
        print(json.dumps({"manifest": result.manifest, "documents": result.documents}, indent=2))
    elif args.format == "markdown":
        print(summary_markdown(result), end="")
    else:
        m = result.manifest
        for meta in m["documents"]:
            print(
                f"{meta['file']}: {meta['chars_compact']}/{m['limit']} chars, guardrails: "
                f"{', '.join(meta['guardrails'])}"
            )
            print(f"  statements: {', '.join(meta['statements'])}")
        for w in m["warnings"]:
            print(f"warning: {w}")
        for f in result.findings:
            print(f"lint {f.severity}: {f.file} {f.id} {f.sid or '-'}: {f.message}")
        if written:
            print(f"wrote {len(result.documents)} document(s), manifest.json and SUMMARY.md to {_display(args.out)}")
        print("Review every document and test it on a non-production OU before attaching it.")
    if failed:
        _err("a generated document has a high-severity lint finding; nothing was written")
    return EXIT_FINDINGS if failed else EXIT_OK


def cmd_lint(args: argparse.Namespace) -> int:
    if args.management_account and not valid_account(args.management_account):
        _err(f"--management-account {args.management_account!r} is not a 12-digit account id")
        return EXIT_ERROR
    opts = LintOptions(
        limit=args.limit,
        strategy=args.strategy,
        break_glass_roles=tuple(args.break_glass_role),
        admin_roles=tuple(args.admin_role) or LintOptions().admin_roles,
        management_account=args.management_account,
    )
    explicit, found, errors = expand_paths(args.paths)
    for e in errors:
        _err(e)
    results: list[report.FileResult] = []
    seen: set[Path] = set()
    for path, strict in [(p, True) for p in explicit] + [(p, False) for p in found]:
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        shown = _display(path)
        try:
            text = path.read_text(encoding="utf-8")
            doc = parse_policy_text(text, shown)
        except (OSError, PolicyError, UnicodeDecodeError) as exc:
            results.append(report.FileResult(shown, None, error=str(exc)))
            continue
        if not strict and not looks_like_policy(doc):
            print(f"skipped {shown}: not an SCP document (no Statement)", file=sys.stderr)
            continue
        findings = lint_policy(doc, opts)
        for f in findings:
            f.file = shown
            f.line = find_line(text, f.sid)
        results.append(
            report.FileResult(shown, len(json.dumps(doc, separators=(",", ":"), ensure_ascii=False)), findings)
        )
    if not results and not errors:
        _err("no policy files found")
        return EXIT_ERROR
    bad_input = bool(errors) or any(r.error for r in results)
    gating = at_or_above(report.all_findings(results), args.fail_on)
    gate = "fail" if gating or bad_input else "pass"
    rendered = {
        "table": lambda: report.render_table(results, args.limit),
        "json": lambda: report.render_json(results),
        "sarif": lambda: report.render_sarif(results),
    }[args.format]()
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if args.sarif:
        args.sarif.write_text(report.render_sarif(results) + "\n", encoding="utf-8")
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(report.render_summary(results, args.fail_on, gate))
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as fh:
            for k, v in report.github_outputs(results, gate).items():
                fh.write(f"{k}={v}\n")
    if bad_input:
        return EXIT_ERROR
    return EXIT_FINDINGS if gating else EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        a, b = load_policy(args.a), load_policy(args.b)
    except PolicyError as exc:
        _err(str(exc))
        return EXIT_ERROR
    for name, doc in ((args.a, a), (args.b, b)):
        if not looks_like_policy(doc):
            _err(f"{name}: not an SCP document (no Statement)")
            return EXIT_ERROR
    d = diff_policies(a, b, _display(args.a), _display(args.b))
    print(json.dumps(d.as_dict(), indent=2) if args.format == "json" else render_text(d))
    return EXIT_FINDINGS if d.changed else EXIT_OK


def cmd_explain(args: argparse.Namespace) -> int:
    try:
        doc = load_policy(args.policy)
    except PolicyError as exc:
        _err(str(exc))
        return EXIT_ERROR
    if not looks_like_policy(doc):
        _err(f"{args.policy}: not an SCP document (no Statement)")
        return EXIT_ERROR
    name = _display(args.policy)
    if args.format == "json":
        print(json.dumps(explanation_data(doc, name), indent=2))
    elif args.format == "markdown":
        print(render_markdown(doc, name), end="")
    else:
        print("\n".join(explain_policy(doc, name)))
    return EXIT_OK


def cmd_catalog(args: argparse.Namespace) -> int:
    if args.key:
        g = catalog.BY_KEY.get(args.key)
        if g is None:
            _err(f"unknown guardrail {args.key!r}; keys: {', '.join(catalog.BY_KEY)}")
            return EXIT_ERROR
        print(json.dumps(g.as_dict(), indent=2) if args.format == "json" else catalog.render_one(g))
        return EXIT_OK
    if args.format == "json":
        print(json.dumps(catalog.as_json(), indent=2))
    elif args.format == "markdown":
        print(catalog.render_markdown(), end="")
    else:
        print(catalog.render_table())
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_OK
    handlers = {
        "build": cmd_build,
        "lint": cmd_lint,
        "diff": cmd_diff,
        "explain": cmd_explain,
        "catalog": cmd_catalog,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
