"""Documentation stays in step with the code."""

import re

from conftest import ROOT

from scp_guardrails import __version__, catalog
from scp_guardrails.lint import RULES

README = (ROOT / "README.md").read_text()
RULES_MD = (ROOT / "docs" / "rules.md").read_text()


def test_every_rule_has_a_section_in_rules_md():
    headings = set(re.findall(r"^## (scp-[a-z-]+)$", RULES_MD, re.M))
    assert headings == {rid.lower() for rid in RULES}


def test_rules_md_severities_match_the_code():
    for rid, rule in RULES.items():
        section = RULES_MD.split(f"## {rid.lower()}\n", 1)[1]
        assert section.lstrip().startswith(f"**{rule.severity.capitalize()}.**"), rid


def test_readme_rule_table_matches_the_code():
    rows = dict(re.findall(r"^\| (SCP-[A-Z-]+) \| (low|medium|high) \|", README, re.M))
    assert rows == {rid: rule.severity for rid, rule in RULES.items()}


def test_readme_catalogue_table_lists_every_key_and_statement():
    rows = dict(re.findall(r"^\| `([a-z_0-9]+)` \| ([A-Za-z0-9, ]+) \|", README, re.M))
    assert set(rows) == set(catalog.BY_KEY)
    for key, sids in rows.items():
        assert [s.strip() for s in sids.split(",")] == list(catalog.BY_KEY[key].statements), key


def test_readme_shape():
    assert README.startswith("# scp-guardrails: AWS service control policy builder and linter\n")
    for heading in (
        "## Demo",
        "## Install",
        "## GitHub Action",
        "## Quickstart",
        "## When to use this",
        "## Guardrail catalogue",
        "## Lint rules",
        "## What this is not",
        "## Frequently asked questions",
    ):
        assert heading in README, heading
    assert "extracted from aws-security-skills" in README
    assert "docs/demo.svg" in README


def test_changelog_has_this_version_dated():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert f"## [{__version__}] - 2026-10-04" in text
    assert "aws-security-skills" in text


def test_good_first_issues_has_six_tasks():
    text = (ROOT / "docs" / "good-first-issues.md").read_text()
    assert len(re.findall(r"^## \d\. ", text, re.M)) == 6


def test_pyproject_version_matches_package():
    text = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{__version__}"' in text


def test_no_em_dashes_in_text_files():
    for path in ROOT.rglob("*"):
        if (
            path.is_file()
            and path.suffix in {".md", ".py", ".yml", ".yaml", ".json", ".toml", ".svg"}
            and ".git" not in path.parts
        ):
            assert chr(0x2014) not in path.read_text(encoding="utf-8"), path
