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
    assert re.search(rf"^## \[{re.escape(__version__)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", text, re.M)
    assert "aws-security-skills" in text


def test_good_first_issues_link_each_open_task_to_its_issue():
    text = (ROOT / "docs" / "good-first-issues.md").read_text()
    tasks = re.findall(r"^## \d\. .*$", text, re.M)
    assert tasks
    assert all(
        re.search(r"\(\[#\d+\]\(https://github.com/basitalisandhu/scp-guardrails/issues/\d+\)\)$", t) for t in tasks
    )


def test_pyproject_version_matches_package():
    text = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{__version__}"' in text


TEXT_SUFFIXES = {".md", ".py", ".yml", ".yaml", ".json", ".toml", ".svg"}
# Local virtual environments, caches and build output are not the project's files: `make install` and the
# CONTRIBUTING set-up create .venv inside the checkout, and third-party packages there may contain any character.
SKIP_DIRS = {"venv", "env", "node_modules", "build", "dist", "scps"}


def project_text_files(root):
    for path in root.rglob("*"):
        rel = path.relative_to(root).parts
        if any((p.startswith(".") and p != ".github") or p in SKIP_DIRS for p in rel[:-1]):
            continue
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            yield path


def test_project_text_files_skips_virtual_environments(tmp_path):
    for rel in (".venv/lib/x.py", "venv/y.md", ".git/z.json", "node_modules/a.json", "src/keep.py", ".github/k.yml"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in project_text_files(tmp_path))
    assert found == [".github/k.yml", "src/keep.py"]


def test_no_em_dashes_in_text_files():
    for path in project_text_files(ROOT):
        assert chr(0x2014) not in path.read_text(encoding="utf-8"), path
