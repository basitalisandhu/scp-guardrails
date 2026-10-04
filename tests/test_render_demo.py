"""docs/demo.svg, the README demo, regenerates from the committed example spec with scripts/render_demo.py.

The test renders into a temporary file and checks the result is well-formed SVG holding the commands and lines of
their real output. It does not compare bytes with the committed SVG, so it stays stable across platforms.
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "render_demo.py"
SVG_NS = "{http://www.w3.org/2000/svg}"
BUILD = "scp-guardrails build --spec spec.yaml --out scps"
LINT = "scp-guardrails lint policies/bad-scp.json"
EXPECTED = "1 file(s), 4 finding(s): 1 high, 2 medium, 1 low."


def svg_text(path: Path) -> str:
    root = ET.parse(path).getroot()
    assert root.tag == f"{SVG_NS}svg"
    return "\n".join("".join(t.itertext()) for t in root.iter(f"{SVG_NS}text")).replace(chr(0xA0), " ")


def test_render_demo_regenerates_a_well_formed_svg(tmp_path: Path) -> None:
    out = tmp_path / "demo.svg"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(out)], cwd=ROOT, capture_output=True, text=True, timeout=600
    )
    assert result.returncode == 0, result.stderr
    text = svg_text(out)
    assert f"$ {BUILD}" in text and f"$ {LINT}" in text
    assert EXPECTED in text
    assert str(ROOT) not in text


def test_committed_demo_is_well_formed_and_shows_the_commands() -> None:
    text = svg_text(ROOT / "docs" / "demo.svg")
    assert f"$ {BUILD}" in text and EXPECTED in text
