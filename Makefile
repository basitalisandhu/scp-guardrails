.PHONY: install lint format test check build demo catalog clean

PY ?= uv run

install:
	uv venv
	uv pip install -e ".[dev]"

lint:
	$(PY) ruff check .
	$(PY) ruff format --check .

format:
	$(PY) ruff format .
	$(PY) ruff check --fix .

test:
	$(PY) pytest -q

check: lint test

build:
	rm -rf dist
	uv build

# Build the example spec, lint the result, then lint the planted bad policy (exit 1 expected).
demo:
	rm -rf .demo && mkdir .demo
	$(PY) scp-guardrails build --spec examples/spec.yaml --out .demo/scps
	$(PY) scp-guardrails lint .demo/scps --fail-on low
	$(PY) scp-guardrails lint tests/fixtures/action/fixture-bad-policy.json; test $$? -eq 1
	rm -rf .demo

# Regenerate docs/catalog.md and docs/demo.svg.
catalog:
	$(PY) scp-guardrails catalog --format markdown > docs/catalog.md
	$(PY) python scripts/render_demo.py

clean:
	rm -rf dist build .pytest_cache .ruff_cache .demo
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
