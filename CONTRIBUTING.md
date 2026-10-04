# Contributing

Thanks for considering a contribution. The project is small on purpose: a spec validator and statement builder, a packer, a linter, a diff, an explainer and a CLI. The most useful contributions are SCPs that lint wrongly (a false positive or a missed lockout) with a minimal policy, guardrails worth adding with the AWS documentation behind them, and keeping the region list in step with the AWS example.

## Set up

Requires Python 3.11 or newer. With [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/basitalisandhu/scp-guardrails
cd scp-guardrails
uv venv && uv pip install -e ".[dev]"
uv run pytest -q
```

Without uv:

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

## Before you open a pull request

```bash
make check      # ruff check, ruff format --check, pytest
make demo       # build the example spec, lint it, lint the planted bad policy
make catalog    # regenerate docs/catalog.md and docs/demo.svg after changing the catalogue or output
```

CI runs the same on Python 3.11, 3.12 and 3.13, and the Action self-test runs `action.yml` against the fixtures.

## Where things live

- `src/scp_guardrails/catalog.py`: the guardrail catalogue and the action lists. A new guardrail needs an entry here, a spec key in `builder.py`, a row in the README table, a regenerated `docs/catalog.md` and tests.
- `src/scp_guardrails/builder.py`: spec validation, statements, packing and the summary.
- `src/scp_guardrails/lint.py`: the rules. Each rule needs an entry in `RULES`, a section in `docs/rules.md`, a row in the README table, and a planted `tests/fixtures/fixture-*.json` with a positive and a negative test.
- `src/scp_guardrails/diff.py`, `explain.py` and `report.py`: diff, narrative and output formats.
- `action.yml`: the composite Action. Inputs reach the shell only through `env`, never through `${{ }}` inside `run`.

## Tests and fixtures

Policies and specs under `tests/fixtures/` are named `fixture-*.json` (or `.yaml`) and use example account ids (`111122223333`, `123456789012`, `999988887777`) and example role names. Never commit a real account id, role ARN from a real organization, or anything in a credential format. Tests never call AWS.

## Style

- `ruff` formats and lints; line length 120.
- Standard library only. A pull request that adds a runtime dependency will be asked to remove it.
- Plain language, no em dashes, and no claim about AWS behaviour without a link to the AWS documentation.
- Deterministic output: the same spec produces byte-identical documents and the same report.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
