# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Spec reader: folded block scalars (`>`) now turn an empty line into one line break instead of two, and a block scalar at the very end of a file without a final line break no longer gains one.
- Spec reader: a `key: value` line indented under a plain value (`protected_roles: Admin` followed by an indented `deny_root_user: true`) is now a parse error with the line number. Before, it was silently read as part of the value.
- Spec reader: content after a top-level scalar without a `---` separator is now a parse error. Before, it was dropped.
- Spec reader: numbers with leading zeros (`012`) are integers, as YAML 1.2 says, not floats.
- `build`: an account id written without quotes, or a single string where a list is expected, now gets an error that says how to write it.
- Tests: the em-dash check no longer reads files inside a local `.venv`, so `make install` followed by `make check` passes on a fresh clone.

## [0.2.0] - 2026-10-13

### Added

- `scp-guardrails explain --format json`: the same statement explanations as the text and Markdown formats (Sid, effect, one-sentence description, purpose and side effects) as structured JSON. Contributed by nawaaaaaAaar in #8.

### Fixed

- `lint`: `aws:PrincipalArn` exemptions now respect case sensitivity. Only the `IgnoreCase` operators compare without regard to case, so a role exemption that differs from the role name by case is no longer treated as exempt. Contributed by Tushar Prajapati in #7.

### Changed

- Dependency updates for the GitHub Actions used in CI and in the action self-test (#9, #10, #11).

## [0.1.0] - 2026-10-04

First release. The builder, the first twelve lint checks, the guardrail catalogue and the spend denies are extracted from the `scp-guardrails`, `aws-spend-guardrails` and `sandbox-account-guardrail-pack` skills in [aws-security-skills](https://github.com/basitalisandhu/aws-security-skills), which keep their own copies.

### Added

- `scp-guardrails build --spec`: deny-list SCPs from a YAML or JSON spec. Seventeen guardrails, each one spec key: deny leaving the organization, deny the root user, protect CloudTrail, GuardDuty, Security Hub and AWS Config, region allowlist (with the NotAction list of the AWS region-deny example), deny IAM users outside listed accounts, require IMDSv2, deny public S3 ACLs, require a tag on new instances, and spend denies (instance types by deny list or allow list, EBS IOPS and volume types, SageMaker GPU types, Bedrock customization and provisioned throughput, whole services, reserved capacity and Savings Plans, budget and anomaly monitor protection). `protected_roles` exempt break-glass roles. First-fit packing under `max_policy_chars`, a hard stop above `max_documents`, `manifest.json`, and `SUMMARY.md` with what each statement denies and its side effects.
- `scp-guardrails lint`: 20 rules with id, severity (low, medium, high), statement Sid and line, explanation and fix. New since the skill: SCP-MGMT-LOCKOUT, SCP-MGMT-ACCOUNT-REF, SCP-REGION-DOC-GAPS, SCP-BREAK-GLASS-NOT-EXEMPT, SCP-CONDITION-OPERATOR, SCP-CONDITION-NEVER-TRUE, SCP-NOTACTION-SCOPE and SCP-SID-FORMAT. Files, directories and globs; table, JSON and SARIF 2.1.0 output; `--fail-on`; GitHub step outputs and job summary.
- `scp-guardrails diff`: semantic diff by statement, action set, resources and condition values.
- `scp-guardrails explain`: plain-English narrative of a policy.
- `scp-guardrails catalog`: the guardrail catalogue as a table, JSON or Markdown, with AWS documentation links (`docs/catalog.md` is generated from it).
- Composite GitHub Action (`action.yml`) that lints policies, uploads SARIF to code scanning and fails above a threshold, with a self-test workflow on planted fixtures.
- CI on Python 3.11, 3.12 and 3.13, a container image `ghcr.io/basitalisandhu/scp-guardrails` published on version tags with an SPDX SBOM, a build provenance attestation and a keyless cosign signature, and PyPI trusted publishing (off until the repository variable `PYPI_PUBLISH` is set).

### Changed from the skill

- Default size limit and attachment count follow the AWS Organizations quotas page as checked on 2026-10-04 (10,240 characters, 10 SCPs per target); the skill used 5,120 and 5. Both are configurable.
- Severities are high, medium and low instead of error, warning and info. Allow with NotAction is medium, since SCPs now accept the element.

[Unreleased]: https://github.com/basitalisandhu/scp-guardrails/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/basitalisandhu/scp-guardrails/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/basitalisandhu/scp-guardrails/releases/tag/v0.1.0
