# Good first issues

Starting points for new contributors. The open ones are filed under the [`good first issue`](https://github.com/basitalisandhu/scp-guardrails/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label; comment on the issue to claim it. Each is self-contained and has acceptance criteria that `make check` can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: `ruff` must pass, the package stays standard-library only, and fixtures use example account ids.

## 1. Terraform output for `build` ([#1](https://github.com/basitalisandhu/scp-guardrails/issues/1))

**Context.** Many organizations manage SCPs with Terraform. Today `build` writes JSON files that a Terraform module has to read with `file()`.

**Acceptance criteria.**

- `build --format terraform --out DIR` writes one `aws_organizations_policy` resource per document (type `SERVICE_CONTROL_POLICY`, content from `jsonencode` of the document) to `DIR/scps.tf`.
- No attachment resources; a comment says where to attach.
- A test checks the file for every document name and that the embedded JSON round-trips.

## 2. Lint `aws organizations list-policies` plus `describe-policy` bundles ([#2](https://github.com/basitalisandhu/scp-guardrails/issues/2))

**Context.** Exporting every SCP from an organization gives one `describe-policy` file per policy. A single JSON array of them would be easier to pass around.

**Acceptance criteria.**

- `lint` accepts a JSON file whose top level is a list of `describe-policy` outputs and lints each, reporting the policy name from `PolicySummary.Name` as the file.
- AWS-managed policies (`AwsManaged: true`) are skipped with a note.
- Tests cover a bundle with one custom and one AWS-managed policy.

## 3. Rule for denies that only cover a deprecated action name ([#3](https://github.com/basitalisandhu/scp-guardrails/issues/3))

**Context.** The security-service guardrails list both `DisassociateFromMasterAccount` and `DisassociateFromAdministratorAccount`. A policy with only the older name leaves the newer API open.

**Acceptance criteria.**

- New rule `SCP-LEGACY-ACTION-ONLY` (medium) for a Deny that lists the older name of a renamed action without the newer one, from a small table in `catalog.py` with a link to the AWS documentation for each pair.
- A section in `docs/rules.md`, a row in the README table, a planted fixture and a negative test.

## Done

- `explain --format json` shipped in 0.2.0 (#8).
- Case-sensitive matching for `aws:PrincipalArn` exemptions shipped in 0.2.0 (#7).
- The attachment plan (`attach_levels`) shipped in 0.3.0 (#5).
