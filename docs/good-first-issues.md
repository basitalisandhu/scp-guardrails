# Good first issues

Issues the maintainer intends to open under the `good first issue` label, written out so they can be filed in one sitting. Each is self-contained and has acceptance criteria that `make check` can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: `ruff` must pass, the package stays standard-library only, and fixtures use example account ids.

## 1. Terraform output for `build`

**Context.** Many organizations manage SCPs with Terraform. Today `build` writes JSON files that a Terraform module has to read with `file()`.

**Acceptance criteria.**

- `build --format terraform --out DIR` writes one `aws_organizations_policy` resource per document (type `SERVICE_CONTROL_POLICY`, content from `jsonencode` of the document) to `DIR/scps.tf`.
- No attachment resources; a comment says where to attach.
- A test checks the file for every document name and that the embedded JSON round-trips.

## 2. Lint `aws organizations list-policies` plus `describe-policy` bundles

**Context.** Exporting every SCP from an organization gives one `describe-policy` file per policy. A single JSON array of them would be easier to pass around.

**Acceptance criteria.**

- `lint` accepts a JSON file whose top level is a list of `describe-policy` outputs and lints each, reporting the policy name from `PolicySummary.Name` as the file.
- AWS-managed policies (`AwsManaged: true`) are skipped with a note.
- Tests cover a bundle with one custom and one AWS-managed policy.

## 3. Rule for denies that only cover a deprecated action name

**Context.** The security-service guardrails list both `DisassociateFromMasterAccount` and `DisassociateFromAdministratorAccount`. A policy with only the older name leaves the newer API open.

**Acceptance criteria.**

- New rule `SCP-LEGACY-ACTION-ONLY` (medium) for a Deny that lists the older name of a renamed action without the newer one, from a small table in `catalog.py` with a link to the AWS documentation for each pair.
- A section in `docs/rules.md`, a row in the README table, a planted fixture and a negative test.

## 4. `explain --format json`

**Context.** Review bots want the narrative as data.

**Acceptance criteria.**

- `explain --format json` prints `{"policy": ..., "statements": [{"sid", "effect", "sentence", "purpose", "side_effects"}]}`.
- The text and Markdown outputs are built from the same data.
- Tests cover a statement with a catalogue match and one without.

## 5. Attachment plan in the build summary

**Context.** When a spec needs more documents than one target can take, the error tells you to split them across the root and OUs, but not how.

**Acceptance criteria.**

- A spec key `attach_levels: [root, ou]` lets `build` place documents across levels, each within `max_documents`, and `SUMMARY.md` lists which document goes where.
- The default behaviour is unchanged.
- Tests cover a spec that needs two levels and one that fits in one.

## 6. Case-sensitive matching for StringLike and ArnLike exemptions

**Context.** The linter matches `aws:PrincipalArn` exemption patterns case-insensitively, which is right for actions but not for `StringLike`, which AWS documents as case-sensitive.

**Acceptance criteria.**

- `SCP-BREAK-GLASS-NOT-EXEMPT` and the every-role check in `SCP-CONDITION-NEVER-TRUE` compare case-sensitively for `StringNotLike` and the `Arn` operators, and case-insensitively only for the `IgnoreCase` operators.
- A test with `--break-glass-role breakglassadmin` against an exemption for `BreakGlassAdmin` reports the finding.
