# Lint rules

`scp-guardrails lint` reads SCP documents (plain JSON, or the output of `aws organizations describe-policy`, whose `Content` string it parses) and reports the findings below. Each finding has a rule id, a severity, the statement `Sid` (or `#<index>` for a statement without one), an explanation and a fix. Nothing is sent anywhere; the checks are static reads of the JSON.

Severities: **high** means the policy is broken or locks people out as written; **medium** means it probably does not do what its author meant; **low** is worth a look in review. `--fail-on` (default `high`) sets the lowest severity that makes the command exit 1. In SARIF, high is `error`, medium is `warning` and low is `note`.

Background that several rules rely on, from the AWS Organizations documentation:

- SCPs do not affect users or roles in the management account, or service-linked roles. They do affect every other user and role in a member account, including the root user and the role the management account uses to administer that account ([Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)).
- `Principal` and `NotPrincipal` are not supported in SCPs; `Action`, `NotAction`, `Resource`, `NotResource` and `Condition` are ([SCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html)).
- All characters count against the maximum SCP size, and the maximum size and the number of SCPs per root, OU or account are on the [quotas page](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html). `lint` measures the compact JSON form; `--limit` defaults to the documented maximum (10,240 characters when checked on 2026-10-04) and can be set lower.

## scp-structure

**High.** The policy is not an object with a `Statement`, or a statement is not an object, has an `Effect` other than `Allow` or `Deny`, has both or neither of `Action` and `NotAction`, or both or neither of `Resource` and `NotResource`. AWS rejects such a policy, or the statement does not mean what it looks like.

Fix: give every statement `Effect`, exactly one of `Action` or `NotAction`, and exactly one of `Resource` or `NotResource`.

## scp-version

**Medium.** `Version` is missing or not `"2012-10-17"`. Older versions do not support policy variables such as `${aws:PrincipalAccount}`, which are then compared literally.

## scp-size

**High.** The compact JSON form is longer than `--limit`. AWS refuses to save it. `scp-guardrails build` packs statements into several documents for you.

## scp-principal

**High.** A statement has `Principal` or `NotPrincipal`. SCPs do not support them. Scope a statement to principals with a `Condition` on `aws:PrincipalArn` instead.

## scp-allow-in-deny-list

**Medium.** An `Allow` statement other than the full allow (`Allow * on *` with no condition) in a deny-list strategy. While `FullAWSAccess` is attached, an extra Allow restricts nothing (only Deny restricts), and an SCP never grants anything (IAM policies grant). It usually signals a misunderstanding of how SCPs combine ([SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html)). Lint an allow-list strategy with `--strategy allow-list`.

## scp-allow-notaction

**Medium.** `Allow` with `NotAction` allows every action not listed, including services AWS launches later. In an allow-list strategy that is rarely the intent; list the allowed actions instead.

## scp-deny-all

**High.** `Deny` of `*` on `*` with no `Condition`. Every action in every attached account is blocked, including by the role the management account uses to get in.

## scp-deny-notaction-bare

**Medium.** `Deny` with `NotAction` and no `Condition` denies every action except the listed ones, in every region, for everyone. It is usually a region deny that lost its condition.

## scp-notaction-scope

**Low.** `Deny` with `NotAction` scoped by a condition other than `aws:RequestedRegion` (for example `aws:MultiFactorAuthPresent`). This is a legitimate pattern, but it denies every action except the listed ones whenever the condition holds, so check it is not meant to be an `Action` list. Also mentions `NotResource` when both negations are used.

## scp-region-blocks-global

**High.** A region deny (a condition on `aws:RequestedRegion`) that uses `Action` with `*` or a whole global service such as `iam:*` or `sts:*`. Global services are served from `us-east-1`, so outside it they are denied too: role assumption, IAM, Organizations, Route 53, CloudFront and Support break.

Fix: use `NotAction` with the global service list from the AWS example [Deny access to AWS based on the requested AWS Region](https://github.com/aws-samples/service-control-policy-examples/blob/main/Region-controls/Deny-access-to-AWS-based-on-the-requested-AWS-region.json), which the [AWS Organizations SCP examples page](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html) links to.

## scp-region-global-gaps

**Medium.** A region deny whose `NotAction` list misses one of the core global services: `iam:*`, `sts:*`, `organizations:*`, `support:*`, `route53:*`, `cloudfront:*`, `budgets:*`, `health:*`.

## scp-region-doc-gaps

**Low.** A region deny whose `NotAction` list lacks entries of the AWS example list above (42 entries in the version this release compares against). AWS notes that the example might not include all of the latest global services or operations, so treat the list as a floor to compare with, not a guarantee.

## scp-no-exemption

**Low.** A region deny, or a statement that protects CloudTrail, GuardDuty, Security Hub or AWS Config, without any `aws:PrincipalArn` condition. Nobody, not even a break-glass or security role, can work outside the regions or change those settings.

## scp-break-glass-not-exempt

**Medium.** Raised only with `--break-glass-role NAME` (repeatable). A Deny statement has an `aws:PrincipalArn` exemption, but the exemption does not cover `arn:aws:iam::<account>:role/NAME`. Wildcards count only under `ArnNotLike`, `ArnNotEquals` and `StringNotLike`; `StringNotEquals` compares literally.

## scp-mgmt-lockout

**High.** A Deny with no condition on resource `*` that covers `sts:AssumeRole` or role administration (`iam:CreateRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`). SCPs do not restrict the management account itself, but the management account administers member accounts by assuming a role in them (`OrganizationAccountAccessRole` for accounts created through Organizations, see [Accessing member accounts](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html)), and the SCP does apply to that role. Name your own role with `--admin-role`.

Fix: exempt that role with an `ArnNotLike` condition on `aws:PrincipalArn`, or narrow the actions.

## scp-mgmt-account-ref

**Medium.** Raised only with `--management-account ID`. A condition on `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:ResourceAccount` or `aws:PrincipalArn` names the management account. SCPs never apply to principals in the management account, so the condition has no effect for them and usually reflects a wrong assumption.

## scp-condition-operator

**Medium.** A condition operator that does not fit its value ([condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)):

- `StringEquals` or `StringNotEquals` (and the `IgnoreCase` forms) with `*` or `?` in a value: these operators match wildcards literally, so `arn:aws:iam::*:role/Admin*` only matches that exact text. Use `ArnLike`/`ArnNotLike` for ARNs and `StringLike`/`StringNotLike` otherwise.
- An `Arn` operator compared with values that are not ARNs.
- A `Numeric` operator with a value that is not a number.
- An operator name that is not a known condition operator, or a set qualifier other than `ForAnyValue` and `ForAllValues`.

## scp-condition-never-true

**Medium.** The statement can never apply, so it denies nothing:

- a condition key with an empty value list;
- the same key required to equal a set of values and not to equal any of them;
- `Null: true` (key absent) on a key another operator requires to have a value;
- `Bool` or `Null` with a value other than `true` or `false`;
- an `aws:PrincipalArn` exemption that matches every principal (`*`), or every IAM role (`arn:aws:iam::*:role/*`), which leaves only IAM users and the root user subject to the statement.

## scp-duplicate-sid

**Medium.** Two statements share a `Sid`. Reviews, diffs and investigations refer to statements by Sid; `scp-guardrails diff` keeps both but cannot pair them reliably.

## scp-sid-format

**Low.** A `Sid` with characters other than ASCII letters and digits. IAM accepts only those characters in `Sid` ([Sid element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_sid.html)).
