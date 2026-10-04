"""The guardrail catalogue: every guardrail `build` can emit, as structured data with its AWS documentation links.

Each guardrail is one or more Deny statements, enabled by one spec key. None of them grants anything. SCPs do not
affect the management account, service-linked roles, or principals outside the organization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .policy import DOCS_QUOTAS, DOCS_REGION_EXAMPLE, DOCS_SCP

# Global and account-level actions exempt from the region guardrail. This is the NotAction list of the AWS example
# "Deny access to AWS based on the requested AWS Region" (aws-samples/service-control-policy-examples, linked from
# the AWS Organizations SCP examples page). AWS notes that the example might not include the latest global services.
GLOBAL_SERVICE_ACTIONS: tuple[str, ...] = (
    "a4b:*",
    "acm:*",
    "aws-marketplace-management:*",
    "aws-marketplace:*",
    "aws-portal:*",
    "budgets:*",
    "ce:*",
    "chime:*",
    "cloudfront:*",
    "config:*",
    "cur:*",
    "directconnect:*",
    "ec2:DescribeRegions",
    "ec2:DescribeTransitGateways",
    "ec2:DescribeVpnGateways",
    "fms:*",
    "globalaccelerator:*",
    "health:*",
    "iam:*",
    "importexport:*",
    "kms:*",
    "mobileanalytics:*",
    "networkmanager:*",
    "organizations:*",
    "pricing:*",
    "route53:*",
    "route53domains:*",
    "route53-recovery-cluster:*",
    "route53-recovery-control-config:*",
    "route53-recovery-readiness:*",
    "s3:GetAccountPublic*",
    "s3:ListAllMyBuckets",
    "s3:ListMultiRegionAccessPoints",
    "s3:PutAccountPublic*",
    "shield:*",
    "sts:*",
    "support:*",
    "trustedadvisor:*",
    "waf-regional:*",
    "waf:*",
    "wafv2:*",
    "wellarchitected:*",
)

# The global services whose absence from a region deny breaks sign-in, role assumption or account administration.
CORE_GLOBALS: tuple[str, ...] = (
    "iam:*",
    "sts:*",
    "organizations:*",
    "support:*",
    "route53:*",
    "cloudfront:*",
    "budgets:*",
    "health:*",
)

SECURITY_SERVICE_ACTIONS: dict[str, tuple[str, ...]] = {
    "ProtectCloudTrail": (
        "cloudtrail:DeleteTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
    ),
    "ProtectGuardDuty": (
        "guardduty:DeleteDetector",
        "guardduty:DeleteMembers",
        "guardduty:DisassociateFromAdministratorAccount",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector",
    ),
    "ProtectSecurityHub": (
        "securityhub:BatchDisableStandards",
        "securityhub:DeleteMembers",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromAdministratorAccount",
        "securityhub:DisassociateFromMasterAccount",
        "securityhub:DisassociateMembers",
    ),
    "ProtectConfig": (
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:DeleteRetentionConfiguration",
        "config:StopConfigurationRecorder",
    ),
}
SECURITY_PREFIXES: tuple[str, ...] = ("cloudtrail:", "guardduty:", "securityhub:", "config:")

DEFAULT_DENY_INSTANCE_TYPES: tuple[str, ...] = (
    "dl*",
    "f*",
    "g*",
    "hpc*",
    "inf*",
    "p*",
    "trn*",
    "u-*",
    "vt*",
    "x*",
    "*.metal*",
    "*.12xlarge",
    "*.16xlarge",
    "*.18xlarge",
    "*.24xlarge",
    "*.32xlarge",
    "*.48xlarge",
)
DEFAULT_SAGEMAKER_TYPES: tuple[str, ...] = ("ml.g*", "ml.inf*", "ml.p*", "ml.trn*")
SAGEMAKER_CREATE: tuple[str, ...] = (
    "sagemaker:CreateEndpointConfig",
    "sagemaker:CreateHyperParameterTuningJob",
    "sagemaker:CreateNotebookInstance",
    "sagemaker:CreateProcessingJob",
    "sagemaker:CreateTrainingJob",
    "sagemaker:CreateTransformJob",
)
COMMITMENT_ACTIONS: tuple[str, ...] = (
    "aws-marketplace:Subscribe",
    "ec2:PurchaseHostReservation",
    "ec2:PurchaseReservedInstancesOffering",
    "elasticache:PurchaseReservedCacheNodesOffering",
    "rds:PurchaseReservedDBInstancesOffering",
    "redshift:PurchaseReservedNodeOffering",
    "savingsplans:CreateSavingsPlan",
)
BUDGET_PROTECT_ACTIONS: tuple[str, ...] = (
    "budgets:DeleteBudgetAction",
    "budgets:ExecuteBudgetAction",
    "budgets:ModifyBudget",
    "budgets:UpdateBudgetAction",
    "ce:DeleteAnomalyMonitor",
    "ce:DeleteAnomalySubscription",
    "ce:UpdateAnomalyMonitor",
    "ce:UpdateAnomalySubscription",
)


@dataclass(frozen=True)
class Guardrail:
    key: str  # the spec key that enables it
    title: str
    category: str  # "baseline" or "spend"
    spec: str  # the value the key takes
    statements: tuple[str, ...]  # Sids the builder emits
    denies: str
    protects: str
    side_effects: str
    exempt: bool  # takes the protected_roles exemption
    docs: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["statements"] = list(self.statements)
        data["docs"] = list(self.docs)
        return data


CATALOG: tuple[Guardrail, ...] = (
    Guardrail(
        key="deny_leave_organization",
        title="Deny leaving the organization",
        category="baseline",
        spec="true",
        statements=("DenyLeaveOrganization",),
        denies="organizations:LeaveOrganization.",
        protects="An attacker with administrator access in a member account cannot detach it from the "
        "organization, which would remove every other SCP and the organization trail.",
        side_effects="None for normal operation. Moving an account out of the organization becomes a "
        "management-account task.",
        exempt=False,
        docs=("https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html",),
    ),
    Guardrail(
        key="deny_root_user",
        title="Deny the root user",
        category="baseline",
        spec="true",
        statements=("DenyRootUser",),
        denies="Every action when aws:PrincipalArn is like arn:aws:iam::*:root (the member account root user).",
        protects="Member-account root users, which IAM policies cannot restrict, can do nothing.",
        side_effects="The few tasks that require root credentials need the SCP detached or the task done another "
        "way. With centralized root access management, member accounts can have no root credentials at all, which "
        "complements this guardrail.",
        exempt=False,
        docs=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html",
        ),
    ),
    Guardrail(
        key="deny_disable_security_services",
        title="Deny disabling CloudTrail, GuardDuty, Security Hub and AWS Config",
        category="baseline",
        spec="true",
        statements=tuple(SECURITY_SERVICE_ACTIONS),
        denies="Deleting or stopping CloudTrail trails, GuardDuty detectors and members, Security Hub and its "
        "standards, and AWS Config recorders and delivery channels.",
        protects="Detection and audit logging cannot be switched off after a compromise.",
        side_effects="guardduty:UpdateDetector and cloudtrail:UpdateTrail are also used for legitimate changes "
        "(finding frequency, protection plans, a new bucket), so those changes must come from a protected role. "
        "Infrastructure as code that manages these resources needs its deployment role in protected_roles.",
        exempt=True,
        docs=(
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
            "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-accounts-orgs.html",
            "https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html",
        ),
    ),
    Guardrail(
        key="allowed_regions",
        title="Region allowlist",
        category="baseline",
        spec="list of region names",
        statements=("DenyOutsideAllowedRegions",),
        denies="Every action outside the listed regions (aws:RequestedRegion), except the global and "
        "account-level services in the NotAction list of the AWS region-deny example.",
        protects="No resources in regions nobody monitors, and less room to use stolen credentials.",
        side_effects="Services whose control plane lives in us-east-1 fail if us-east-1 is not allowed and they "
        "are not in the NotAction list. AWS adds services, so compare the list with the current AWS example. "
        "Regional STS endpoints in denied regions stop working, which is intended.",
        exempt=True,
        docs=(DOCS_REGION_EXAMPLE,),
    ),
    Guardrail(
        key="deny_iam_users_outside",
        title="Deny IAM users outside the identity account",
        category="baseline",
        spec="list of 12-digit account ids",
        statements=("DenyIamUsersOutsideIdentityAccount",),
        denies="iam:CreateUser, iam:CreateAccessKey and iam:CreateLoginProfile unless aws:PrincipalAccount is "
        "one of the listed accounts.",
        protects="No new long-lived IAM user credentials in workload accounts; people and pipelines use IAM "
        "Identity Center and roles.",
        side_effects="Third-party tools that still need an IAM user and access key must be set up in a listed "
        "account. Existing users and keys are not removed.",
        exempt=False,
        docs=("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",),
    ),
    Guardrail(
        key="require_imdsv2",
        title="Require IMDSv2",
        category="baseline",
        spec="true",
        statements=("RequireImdsv2OnLaunch", "DenyImdsOptionChanges", "DenyImdsv1RoleCredentials"),
        denies="Launching instances unless ec2:MetadataHttpTokens is required, changing instance metadata "
        "options, and any call made with role credentials delivered by IMDSv1 (ec2:RoleDelivery below 2.0).",
        protects="Instance role credentials cannot be taken through server-side request forgery against the "
        "version 1 metadata service.",
        side_effects="Launch templates, Auto Scaling groups and older AMIs or SDKs that use IMDSv1 fail to launch "
        "or lose credentials. Set HttpTokens=required in launch templates first.",
        exempt=True,
        docs=(
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html",
        ),
    ),
    Guardrail(
        key="deny_public_s3_acls",
        title="Deny public S3 ACLs",
        category="baseline",
        spec="true",
        statements=("DenyPublicS3CannedAcls", "ProtectAccountPublicAccessBlock"),
        denies="Creating buckets or writing objects and ACLs with the public-read, public-read-write or "
        "authenticated-read canned ACL, and changing the account-level S3 public access block.",
        protects="Data cannot be made public through canned ACLs, and the account public access block stays on.",
        side_effects="Public static websites need a deliberate exception (an account in its own OU, or CloudFront "
        "with origin access control). Bucket policies that grant public access are stopped by the public access "
        "block, not by this SCP.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",),
    ),
    Guardrail(
        key="require_instance_tag",
        title="Require a tag on new instances",
        category="baseline",
        spec="tag key, for example Owner",
        statements=("RequireTagOnLaunch",),
        denies="ec2:RunInstances when the request does not carry the tag (aws:RequestTag/<key> is null).",
        protects="Every new instance has an owner to contact, which makes clean-up and cost attribution possible.",
        side_effects="Consoles, scripts and launch templates must add the tag in the launch request. It does not "
        "check the tag value or existing instances.",
        exempt=False,
        docs=("https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html",),
    ),
    Guardrail(
        key="deny_instance_types",
        title="Deny expensive EC2 instance types",
        category="spend",
        spec="list of type patterns, or true for the default list",
        statements=("DenyExpensiveInstanceTypes",),
        denies="ec2:RunInstances and ec2:StartInstances when ec2:InstanceType matches the list (by default large, "
        "GPU, accelerator and bare-metal types).",
        protects="Sandbox and agent accounts cannot start the instance types that run up a large bill fastest.",
        side_effects="Instance families change; review the list against current instance types. Use either this "
        "or allowed_instance_types, not both.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html",),
    ),
    Guardrail(
        key="allowed_instance_types",
        title="Allow only listed EC2 instance types",
        category="spend",
        spec="list of type patterns",
        statements=("DenyInstanceTypesNotAllowed",),
        denies="ec2:RunInstances and ec2:StartInstances when ec2:InstanceType matches none of the list.",
        protects="Only the instance types the team agreed can run.",
        side_effects="Every new family needs a spec change. Use either this or deny_instance_types, not both.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html",),
    ),
    Guardrail(
        key="max_volume_iops",
        title="Cap EBS volume IOPS",
        category="spend",
        spec="number",
        statements=("DenyHighIopsVolumes",),
        denies="ec2:CreateVolume and ec2:RunInstances when ec2:VolumeIops is above the number.",
        protects="No provisioned-IOPS volumes far beyond what a sandbox needs.",
        side_effects="Snapshot restores and AMIs with high-IOPS volumes fail to launch.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html",),
    ),
    Guardrail(
        key="deny_volume_types",
        title="Deny EBS volume types",
        category="spend",
        spec="list of volume types, for example io1, io2",
        statements=("DenyProvisionedIopsVolumeTypes",),
        denies="ec2:CreateVolume and ec2:RunInstances when ec2:VolumeType is in the list.",
        protects="No provisioned-IOPS volume types in accounts that do not need them.",
        side_effects="AMIs whose block device mappings use a listed type fail to launch.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html",),
    ),
    Guardrail(
        key="sagemaker_instance_types",
        title="Deny SageMaker GPU instance types",
        category="spend",
        spec="list of ml.* patterns, or true for the default list",
        statements=("DenySageMakerGpuInstanceTypes",),
        denies="SageMaker create calls for notebooks, training, processing, transform, tuning and endpoint "
        "configurations when any sagemaker:InstanceTypes value matches the list.",
        protects="No GPU or accelerator SageMaker capacity in sandbox accounts.",
        side_effects="Serverless and CPU workloads are unaffected; any GPU experiment needs another account.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html",),
    ),
    Guardrail(
        key="deny_bedrock_customization",
        title="Deny Bedrock model customization and provisioned throughput",
        category="spend",
        spec="true",
        statements=("DenyBedrockCustomizationAndThroughput",),
        denies="bedrock:CreateModelCustomizationJob and bedrock:CreateProvisionedModelThroughput.",
        protects="No long-running customization jobs or committed throughput purchases from a sandbox.",
        side_effects="On-demand model invocation is unaffected.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/bedrock/latest/userguide/prov-throughput.html",),
    ),
    Guardrail(
        key="deny_services",
        title="Deny whole services",
        category="spend",
        spec="list of IAM service prefixes, for example redshift",
        statements=("DenyExpensiveServices",),
        denies="Every action of the listed services.",
        protects="Services the team decided a sandbox never needs cannot be used at all.",
        side_effects="iam, sts and organizations are refused by the builder, since denying them locks the account.",
        exempt=True,
        docs=(DOCS_SCP,),
    ),
    Guardrail(
        key="deny_commitments",
        title="Deny reserved capacity and Savings Plans purchases",
        category="spend",
        spec="true",
        statements=("DenyPurchaseCommitments",),
        denies="Reserved instance, reserved node and host reservation purchases, Savings Plans creation and "
        "Marketplace subscriptions.",
        protects="No multi-year financial commitments made from a member account.",
        side_effects="Commitments are bought centrally, from the management account or a protected role.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/savingsplans/latest/userguide/what-is-savings-plans.html",),
    ),
    Guardrail(
        key="protect_budgets",
        title="Protect budgets and cost anomaly monitors",
        category="spend",
        spec="true",
        statements=("ProtectBudgetsAndAnomalyMonitors",),
        denies="Changing or deleting budgets and budget actions, and changing or deleting cost anomaly monitors "
        "and subscriptions.",
        protects="The spend alerts that would notice a runaway account cannot be turned off from inside it.",
        side_effects="Budgets created in the management account are not affected by member-account SCPs.",
        exempt=True,
        docs=("https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html",),
    ),
)

BY_KEY: dict[str, Guardrail] = {g.key: g for g in CATALOG}
BY_SID: dict[str, Guardrail] = {sid: g for g in CATALOG for sid in g.statements}

GENERAL_NOTES: tuple[str, ...] = (
    "Every guardrail is a Deny; none grants anything. Keep FullAWSAccess (or your allow statements) attached.",
    "SCPs do not affect users or roles in the management account, or service-linked roles.",
    "protected_roles become an ArnNotLike condition on aws:PrincipalArn with arn:aws:iam::*:role/<name>. Keep "
    "the list short: every exempt role is a way around the guardrail.",
    "Test every document on an OU with one non-production account before attaching it more widely.",
)
GENERAL_DOCS: tuple[str, ...] = (DOCS_SCP, DOCS_QUOTAS, DOCS_REGION_EXAMPLE)


def render_table() -> str:
    rows = [("KEY", "CATEGORY", "STATEMENTS", "TITLE")]
    rows += [(g.key, g.category, ", ".join(g.statements), g.title) for g in CATALOG]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    lines = []
    for r in rows:
        lines.append("  ".join(r[i].ljust(widths[i]) for i in range(3)) + "  " + r[3])
    lines.insert(1, "-" * len(lines[0]))
    lines.append("")
    lines.append("Run `scp-guardrails catalog --format markdown` for what each one denies, its side effects and")
    lines.append("the AWS documentation; `scp-guardrails catalog --key <key>` for one guardrail.")
    return "\n".join(lines)


def render_one(g: Guardrail) -> str:
    lines = [
        f"{g.key}: {g.title} ({g.category})",
        f"  spec value:   {g.spec}",
        f"  statements:   {', '.join(g.statements)}",
        f"  denies:       {g.denies}",
        f"  protects:     {g.protects}",
        f"  side effects: {g.side_effects}",
        f"  exemption:    {'protected_roles apply' if g.exempt else 'none'}",
    ]
    lines += [f"  docs:         {d}" for d in g.docs]
    return "\n".join(lines)


def render_markdown() -> str:
    out = [
        "# Guardrail catalogue",
        "",
        "Generated by `scp-guardrails catalog --format markdown`; do not edit by hand.",
        "",
        "Each guardrail that `scp-guardrails build` can emit: the spec key that enables it, the statements, what it "
        "denies, what it protects, and the side effects to accept or work around before attaching it.",
        "",
    ]
    out += [f"- {n}" for n in GENERAL_NOTES]
    out += ["", "| Key | Category | Statements | Denies |", "| --- | --- | --- | --- |"]
    for g in CATALOG:
        sids = ", ".join(f"`{s}`" for s in g.statements)
        out.append(f"| [`{g.key}`](#{g.key}) | {g.category} | {sids} | {g.denies} |")
    for g in CATALOG:
        out += [
            "",
            f"## {g.key}",
            "",
            f"**{g.title}.** Spec value: {g.spec}.",
            "",
            f"- **Statements:** {', '.join(f'`{s}`' for s in g.statements)}"
            + (" (each with the protected-role exemption)" if g.exempt else ""),
            f"- **Denies:** {g.denies}",
            f"- **Protects:** {g.protects}",
            f"- **Side effects:** {g.side_effects}",
            "- **AWS documentation:** " + ", ".join(f"<{d}>" for d in g.docs),
        ]
    out += ["", "## Limits", ""]
    out += [
        f"- AWS Organizations quotas ({DOCS_QUOTAS}): the quotas page lists a maximum SCP document size and a "
        "maximum number of SCPs attached directly to a root, OU or account. `build` packs statements into as few "
        "documents as fit under `max_policy_chars` and fails when they need more than `max_documents`.",
        "- All characters count against the size limit; `build` measures the compact JSON form, which is what you "
        "should upload.",
        "- Inheritance: an account is subject to every SCP attached to the root, to each OU above it and to itself, "
        "and each level has its own attachment quota.",
        "",
    ]
    return "\n".join(out)


def as_json() -> dict[str, Any]:
    return {
        "notes": list(GENERAL_NOTES),
        "docs": list(GENERAL_DOCS),
        "guardrails": [g.as_dict() for g in CATALOG],
    }
