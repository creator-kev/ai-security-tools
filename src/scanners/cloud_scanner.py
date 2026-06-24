"""AWS Cloud Security Scanner — IAM Misconfiguration Auditor.

Read-only scanner for AWS IAM. Identifies common privilege escalation and
exposure risks without changing any state.

References:
- AWS Well-Architected Framework — Security Pillar
- CloudGoat (Rhino Security Labs) — IAM privilege escalation techniques
- PenTest Partners — AWS IAM enumeration methodology
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckCategory(str, Enum):
    IAM_POLICY = "iam_policy"
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    IAM_GROUP = "iam_group"
    S3_BUCKET = "s3_bucket"
    EC2_SECURITY_GROUP = "ec2_security_group"
    CLOUDTRAIL = "cloudtrail"
    GENERAL = "general"


@dataclass
class CloudFinding:
    finding_id: str
    category: CheckCategory
    title: str
    description: str
    severity: Severity
    resource: str
    region: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "resource": self.resource,
            "region": self.region,
            "remediation": self.remediation,
            "references": self.references,
            "details": self.details,
        }


@dataclass
class CloudScanResult:
    profile: str
    region: str
    account_id: str = ""
    findings: List[CloudFinding] = field(default_factory=list)
    scan_errors: List[str] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "region": self.region,
            "account_id": self.account_id,
            "findings": [f.to_dict() for f in self.findings],
            "scan_errors": self.scan_errors,
            "scan_metadata": self.scan_metadata,
        }


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class CloudScanner:
    """AWS cloud security scanner (IAM-focused, read-only).

    Supports:
    - AWS CLI profile-based auth
    - boto3 when available
    - Graceful fallback to CLI when boto3 is unavailable
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config: Dict[str, Any] = {}
        if config_path:
            try:
                import yaml
                with open(config_path) as fh:
                    self.config = yaml.safe_load(fh) or {}
            except Exception as exc:
                logger.debug("Could not read cloud scanner config: %s", exc)

        scanner_config = self.config.get("scanners", {}).get("cloud", {})
        self.profile: str = scanner_config.get("profile", "default")
        self.region: str = scanner_config.get("region", "us-east-1")
        self.output_dir: str = scanner_config.get("output_dir", str(Path.home() / "pentest" / "cloud"))
        self._aws_available = self._check_aws_cli()
        self._boto3_available = self._check_boto3()

    # ------------------------------------------------------------------
    # Auth / availability
    # ------------------------------------------------------------------

    def _check_aws_cli(self) -> bool:
        try:
            subprocess.run(
                ["aws", "--version"],
                capture_output=True,
                check=False,
                timeout=10,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_boto3(self) -> bool:
        try:
            import boto3  # noqa: F401
            return True
        except ImportError:
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _aws_cmd(self, *args: str) -> subprocess.CompletedProcess:
        cmd = [
            "aws",
            "--profile",
            self.profile,
            "--region",
            self.region,
            "--output",
            "json",
        ] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def _boto3_client(self, service: str):
        if not self._boto3_available:
            raise RuntimeError("boto3 not installed")
        import boto3
        return boto3.client(service, region_name=self.region)

    def _add_finding(self, result: CloudScanResult, finding: CloudFinding) -> None:
        result.findings.append(finding)

    def _add_error(self, result: CloudScanResult, msg: str) -> None:
        logger.error(msg)
        result.scan_errors.append(msg)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def scan(self) -> CloudScanResult:
        result = CloudScanResult(profile=self.profile, region=self.region)

        if self._boto3_available:
            self._scan_with_boto3(result)
        elif self._aws_available:
            self._scan_with_cli(result)
        else:
            self._add_error(result, "Neither AWS CLI nor boto3 is available")

        self.scan_metadata(result)
        return result

    def _scan_with_boto3(self, result: CloudScanResult) -> None:
        try:
            sts = self._boto3_client("sts")
            identity = sts.get_caller_identity()
            result.account_id = identity.get("Account", "")
        except Exception as exc:
            self._add_error(result, f"Failed to get caller identity: {exc}")
            return

        self._scan_iam(result)
        self._scan_s3(result)
        self._scan_cloudtrail(result)

    def _scan_with_cli(self, result: CloudScanResult) -> None:
        # Get caller identity
        p = self._aws_cmd("sts", "get-caller-identity")
        if p.returncode == 0:
            import json
            try:
                identity = json.loads(p.stdout)
                result.account_id = identity.get("Account", "")
            except Exception:
                pass
        else:
            self._add_error(result, f"AWS CLI auth failed: {p.stderr.strip()}")

        self._scan_iam_cli(result)

    # ------------------------------------------------------------------
    # IAM checks (boto3)
    # ------------------------------------------------------------------

    def _scan_iam(self, result: CloudScanResult) -> None:
        try:
            iam = self._boto3_client("iam")
        except Exception as exc:
            self._add_error(result, f"Failed to init IAM client: {exc}")
            return

        # 1. Enumerate users, groups, roles, policies
        entities: Dict[str, Any] = {"users": [], "groups": [], "roles": [], "policies": []}
        try:
            entities["users"] = iam.list_users().get("Users", [])
        except Exception as exc:
            self._add_error(result, f"list_users failed: {exc}")

        try:
            entities["roles"] = iam.list_roles().get("Roles", [])
        except Exception as exc:
            self._add_error(result, f"list_roles failed: {exc}")

        # 2. Users without MFA
        for user in entities.get("users", []):
            user_name = user.get("UserName", "")
            try:
                mfa = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
                if not mfa:
                    self._add_finding(result, CloudFinding(
                        finding_id=f"MFA_MISSING_{user_name}",
                        category=CheckCategory.IAM_USER,
                        title="IAM user without MFA",
                        description=f"User '{user_name}' has no MFA device attached.",
                        severity=Severity.HIGH,
                        resource=f"arn:aws:iam::{result.account_id}:user/{user_name}",
                        remediation="Attach an MFA device to this user.",
                    ))
            except Exception as exc:
                logger.debug("list_mfa_devices failed for %s: %s", user_name, exc)

        # 3. Roles with wildcard trust / overly permissive AssumeRole
        for role in entities.get("roles", []):
            role_name = role.get("RoleName", "")
            doc = role.get("AssumeRolePolicyDocument", {})
            statement = doc.get("Statement", [])
            if isinstance(statement, dict):
                statement = [statement]
            for stmt in statement:
                principal = stmt.get("Principal", {})
                effect = stmt.get("Effect", "")
                if effect != "Allow":
                    continue
                if principal == "*" or principal.get("AWS") == "*":
                    self._add_finding(result, CloudFinding(
                        finding_id=f"ROLE_TRUST_WILDCARD_{role_name}",
                        category=CheckCategory.IAM_ROLE,
                        title="IAM role trust policy allows wildcard principal",
                        description=f"Role '{role_name}' allows '*' in its trust policy.",
                        severity=Severity.CRITICAL,
                        resource=role.get("Arn", ""),
                        remediation="Restrict the trust policy to specific principals.",
                    ))

        # 4. Inline + managed policy checks for wildcards
        self._scan_iam_policies(result, iam, entities)

    def _scan_iam_policies(self, result: CloudScanResult, iam: Any, entities: Dict[str, Any]) -> None:
        def evaluate_policy(policy_doc: Dict[str, Any], resource_arn: str, policy_name: str) -> None:
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                effect = stmt.get("Effect", "")
                if effect != "Allow":
                    continue
                actions: List[str] = []
                action = stmt.get("Action", "")
                if isinstance(action, str):
                    actions = [action]
                elif isinstance(action, list):
                    actions = action
                resource_val = stmt.get("Resource", "")
                if "*" in actions or "*" in str(resource_val):
                    self._add_finding(result, CloudFinding(
                        finding_id=f"POLICY_WILDCARD_{policy_name}",
                        category=CheckCategory.IAM_POLICY,
                        title="IAM policy contains wildcard privilege",
                        description=f"Policy '{policy_name}' allows wildcard action/resource.",
                        severity=Severity.HIGH,
                        resource=resource_arn,
                        remediation="Replace wildcards with least-privilege actions and resource ARNs.",
                        details={"actions": actions, "resource": str(resource_val)},
                    ))

        # Managed policies attached to users/groups/roles
        for role in entities.get("roles", []):
            role_name = role.get("RoleName", "")
            try:
                for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                    pol = iam.get_policy(PolicyArn=p["PolicyArn"]).get("Policy", {})
                    default_ver = pol.get("DefaultVersionId", "v1")
                    versions = iam.list_policy_versions(PolicyArn=p["PolicyArn"]).get("Versions", [])
                    for ver in versions:
                        if ver.get("IsDefaultVersion"):
                            doc = iam.get_policy_version(
                                PolicyArn=p["PolicyArn"],
                                VersionId=ver["VersionId"],
                            ).get("PolicyVersion", {}).get("Document", {})
                            evaluate_policy(doc, p["PolicyArn"], p["PolicyName"])
            except Exception as exc:
                logger.debug("Policy scan failed for role %s: %s", role_name, exc)

    # ------------------------------------------------------------------
    # S3 checks (boto3)
    # ------------------------------------------------------------------

    def _scan_s3(self, result: CloudScanResult) -> None:
        try:
            s3 = self._boto3_client("s3")
            for bucket in s3.list_buckets().get("Buckets", []):
                name = bucket.get("Name", "")
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        uri = grantee.get("URI", "")
                        if "AllUsers" in uri or grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                            self._add_finding(result, CloudFinding(
                                finding_id=f"S3_PUBLIC_{name}",
                                category=CheckCategory.S3_BUCKET,
                                title="S3 bucket is publicly accessible (ACL)",
                                description=f"Bucket '{name}' has a public ACL grant.",
                                severity=Severity.CRITICAL,
                                resource=f"arn:aws:s3:::{name}",
                                remediation="Remove public ACL grants; use bucket policies instead.",
                            ))
                except Exception as exc:
                    logger.debug("S3 ACL check failed for %s: %s", name, exc)
        except Exception as exc:
            self._add_error(result, f"S3 scan failed: {exc}")

    # ------------------------------------------------------------------
    # CloudTrail checks
    # ------------------------------------------------------------------

    def _scan_cloudtrail(self, result: CloudScanResult) -> None:
        try:
            ct = self._boto3_client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            if not trails:
                self._add_finding(result, CloudFinding(
                    finding_id="CLOUDTRAIL_MISSING",
                    category=CheckCategory.CLOUDTRAIL,
                    title="No CloudTrail trails configured",
                    description="No CloudTrail was found in this account/region.",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:cloudtrail:{result.region}:{result.account_id}:trail/",
                    remediation="Enable CloudTrail in all regions for audit logging.",
                ))
        except Exception as exc:
            self._add_error(result, f"CloudTrail scan failed: {exc}")

    # ------------------------------------------------------------------
    # CLI fallback scans
    # ------------------------------------------------------------------

    def _scan_iam_cli(self, result: CloudScanResult) -> None:
        p = self._aws_cmd("iam", "list-users")
        if p.returncode == 0:
            import json
            try:
                users = json.loads(p.stdout).get("Users", [])
                for user in users:
                    user_name = user.get("UserName", "")
                    m = self._aws_cmd("iam", "list-mfa-devices", "--user-name", user_name)
                    if m.returncode == 0:
                        mfa = json.loads(m.stdout).get("MFADevices", [])
                        if not mfa:
                            self._add_finding(result, CloudFinding(
                                finding_id=f"MFA_MISSING_{user_name}",
                                category=CheckCategory.IAM_USER,
                                title="IAM user without MFA",
                                description=f"User '{user_name}' lacks MFA.",
                                severity=Severity.HIGH,
                                resource=user.get("Arn", ""),
                                remediation="Attach an MFA device.",
                            ))
            except Exception as exc:
                self._add_error(result, f"IAM CLI parse failed: {exc}")
        else:
            self._add_error(result, f"iam list-users failed: {p.stderr.strip()}")

    # ------------------------------------------------------------------
    # Metadata / reporting
    # ------------------------------------------------------------------

    def scan_metadata(self, result: CloudScanResult) -> None:
        result.scan_metadata["aws_cli"] = self._aws_available
        result.scan_metadata["boto3"] = self._boto3_available
        result.scan_metadata["profile"] = self.profile
        result.scan_metadata["region"] = self.region
