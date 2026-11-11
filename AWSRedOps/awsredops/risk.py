"""Passive IAM privilege-risk checks; never performs privileged actions."""
from __future__ import annotations

from typing import Any

from .errors import OpsError
from .utils import identity_parts

# Conditions and resource scoping can make apparent permissions ineffective.
# These are risk combinations for review, not instructions for escalation.
RISK_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("role_pass_and_compute", "high", ("iam:PassRole", "ec2:RunInstances")),
    ("role_pass_and_function", "high", ("iam:PassRole", "lambda:CreateFunction")),
    ("modify_own_inline_user_policy", "high", ("iam:PutUserPolicy",)),
    ("create_policy_versions", "high", ("iam:CreatePolicyVersion",)),
    ("attach_user_policy", "high", ("iam:AttachUserPolicy",)),
    ("change_role_trust", "high", ("iam:UpdateAssumeRolePolicy",)),
    ("change_group_membership", "medium", ("iam:AddUserToGroup",)),
)


class PrivilegeRiskAudit:
    def __init__(self, session: Any):
        self.sts = session.client("sts")
        self.iam = session.client("iam")

    def _principal(self, provided: str | None) -> str:
        if provided:
            if not provided.startswith("arn:") or (":user/" not in provided and ":role/" not in provided):
                raise OpsError("--principal-arn must be an IAM user or IAM role ARN")
            return provided
        caller = identity_parts(self.sts.get_caller_identity()["Arn"])
        if caller["type"] in {"user", "role"}:
            return caller["arn"]
        if caller["type"] == "assumed-role":
            # Resolve role ARN through IAM to preserve an IAM role path.
            role = self.iam.get_role(RoleName=caller["role_name"])
            return role["Role"]["Arn"]
        raise OpsError("Cannot infer a simulatable user/role. Pass --principal-arn for an IAM user/role you may audit.")

    def collect(self, principal_arn: str | None = None) -> dict[str, Any]:
        target = self._principal(principal_arn)
        actions = sorted({action for _, _, combo in RISK_RULES for action in combo})
        results: dict[str, Any] = {}
        # SimulatePrincipalPolicy supports pagination; caller must have iam:SimulatePrincipalPolicy.
        for page in self.iam.get_paginator("simulate_principal_policy").paginate(
            PolicySourceArn=target, ActionNames=actions, ResourceArns=["*"],
        ):
            for record in page.get("EvaluationResults", []):
                results[record["EvalActionName"]] = {
                    "decision": record.get("EvalDecision", "unknown"),
                    "missing_context": record.get("MissingContextValues", []),
                }
        findings = []
        for rule_name, severity, required in RISK_RULES:
            if all(results.get(action, {}).get("decision", "").lower() == "allowed" for action in required):
                findings.append({"rule": rule_name, "severity": severity, "actions": required, "note": "Potential policy exposure; validate resource ARNs, conditions, SCPs, permission boundaries and trust relationships."})
        return {
            "principal_arn": target,
            "evaluations": results,
            "findings": findings,
            "limitations": "Read-only IAM policy simulation. Wildcard-resource evaluations are heuristic; results may differ from actual authorization for real resources and context.",
        }
