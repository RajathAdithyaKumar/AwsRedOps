"""Read-only IAM Identity Center instance, permission-set and assignment audit."""
from __future__ import annotations

from typing import Any

from .errors import explain_aws_error
from .utils import pages


class SSOInventory:
    def __init__(self, session: Any, region: str):
        self.admin = session.client("sso-admin", region_name=region)
        self.identitystore = session.client("identitystore", region_name=region)
        self.errors: list[str] = []
        self.name_cache: dict[tuple[str, str, str], str] = {}

    def _try(self, label: str, fn: Any, fallback: Any) -> Any:
        try:
            return fn()
        except Exception as exc:
            self.errors.append(explain_aws_error(exc, label))
            return fallback

    def _name(self, store: str, principal_type: str, principal_id: str) -> str | None:
        key = (store, principal_type, principal_id)
        if key not in self.name_cache:
            if principal_type == "USER":
                response = self._try("identitystore describe_user", lambda: self.identitystore.describe_user(IdentityStoreId=store, UserId=principal_id), {})
                display = response.get("UserName") or response.get("DisplayName")
            else:
                response = self._try("identitystore describe_group", lambda: self.identitystore.describe_group(IdentityStoreId=store, GroupId=principal_id), {})
                display = response.get("DisplayName")
            self.name_cache[key] = display or ""
        return self.name_cache[key] or None

    def collect(self, max_assignments: int = 2500) -> dict[str, Any]:
        instances = self._try("sso-admin list_instances", lambda: list(pages(self.admin, "list_instances", "Instances")), [])
        result: list[dict[str, Any]] = []
        assignment_count = 0
        for instance in instances:
            instance_arn, store_id = instance["InstanceArn"], instance["IdentityStoreId"]
            record: dict[str, Any] = {"instance_arn": instance_arn, "identity_store_id": store_id, "permission_sets": []}
            sets = self._try("sso-admin list_permission_sets", lambda: list(pages(self.admin, "list_permission_sets", "PermissionSets", InstanceArn=instance_arn)), [])
            for set_arn in sets:
                ps = self._try("sso-admin describe_permission_set", lambda: self.admin.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=set_arn)["PermissionSet"], {})
                managed = self._try("sso-admin list_managed_policies", lambda: list(pages(self.admin, "list_managed_policies_in_permission_set", "AttachedManagedPolicies", InstanceArn=instance_arn, PermissionSetArn=set_arn)), [])
                inline = self._try("sso-admin inline_permission_set", lambda: self.admin.get_inline_policy_for_permission_set(InstanceArn=instance_arn, PermissionSetArn=set_arn).get("InlinePolicy"), None)
                accounts = self._try("sso-admin provisioned_accounts", lambda: list(pages(self.admin, "list_accounts_for_provisioned_permission_set", "AccountIds", InstanceArn=instance_arn, PermissionSetArn=set_arn)), [])
                assignments = []
                for account in accounts:
                    if assignment_count >= max_assignments:
                        break
                    rows = self._try("sso-admin list_account_assignments", lambda: list(pages(self.admin, "list_account_assignments", "AccountAssignments", InstanceArn=instance_arn, AccountId=account, PermissionSetArn=set_arn)), [])
                    for assignment in rows:
                        if assignment_count >= max_assignments:
                            break
                        row = dict(assignment)
                        row["principal_name"] = self._name(store_id, assignment["PrincipalType"], assignment["PrincipalId"])
                        assignments.append(row)
                        assignment_count += 1
                record["permission_sets"].append({"arn": set_arn, "name": ps.get("Name"), "session_duration": ps.get("SessionDuration"), "managed_policies": managed, "inline_policy": inline, "provisioned_accounts": accounts, "assignments": assignments})
            result.append(record)
        return {"instances": result, "assignment_count": assignment_count, "truncated": assignment_count >= max_assignments, "errors": self.errors}
