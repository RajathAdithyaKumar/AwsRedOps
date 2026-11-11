"""Read-only IAM policy and principal inventories."""
from __future__ import annotations

from typing import Any

from .errors import explain_aws_error
from .utils import pages


class IAMInventory:
    def __init__(self, session: Any):
        self.iam = session.client("iam")
        self.errors: list[str] = []

    def _try(self, description: str, fn: Any, default: Any) -> Any:
        try:
            return fn()
        except Exception as exc:
            self.errors.append(explain_aws_error(exc, description))
            return default

    def _policies(self, kind: str, name: str, include_documents: bool) -> dict[str, Any]:
        methods = {
            "user": ("list_attached_user_policies", "list_user_policies", "get_user_policy", "UserName"),
            "role": ("list_attached_role_policies", "list_role_policies", "get_role_policy", "RoleName"),
            "group": ("list_attached_group_policies", "list_group_policies", "get_group_policy", "GroupName"),
        }
        managed_api, inline_api, get_inline_api, kw = methods[kind]
        managed = self._try(f"{name} managed policies", lambda: list(pages(self.iam, managed_api, "AttachedPolicies", **{kw: name})), [])
        inline_names = self._try(f"{name} inline policies", lambda: list(pages(self.iam, inline_api, "PolicyNames", **{kw: name})), [])
        inline: list[dict[str, Any]] = []
        for policy_name in inline_names:
            record: dict[str, Any] = {"name": policy_name}
            if include_documents:
                record["document"] = self._try(
                    f"{name} policy {policy_name}",
                    lambda: getattr(self.iam, get_inline_api)(**{kw: name, "PolicyName": policy_name})["PolicyDocument"],
                    None,
                )
            inline.append(record)
        if include_documents:
            for entry in managed:
                arn = entry["PolicyArn"]
                policy = self._try(f"managed policy {arn}", lambda: self.iam.get_policy(PolicyArn=arn)["Policy"], None)
                if policy:
                    entry["document"] = self._try(
                        f"managed policy version {arn}",
                        lambda: self.iam.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"],
                        None,
                    )
        return {"managed": managed, "inline": inline}

    def collect(self, include_documents: bool = False) -> dict[str, Any]:
        principals: dict[str, Any] = {}
        for kind, api, member in (
            ("users", "list_users", "Users"),
            ("roles", "list_roles", "Roles"),
            ("groups", "list_groups", "Groups"),
        ):
            collected = []
            for item in self._try(api, lambda: list(pages(self.iam, api, member)), []):
                singular = kind[:-1]
                name = item[f"{singular.title()}Name"]
                collected.append({"name": name, "arn": item["Arn"], "id": item.get(f"{singular.title()}Id"), "policies": self._policies(singular, name, include_documents)})
            principals[kind] = collected
        principals["errors"] = self.errors
        principals["summary"] = f"{len(principals["users"])} users, {len(principals["roles"])} roles, {len(principals["groups"])} groups"
        return principals
