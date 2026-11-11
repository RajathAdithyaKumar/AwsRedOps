"""Cross-region EC2, Lambda, and S3 inventory; all read-only calls."""
from __future__ import annotations

from typing import Any

from .errors import OpsError, explain_aws_error
from .utils import pages


class InfrastructureInventory:
    def __init__(self, session: Any, home_region: str):
        self.session = session
        self.region = home_region
        self.errors: list[str] = []

    def regions(self, chosen: list[str] | None, all_regions: bool) -> list[str]:
        if chosen and all_regions:
            raise OpsError("Choose --regions or --all-regions, not both")
        if chosen:
            return sorted(set(chosen))
        if all_regions:
            response = self.session.client("ec2", region_name=self.region).describe_regions(AllRegions=False)
            return sorted(r["RegionName"] for r in response["Regions"])
        return [self.region]

    def collect(self, regions: list[str]) -> dict[str, Any]:
        output: dict[str, Any] = {"regions": {}, "s3_buckets": [], "errors": self.errors}
        s3 = self.session.client("s3", region_name=self.region)
        try:
            for bucket in s3.list_buckets().get("Buckets", []):
                row: dict[str, Any] = {"name": bucket["Name"], "created": bucket.get("CreationDate")}
                try:
                    row["region"] = s3.get_bucket_location(Bucket=bucket["Name"]).get("LocationConstraint") or "us-east-1"
                except Exception as exc:
                    self.errors.append(explain_aws_error(exc, f"s3 bucket region {bucket['Name']}"))
                    row["region"] = None
                output["s3_buckets"].append(row)
        except Exception as exc:
            self.errors.append(explain_aws_error(exc, "s3 list_buckets"))

        for region in regions:
            entry: dict[str, Any] = {"ec2_instances": [], "lambda_functions": []}
            try:
                ec2 = self.session.client("ec2", region_name=region)
                for reservation in pages(ec2, "describe_instances", "Reservations"):
                    for inst in reservation.get("Instances", []):
                        entry["ec2_instances"].append({
                            "instance_id": inst.get("InstanceId"), "instance_type": inst.get("InstanceType"),
                            "state": inst.get("State", {}).get("Name"), "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"), "private_ip": inst.get("PrivateIpAddress"),
                            "public_ip": inst.get("PublicIpAddress"), "iam_instance_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                            "tags": inst.get("Tags", []),
                        })
            except Exception as exc:
                self.errors.append(explain_aws_error(exc, f"ec2 {region}"))
            try:
                lam = self.session.client("lambda", region_name=region)
                for function in pages(lam, "list_functions", "Functions"):
                    entry["lambda_functions"].append({
                        "name": function.get("FunctionName"), "arn": function.get("FunctionArn"),
                        "runtime": function.get("Runtime"), "role": function.get("Role"),
                        "last_modified": function.get("LastModified"), "vpc_config": function.get("VpcConfig"),
                    })
            except Exception as exc:
                self.errors.append(explain_aws_error(exc, f"lambda {region}"))
            output["regions"][region] = entry
        return output
