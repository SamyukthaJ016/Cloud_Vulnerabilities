"""
IaC MCP Server
Scans Terraform, CloudFormation, and Kubernetes manifest files for common misconfigurations.
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from backend.mcp.mcp_base import Severity
from backend.mcp_servers.base_server import BaseMCPServer, MCPResource, MCPTool, ToolCategory

logger = logging.getLogger("iac_mcp_server")


EXCLUDED_DIRS = {
    ".git",
    ".vercel",
    ".venv",
    ".venv311",
    "__pycache__",
    "node_modules",
    "reports",
    "logs",
}

IAC_EXTENSIONS = {".tf", ".tfvars", ".hcl", ".json", ".yaml", ".yml"}


class IaCMCPServer(BaseMCPServer):
    """MCP scanner for IaC templates."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("iac", config or {})

    def _setup_tools(self) -> None:
        self.register_tool(MCPTool(
            name="iac/discover_templates",
            description="Discover Terraform, CloudFormation, and Kubernetes manifest files in the repository",
            category=ToolCategory.DISCOVERY,
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            handler=self._discover_templates,
        ))
        self.register_tool(MCPTool(
            name="iac/full_scan",
            description="Scan IaC files for cloud security misconfigurations",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "account_id": {"type": "string"},
                    "path": {"type": "string"},
                    "deep_scan": {"type": "boolean", "default": False},
                    "files": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "filename": {"type": "string"},
                                "content": {"type": "string"},
                            },
                            "required": ["filename", "content"],
                        },
                    },
                },
            },
            handler=self._full_scan,
        ))

    def _setup_resources(self) -> None:
        self.register_resource(MCPResource(
            uri="iac://templates",
            name="IaC Templates",
            description="Terraform, CloudFormation, and Kubernetes manifest files discovered in the repository",
            mime_type="application/json",
        ))

    async def _fetch_resource_content(self, uri: str) -> str:
        if uri != "iac://templates":
            raise ValueError(f"Unknown IaC resource: {uri}")
        return json.dumps(await self._discover_templates(), indent=2)

    def _root_path(self, requested_path: Optional[str] = None) -> Path:
        configured = requested_path or self.config.get("root_path") or os.getcwd()
        path = Path(configured)
        if not path.is_absolute():
            path = Path(os.getcwd()) / path
        return path.resolve()

    async def _discover_templates(self, path: Optional[str] = None) -> Dict[str, Any]:
        root = self._root_path(path)
        files = [str(p) for p in self._iter_candidate_files(root) if self._classify_file(p)]
        return {"root": str(root), "count": len(files), "files": files}

    async def _full_scan(
        self,
        account_id: str = "repository",
        path: Optional[str] = None,
        deep_scan: bool = False,
        files: Optional[List[Dict[str, Any]]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        started = time.time()
        root = self._root_path(path)
        uploaded_files = self._normalize_uploaded_files(files or [])
        template_files = [] if uploaded_files else [p for p in self._iter_candidate_files(root) if self._classify_file(p)]

        resources: List[Dict[str, Any]] = [{
            "provider": "iac",
            "resource_type": "iac_workspace",
            "name": "uploaded_iac_files" if uploaded_files else root.name or "repository",
            "region": "local",
            "config": {
                "root": str(root) if not uploaded_files else None,
                "files_scanned": len(uploaded_files) if uploaded_files else len(template_files),
                "deep_scan": deep_scan,
                "source": "uploaded_files" if uploaded_files else "repository",
            },
            "is_public": False,
        }]
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        if uploaded_files:
            for uploaded in uploaded_files:
                filename = uploaded["filename"]
                text = uploaded["content"]
                file_type = self._classify_uploaded_file(filename, text)
                if not file_type:
                    errors.append(f"{filename}: unsupported IaC file type")
                    continue

                resource = {
                    "provider": "iac",
                    "resource_type": file_type,
                    "name": filename,
                    "region": "local",
                    "config": {
                        "file": filename,
                        "scanner": file_type,
                        "source": "uploaded_content",
                        "size_bytes": len(text.encode("utf-8")),
                    },
                    "is_public": False,
                }
                resources.append(resource)

                try:
                    if file_type == "terraform":
                        findings.extend(self._scan_terraform(resource, text))
                    elif file_type == "cloudformation":
                        findings.extend(self._scan_cloudformation(resource, Path(filename), text))
                    elif file_type == "kubernetes":
                        findings.extend(self._scan_kubernetes(resource, Path(filename), text))
                except Exception as exc:
                    logger.warning("Failed to scan uploaded IaC file %s: %s", filename, exc)
                    errors.append(f"{filename}: {exc}")

            if len(resources) == 1:
                findings.append(self._finding(
                    resources[0],
                    "INFO",
                    "No supported IaC templates found",
                    "The uploaded content did not include supported Terraform, CloudFormation, or Kubernetes templates.",
                    "Upload .tf, .tfvars, .hcl, .yaml, .yml, or .json files containing Terraform, CloudFormation, or Kubernetes resources.",
                    ["CIS Infrastructure as Code"],
                ))
        else:
            for template_file in template_files:
                file_type = self._classify_file(template_file)
                resource = {
                    "provider": "iac",
                    "resource_type": file_type,
                    "name": str(template_file.relative_to(root)) if template_file.is_relative_to(root) else template_file.name,
                    "region": "local",
                    "config": {"file": str(template_file), "scanner": file_type},
                    "is_public": False,
                }
                resources.append(resource)

                try:
                    text = template_file.read_text(encoding="utf-8", errors="ignore")
                    if file_type == "terraform":
                        findings.extend(self._scan_terraform(resource, text))
                    elif file_type == "cloudformation":
                        findings.extend(self._scan_cloudformation(resource, template_file, text))
                    elif file_type == "kubernetes":
                        findings.extend(self._scan_kubernetes(resource, template_file, text))
                except Exception as exc:
                    logger.warning("Failed to scan IaC file %s: %s", template_file, exc)
                    errors.append(f"{template_file}: {exc}")

        if len(resources) == 1 and not uploaded_files:
            findings.append(self._finding(
                resources[0],
                "INFO",
                "No IaC templates found",
                "The IaC scanner ran successfully but did not find Terraform, CloudFormation, or Kubernetes templates in the deployment workspace.",
                "Add Terraform, CloudFormation, or Kubernetes templates under infra, terraform, cloudformation, deployment, or the repository root to include them in scans.",
                ["CIS Infrastructure as Code"],
            ))

        return {
            "provider": "iac",
            "account_id": account_id or ("uploaded-files" if uploaded_files else "repository"),
            "resources": resources,
            "findings": findings,
            "scan_duration": round(time.time() - started, 3),
            "errors": errors,
            "summary": {
                "files_scanned": len(resources) - 1,
                "findings": len(findings),
                "source": "uploaded_files" if uploaded_files else "repository",
            },
        }

    def _normalize_uploaded_files(self, files: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        normalized: List[Dict[str, str]] = []
        for index, item in enumerate(files):
            filename = str(item.get("filename") or f"uploaded-{index + 1}.tf").strip()
            content = item.get("content")
            if content is None:
                continue
            text = str(content)
            if not text.strip():
                continue
            normalized.append({"filename": filename, "content": text})
        return normalized

    def _classify_uploaded_file(self, filename: str, text: str) -> Optional[str]:
        suffix = Path(filename).suffix.lower()
        if suffix in {".tf", ".tfvars", ".hcl"}:
            return "terraform"

        lower = text.lower()
        if re.search(r'\bresource\s+"[^"]+"\s+"[^"]+"\s*{', text, re.IGNORECASE):
            return "terraform"

        if suffix in {".yaml", ".yml", ".json"} or "awstemplateformatversion" in lower or "aws::" in lower:
            if "AWSTemplateFormatVersion" in text or "AWS::" in text:
                return "cloudformation"
            if re.search(r"(?m)^apiVersion\s*:", text) and re.search(r"(?m)^kind\s*:", text):
                return "kubernetes"
            try:
                data = json.loads(text)
                if isinstance(data, dict) and data.get("apiVersion") and data.get("kind"):
                    return "kubernetes"
                if isinstance(data, list) and any(isinstance(item, dict) and item.get("apiVersion") and item.get("kind") for item in data):
                    return "kubernetes"
            except Exception:
                pass

        return None

    def _iter_candidate_files(self, root: Path) -> Iterable[Path]:
        if root.is_file():
            yield root
            return

        preferred_dirs = [
            root / "infra",
            root / "terraform",
            root / "cloudformation",
            root / "cfn",
            root / "deployment",
            root,
        ]
        seen: set[Path] = set()
        for base in preferred_dirs:
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if path in seen or not path.is_file():
                    continue
                if any(part in EXCLUDED_DIRS for part in path.parts):
                    continue
                if path.suffix.lower() in IAC_EXTENSIONS:
                    seen.add(path)
                    yield path

    def _classify_file(self, path: Path) -> Optional[str]:
        suffix = path.suffix.lower()
        if suffix in {".tf", ".tfvars", ".hcl"}:
            return "terraform"

        if suffix in {".yaml", ".yml", ".json"}:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return None
            if "AWSTemplateFormatVersion" in text or "AWS::" in text:
                return "cloudformation"
            if re.search(r"(?m)^apiVersion\s*:", text) and re.search(r"(?m)^kind\s*:", text):
                return "kubernetes"
            try:
                data = json.loads(text)
                if isinstance(data, dict) and data.get("apiVersion") and data.get("kind"):
                    return "kubernetes"
                if isinstance(data, list) and any(isinstance(item, dict) and item.get("apiVersion") and item.get("kind") for item in data):
                    return "kubernetes"
            except Exception:
                pass
        return None

    def _scan_terraform(self, resource: Dict[str, Any], text: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lower = text.lower()

        if re.search(r'acl\s*=\s*"public-(read|read-write)"', lower):
            findings.append(self._finding(
                resource,
                "HIGH",
                "Terraform grants public S3 ACL",
                "An S3 bucket ACL allows public read or write access.",
                "Remove public ACLs and enforce S3 Block Public Access.",
                ["CIS AWS 2.1.5"],
            ))

        if 'resource "aws_s3_bucket"' in lower and "aws_s3_bucket_public_access_block" not in lower:
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "S3 bucket lacks explicit public access block",
                "Terraform defines an S3 bucket but no matching public access block resource was detected in this file.",
                "Add aws_s3_bucket_public_access_block with all block public access settings enabled.",
                ["CIS AWS 2.1.5"],
            ))

        for block in self._terraform_blocks(lower, "aws_security_group_rule") + self._terraform_blocks(lower, "aws_security_group"):
            if "0.0.0.0/0" in block or "::/0" in block:
                severity = "HIGH"
                issue = "Security group allows unrestricted ingress"
                if re.search(r"from_port\s*=\s*(22|3389)", block) or re.search(r"to_port\s*=\s*(22|3389)", block):
                    severity = "CRITICAL"
                    issue = "Security group exposes administrative access"
                findings.append(self._finding(
                    resource,
                    severity,
                    issue,
                    "A security group rule allows traffic from the public internet.",
                    "Restrict ingress CIDR blocks to trusted ranges and avoid exposing SSH/RDP publicly.",
                    ["CIS AWS 4.1", "CIS AWS 4.2"],
                ))
                break

        if re.search(r"publicly_accessible\s*=\s*true", lower):
            findings.append(self._finding(
                resource,
                "HIGH",
                "Database is publicly accessible",
                "Terraform config marks a database resource as publicly accessible.",
                "Place databases in private subnets and disable public accessibility.",
                ["CIS AWS 2.3"],
            ))

        if 'resource "aws_db_instance"' in lower and "storage_encrypted" not in lower:
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "Database encryption is not explicit",
                "An RDS instance is defined without an explicit storage_encrypted setting in this file.",
                "Set storage_encrypted = true and use a customer-managed KMS key where appropriate.",
                ["CIS AWS 2.3.1"],
            ))

        if re.search(r"associate_public_ip_address\s*=\s*true", lower):
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "Instance receives a public IP address",
                "Terraform config associates a public IP address with a compute instance or launch template.",
                "Prefer private subnets and expose services through controlled load balancers or bastion patterns.",
                ["CIS AWS 4.0"],
            ))

        if re.search(r'actions?\s*=\s*\[?\s*"\*"', lower) and re.search(r'resources?\s*=\s*\[?\s*"\*"', lower):
            findings.append(self._finding(
                resource,
                "HIGH",
                "IAM policy allows wildcard action and resource",
                "An IAM policy appears to grant '*' actions over '*' resources.",
                "Replace wildcard IAM permissions with least-privilege actions and scoped resources.",
                ["CIS AWS 1.16"],
            ))

        return findings

    def _terraform_blocks(self, text: str, resource_type: str) -> List[str]:
        pattern = re.compile(rf'resource\s+"{re.escape(resource_type)}"\s+"[^"]+"\s*{{', re.IGNORECASE)
        blocks: List[str] = []
        for match in pattern.finditer(text):
            start = match.start()
            depth = 0
            for index in range(match.end() - 1, len(text)):
                if text[index] == "{":
                    depth += 1
                elif text[index] == "}":
                    depth -= 1
                    if depth == 0:
                        blocks.append(text[start:index + 1])
                        break
        return blocks

    def _scan_cloudformation(self, resource: Dict[str, Any], path: Path, text: str) -> List[Dict[str, Any]]:
        try:
            if path.suffix.lower() == ".json":
                template = json.loads(text)
            else:
                try:
                    import yaml
                except ImportError as exc:
                    raise RuntimeError("PyYAML is required for CloudFormation YAML scanning") from exc
                template = self._load_cloudformation_yaml(yaml, text)
        except Exception as exc:
            return [self._finding(
                resource,
                "LOW",
                "CloudFormation template could not be parsed",
                f"The template was identified as CloudFormation but could not be parsed: {exc}",
                "Validate the template syntax before deployment.",
                ["IaC Hygiene"],
            )]

        findings: List[Dict[str, Any]] = []
        resources = (template or {}).get("Resources") or {}
        for logical_id, item in resources.items():
            if not isinstance(item, dict):
                continue
            resource_type = item.get("Type")
            properties = item.get("Properties") or {}

            if resource_type == "AWS::S3::Bucket":
                access_control = str(properties.get("AccessControl", "")).lower()
                if access_control in {"publicread", "publicreadwrite", "authenticatedread"}:
                    findings.append(self._finding(
                        resource,
                        "HIGH",
                        f"{logical_id} grants public S3 access",
                        "The bucket AccessControl setting may expose bucket data publicly.",
                        "Remove public ACLs and enable PublicAccessBlockConfiguration.",
                        ["CIS AWS 2.1.5"],
                    ))
                if "PublicAccessBlockConfiguration" not in properties:
                    findings.append(self._finding(
                        resource,
                        "MEDIUM",
                        f"{logical_id} lacks S3 public access block",
                        "The bucket does not define PublicAccessBlockConfiguration.",
                        "Set BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets to true.",
                        ["CIS AWS 2.1.5"],
                    ))
                if "BucketEncryption" not in properties:
                    findings.append(self._finding(
                        resource,
                        "MEDIUM",
                        f"{logical_id} lacks bucket encryption",
                        "The bucket does not define default server-side encryption.",
                        "Enable BucketEncryption with SSE-S3 or SSE-KMS.",
                        ["CIS AWS 2.1.1"],
                    ))

            if resource_type == "AWS::EC2::SecurityGroup":
                for rule in properties.get("SecurityGroupIngress") or []:
                    if not isinstance(rule, dict):
                        continue
                    cidr = rule.get("CidrIp") or rule.get("CidrIpv6")
                    if cidr in {"0.0.0.0/0", "::/0"}:
                        from_port = str(rule.get("FromPort", ""))
                        to_port = str(rule.get("ToPort", ""))
                        admin_port = from_port in {"22", "3389"} or to_port in {"22", "3389"}
                        findings.append(self._finding(
                            resource,
                            "CRITICAL" if admin_port else "HIGH",
                            f"{logical_id} allows unrestricted ingress",
                            "A security group ingress rule allows traffic from the public internet.",
                            "Restrict ingress to trusted CIDR ranges and avoid exposing administrative ports.",
                            ["CIS AWS 4.1", "CIS AWS 4.2"],
                        ))

            if resource_type == "AWS::RDS::DBInstance":
                if properties.get("PubliclyAccessible") is True:
                    findings.append(self._finding(
                        resource,
                        "HIGH",
                        f"{logical_id} database is public",
                        "The database instance is configured as publicly accessible.",
                        "Disable public accessibility and place the database in private subnets.",
                        ["CIS AWS 2.3"],
                    ))
                if properties.get("StorageEncrypted") is not True:
                    findings.append(self._finding(
                        resource,
                        "MEDIUM",
                        f"{logical_id} database encryption is not enabled",
                        "The database instance does not explicitly enable storage encryption.",
                        "Set StorageEncrypted to true and configure KMS encryption.",
                        ["CIS AWS 2.3.1"],
                    ))

            if resource_type in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"}:
                if self._contains_wildcard_iam(properties):
                    findings.append(self._finding(
                        resource,
                        "HIGH",
                        f"{logical_id} contains broad IAM permissions",
                        "An IAM policy document appears to grant wildcard action and resource permissions.",
                        "Scope IAM actions and resources to the minimum required permissions.",
                        ["CIS AWS 1.16"],
                    ))

        return findings

    def _load_cloudformation_yaml(self, yaml_module: Any, text: str) -> Dict[str, Any]:
        """Load CloudFormation YAML while preserving intrinsic functions as data."""
        class CloudFormationLoader(yaml_module.SafeLoader):
            pass

        def construct_intrinsic(loader: Any, tag_suffix: str, node: Any) -> Any:
            key = f"!{tag_suffix}"
            if isinstance(node, yaml_module.ScalarNode):
                return {key: loader.construct_scalar(node)}
            if isinstance(node, yaml_module.SequenceNode):
                return {key: loader.construct_sequence(node)}
            if isinstance(node, yaml_module.MappingNode):
                return {key: loader.construct_mapping(node)}
            return {key: None}

        CloudFormationLoader.add_multi_constructor("!", construct_intrinsic)
        return yaml_module.load(text, Loader=CloudFormationLoader) or {}

    def _contains_wildcard_iam(self, value: Any) -> bool:
        if isinstance(value, dict):
            action = value.get("Action")
            resource = value.get("Resource")
            if self._has_wildcard(action) and self._has_wildcard(resource):
                return True
            return any(self._contains_wildcard_iam(v) for v in value.values())
        if isinstance(value, list):
            return any(self._contains_wildcard_iam(v) for v in value)
        return False

    def _has_wildcard(self, value: Any) -> bool:
        if value == "*":
            return True
        if isinstance(value, list):
            return "*" in value
        return False

    def _scan_kubernetes(self, resource: Dict[str, Any], path: Path, text: str) -> List[Dict[str, Any]]:
        try:
            documents = self._load_kubernetes_documents(path, text)
        except Exception as exc:
            return [self._finding(
                resource,
                "LOW",
                "Kubernetes manifest could not be parsed",
                f"The manifest was identified as Kubernetes YAML/JSON but could not be parsed: {exc}",
                "Validate the Kubernetes manifest before deployment.",
                ["Kubernetes Manifest Hygiene"],
            )]

        findings: List[Dict[str, Any]] = []
        has_workload = False
        has_network_policy = False

        for doc in documents:
            kind = str(doc.get("kind") or "")
            metadata = doc.get("metadata") or {}
            name = str(metadata.get("name") or path.name)
            namespace = str(metadata.get("namespace") or "default")
            spec = doc.get("spec") or {}

            if kind == "NetworkPolicy":
                has_network_policy = True

            if kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}:
                has_workload = True
                pod_spec = self._kubernetes_pod_spec(kind, spec)
                if pod_spec.get("hostNetwork") is True:
                    findings.append(self._finding(
                        resource,
                        "HIGH",
                        f"{kind} {namespace}/{name} uses hostNetwork",
                        "The workload shares the host network namespace, increasing blast radius and bypass risk.",
                        "Disable hostNetwork unless it is strictly required and isolate the workload with policy.",
                        ["Kubernetes Pod Security Standards"],
                    ))
                if pod_spec.get("automountServiceAccountToken") is not False:
                    findings.append(self._finding(
                        resource,
                        "MEDIUM",
                        f"{kind} {namespace}/{name} auto-mounts service account tokens",
                        "The workload does not explicitly disable automatic service account token mounting.",
                        "Set automountServiceAccountToken: false unless the workload needs Kubernetes API access.",
                        ["Kubernetes Least Privilege"],
                    ))

                for container in self._kubernetes_containers(pod_spec):
                    container_name = str(container.get("name") or "container")
                    image = str(container.get("image") or "")
                    security_context = container.get("securityContext") or {}
                    resource_limits = container.get("resources") or {}

                    if security_context.get("privileged") is True:
                        findings.append(self._finding(
                            resource,
                            "CRITICAL",
                            f"{kind} {namespace}/{name} container {container_name} is privileged",
                            "A privileged container can access host-level capabilities and devices.",
                            "Remove privileged: true and grant only the exact Linux capabilities required.",
                            ["Kubernetes Pod Security Standards"],
                        ))
                    if security_context.get("allowPrivilegeEscalation") is True:
                        findings.append(self._finding(
                            resource,
                            "HIGH",
                            f"{kind} {namespace}/{name} allows privilege escalation",
                            "The container can gain more privileges than its parent process.",
                            "Set allowPrivilegeEscalation: false and run with a restricted security context.",
                            ["Kubernetes Pod Security Standards"],
                        ))
                    if security_context.get("runAsNonRoot") is not True:
                        findings.append(self._finding(
                            resource,
                            "MEDIUM",
                            f"{kind} {namespace}/{name} does not enforce non-root execution",
                            "The container security context does not require runAsNonRoot: true.",
                            "Set runAsNonRoot: true and use an image that can run as a non-root user.",
                            ["Kubernetes Pod Security Standards"],
                        ))

                    added_caps = ((security_context.get("capabilities") or {}).get("add") or [])
                    if any(str(cap).upper() in {"ALL", "SYS_ADMIN", "NET_ADMIN"} for cap in added_caps):
                        findings.append(self._finding(
                            resource,
                            "HIGH",
                            f"{kind} {namespace}/{name} adds dangerous Linux capabilities",
                            "The manifest adds broad or host-sensitive Linux capabilities to a container.",
                            "Drop all capabilities by default and add back only narrowly required capabilities.",
                            ["Kubernetes Pod Security Standards"],
                        ))

                    if image.endswith(":latest") or (image and ":" not in image):
                        findings.append(self._finding(
                            resource,
                            "MEDIUM",
                            f"{kind} {namespace}/{name} uses a mutable image tag",
                            "The container image tag is missing or uses latest, making deployments non-reproducible.",
                            "Pin images to immutable versions or digests.",
                            ["Kubernetes Supply Chain"],
                        ))
                    if "limits" not in resource_limits:
                        findings.append(self._finding(
                            resource,
                            "MEDIUM",
                            f"{kind} {namespace}/{name} has no resource limits",
                            "The container does not define CPU/memory limits.",
                            "Set conservative CPU and memory requests/limits for each container.",
                            ["Kubernetes Resource Governance"],
                        ))

            if kind in {"Role", "ClusterRole"}:
                for rule in spec.get("rules") or doc.get("rules") or []:
                    if not isinstance(rule, dict):
                        continue
                    if self._has_wildcard(rule.get("apiGroups")) and self._has_wildcard(rule.get("resources")) and self._has_wildcard(rule.get("verbs")):
                        findings.append(self._finding(
                            resource,
                            "CRITICAL" if kind == "ClusterRole" else "HIGH",
                            f"{kind} {namespace}/{name} grants wildcard RBAC",
                            "The RBAC rule grants wildcard apiGroups, resources, and verbs.",
                            "Replace wildcard RBAC with named resources and the minimum verbs required.",
                            ["Kubernetes RBAC Least Privilege"],
                        ))

            if kind == "Service":
                service_type = str(spec.get("type") or "ClusterIP")
                if service_type == "LoadBalancer":
                    findings.append(self._finding(
                        resource,
                        "HIGH",
                        f"Service {namespace}/{name} is externally load-balanced",
                        "A LoadBalancer service can expose workloads outside the cluster.",
                        "Restrict exposure through ingress controls, private load balancers, and network policy.",
                        ["Kubernetes Network Exposure"],
                    ))
                if service_type == "NodePort":
                    findings.append(self._finding(
                        resource,
                        "MEDIUM",
                        f"Service {namespace}/{name} uses NodePort",
                        "A NodePort service exposes a port on every node in the cluster.",
                        "Prefer ClusterIP plus a controlled ingress or load balancer.",
                        ["Kubernetes Network Exposure"],
                    ))

            if kind == "Secret" and (doc.get("data") or doc.get("stringData")):
                findings.append(self._finding(
                    resource,
                    "HIGH",
                    f"Secret {namespace}/{name} is stored in source-controlled manifest form",
                    "The manifest contains Kubernetes Secret data that can leak through source control or CI logs.",
                    "Use an external secret manager or sealed/encrypted secret workflow.",
                    ["Kubernetes Secret Management"],
                ))

        if has_workload and not has_network_policy:
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "Kubernetes workloads lack a matching NetworkPolicy",
                "The manifest set includes workloads but no NetworkPolicy object to restrict pod traffic.",
                "Add namespace-scoped ingress and egress NetworkPolicies for the deployed workloads.",
                ["Kubernetes Network Segmentation"],
            ))

        return findings

    def _load_kubernetes_documents(self, path: Path, text: str) -> List[Dict[str, Any]]:
        stripped = text.strip()
        if path.suffix.lower() == ".json" or stripped.startswith("{") or stripped.startswith("["):
            data = json.loads(text)
            return self._flatten_kubernetes_documents(data)

        import yaml
        documents: List[Dict[str, Any]] = []
        for doc in yaml.safe_load_all(text):
            documents.extend(self._flatten_kubernetes_documents(doc))
        return documents

    def _flatten_kubernetes_documents(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            documents: List[Dict[str, Any]] = []
            for item in data:
                documents.extend(self._flatten_kubernetes_documents(item))
            return documents
        if isinstance(data, dict):
            if data.get("kind") == "List" and isinstance(data.get("items"), list):
                return self._flatten_kubernetes_documents(data["items"])
            return [data]
        return []

    def _kubernetes_pod_spec(self, kind: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        if kind == "Pod":
            return spec
        if kind == "CronJob":
            return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        return ((spec.get("template") or {}).get("spec") or {})

    def _kubernetes_containers(self, pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        containers: List[Dict[str, Any]] = []
        for key in ("initContainers", "containers"):
            for container in pod_spec.get(key) or []:
                if isinstance(container, dict):
                    containers.append(container)
        return containers

    def _finding(
        self,
        resource: Dict[str, Any],
        severity: str,
        issue: str,
        description: str,
        recommendation: str,
        compliance: List[str],
    ) -> Dict[str, Any]:
        return {
            "resource": resource,
            "severity": severity if severity in Severity.__members__ else "MEDIUM",
            "issue": f"[IAC-SCANNER] {issue}",
            "description": description,
            "recommendation": recommendation,
            "compliance": compliance,
            "detection_tool": "IAC-SCANNER",
            "tool_category": "iac_scan",
        }


def create_iac_server(config: Optional[Dict[str, Any]] = None) -> IaCMCPServer:
    return IaCMCPServer(config or {})
