"""
Kubernetes MCP Server
Scans live Kubernetes clusters from kubeconfig, enriches managed cluster metadata,
and compares live resources against Kubernetes IaC manifests.
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from backend.mcp.mcp_base import Severity
from backend.mcp_servers.base_server import BaseMCPServer, MCPResource, MCPTool, ToolCategory

logger = logging.getLogger("kubernetes_mcp_server")


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

SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
}

DRIFT_KINDS = WORKLOAD_KINDS | {
    "Service",
    "Namespace",
    "NetworkPolicy",
    "RoleBinding",
    "ClusterRoleBinding",
}

CLUSTER_SCOPED_KINDS = {
    "Namespace",
    "ClusterRole",
    "ClusterRoleBinding",
    "PersistentVolume",
    "StorageClass",
}


def build_kubernetes_api_client(kubeconfig: str, context: Optional[str] = None):
    """Build an isolated Kubernetes ApiClient from kubeconfig text."""
    if not kubeconfig:
        raise ValueError("kubeconfig is required")

    import yaml
    from kubernetes import client
    from kubernetes.config.kube_config import KubeConfigLoader

    config_dict = yaml.safe_load(kubeconfig)
    if not isinstance(config_dict, dict):
        raise ValueError("kubeconfig must be a YAML object")

    configuration = client.Configuration()
    loader_kwargs = {"config_dict": config_dict}
    if context:
        loader_kwargs["active_context"] = context
    loader = KubeConfigLoader(**loader_kwargs)
    loader.load_and_set(configuration)
    return client.ApiClient(configuration=configuration)


class KubernetesMCPServer(BaseMCPServer):
    """MCP scanner for live Kubernetes clusters and YAML/JSON manifests."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("kubernetes", config or {})

    def _setup_tools(self) -> None:
        self.register_tool(MCPTool(
            name="kubernetes/discover_manifests",
            description="Discover Kubernetes manifest files in the repository",
            category=ToolCategory.DISCOVERY,
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            handler=self._discover_manifests,
        ))
        self.register_tool(MCPTool(
            name="kubernetes/full_scan",
            description="Scan a live Kubernetes cluster for security risks and IaC drift",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "account_id": {"type": "string"},
                    "path": {"type": "string"},
                    "deep_scan": {"type": "boolean", "default": False},
                    "mode": {"type": "string", "enum": ["live", "manifest"], "default": "live"},
                },
            },
            handler=self._full_scan,
        ))

    def _setup_resources(self) -> None:
        self.register_resource(MCPResource(
            uri="kubernetes://manifests",
            name="Kubernetes Manifests",
            description="Kubernetes manifests discovered in the repository",
            mime_type="application/json",
        ))

    async def _fetch_resource_content(self, uri: str) -> str:
        if uri != "kubernetes://manifests":
            raise ValueError(f"Unknown Kubernetes resource: {uri}")
        return json.dumps(await self._discover_manifests(), indent=2)

    def _root_path(self, requested_path: Optional[str] = None) -> Path:
        configured = requested_path or self.config.get("root_path") or os.getcwd()
        path = Path(configured)
        if not path.is_absolute():
            path = Path(os.getcwd()) / path
        return path.resolve()

    async def _discover_manifests(self, path: Optional[str] = None) -> Dict[str, Any]:
        root = self._root_path(path)
        files = [str(p) for p in self._iter_candidate_files(root) if self._looks_like_kubernetes_file(p)]
        return {"root": str(root), "count": len(files), "files": files}

    async def _full_scan(
        self,
        account_id: str = "repository",
        path: Optional[str] = None,
        deep_scan: bool = False,
        mode: str = "live",
        **_: Any,
    ) -> Dict[str, Any]:
        if mode != "manifest" and self.config.get("kubeconfig"):
            return await self._full_live_scan(account_id=account_id, path=path, deep_scan=deep_scan)
        if mode == "live":
            return self._missing_kubeconfig_result(account_id)
        return await self._full_manifest_scan(account_id=account_id, path=path, deep_scan=deep_scan)

    async def _full_manifest_scan(
        self,
        account_id: str = "repository",
        path: Optional[str] = None,
        deep_scan: bool = False,
    ) -> Dict[str, Any]:
        started = time.time()
        root = self._root_path(path)
        manifest_documents = self._load_manifest_documents(root)

        resources: List[Dict[str, Any]] = [{
            "provider": "kubernetes",
            "resource_type": "manifest_workspace",
            "name": root.name or "repository",
            "region": "local",
            "config": {
                "root": str(root),
                "files_scanned": len({str(path) for path, _ in manifest_documents}),
                "deep_scan": deep_scan,
            },
            "is_public": False,
        }]
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        for manifest_file, document in manifest_documents:
            try:
                resource = self._resource_from_manifest(manifest_file, document)
                resources.append(resource)
                findings.extend(self._scan_manifest(resource, document))
            except Exception as exc:
                logger.warning("Failed to scan Kubernetes manifest %s: %s", manifest_file, exc)
                errors.append(f"{manifest_file}: {exc}")

        if len(resources) == 1:
            findings.append(self._finding(
                resources[0],
                "INFO",
                "No Kubernetes manifests found",
                "The Kubernetes scanner ran successfully but did not find Kubernetes manifests in the deployment workspace.",
                "Add Kubernetes YAML/JSON manifests under k8s, kubernetes, manifests, charts, helm, or the repository root to include them in scans.",
            ))

        return {
            "provider": "kubernetes",
            "account_id": account_id or "repository",
            "resources": resources,
            "findings": findings,
            "scan_duration": round(time.time() - started, 3),
            "errors": errors,
            "summary": {
                "scan_mode": "manifest",
                "files_scanned": len({str(path) for path, _ in manifest_documents}),
                "resources": max(len(resources) - 1, 0),
                "findings": len(findings),
            },
        }

    async def _full_live_scan(
        self,
        account_id: str = "cluster",
        path: Optional[str] = None,
        deep_scan: bool = False,
    ) -> Dict[str, Any]:
        started = time.time()
        errors: List[str] = []
        resources: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        live_documents: List[Dict[str, Any]] = []

        root = self._root_path(path)
        managed_metadata = self._managed_cluster_metadata()
        cluster_name = (
            self.config.get("cluster_name")
            or managed_metadata.get("cluster_name")
            or self.config.get("context")
            or account_id
            or "cluster"
        )
        cluster_resource = {
            "provider": "kubernetes",
            "resource_type": "cluster",
            "name": cluster_name,
            "region": managed_metadata.get("location") or managed_metadata.get("region") or "live",
            "config": {
                "context": self.config.get("context"),
                "cluster_name": cluster_name,
                "deep_scan": deep_scan,
                "scan_mode": "live",
                "managed_provider": managed_metadata.get("provider"),
                "managed_api_detected": bool(managed_metadata.get("provider")),
            },
            "is_public": False,
        }
        resources.append(cluster_resource)

        try:
            from kubernetes import client

            api_client = build_kubernetes_api_client(
                self.config.get("kubeconfig"),
                self.config.get("context"),
            )
            core = client.CoreV1Api(api_client)
            apps = client.AppsV1Api(api_client)
            batch = client.BatchV1Api(api_client)
            rbac = client.RbacAuthorizationV1Api(api_client)
            networking = client.NetworkingV1Api(api_client)
        except Exception as exc:
            return {
                "provider": "kubernetes",
                "account_id": account_id or cluster_name,
                "resources": resources,
                "findings": [self._finding(
                    cluster_resource,
                    "HIGH",
                    "Kubernetes kubeconfig could not be loaded",
                    f"The saved kubeconfig could not be used to create a Kubernetes client: {exc}",
                    "Verify the kubeconfig YAML, selected context, embedded certificates/tokens, and that it does not depend on a local exec auth plugin unavailable in Vercel.",
                )],
                "scan_duration": round(time.time() - started, 3),
                "errors": [str(exc)],
                "summary": {"scan_mode": "live", "resources": 0, "findings": 1, "partial_errors": 1},
            }

        def record_error(scope: str, exc: Exception) -> None:
            message = f"{scope}: {exc}"
            logger.warning("Kubernetes live scan partial failure: %s", message)
            errors.append(message)

        def add_document(document: Dict[str, Any]) -> None:
            live_documents.append(document)
            resource = self._resource_from_live_document(document)
            resources.append(resource)
            findings.extend(self._scan_manifest(resource, document))

        list_calls = [
            ("namespaces", lambda: core.list_namespace().items),
            ("pods", lambda: core.list_pod_for_all_namespaces().items),
            ("services", lambda: core.list_service_for_all_namespaces().items),
            ("secrets", lambda: core.list_secret_for_all_namespaces().items),
            ("deployments", lambda: apps.list_deployment_for_all_namespaces().items),
            ("statefulsets", lambda: apps.list_stateful_set_for_all_namespaces().items),
            ("daemonsets", lambda: apps.list_daemon_set_for_all_namespaces().items),
            ("jobs", lambda: batch.list_job_for_all_namespaces().items),
            ("cronjobs", lambda: batch.list_cron_job_for_all_namespaces().items),
            ("network_policies", lambda: networking.list_network_policy_for_all_namespaces().items),
            ("cluster_role_bindings", lambda: rbac.list_cluster_role_binding().items),
            ("role_bindings", lambda: rbac.list_role_binding_for_all_namespaces().items),
        ]

        for scope, loader in list_calls:
            try:
                for item in loader():
                    add_document(api_client.sanitize_for_serialization(item))
            except Exception as exc:
                record_error(scope, exc)

        findings.extend(self._scan_network_policy_coverage(live_documents))

        managed_resources, managed_findings, managed_status = self._query_managed_cluster_api(
            cluster_resource,
            managed_metadata,
        )
        resources.extend(managed_resources)
        findings.extend(managed_findings)

        drift_result = self._compare_live_to_iac(root, live_documents)
        resources.append(drift_result["resource"])
        findings.extend(drift_result["findings"])

        if len(resources) == 2 and errors:
            findings.append(self._finding(
                cluster_resource,
                "HIGH",
                "Kubernetes API access is insufficient",
                "The kubeconfig connected to the cluster, but the scanner could not list the required Kubernetes resources.",
                "Grant the scanner service account read-only list/get permissions for namespaces, pods, workloads, services, secrets metadata, NetworkPolicies, and RBAC bindings.",
            ))
        elif len(resources) == 2:
            findings.append(self._finding(
                cluster_resource,
                "INFO",
                "No Kubernetes resources discovered",
                "The live cluster scan completed but did not discover namespaces, workloads, services, NetworkPolicies, or RBAC bindings.",
                "Confirm the kubeconfig context points to the expected cluster and namespace scope.",
            ))

        kind_counts = self._kind_counts(live_documents)
        return {
            "provider": "kubernetes",
            "account_id": account_id or cluster_name,
            "resources": resources,
            "findings": findings,
            "scan_duration": round(time.time() - started, 3),
            "errors": errors,
            "summary": {
                "scan_mode": "live",
                "resources": max(len(resources) - 2, 0),
                "findings": len(findings),
                "partial_errors": len(errors),
                "namespaces": kind_counts.get("Namespace", 0),
                "network_policies": kind_counts.get("NetworkPolicy", 0),
                "managed_cluster_api": managed_status,
                "iac_drift": drift_result["summary"],
            },
        }

    def _missing_kubeconfig_result(self, account_id: str) -> Dict[str, Any]:
        resource = {
            "provider": "kubernetes",
            "resource_type": "cluster",
            "name": account_id or "cluster",
            "region": "live",
            "config": {"scan_mode": "live"},
            "is_public": False,
        }
        return {
            "provider": "kubernetes",
            "account_id": account_id or "cluster",
            "resources": [resource],
            "findings": [self._finding(
                resource,
                "HIGH",
                "Kubernetes kubeconfig is required",
                "Live Kubernetes scanning requires a saved kubeconfig credential.",
                "Open Manage Credentials, add a Kubernetes kubeconfig, and retry the scan.",
            )],
            "scan_duration": 0.0,
            "errors": ["kubeconfig is required for live scanning"],
            "summary": {"scan_mode": "live", "resources": 0, "findings": 1},
        }

    def _iter_candidate_files(self, root: Path) -> Iterable[Path]:
        if root.is_file():
            yield root
            return

        preferred_dirs = [
            root / "k8s",
            root / "kubernetes",
            root / "manifests",
            root / "charts",
            root / "helm",
            root,
        ]
        seen: Set[Path] = set()
        for base in preferred_dirs:
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if path in seen or not path.is_file():
                    continue
                if any(part in EXCLUDED_DIRS for part in path.parts):
                    continue
                if path.suffix.lower() in {".yaml", ".yml", ".json"}:
                    seen.add(path)
                    yield path

    def _looks_like_kubernetes_file(self, path: Path) -> bool:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
        return ("apiVersion:" in text and "kind:" in text) or ('"apiVersion"' in text and '"kind"' in text)

    def _load_documents(self, path: Path) -> List[Any]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix.lower() == ".json":
            data = json.loads(text)
            return data if isinstance(data, list) else [data]

        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required for Kubernetes YAML scanning") from exc

        return list(yaml.safe_load_all(text))

    def _load_manifest_documents(self, root: Path) -> List[Tuple[Path, Dict[str, Any]]]:
        documents: List[Tuple[Path, Dict[str, Any]]] = []
        for manifest_file in self._iter_candidate_files(root):
            if not self._looks_like_kubernetes_file(manifest_file):
                continue
            try:
                for document in self._load_documents(manifest_file):
                    if not isinstance(document, dict):
                        continue
                    if document.get("kind") and document.get("apiVersion"):
                        documents.append((manifest_file, document))
            except Exception as exc:
                logger.warning("Failed to parse Kubernetes manifest %s: %s", manifest_file, exc)
        return documents

    def _resource_from_manifest(self, path: Path, document: Dict[str, Any]) -> Dict[str, Any]:
        metadata = document.get("metadata") or {}
        kind = document.get("kind", "Unknown")
        namespace = self._document_namespace(document)
        name = metadata.get("name", path.stem)
        return {
            "provider": "kubernetes",
            "resource_type": kind.lower(),
            "name": f"{namespace}/{kind}/{name}",
            "region": "cluster",
            "config": {
                "file": str(path),
                "apiVersion": document.get("apiVersion"),
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "scan_mode": "manifest",
            },
            "is_public": kind == "Service" and (document.get("spec") or {}).get("type") == "LoadBalancer",
        }

    def _resource_from_live_document(self, document: Dict[str, Any]) -> Dict[str, Any]:
        metadata = document.get("metadata") or {}
        kind = document.get("kind", "Unknown")
        namespace = self._document_namespace(document)
        name = metadata.get("name", "unnamed")
        return {
            "provider": "kubernetes",
            "resource_type": kind.lower(),
            "name": f"{namespace}/{kind}/{name}",
            "region": "cluster",
            "config": {
                "apiVersion": document.get("apiVersion"),
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "labels": metadata.get("labels") or {},
                "scan_mode": "live",
            },
            "is_public": kind == "Service" and (document.get("spec") or {}).get("type") == "LoadBalancer",
        }

    def _scan_manifest(self, resource: Dict[str, Any], document: Dict[str, Any]) -> List[Dict[str, Any]]:
        kind = document.get("kind")
        findings: List[Dict[str, Any]] = []

        if kind in WORKLOAD_KINDS:
            findings.extend(self._scan_workload(resource, document))
        elif kind == "Service":
            findings.extend(self._scan_service(resource, document))
        elif kind in {"ClusterRoleBinding", "RoleBinding"}:
            findings.extend(self._scan_binding(resource, document))
        elif kind == "Namespace":
            findings.extend(self._scan_namespace(resource, document))
        elif kind == "NetworkPolicy":
            findings.extend(self._scan_network_policy(resource, document))
        elif kind == "Secret" and (resource.get("config") or {}).get("scan_mode") == "manifest":
            findings.append(self._finding(
                resource,
                "LOW",
                "Kubernetes Secret stored in IaC",
                "A Kubernetes Secret manifest is present in source-controlled IaC. Secret data may be base64 encoded but is not encrypted by default.",
                "Store secrets in an external secret manager or use sealed/encrypted secrets before committing manifests.",
            ))

        return findings

    def _scan_workload(self, resource: Dict[str, Any], document: Dict[str, Any]) -> List[Dict[str, Any]]:
        pod_spec = self._pod_spec(document)
        findings: List[Dict[str, Any]] = []
        if not pod_spec:
            return findings

        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(field) is True:
                findings.append(self._finding(
                    resource,
                    "HIGH",
                    f"{field} enabled",
                    f"The pod spec enables {field}, which weakens workload isolation.",
                    f"Disable {field} unless the workload has a documented platform-level requirement.",
                ))

        if pod_spec.get("automountServiceAccountToken") is not False:
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "Service account token auto-mount is enabled",
                "Pods can receive a Kubernetes API token by default, increasing blast radius if the workload is compromised.",
                "Set automountServiceAccountToken: false or bind a least-privilege service account only when needed.",
            ))

        containers = list(pod_spec.get("containers") or []) + list(pod_spec.get("initContainers") or [])
        for container in containers:
            findings.extend(self._scan_container(resource, container))

        return findings

    def _pod_spec(self, document: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kind = document.get("kind")
        spec = document.get("spec") or {}
        if kind == "Pod":
            return spec
        if kind == "CronJob":
            return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
        if kind == "Job":
            return ((spec.get("template") or {}).get("spec") or {})
        return ((spec.get("template") or {}).get("spec") or {})

    def _scan_container(self, resource: Dict[str, Any], container: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        name = container.get("name", "container")
        image = container.get("image", "")
        security_context = container.get("securityContext") or {}

        if image.endswith(":latest") or ":" not in image.split("/")[-1]:
            findings.append(self._finding(
                resource,
                "MEDIUM",
                f"{name} uses an unpinned image tag",
                f"Container image '{image or 'unknown'}' is not pinned to an immutable version.",
                "Use explicit immutable tags or image digests for production workloads.",
            ))

        if security_context.get("privileged") is True:
            findings.append(self._finding(
                resource,
                "CRITICAL",
                f"{name} runs privileged",
                "Privileged containers can access host devices and bypass major container isolation controls.",
                "Remove privileged: true and grant only the exact capabilities the workload needs.",
            ))

        if security_context.get("allowPrivilegeEscalation") is not False:
            findings.append(self._finding(
                resource,
                "MEDIUM",
                f"{name} can escalate privileges",
                "allowPrivilegeEscalation is not explicitly disabled for this container.",
                "Set allowPrivilegeEscalation: false in the container securityContext.",
            ))

        if security_context.get("runAsNonRoot") is not True:
            findings.append(self._finding(
                resource,
                "MEDIUM",
                f"{name} does not enforce non-root execution",
                "The container does not explicitly require a non-root user.",
                "Set runAsNonRoot: true and use a non-root image user.",
            ))

        capabilities = ((security_context.get("capabilities") or {}).get("add") or [])
        risky_caps = sorted({cap for cap in capabilities if cap in {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}})
        if risky_caps:
            findings.append(self._finding(
                resource,
                "HIGH",
                f"{name} adds risky Linux capabilities",
                f"The container adds high-risk capabilities: {', '.join(risky_caps)}.",
                "Drop all capabilities by default and add only the minimum required capability set.",
            ))

        resources = container.get("resources") or {}
        if not resources.get("requests") or not resources.get("limits"):
            findings.append(self._finding(
                resource,
                "LOW",
                f"{name} is missing resource requests or limits",
                "Missing CPU/memory requests or limits can cause noisy-neighbor issues and makes denial-of-service harder to contain.",
                "Define CPU and memory requests and limits for each container.",
            ))

        if security_context.get("readOnlyRootFilesystem") is not True:
            findings.append(self._finding(
                resource,
                "LOW",
                f"{name} root filesystem is writable",
                "A writable root filesystem gives attackers more room to persist tools after compromise.",
                "Set readOnlyRootFilesystem: true and mount explicit writable volumes where required.",
            ))

        return findings

    def _scan_service(self, resource: Dict[str, Any], document: Dict[str, Any]) -> List[Dict[str, Any]]:
        service_type = (document.get("spec") or {}).get("type", "ClusterIP")
        if service_type == "LoadBalancer":
            return [self._finding(
                resource,
                "MEDIUM",
                "Service exposes an external load balancer",
                "The service is configured as type LoadBalancer, which may expose the workload publicly.",
                "Confirm this exposure is required and restrict ingress with network policies, firewall rules, and authentication.",
            )]
        if service_type == "NodePort":
            return [self._finding(
                resource,
                "LOW",
                "Service exposes a node port",
                "NodePort services expose a port on every node and can expand the reachable attack surface.",
                "Prefer ClusterIP behind an ingress/controller or restrict node access at the network layer.",
            )]
        return []

    def _scan_binding(self, resource: Dict[str, Any], document: Dict[str, Any]) -> List[Dict[str, Any]]:
        role_ref = document.get("roleRef") or {}
        if role_ref.get("kind") == "ClusterRole" and role_ref.get("name") == "cluster-admin":
            return [self._finding(
                resource,
                "CRITICAL",
                "Binding grants cluster-admin",
                "This RBAC binding grants full cluster-admin permissions.",
                "Replace cluster-admin with a narrowly scoped Role or ClusterRole.",
            )]
        return []

    def _scan_namespace(self, resource: Dict[str, Any], document: Dict[str, Any]) -> List[Dict[str, Any]]:
        metadata = document.get("metadata") or {}
        name = metadata.get("name", "unknown")
        labels = metadata.get("labels") or {}
        if self._is_system_namespace(name):
            return []

        enforce = labels.get("pod-security.kubernetes.io/enforce")
        if enforce not in {"baseline", "restricted"}:
            return [self._finding(
                resource,
                "MEDIUM",
                "Namespace lacks Pod Security enforcement",
                f"Namespace '{name}' does not enforce baseline or restricted Pod Security Standards.",
                "Label the namespace with pod-security.kubernetes.io/enforce=baseline or restricted, then handle documented exceptions explicitly.",
            )]
        return []

    def _scan_network_policy(self, resource: Dict[str, Any], document: Dict[str, Any]) -> List[Dict[str, Any]]:
        spec = document.get("spec") or {}
        findings: List[Dict[str, Any]] = []
        policy_types = set(spec.get("policyTypes") or [])
        ingress_rules = spec.get("ingress") or []
        egress_rules = spec.get("egress") or []

        if "Egress" not in policy_types:
            findings.append(self._finding(
                resource,
                "LOW",
                "NetworkPolicy does not restrict egress",
                "The policy does not include Egress in policyTypes, so selected pods may still initiate unrestricted outbound connections.",
                "Add explicit egress policy rules for required destinations and include Egress in policyTypes.",
            ))

        for rule in ingress_rules + egress_rules:
            for peer in rule.get("from", []) + rule.get("to", []):
                cidr = (peer.get("ipBlock") or {}).get("cidr")
                if cidr in {"0.0.0.0/0", "::/0"}:
                    findings.append(self._finding(
                        resource,
                        "MEDIUM",
                        "NetworkPolicy allows all IP ranges",
                        f"The policy includes an unrestricted IP block ({cidr}).",
                        "Restrict ipBlock CIDRs to the smallest required ranges.",
                    ))
                    return findings

        if not ingress_rules and not egress_rules:
            return findings
        return findings

    def _scan_network_policy_coverage(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        namespace_resources: Dict[str, Dict[str, Any]] = {}
        workload_namespaces: Set[str] = set()
        policy_namespaces: Set[str] = set()

        for document in documents:
            kind = document.get("kind")
            metadata = document.get("metadata") or {}
            if kind == "Namespace":
                name = metadata.get("name")
                if name:
                    namespace_resources[name] = self._resource_from_live_document(document)
            elif kind in WORKLOAD_KINDS:
                namespace = self._document_namespace(document)
                if not self._is_system_namespace(namespace):
                    workload_namespaces.add(namespace)
            elif kind == "NetworkPolicy":
                namespace = self._document_namespace(document)
                if not self._is_system_namespace(namespace):
                    policy_namespaces.add(namespace)

        findings: List[Dict[str, Any]] = []
        for namespace in sorted(workload_namespaces - policy_namespaces):
            resource = namespace_resources.get(namespace) or {
                "provider": "kubernetes",
                "resource_type": "namespace",
                "name": f"cluster/Namespace/{namespace}",
                "region": "cluster",
                "config": {"namespace": namespace, "scan_mode": "live"},
                "is_public": False,
            }
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "Namespace has workloads without NetworkPolicy",
                f"Namespace '{namespace}' contains workloads but no NetworkPolicy was discovered.",
                "Add default-deny ingress and egress NetworkPolicies, then allow only the required traffic paths.",
            ))
        return findings

    def _query_managed_cluster_api(
        self,
        cluster_resource: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        provider = metadata.get("provider")
        if not provider:
            return [], [], {"provider": None, "queried": False, "reason": "not_detected"}

        try:
            if provider == "eks":
                return self._query_eks_api(cluster_resource, metadata)
            if provider == "gke":
                return self._query_gke_api(cluster_resource, metadata)
        except Exception as exc:
            logger.warning("Managed Kubernetes API query failed for %s: %s", provider, exc)
            return [], [self._finding(
                cluster_resource,
                "LOW",
                f"{provider.upper()} management API query failed",
                f"The live Kubernetes scan completed, but CloudGuard could not query the {provider.upper()} management API: {exc}",
                f"Verify the saved cloud credentials have read access to the {provider.upper()} cluster metadata API.",
            )], {"provider": provider, "queried": False, "error": str(exc)}

        return [], [], {"provider": provider, "queried": False, "reason": "unsupported"}

    def _query_eks_api(
        self,
        cluster_resource: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        aws_config = self.config.get("aws") or {}
        cluster_name = metadata.get("cluster_name")
        region = metadata.get("region") or aws_config.get("region") or "us-east-1"
        if not cluster_name:
            return [], [], {"provider": "eks", "queried": False, "reason": "cluster_name_unknown"}
        if not aws_config.get("access_key_id") or not aws_config.get("secret_access_key"):
            return [], [self._cloud_credential_missing_finding(cluster_resource, "EKS", "AWS")], {
                "provider": "eks",
                "queried": False,
                "reason": "missing_aws_credentials",
            }

        import boto3

        session = boto3.Session(
            aws_access_key_id=aws_config.get("access_key_id"),
            aws_secret_access_key=aws_config.get("secret_access_key"),
            aws_session_token=aws_config.get("session_token"),
            region_name=region,
        )
        if aws_config.get("role_arn"):
            sts = session.client("sts")
            assumed = sts.assume_role(
                RoleArn=aws_config["role_arn"],
                RoleSessionName="cloudguard-kubernetes-management",
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=assumed["AccessKeyId"],
                aws_secret_access_key=assumed["SecretAccessKey"],
                aws_session_token=assumed["SessionToken"],
                region_name=region,
            )

        cluster = session.client("eks", region_name=region).describe_cluster(name=cluster_name)["cluster"]
        resource = self._managed_cluster_resource("eks", metadata, cluster)
        findings = self._scan_eks_cluster(resource, cluster)
        return [resource], findings, {"provider": "eks", "queried": True, "region": region}

    def _query_gke_api(
        self,
        cluster_resource: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        gcp_config = self.config.get("gcp") or {}
        if not gcp_config.get("service_account_json"):
            return [], [self._cloud_credential_missing_finding(cluster_resource, "GKE", "GCP")], {
                "provider": "gke",
                "queried": False,
                "reason": "missing_gcp_credentials",
            }

        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        service_account_info = json.loads(gcp_config["service_account_json"])
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        project = metadata.get("project") or gcp_config.get("project_id") or service_account_info.get("project_id")
        cluster_name = metadata.get("cluster_name")
        location = metadata.get("location") or "-"
        if not project or not cluster_name:
            return [], [], {"provider": "gke", "queried": False, "reason": "project_or_cluster_unknown"}

        service = build("container", "v1", credentials=credentials, cache_discovery=False)
        parent = f"projects/{project}/locations/{location}"
        if location == "-":
            clusters = service.projects().locations().clusters().list(parent=parent).execute().get("clusters", [])
            cluster = next((item for item in clusters if item.get("name") == cluster_name), None)
            if not cluster:
                return [], [], {"provider": "gke", "queried": False, "reason": "cluster_not_found"}
        else:
            cluster = service.projects().locations().clusters().get(
                name=f"{parent}/clusters/{cluster_name}"
            ).execute()

        resource = self._managed_cluster_resource("gke", metadata, cluster)
        findings = self._scan_gke_cluster(resource, cluster)
        return [resource], findings, {"provider": "gke", "queried": True, "project": project, "location": location}

    def _cloud_credential_missing_finding(
        self,
        cluster_resource: Dict[str, Any],
        managed_provider: str,
        cloud_provider: str,
    ) -> Dict[str, Any]:
        return self._finding(
            cluster_resource,
            "INFO",
            f"{managed_provider} management API credentials unavailable",
            f"The kubeconfig identifies this as a {managed_provider} cluster, but no default {cloud_provider} credential is available for management API enrichment.",
            f"Add a default {cloud_provider} credential with read access to the cluster metadata API to include managed-control-plane checks.",
        )

    def _managed_cluster_resource(
        self,
        provider: str,
        metadata: Dict[str, Any],
        cluster: Dict[str, Any],
    ) -> Dict[str, Any]:
        name = (
            cluster.get("name")
            or metadata.get("cluster_name")
            or cluster.get("id", "").split("/")[-1]
            or provider
        )
        config = self._redact_cluster_metadata(provider, cluster)
        config.update({
            "managed_provider": provider,
            "detected_from": metadata.get("detected_from"),
            "management_api_queried": True,
        })
        return {
            "provider": "kubernetes",
            "resource_type": f"{provider}_managed_cluster",
            "name": name,
            "region": metadata.get("location") or metadata.get("region") or cluster.get("location") or "managed",
            "config": config,
            "is_public": self._managed_cluster_public(provider, cluster),
        }

    def _scan_eks_cluster(self, resource: Dict[str, Any], cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        vpc_config = cluster.get("resourcesVpcConfig") or {}
        if vpc_config.get("endpointPublicAccess") is True:
            cidrs = vpc_config.get("publicAccessCidrs") or []
            severity = "HIGH" if "0.0.0.0/0" in cidrs else "MEDIUM"
            findings.append(self._finding(
                resource,
                severity,
                "EKS public API endpoint is enabled",
                "The EKS control-plane endpoint is reachable from public networks.",
                "Disable public endpoint access or restrict publicAccessCidrs to trusted administrative networks.",
            ))

        enabled_logs = set()
        for log_cfg in (cluster.get("logging") or {}).get("clusterLogging") or []:
            if log_cfg.get("enabled"):
                enabled_logs.update(log_cfg.get("types") or [])
        missing_logs = {"api", "audit", "authenticator"} - enabled_logs
        if missing_logs:
            findings.append(self._finding(
                resource,
                "LOW",
                "EKS control-plane logging is incomplete",
                f"Missing recommended EKS log types: {', '.join(sorted(missing_logs))}.",
                "Enable EKS API, audit, authenticator, controllerManager, and scheduler logs for security investigations.",
            ))
        return findings

    def _scan_gke_cluster(self, resource: Dict[str, Any], cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if (cluster.get("legacyAbac") or {}).get("enabled"):
            findings.append(self._finding(
                resource,
                "HIGH",
                "GKE legacy ABAC is enabled",
                "Legacy ABAC grants broad Kubernetes API permissions and bypasses modern RBAC controls.",
                "Disable legacy ABAC and rely on Kubernetes RBAC with least-privilege roles.",
            ))

        master_auth = cluster.get("masterAuthorizedNetworksConfig") or {}
        if not master_auth.get("enabled"):
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "GKE master authorized networks are disabled",
                "The GKE control plane is not restricted by master authorized networks.",
                "Enable master authorized networks or use private endpoint access for administration.",
            ))

        network_policy = cluster.get("networkPolicy") or {}
        if not network_policy.get("enabled"):
            findings.append(self._finding(
                resource,
                "MEDIUM",
                "GKE NetworkPolicy is disabled",
                "The GKE cluster does not have NetworkPolicy enforcement enabled at the cluster level.",
                "Enable NetworkPolicy on the cluster and deploy namespace-level default-deny policies.",
            ))
        return findings

    def _compare_live_to_iac(self, root: Path, live_documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        manifest_documents = self._load_manifest_documents(root)
        drift_resource = {
            "provider": "kubernetes",
            "resource_type": "iac_drift_report",
            "name": root.name or "repository",
            "region": "local",
            "config": {
                "root": str(root),
                "scan_mode": "live_vs_iac",
            },
            "is_public": False,
        }

        live_index: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        manifest_index: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        manifest_files: Dict[Tuple[str, str, str], str] = {}

        for document in live_documents:
            key = self._resource_key(document)
            if key and key[0] in DRIFT_KINDS and not self._is_system_namespace(key[1]):
                live_index[key] = document

        for path, document in manifest_documents:
            key = self._resource_key(document)
            if key and key[0] in DRIFT_KINDS and not self._is_system_namespace(key[1]):
                manifest_index[key] = document
                manifest_files[key] = str(path)

        live_keys = set(live_index)
        manifest_keys = set(manifest_index)
        live_only = sorted(live_keys - manifest_keys)
        manifest_only = sorted(manifest_keys - live_keys)
        mismatches = []

        for key in sorted(live_keys & manifest_keys):
            live_snapshot = self._posture_snapshot(live_index[key])
            manifest_snapshot = self._posture_snapshot(manifest_index[key])
            if live_snapshot != manifest_snapshot:
                mismatches.append({
                    "resource": self._resource_label(key),
                    "file": manifest_files.get(key),
                    "changed_fields": self._changed_snapshot_fields(live_snapshot, manifest_snapshot),
                })

        summary = {
            "manifest_files": len({path for path, _ in manifest_documents}),
            "manifest_resources": len(manifest_index),
            "live_resources_compared": len(live_index),
            "live_only": len(live_only),
            "manifest_only": len(manifest_only),
            "spec_mismatches": len(mismatches),
        }
        drift_resource["config"].update(summary)
        drift_resource["config"]["sample_live_only"] = [self._resource_label(key) for key in live_only[:20]]
        drift_resource["config"]["sample_manifest_only"] = [self._resource_label(key) for key in manifest_only[:20]]
        drift_resource["config"]["sample_mismatches"] = mismatches[:20]

        findings: List[Dict[str, Any]] = []
        if not manifest_documents and live_index:
            findings.append(self._finding(
                drift_resource,
                "INFO",
                "No Kubernetes IaC manifests found for drift comparison",
                "CloudGuard queried live Kubernetes resources, but no Kubernetes YAML/JSON manifests were found in the repository to compare against.",
                "Add Kubernetes manifests or rendered Helm output to the repository so live resources can be checked for drift.",
            ))

        for key in live_only[:10]:
            findings.append(self._finding(
                drift_resource,
                "MEDIUM",
                "Live Kubernetes resource is not declared in IaC",
                f"{self._resource_label(key)} exists in the cluster but was not found in repository Kubernetes manifests.",
                "Confirm whether this resource is expected. If yes, add it to IaC; if not, remove it from the cluster.",
            ))

        for key in manifest_only[:10]:
            findings.append(self._finding(
                drift_resource,
                "LOW",
                "IaC resource is not deployed",
                f"{self._resource_label(key)} exists in repository Kubernetes manifests but was not found in the live cluster.",
                "Apply the manifest or remove stale IaC to keep deployed infrastructure aligned with source control.",
            ))

        for mismatch in mismatches[:10]:
            findings.append(self._finding(
                drift_resource,
                "MEDIUM",
                "Live Kubernetes resource differs from IaC",
                f"{mismatch['resource']} differs from its manifest in: {', '.join(mismatch['changed_fields'])}.",
                "Reconcile the live resource with IaC, then redeploy from source control.",
            ))

        return {"resource": drift_resource, "findings": findings, "summary": summary}

    def _posture_snapshot(self, document: Dict[str, Any]) -> Dict[str, Any]:
        kind = document.get("kind")
        metadata = document.get("metadata") or {}
        spec = document.get("spec") or {}

        if kind == "Service":
            return {
                "type": spec.get("type", "ClusterIP"),
                "selector": spec.get("selector") or {},
                "ports": sorted([
                    {
                        "port": port.get("port"),
                        "targetPort": port.get("targetPort"),
                        "protocol": port.get("protocol", "TCP"),
                    }
                    for port in spec.get("ports") or []
                ], key=lambda item: str(item)),
            }

        if kind in WORKLOAD_KINDS:
            pod_spec = self._pod_spec(document) or {}
            containers = []
            for container in list(pod_spec.get("containers") or []) + list(pod_spec.get("initContainers") or []):
                security_context = container.get("securityContext") or {}
                containers.append({
                    "name": container.get("name"),
                    "image": container.get("image"),
                    "privileged": security_context.get("privileged"),
                    "allowPrivilegeEscalation": security_context.get("allowPrivilegeEscalation"),
                    "runAsNonRoot": security_context.get("runAsNonRoot"),
                    "readOnlyRootFilesystem": security_context.get("readOnlyRootFilesystem"),
                })
            return {
                "replicas": spec.get("replicas"),
                "hostNetwork": pod_spec.get("hostNetwork"),
                "hostPID": pod_spec.get("hostPID"),
                "hostIPC": pod_spec.get("hostIPC"),
                "automountServiceAccountToken": pod_spec.get("automountServiceAccountToken"),
                "serviceAccountName": pod_spec.get("serviceAccountName"),
                "containers": sorted(containers, key=lambda item: str(item.get("name"))),
            }

        if kind == "NetworkPolicy":
            return {
                "podSelector": spec.get("podSelector") or {},
                "policyTypes": sorted(spec.get("policyTypes") or []),
                "hasIngress": "ingress" in spec,
                "hasEgress": "egress" in spec,
            }

        if kind == "Namespace":
            labels = metadata.get("labels") or {}
            return {
                "pod-security-enforce": labels.get("pod-security.kubernetes.io/enforce"),
                "pod-security-audit": labels.get("pod-security.kubernetes.io/audit"),
                "pod-security-warn": labels.get("pod-security.kubernetes.io/warn"),
            }

        if kind in {"ClusterRoleBinding", "RoleBinding"}:
            return {
                "roleRef": document.get("roleRef") or {},
                "subjects": sorted(document.get("subjects") or [], key=lambda item: str(item)),
            }

        return {"apiVersion": document.get("apiVersion"), "kind": kind}

    def _changed_snapshot_fields(self, live: Dict[str, Any], manifest: Dict[str, Any]) -> List[str]:
        changed = sorted({key for key in set(live) | set(manifest) if live.get(key) != manifest.get(key)})
        return changed or ["resource posture"]

    def _managed_cluster_metadata(self) -> Dict[str, Any]:
        kubeconfig = self._kubeconfig_dict()
        context_name, cluster_name, cluster_entry = self._active_kubeconfig_cluster(kubeconfig)
        cluster_body = (cluster_entry or {}).get("cluster") or {}
        server = cluster_body.get("server", "")
        candidates = [
            self.config.get("cluster_name"),
            self.config.get("context"),
            context_name,
            cluster_name,
            server,
        ]
        candidates = [candidate for candidate in candidates if candidate]

        for candidate in candidates:
            match = re.search(r"arn:aws[^:]*:eks:([^:]+):(\d+):cluster/([^/\s]+)", candidate)
            if match:
                return {
                    "provider": "eks",
                    "region": match.group(1),
                    "account_id": match.group(2),
                    "cluster_name": match.group(3),
                    "detected_from": "kubeconfig_arn",
                }

        if "eks.amazonaws.com" in server:
            region_match = re.search(r"\.([a-z]{2}-[a-z]+-\d)\.eks\.amazonaws\.com", server)
            return {
                "provider": "eks",
                "region": region_match.group(1) if region_match else None,
                "cluster_name": self.config.get("cluster_name") or cluster_name or context_name,
                "detected_from": "kubeconfig_server",
            }

        for candidate in candidates:
            match = re.search(r"(?:^|/)gke_([^_]+)_([^_]+)_(.+)$", candidate)
            if match:
                return {
                    "provider": "gke",
                    "project": match.group(1),
                    "location": match.group(2),
                    "cluster_name": match.group(3),
                    "detected_from": "kubeconfig_context",
                }

        if "container.googleapis.com" in server:
            return {
                "provider": "gke",
                "cluster_name": self.config.get("cluster_name") or cluster_name or context_name,
                "detected_from": "kubeconfig_server",
            }

        return {
            "provider": None,
            "cluster_name": self.config.get("cluster_name") or cluster_name or context_name,
            "detected_from": None,
        }

    def _kubeconfig_dict(self) -> Dict[str, Any]:
        try:
            import yaml

            parsed = yaml.safe_load(self.config.get("kubeconfig") or "")
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _active_kubeconfig_cluster(self, kubeconfig: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
        context_name = self.config.get("context") or kubeconfig.get("current-context")
        context_entry = None
        for item in kubeconfig.get("contexts") or []:
            if item.get("name") == context_name:
                context_entry = item
                break
        if not context_entry and (kubeconfig.get("contexts") or []):
            context_entry = kubeconfig["contexts"][0]
            context_name = context_entry.get("name")

        cluster_name = ((context_entry or {}).get("context") or {}).get("cluster")
        cluster_entry: Dict[str, Any] = {}
        for item in kubeconfig.get("clusters") or []:
            if item.get("name") == cluster_name:
                cluster_entry = item
                break
        if not cluster_entry and (kubeconfig.get("clusters") or []):
            cluster_entry = kubeconfig["clusters"][0]
            cluster_name = cluster_entry.get("name")
        return context_name, cluster_name, cluster_entry

    def _redact_cluster_metadata(self, provider: str, cluster: Dict[str, Any]) -> Dict[str, Any]:
        if provider == "eks":
            vpc = cluster.get("resourcesVpcConfig") or {}
            return {
                "arn": cluster.get("arn"),
                "version": cluster.get("version"),
                "status": cluster.get("status"),
                "platformVersion": cluster.get("platformVersion"),
                "endpointPublicAccess": vpc.get("endpointPublicAccess"),
                "endpointPrivateAccess": vpc.get("endpointPrivateAccess"),
                "publicAccessCidrs": vpc.get("publicAccessCidrs") or [],
            }
        if provider == "gke":
            return {
                "name": cluster.get("name"),
                "location": cluster.get("location"),
                "status": cluster.get("status"),
                "currentMasterVersion": cluster.get("currentMasterVersion"),
                "networkPolicy": cluster.get("networkPolicy") or {},
                "privateClusterConfig": cluster.get("privateClusterConfig") or {},
                "masterAuthorizedNetworksConfig": cluster.get("masterAuthorizedNetworksConfig") or {},
            }
        return {}

    def _managed_cluster_public(self, provider: str, cluster: Dict[str, Any]) -> bool:
        if provider == "eks":
            return bool((cluster.get("resourcesVpcConfig") or {}).get("endpointPublicAccess"))
        if provider == "gke":
            return not bool((cluster.get("privateClusterConfig") or {}).get("enablePrivateEndpoint"))
        return False

    def _document_namespace(self, document: Dict[str, Any]) -> str:
        kind = document.get("kind")
        metadata = document.get("metadata") or {}
        if kind in CLUSTER_SCOPED_KINDS:
            return "cluster"
        return metadata.get("namespace") or "default"

    def _resource_key(self, document: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
        metadata = document.get("metadata") or {}
        kind = document.get("kind")
        name = metadata.get("name")
        if not kind or not name:
            return None
        return kind, self._document_namespace(document), name

    def _resource_label(self, key: Tuple[str, str, str]) -> str:
        kind, namespace, name = key
        if namespace == "cluster":
            return f"{kind}/{name}"
        return f"{namespace}/{kind}/{name}"

    def _kind_counts(self, documents: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for document in documents:
            kind = document.get("kind") or "Unknown"
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def _is_system_namespace(self, namespace: Optional[str]) -> bool:
        if not namespace:
            return False
        return namespace in SYSTEM_NAMESPACES or namespace.startswith("kube-")

    def _finding(
        self,
        resource: Dict[str, Any],
        severity: str,
        issue: str,
        description: str,
        recommendation: str,
    ) -> Dict[str, Any]:
        return {
            "resource": resource,
            "severity": severity if severity in Severity.__members__ else "MEDIUM",
            "issue": f"[K8S-SCANNER] {issue}",
            "description": description,
            "recommendation": recommendation,
            "compliance": ["Kubernetes Pod Security Standards", "CIS Kubernetes Benchmark"],
            "detection_tool": "K8S-SCANNER",
            "tool_category": "kubernetes_scan",
        }


def create_kubernetes_server(config: Optional[Dict[str, Any]] = None) -> KubernetesMCPServer:
    return KubernetesMCPServer(config or {})
