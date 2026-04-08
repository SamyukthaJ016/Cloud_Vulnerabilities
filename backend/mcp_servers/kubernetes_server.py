"""
Kubernetes MCP Server - security scanning for Kubernetes clusters
"""

import ipaddress
import json
import logging
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from kubernetes import client, config
from kubernetes.client import ApiClient
from kubernetes.config.config_exception import ConfigException

from backend.mcp_servers.base_server import BaseMCPServer, MCPResource, MCPTool, ToolCategory
from backend.utils.kubeconfig import KubeconfigPreparationError, prepare_kubeconfig_text
from backend.vulnerability.vulnerability_scanner import Vulnerability, VulnerabilityScanner

logger = logging.getLogger("kubernetes_mcp_server")


class KubernetesMCPServer(BaseMCPServer):
    """Kubernetes MCP Server for cluster posture scanning."""
    SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
    MAX_DEEP_SCAN_IMAGES = 10
    MAX_VULNERABILITY_FINDINGS_PER_IMAGE = 20
    SECRET_FANOUT_THRESHOLD = 3
    PVC_FANOUT_THRESHOLD = 2
    COMPLIANCE_CONTROL_CATALOG = {
        "CIS": {
            "CIS-K8S-POD-SECURITY-ENFORCEMENT": "Enforce pod security standards or equivalent admission policy.",
            "CIS-K8S-WORKLOAD-HARDENING": "Harden workloads against privilege escalation, root execution, and host access.",
            "CIS-K8S-NODE-POSTURE": "Harden nodes and restrict workload placement onto sensitive nodes.",
            "CIS-K8S-RBAC-LEAST-PRIVILEGE": "Restrict RBAC roles and bindings to least privilege.",
            "CIS-K8S-SERVICEACCOUNT-MINIMIZATION": "Minimize service account use and token exposure.",
            "CIS-K8S-SECRETS-MANAGEMENT": "Limit secret exposure, sprawl, and unnecessary distribution.",
            "CIS-K8S-NETWORK-SEGMENTATION": "Apply restrictive NetworkPolicies and default-deny controls.",
            "CIS-K8S-EXPOSURE-CONTROL": "Restrict external exposure and require secure ingress patterns.",
            "CIS-K8S-IMAGE-HYGIENE": "Use pinned and patched container images.",
            "CIS-K8S-RESOURCE-GOVERNANCE": "Set workload resource requests and limits.",
            "CIS-K8S-STORAGE-HARDENING": "Use secure storage backends and control persistent data sharing.",
        },
        "NSA-CISA": {
            "NSA-CISA-K8S-ADMISSION-AND-POD-SECURITY": "Use admission policy and pod security controls.",
            "NSA-CISA-K8S-HARDEN-WORKLOADS": "Harden workloads, containers, and runtime settings.",
            "NSA-CISA-K8S-HARDEN-NODES": "Reduce node exposure and keep sensitive nodes isolated from untrusted workloads.",
            "NSA-CISA-K8S-RESTRICT-RBAC": "Restrict RBAC and administrator privileges.",
            "NSA-CISA-K8S-HARDEN-SERVICE-ACCOUNTS": "Reduce service account trust and token exposure.",
            "NSA-CISA-K8S-RESTRICT-SECRETS": "Reduce secret exposure and secret fan-out.",
            "NSA-CISA-K8S-SEGMENT-NETWORK": "Segment workloads with restrictive network policy.",
            "NSA-CISA-K8S-MINIMIZE-EXPOSURE": "Minimize public exposure through services and ingress.",
            "NSA-CISA-K8S-VERIFY-IMAGES": "Verify, pin, and patch workload images.",
            "NSA-CISA-K8S-SECURE-STORAGE": "Use resilient and secure persistent storage patterns.",
        },
    }

    def __init__(self, cfg: Dict[str, Any]):
        self.api_client: Optional[ApiClient] = None
        self.core_v1: Optional[client.CoreV1Api] = None
        self.apps_v1: Optional[client.AppsV1Api] = None
        self.batch_v1: Optional[client.BatchV1Api] = None
        self.rbac_v1: Optional[client.RbacAuthorizationV1Api] = None
        self.networking_v1: Optional[client.NetworkingV1Api] = None
        self.storage_v1: Optional[client.StorageV1Api] = None
        self.version_api: Optional[client.VersionApi] = None
        self.active_context: Optional[str] = None
        self.cluster_name: Optional[str] = cfg.get("cluster_name")
        self._temp_kubeconfig_path: Optional[Path] = None
        self.vulnerability_scanner = VulnerabilityScanner()
        self._initialize_kube_client(cfg)
        super().__init__("kubernetes", cfg)

    def _initialize_kube_client(self, cfg: Dict[str, Any]) -> None:
        kubeconfig_text = cfg.get("kubeconfig")
        context_name = cfg.get("context")

        try:
            if kubeconfig_text:
                kubeconfig_text = prepare_kubeconfig_text(kubeconfig_text)
                with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
                    handle.write(kubeconfig_text)
                    self._temp_kubeconfig_path = Path(handle.name)

                self.api_client = config.new_client_from_config(
                    config_file=str(self._temp_kubeconfig_path),
                    context=context_name or None,
                )
                contexts, current_context = config.list_kube_config_contexts(
                    config_file=str(self._temp_kubeconfig_path)
                )
                if context_name:
                    self.active_context = context_name
                elif current_context:
                    self.active_context = current_context.get("name")
                if not self.cluster_name and current_context:
                    self.cluster_name = current_context.get("context", {}).get("cluster")
            else:
                kubeconfig_path = cfg.get("kubeconfig_path")
                self.api_client = config.new_client_from_config(
                    config_file=kubeconfig_path or None,
                    context=context_name or None,
                )
                self.active_context = context_name

            self.core_v1 = client.CoreV1Api(self.api_client)
            self.apps_v1 = client.AppsV1Api(self.api_client)
            self.batch_v1 = client.BatchV1Api(self.api_client)
            self.rbac_v1 = client.RbacAuthorizationV1Api(self.api_client)
            self.networking_v1 = client.NetworkingV1Api(self.api_client)
            self.storage_v1 = client.StorageV1Api(self.api_client)
            self.version_api = client.VersionApi(self.api_client)
            logger.info("[Kubernetes] Authenticated for context=%s cluster=%s", self.active_context, self.cluster_name)
        except (ConfigException, KubeconfigPreparationError) as exc:
            logger.error("[Kubernetes] Failed to initialize kube client: %s", exc)
            raise ConfigException(str(exc)) from exc

    def _setup_tools(self) -> None:
        self.register_tool(MCPTool(
            name="kubernetes/discover_cluster_resources",
            description="Discover namespaces, pods, and services in the Kubernetes cluster",
            category=ToolCategory.DISCOVERY,
            input_schema={"type": "object", "properties": {}},
            handler=self._discover_cluster_resources,
        ))

        self.register_tool(MCPTool(
            name="kubernetes/check_cluster_security",
            description="Check pod security, service exposure, RBAC, and network policy coverage",
            category=ToolCategory.VULNERABILITY,
            input_schema={"type": "object", "properties": {}},
            handler=self._check_cluster_security,
        ))

        self.register_tool(MCPTool(
            name="kubernetes/full_scan",
            description="Perform a full Kubernetes cluster security scan",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "string",
                        "description": "Optional cluster identifier",
                    },
                    "deep_scan": {
                        "type": "boolean",
                        "description": "Reserved for future deeper workload scanning",
                        "default": False,
                    },
                    "offensive_scan": {
                        "type": "boolean",
                        "description": "Accepted for compatibility with the shared multi-cloud scan pipeline; ignored for Kubernetes.",
                        "default": False,
                    },
                },
            },
            handler=self._full_scan,
        ))

    def _setup_resources(self) -> None:
        self.register_resource(MCPResource(
            uri="kubernetes://cluster/info",
            name="Kubernetes Cluster Information",
            description="Cluster context and version information",
            mime_type="application/json",
        ))
        self.register_resource(MCPResource(
            uri="kubernetes://cluster/namespaces",
            name="Kubernetes Namespaces",
            description="List of namespaces in the cluster",
            mime_type="application/json",
        ))

    async def _fetch_resource_content(self, uri: str) -> str:
        if uri == "kubernetes://cluster/info":
            version = self.version_api.get_code() if self.version_api else None
            return json.dumps({
                "cluster_name": self.cluster_name,
                "context": self.active_context,
                "version": getattr(version, "git_version", None),
            }, indent=2)

        if uri == "kubernetes://cluster/namespaces":
            namespaces = self.core_v1.list_namespace().items if self.core_v1 else []
            return json.dumps({
                "namespaces": [ns.metadata.name for ns in namespaces],
                "count": len(namespaces),
            }, indent=2)

        raise ValueError(f"Unknown resource URI: {uri}")

    def _namespace_resource(self, namespace: client.V1Namespace) -> Dict[str, Any]:
        labels = namespace.metadata.labels or {}
        return {
            "provider": "kubernetes",
            "resource_type": "namespace",
            "name": namespace.metadata.name,
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "labels": labels,
                "pod_security_enforce": labels.get("pod-security.kubernetes.io/enforce"),
                "annotations": namespace.metadata.annotations or {},
            },
            "is_public": False,
            "tags": labels,
        }

    def _pod_resource(self, pod: client.V1Pod) -> Dict[str, Any]:
        spec = pod.spec
        labels = pod.metadata.labels or {}
        return {
            "provider": "kubernetes",
            "resource_type": "pod",
            "name": f"{pod.metadata.namespace}/{pod.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": pod.metadata.namespace,
                "service_account": spec.service_account_name or "default",
                "host_network": bool(spec.host_network),
                "host_pid": bool(spec.host_pid),
                "host_ipc": bool(spec.host_ipc),
                "node_name": getattr(spec, "node_name", None),
                "node_selector": spec.node_selector or {},
                "tolerations": len(spec.tolerations or []),
                "containers": [container.name for container in spec.containers or []],
            },
            "is_public": False,
            "tags": labels,
        }

    def _service_resource(self, svc: client.V1Service) -> Dict[str, Any]:
        spec = svc.spec
        labels = svc.metadata.labels or {}
        is_public = spec.type in {"LoadBalancer", "NodePort"} or bool(spec.external_i_ps)
        return {
            "provider": "kubernetes",
            "resource_type": "service",
            "name": f"{svc.metadata.namespace}/{svc.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": svc.metadata.namespace,
                "type": spec.type,
                "ports": [port.port for port in spec.ports or []],
                "external_ips": spec.external_i_ps or [],
                "load_balancer_ip": spec.load_balancer_ip,
                "load_balancer_class": getattr(spec, "load_balancer_class", None),
                "annotations": svc.metadata.annotations or {},
            },
            "is_public": is_public,
            "tags": labels,
        }

    def _ingress_resource(self, ingress: client.V1Ingress) -> Dict[str, Any]:
        spec = ingress.spec
        labels = ingress.metadata.labels or {}
        rules = spec.rules or []
        tls_hosts = sorted({
            host
            for tls in (spec.tls or [])
            for host in (tls.hosts or [])
            if host
        })
        rule_hosts = [rule.host for rule in rules if getattr(rule, "host", None)]

        return {
            "provider": "kubernetes",
            "resource_type": "ingress",
            "name": f"{ingress.metadata.namespace}/{ingress.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": ingress.metadata.namespace,
                "ingress_class_name": getattr(spec, "ingress_class_name", None),
                "hosts": rule_hosts,
                "tls_hosts": tls_hosts,
                "annotations": ingress.metadata.annotations or {},
            },
            "is_public": bool(rule_hosts),
            "tags": labels,
        }

    def _network_policy_resource(self, policy: client.V1NetworkPolicy) -> Dict[str, Any]:
        spec = policy.spec
        labels = policy.metadata.labels or {}
        policy_types = list(spec.policy_types or [])

        return {
            "provider": "kubernetes",
            "resource_type": "network_policy",
            "name": f"{policy.metadata.namespace}/{policy.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": policy.metadata.namespace,
                "policy_types": policy_types,
                "pod_selector": getattr(spec.pod_selector, "match_labels", None) or {},
                "ingress_rules": len(spec.ingress or []),
                "egress_rules": len(spec.egress or []),
            },
            "is_public": False,
            "tags": labels,
        }

    def _service_account_resource(self, service_account: client.V1ServiceAccount) -> Dict[str, Any]:
        labels = service_account.metadata.labels or {}
        return {
            "provider": "kubernetes",
            "resource_type": "service_account",
            "name": f"{service_account.metadata.namespace}/{service_account.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": service_account.metadata.namespace,
                "automount_service_account_token": getattr(service_account, "automount_service_account_token", None),
                "image_pull_secrets": [
                    secret.name
                    for secret in (service_account.image_pull_secrets or [])
                    if getattr(secret, "name", None)
                ],
                "secrets": [
                    secret.name
                    for secret in (service_account.secrets or [])
                    if getattr(secret, "name", None)
                ],
                "annotations": service_account.metadata.annotations or {},
            },
            "is_public": False,
            "tags": labels,
        }

    def _secret_resource(self, secret: client.V1Secret) -> Dict[str, Any]:
        labels = secret.metadata.labels or {}
        return {
            "provider": "kubernetes",
            "resource_type": "secret",
            "name": f"{secret.metadata.namespace}/{secret.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": secret.metadata.namespace,
                "type": secret.type or "Opaque",
                "immutable": bool(getattr(secret, "immutable", False)),
                "data_keys": sorted((secret.data or {}).keys()),
                "annotations": secret.metadata.annotations or {},
            },
            "is_public": False,
            "tags": labels,
        }

    def _persistent_volume_backend(self, spec: client.V1PersistentVolumeSpec) -> str:
        if getattr(spec, "host_path", None):
            return "hostPath"
        if getattr(spec, "local", None):
            return "local"
        if getattr(spec, "nfs", None):
            return "nfs"
        csi = getattr(spec, "csi", None)
        if csi and getattr(csi, "driver", None):
            return f"csi:{csi.driver}"
        if getattr(spec, "aws_elastic_block_store", None):
            return "awsElasticBlockStore"
        if getattr(spec, "gce_persistent_disk", None):
            return "gcePersistentDisk"
        if getattr(spec, "azure_disk", None):
            return "azureDisk"
        if getattr(spec, "azure_file", None):
            return "azureFile"
        if getattr(spec, "cephfs", None):
            return "cephfs"
        if getattr(spec, "rbd", None):
            return "rbd"
        if getattr(spec, "iscsi", None):
            return "iscsi"
        return "unknown"

    def _persistent_volume_resource(self, persistent_volume: client.V1PersistentVolume) -> Dict[str, Any]:
        spec = persistent_volume.spec
        labels = persistent_volume.metadata.labels or {}
        claim_ref = getattr(spec, "claim_ref", None)
        return {
            "provider": "kubernetes",
            "resource_type": "persistent_volume",
            "name": persistent_volume.metadata.name,
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "storage_class": getattr(spec, "storage_class_name", None),
                "capacity": (spec.capacity or {}).get("storage"),
                "access_modes": list(spec.access_modes or []),
                "reclaim_policy": getattr(spec, "persistent_volume_reclaim_policy", None),
                "volume_mode": getattr(spec, "volume_mode", None),
                "backend": self._persistent_volume_backend(spec),
                "claim_ref": (
                    f"{claim_ref.namespace}/{claim_ref.name}"
                    if claim_ref and getattr(claim_ref, "namespace", None) and getattr(claim_ref, "name", None)
                    else None
                ),
            },
            "is_public": False,
            "tags": labels,
        }

    def _persistent_volume_claim_resource(self, persistent_volume_claim: client.V1PersistentVolumeClaim) -> Dict[str, Any]:
        spec = persistent_volume_claim.spec
        labels = persistent_volume_claim.metadata.labels or {}
        requests = getattr(getattr(spec, "resources", None), "requests", None) or {}
        return {
            "provider": "kubernetes",
            "resource_type": "persistent_volume_claim",
            "name": f"{persistent_volume_claim.metadata.namespace}/{persistent_volume_claim.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": persistent_volume_claim.metadata.namespace,
                "storage_class": getattr(spec, "storage_class_name", None),
                "access_modes": list(spec.access_modes or []),
                "volume_name": getattr(spec, "volume_name", None),
                "requested_storage": requests.get("storage"),
                "volume_mode": getattr(spec, "volume_mode", None),
            },
            "is_public": False,
            "tags": labels,
        }

    def _storage_class_resource(self, storage_class: client.V1StorageClass) -> Dict[str, Any]:
        labels = storage_class.metadata.labels or {}
        return {
            "provider": "kubernetes",
            "resource_type": "storage_class",
            "name": storage_class.metadata.name,
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "provisioner": storage_class.provisioner,
                "reclaim_policy": getattr(storage_class, "reclaim_policy", None),
                "volume_binding_mode": getattr(storage_class, "volume_binding_mode", None),
                "allow_volume_expansion": bool(getattr(storage_class, "allow_volume_expansion", False)),
                "mount_options": list(getattr(storage_class, "mount_options", None) or []),
            },
            "is_public": False,
            "tags": labels,
        }

    def _node_resource(self, node: client.V1Node) -> Dict[str, Any]:
        labels = node.metadata.labels or {}
        status = node.status
        spec = node.spec
        addresses = status.addresses or []
        external_ips = [address.address for address in addresses if address.type == "ExternalIP" and address.address]
        internal_ips = [address.address for address in addresses if address.type == "InternalIP" and address.address]
        taints = [
            {
                "key": taint.key,
                "value": getattr(taint, "value", None),
                "effect": getattr(taint, "effect", None),
            }
            for taint in (spec.taints or [])
        ]

        return {
            "provider": "kubernetes",
            "resource_type": "node",
            "name": node.metadata.name,
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "schedulable": not bool(getattr(spec, "unschedulable", False)),
                "external_ips": external_ips,
                "internal_ips": internal_ips,
                "provider_id": getattr(spec, "provider_id", None),
                "kubelet_version": getattr(getattr(status, "node_info", None), "kubelet_version", None),
                "container_runtime_version": getattr(getattr(status, "node_info", None), "container_runtime_version", None),
                "os_image": getattr(getattr(status, "node_info", None), "os_image", None),
                "taints": taints,
                "roles": sorted([
                    key
                    for key in labels
                    if key.startswith("node-role.kubernetes.io/")
                ]),
            },
            "is_public": bool(external_ips),
            "tags": labels,
        }

    def _image_resource(self, image: str, namespaces: Set[str], workloads: Set[str]) -> Dict[str, Any]:
        return {
            "provider": "kubernetes",
            "resource_type": "container_image",
            "name": image,
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespaces": sorted(namespaces),
                "workloads": sorted(workloads),
                "source": "kubernetes workload image",
            },
            "is_public": False,
            "tags": {},
        }

    def _controller_resource(
        self,
        kind: str,
        namespace: str,
        name: str,
        labels: Dict[str, str],
        template_spec: Optional[client.V1PodSpec],
        desired_replicas: Optional[int] = None,
        ready_replicas: Optional[int] = None,
        schedule: Optional[str] = None,
    ) -> Dict[str, Any]:
        template_spec = template_spec or client.V1PodSpec(containers=[])
        return {
            "provider": "kubernetes",
            "resource_type": kind.lower(),
            "name": f"{namespace}/{name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": namespace,
                "service_account": template_spec.service_account_name or "default",
                "host_network": bool(template_spec.host_network),
                "host_pid": bool(template_spec.host_pid),
                "host_ipc": bool(template_spec.host_ipc),
                "node_name": getattr(template_spec, "node_name", None),
                "node_selector": template_spec.node_selector or {},
                "tolerations": len(template_spec.tolerations or []),
                "containers": [container.name for container in self._iter_workload_containers(template_spec)],
                "desired_replicas": desired_replicas,
                "ready_replicas": ready_replicas,
                "schedule": schedule,
            },
            "is_public": False,
            "tags": labels,
        }

    def _rbac_rule_resource(
        self,
        kind: str,
        name: str,
        namespace: Optional[str],
        rule_count: int,
    ) -> Dict[str, Any]:
        return {
            "provider": "kubernetes",
            "resource_type": kind.lower(),
            "name": f"{namespace + '/' if namespace else ''}{name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": namespace,
                "rules": rule_count,
            },
            "is_public": False,
        }

    def _binding_resource(self, binding: Any, resource_type: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        return {
            "provider": "kubernetes",
            "resource_type": resource_type,
            "name": f"{namespace + '/' if namespace else ''}{binding.metadata.name}",
            "region": self.cluster_name or self.active_context or "cluster",
            "config": {
                "namespace": namespace,
                "role_ref": getattr(binding.role_ref, "name", None),
                "subjects": [
                    {
                        "kind": subject.kind,
                        "name": subject.name,
                        "namespace": getattr(subject, "namespace", None),
                    }
                    for subject in (binding.subjects or [])
                ],
            },
            "is_public": False,
        }

    async def _discover_cluster_resources(self) -> Dict[str, Any]:
        namespaces = self.core_v1.list_namespace().items if self.core_v1 else []
        nodes = self.core_v1.list_node().items if self.core_v1 else []
        pods = self.core_v1.list_pod_for_all_namespaces().items if self.core_v1 else []
        services = self.core_v1.list_service_for_all_namespaces().items if self.core_v1 else []
        service_accounts = self.core_v1.list_service_account_for_all_namespaces().items if self.core_v1 else []
        secrets = self.core_v1.list_secret_for_all_namespaces().items if self.core_v1 else []
        persistent_volumes = self.core_v1.list_persistent_volume().items if self.core_v1 else []
        persistent_volume_claims = self.core_v1.list_persistent_volume_claim_for_all_namespaces().items if self.core_v1 else []
        ingresses = self.networking_v1.list_ingress_for_all_namespaces().items if self.networking_v1 else []
        network_policies = self.networking_v1.list_network_policy_for_all_namespaces().items if self.networking_v1 else []
        storage_classes = self.storage_v1.list_storage_class().items if self.storage_v1 else []
        deployments = self.apps_v1.list_deployment_for_all_namespaces().items if self.apps_v1 else []
        statefulsets = self.apps_v1.list_stateful_set_for_all_namespaces().items if self.apps_v1 else []
        daemonsets = self.apps_v1.list_daemon_set_for_all_namespaces().items if self.apps_v1 else []
        jobs = self.batch_v1.list_job_for_all_namespaces().items if self.batch_v1 else []
        cronjobs = self.batch_v1.list_cron_job_for_all_namespaces().items if self.batch_v1 else []

        resources: List[Dict[str, Any]] = []
        resources.extend(self._namespace_resource(ns) for ns in namespaces)
        resources.extend(self._node_resource(node) for node in nodes)
        resources.extend(self._pod_resource(pod) for pod in pods)
        resources.extend(self._service_resource(svc) for svc in services)
        resources.extend(self._service_account_resource(service_account) for service_account in service_accounts)
        resources.extend(self._secret_resource(secret) for secret in secrets)
        resources.extend(self._persistent_volume_resource(persistent_volume) for persistent_volume in persistent_volumes)
        resources.extend(self._persistent_volume_claim_resource(persistent_volume_claim) for persistent_volume_claim in persistent_volume_claims)
        resources.extend(self._ingress_resource(ingress) for ingress in ingresses)
        resources.extend(self._network_policy_resource(policy) for policy in network_policies)
        resources.extend(self._storage_class_resource(storage_class) for storage_class in storage_classes)
        resources.extend(
            self._controller_resource(
                "Deployment",
                deployment.metadata.namespace,
                deployment.metadata.name,
                deployment.metadata.labels or {},
                deployment.spec.template.spec,
                desired_replicas=deployment.spec.replicas,
                ready_replicas=getattr(deployment.status, "ready_replicas", None),
            )
            for deployment in deployments
        )
        resources.extend(
            self._controller_resource(
                "StatefulSet",
                statefulset.metadata.namespace,
                statefulset.metadata.name,
                statefulset.metadata.labels or {},
                statefulset.spec.template.spec,
                desired_replicas=statefulset.spec.replicas,
                ready_replicas=getattr(statefulset.status, "ready_replicas", None),
            )
            for statefulset in statefulsets
        )
        resources.extend(
            self._controller_resource(
                "DaemonSet",
                daemonset.metadata.namespace,
                daemonset.metadata.name,
                daemonset.metadata.labels or {},
                daemonset.spec.template.spec,
                desired_replicas=getattr(daemonset.status, "desired_number_scheduled", None),
                ready_replicas=getattr(daemonset.status, "number_ready", None),
            )
            for daemonset in daemonsets
        )
        resources.extend(
            self._controller_resource(
                "Job",
                job.metadata.namespace,
                job.metadata.name,
                job.metadata.labels or {},
                job.spec.template.spec,
                desired_replicas=getattr(job.spec, "parallelism", None),
                ready_replicas=getattr(job.status, "succeeded", None),
            )
            for job in jobs
        )
        resources.extend(
            self._controller_resource(
                "CronJob",
                cronjob.metadata.namespace,
                cronjob.metadata.name,
                cronjob.metadata.labels or {},
                cronjob.spec.job_template.spec.template.spec if cronjob.spec and cronjob.spec.job_template and cronjob.spec.job_template.spec else None,
                schedule=getattr(cronjob.spec, "schedule", None),
            )
            for cronjob in cronjobs
        )

        return {
            "cluster_name": self.cluster_name,
            "context": self.active_context,
            "resources": resources,
            "summary": {
                "namespaces": len(namespaces),
                "nodes": len(nodes),
                "pods": len(pods),
                "services": len(services),
                "service_accounts": len(service_accounts),
                "secrets": len(secrets),
                "persistent_volumes": len(persistent_volumes),
                "persistent_volume_claims": len(persistent_volume_claims),
                "ingresses": len(ingresses),
                "network_policies": len(network_policies),
                "storage_classes": len(storage_classes),
                "deployments": len(deployments),
                "statefulsets": len(statefulsets),
                "daemonsets": len(daemonsets),
                "jobs": len(jobs),
                "cronjobs": len(cronjobs),
            },
        }

    def _iter_workload_containers(self, spec: client.V1PodSpec) -> List[Any]:
        containers: List[Any] = []
        containers.extend(spec.init_containers or [])
        containers.extend(spec.containers or [])
        containers.extend(spec.ephemeral_containers or [])
        return containers

    def _resource_namespace(self, resource: Dict[str, Any]) -> Optional[str]:
        config = resource.get("config", {})
        namespace = config.get("namespace")
        if namespace:
            return namespace
        name = resource.get("name", "")
        if "/" in name:
            return name.split("/", 1)[0]
        return None

    def _control_plane_label_keys(self) -> Set[str]:
        return {
            "node-role.kubernetes.io/control-plane",
            "node-role.kubernetes.io/master",
        }

    def _control_plane_taint_keys(self) -> Set[str]:
        return {
            "node-role.kubernetes.io/control-plane",
            "node-role.kubernetes.io/master",
        }

    def _is_control_plane_node(self, node: client.V1Node) -> bool:
        labels = node.metadata.labels or {}
        return any(key in labels for key in self._control_plane_label_keys())

    def _is_eks_node(self, node: client.V1Node) -> bool:
        labels = node.metadata.labels or {}
        provider_id = (getattr(node.spec, "provider_id", None) or "").lower()
        return (
            provider_id.startswith("aws:///")
            or "eks.amazonaws.com/nodegroup" in labels
            or any(label.startswith("alpha.eksctl.io/") for label in labels)
        )

    def _is_gke_node(self, node: client.V1Node) -> bool:
        labels = node.metadata.labels or {}
        provider_id = (getattr(node.spec, "provider_id", None) or "").lower()
        return (
            provider_id.startswith("gce://")
            or "cloud.google.com/gke-nodepool" in labels
            or "iam.gke.io/gke-metadata-server-enabled" in labels
        )

    def _infer_managed_cluster_platforms(
        self,
        nodes: List[client.V1Node],
        storage_classes: List[client.V1StorageClass],
    ) -> Set[str]:
        platforms: Set[str] = set()

        for node in nodes:
            if self._is_eks_node(node):
                platforms.add("eks")
            if self._is_gke_node(node):
                platforms.add("gke")

        for storage_class in storage_classes:
            provisioner = (storage_class.provisioner or "").lower()
            if provisioner in {"ebs.csi.aws.com", "efs.csi.aws.com", "kubernetes.io/aws-ebs"}:
                platforms.add("eks")
            if provisioner in {"pd.csi.storage.gke.io", "filestore.csi.storage.gke.io", "kubernetes.io/gce-pd"}:
                platforms.add("gke")

        return platforms

    def _node_has_control_plane_noschedule_taint(self, node: client.V1Node) -> bool:
        for taint in node.spec.taints or []:
            if taint.key in self._control_plane_taint_keys() and getattr(taint, "effect", None) in {"NoSchedule", "NoExecute"}:
                return True
        return False

    def _workload_has_broad_toleration(self, spec: client.V1PodSpec) -> bool:
        for toleration in spec.tolerations or []:
            operator = getattr(toleration, "operator", None) or "Equal"
            key = getattr(toleration, "key", None)
            effect = getattr(toleration, "effect", None)
            if operator == "Exists" and not key and not effect:
                return True
        return False

    def _workload_tolerates_control_plane(self, spec: client.V1PodSpec) -> bool:
        for toleration in spec.tolerations or []:
            key = getattr(toleration, "key", None)
            operator = getattr(toleration, "operator", None) or "Equal"
            if key in self._control_plane_taint_keys() and operator in {"Exists", "Equal"}:
                return True
        return False

    def _workload_targets_control_plane(self, spec: client.V1PodSpec) -> bool:
        node_selector = spec.node_selector or {}
        if any(key in node_selector for key in self._control_plane_label_keys()):
            return True

        affinity = getattr(spec, "affinity", None)
        node_affinity = getattr(affinity, "node_affinity", None) if affinity else None
        required = getattr(node_affinity, "required_during_scheduling_ignored_during_execution", None) if node_affinity else None
        for term in getattr(required, "node_selector_terms", None) or []:
            for expression in getattr(term, "match_expressions", None) or []:
                if expression.key in self._control_plane_label_keys():
                    return True

        return self._workload_tolerates_control_plane(spec)

    def _collect_deep_scan_images(self, pods: List[client.V1Pod], controllers: List[Tuple[str, str, str, Optional[client.V1PodSpec]]]) -> Dict[str, Dict[str, Set[str]]]:
        images: Dict[str, Dict[str, Set[str]]] = {}

        def record_image(image: Optional[str], namespace: Optional[str], workload_name: str) -> None:
            if not image or not namespace or namespace in self.SYSTEM_NAMESPACES:
                return
            image_info = images.setdefault(image, {"namespaces": set(), "workloads": set()})
            image_info["namespaces"].add(namespace)
            image_info["workloads"].add(workload_name)

        for pod in pods:
            namespace = getattr(pod.metadata, "namespace", None)
            workload_name = f"Pod {namespace}/{pod.metadata.name}"
            for container in self._iter_workload_containers(pod.spec):
                record_image(container.image, namespace, workload_name)

        for kind, namespace, name, template_spec in controllers:
            if not template_spec:
                continue
            workload_name = f"{kind} {namespace}/{name}"
            for container in self._iter_workload_containers(template_spec):
                record_image(container.image, namespace, workload_name)

        return images

    def _check_workload_spec_security(
        self,
        spec: client.V1PodSpec,
        resource: Dict[str, Any],
        workload_label: str,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        pod_sc = spec.security_context

        if (spec.service_account_name or "default") == "default":
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": f"{workload_label} Using Default Service Account",
                "description": f"{workload_label} {resource['name']} is using the default service account.",
                "recommendation": "Create a dedicated service account with least-privilege RBAC bindings.",
                "detection_tool": "kubernetes-pod-checker",
            })

        if getattr(spec, "automount_service_account_token", None) is not False:
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Service Account Token Auto-Mounted",
                "description": f"{workload_label} {resource['name']} auto-mounts a service account token.",
                "recommendation": "Disable automountServiceAccountToken unless the workload needs Kubernetes API access.",
                "detection_tool": "kubernetes-pod-checker",
            })

        if pod_sc and getattr(pod_sc, "run_as_user", None) == 0:
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": f"{workload_label} Running as Root",
                "description": f"{workload_label} {resource['name']} has a pod-level securityContext with runAsUser=0.",
                "recommendation": "Run workloads as a non-root user and enforce Pod Security Standards.",
                "detection_tool": "kubernetes-pod-checker",
            })

        if spec.host_network or spec.host_pid or spec.host_ipc:
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": f"{workload_label} Using Host Namespaces",
                "description": f"{workload_label} {resource['name']} is using hostNetwork, hostPID, or hostIPC.",
                "recommendation": "Disable host namespace sharing unless the workload strictly requires it.",
                "detection_tool": "kubernetes-pod-checker",
            })

        for volume in spec.volumes or []:
            host_path = getattr(volume, "host_path", None)
            if host_path:
                findings.append({
                    "resource": resource,
                    "severity": "HIGH",
                    "issue": f"{workload_label} Using hostPath Volume",
                    "description": f"{workload_label} {resource['name']} mounts host path {host_path.path}.",
                    "recommendation": "Avoid hostPath mounts for application workloads unless there is a strong operational need.",
                    "detection_tool": "kubernetes-pod-checker",
                })

        namespace = self._resource_namespace(resource)
        if namespace not in self.SYSTEM_NAMESPACES:
            if workload_label != "Pod" and getattr(spec, "node_name", None):
                findings.append({
                    "resource": resource,
                    "severity": "LOW",
                    "issue": "Workload Pinned to Specific Node",
                    "description": f"{workload_label} {resource['name']} is pinned to node {spec.node_name}.",
                    "recommendation": "Avoid pinning workloads to specific nodes unless there is a strong operational reason.",
                    "detection_tool": "kubernetes-node-checker",
                })

            if self._workload_targets_control_plane(spec):
                findings.append({
                    "resource": resource,
                    "severity": "HIGH",
                    "issue": "Workload Can Run on Control-Plane Nodes",
                    "description": f"{workload_label} {resource['name']} can schedule onto control-plane nodes via selectors, affinity, or tolerations.",
                    "recommendation": "Keep application workloads off control-plane nodes unless they are explicitly administrative components.",
                    "detection_tool": "kubernetes-node-checker",
                })

            if self._workload_has_broad_toleration(spec):
                findings.append({
                    "resource": resource,
                    "severity": "MEDIUM",
                    "issue": "Workload Uses Broad Toleration",
                    "description": f"{workload_label} {resource['name']} defines an unconstrained toleration that can widen placement onto sensitive or tainted nodes.",
                    "recommendation": "Scope tolerations to the exact taints and effects the workload requires.",
                    "detection_tool": "kubernetes-node-checker",
                })

        for container in self._iter_workload_containers(spec):
            sec = container.security_context
            image = container.image or ""
            resources_cfg = container.resources or client.V1ResourceRequirements()
            requests = resources_cfg.requests or {}
            limits = resources_cfg.limits or {}
            pod_run_as_non_root = bool(pod_sc and getattr(pod_sc, "run_as_non_root", None) is True)
            container_run_as_non_root = bool(sec and getattr(sec, "run_as_non_root", None) is True)
            seccomp_profile = (
                getattr(sec, "seccomp_profile", None)
                or getattr(pod_sc, "seccomp_profile", None)
            )

            if image.endswith(":latest"):
                findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Container Uses latest Tag",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} uses the mutable image tag {image}.",
                        "recommendation": "Pin container images to an immutable version or digest.",
                        "detection_tool": "kubernetes-image-checker",
                    })
            elif ":" not in image and "@sha256:" not in image:
                findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Container Image Not Pinned",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} does not specify an explicit tag or digest.",
                        "recommendation": "Pin container images to a version tag or digest to make deployments reproducible.",
                        "detection_tool": "kubernetes-image-checker",
                    })

            if sec and getattr(sec, "privileged", False):
                findings.append({
                        "resource": resource,
                        "severity": "CRITICAL",
                        "issue": "Privileged Container",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} runs in privileged mode.",
                        "recommendation": "Remove privileged mode and use a constrained securityContext.",
                        "detection_tool": "kubernetes-pod-checker",
                    })
            if sec and getattr(sec, "allow_privilege_escalation", None) is True:
                findings.append({
                        "resource": resource,
                        "severity": "HIGH",
                        "issue": "Privilege Escalation Allowed",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} allows privilege escalation.",
                        "recommendation": "Set allowPrivilegeEscalation=false for application containers.",
                        "detection_tool": "kubernetes-pod-checker",
                    })
            if sec and getattr(sec, "run_as_user", None) == 0:
                findings.append({
                        "resource": resource,
                        "severity": "HIGH",
                        "issue": "Container Running as Root",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} is configured to run as root.",
                        "recommendation": "Configure the container to run as a non-root UID.",
                        "detection_tool": "kubernetes-pod-checker",
                    })

            if not (container_run_as_non_root or pod_run_as_non_root):
                findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Container Missing runAsNonRoot",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} does not enforce runAsNonRoot.",
                        "recommendation": "Set runAsNonRoot=true at the pod or container level.",
                        "detection_tool": "kubernetes-pod-checker",
                    })

            if not (sec and getattr(sec, "read_only_root_filesystem", None) is True):
                findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Writable Root Filesystem",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} does not enable readOnlyRootFilesystem.",
                        "recommendation": "Set readOnlyRootFilesystem=true for application containers where possible.",
                        "detection_tool": "kubernetes-pod-checker",
                    })

            if not (seccomp_profile and getattr(seccomp_profile, "type", None)):
                findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Missing Seccomp Profile",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} does not declare a seccomp profile.",
                        "recommendation": "Set seccompProfile.type to RuntimeDefault or a custom hardened profile.",
                        "detection_tool": "kubernetes-pod-checker",
                    })

            capabilities = getattr(sec, "capabilities", None)
            dropped_caps = {
                capability.upper()
                for capability in (getattr(capabilities, "drop", None) or [])
            }
            if "ALL" not in dropped_caps:
                findings.append({
                        "resource": resource,
                        "severity": "LOW",
                        "issue": "Capabilities Not Fully Dropped",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} does not drop ALL Linux capabilities.",
                        "recommendation": "Drop ALL capabilities and add back only the specific capabilities the workload requires.",
                        "detection_tool": "kubernetes-pod-checker",
                    })

            missing_requests = [key for key in ("cpu", "memory") if key not in requests]
            missing_limits = [key for key in ("cpu", "memory") if key not in limits]
            if missing_requests or missing_limits:
                missing_parts: List[str] = []
                if missing_requests:
                    missing_parts.append(f"requests: {', '.join(missing_requests)}")
                if missing_limits:
                    missing_parts.append(f"limits: {', '.join(missing_limits)}")
                findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Missing Resource Requests or Limits",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} is missing {('; '.join(missing_parts))}.",
                        "recommendation": "Define CPU and memory requests and limits for each container.",
                        "detection_tool": "kubernetes-resource-checker",
                    })

            for env_var in container.env or []:
                value_from = getattr(env_var, "value_from", None)
                secret_ref = getattr(value_from, "secret_key_ref", None) if value_from else None
                if secret_ref and secret_ref.name:
                    findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Secret Exposed Through Environment Variable",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} injects secret {secret_ref.name} into env var {env_var.name}.",
                        "recommendation": "Prefer mounted secret volumes or an external secret manager over environment-variable injection for sensitive values.",
                        "detection_tool": "kubernetes-secret-checker",
                    })

            for env_from in container.env_from or []:
                secret_ref = getattr(env_from, "secret_ref", None)
                if secret_ref and secret_ref.name:
                    findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Secret Imported Through envFrom",
                        "description": f"Container {container.name} in {workload_label.lower()} {resource['name']} imports secret {secret_ref.name} with envFrom.",
                        "recommendation": "Minimize secret fan-out and prefer mounted secret volumes or an external secret manager.",
                        "detection_tool": "kubernetes-secret-checker",
                    })

        return findings

    def _check_pod_security(self, pod: client.V1Pod, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self._check_workload_spec_security(pod.spec, resource, "Pod")

    def _check_controller_security(self, resource: Dict[str, Any], template_spec: Optional[client.V1PodSpec], kind: str) -> List[Dict[str, Any]]:
        if not template_spec:
            return []
        return self._check_workload_spec_security(template_spec, resource, kind)

    def _record_secret_usage(
        self,
        usage_map: Dict[Tuple[str, str], Set[str]],
        namespace: Optional[str],
        secret_name: Optional[str],
        consumer: str,
    ) -> None:
        if not namespace or not secret_name:
            return
        usage_map.setdefault((namespace, secret_name), set()).add(consumer)

    def _record_secret_usage_from_workload(
        self,
        spec: Optional[client.V1PodSpec],
        namespace: Optional[str],
        workload_name: str,
        usage_map: Dict[Tuple[str, str], Set[str]],
    ) -> None:
        if not spec or not namespace:
            return

        for volume in spec.volumes or []:
            secret_volume = getattr(volume, "secret", None)
            if secret_volume and getattr(secret_volume, "secret_name", None):
                self._record_secret_usage(usage_map, namespace, secret_volume.secret_name, workload_name)

            projected = getattr(volume, "projected", None)
            for source in (getattr(projected, "sources", None) or []):
                secret_source = getattr(source, "secret", None)
                if secret_source and getattr(secret_source, "name", None):
                    self._record_secret_usage(usage_map, namespace, secret_source.name, workload_name)

        for image_pull_secret in spec.image_pull_secrets or []:
            if getattr(image_pull_secret, "name", None):
                self._record_secret_usage(usage_map, namespace, image_pull_secret.name, workload_name)

        for container in self._iter_workload_containers(spec):
            for env_var in container.env or []:
                value_from = getattr(env_var, "value_from", None)
                secret_ref = getattr(value_from, "secret_key_ref", None) if value_from else None
                if secret_ref and secret_ref.name:
                    self._record_secret_usage(usage_map, namespace, secret_ref.name, workload_name)

            for env_from in container.env_from or []:
                secret_ref = getattr(env_from, "secret_ref", None)
                if secret_ref and secret_ref.name:
                    self._record_secret_usage(usage_map, namespace, secret_ref.name, workload_name)

    def _record_service_account_usage(
        self,
        usage_map: Dict[Tuple[str, str], Set[str]],
        namespace: Optional[str],
        service_account_name: Optional[str],
        workload_name: str,
    ) -> None:
        if not namespace:
            return
        usage_map.setdefault((namespace, service_account_name or "default"), set()).add(workload_name)

    def _record_persistent_volume_claim_usage(
        self,
        usage_map: Dict[Tuple[str, str], Set[str]],
        namespace: Optional[str],
        claim_name: Optional[str],
        workload_name: str,
    ) -> None:
        if not namespace or not claim_name:
            return
        usage_map.setdefault((namespace, claim_name), set()).add(workload_name)

    def _record_persistent_volume_claim_usage_from_workload(
        self,
        spec: Optional[client.V1PodSpec],
        namespace: Optional[str],
        workload_name: str,
        usage_map: Dict[Tuple[str, str], Set[str]],
    ) -> None:
        if not spec or not namespace:
            return

        for volume in spec.volumes or []:
            pvc_source = getattr(volume, "persistent_volume_claim", None)
            claim_name = getattr(pvc_source, "claim_name", None)
            if claim_name:
                self._record_persistent_volume_claim_usage(usage_map, namespace, claim_name, workload_name)

    def _merge_risk_markers(
        self,
        existing_markers: List[Dict[str, str]],
        new_markers: List[Dict[str, str]],
    ) -> List[Dict[str, str]]:
        merged = list(existing_markers)
        seen = {(marker["severity"], marker["issue"]) for marker in merged}
        for marker in new_markers:
            marker_key = (marker["severity"], marker["issue"])
            if marker_key not in seen:
                merged.append(marker)
                seen.add(marker_key)
        return merged

    def _record_service_account_subject_risks(
        self,
        subjects: Optional[List[Any]],
        binding_namespace: Optional[str],
        risk_markers: List[Dict[str, str]],
        risky_service_accounts: Dict[Tuple[str, str], List[Dict[str, str]]],
    ) -> None:
        if not risk_markers:
            return

        for subject in subjects or []:
            if getattr(subject, "kind", None) != "ServiceAccount":
                continue
            namespace = getattr(subject, "namespace", None) or binding_namespace
            name = getattr(subject, "name", None)
            if not namespace or not name:
                continue
            key = (namespace, name)
            risky_service_accounts[key] = self._merge_risk_markers(
                risky_service_accounts.get(key, []),
                risk_markers,
            )

    def _check_service_account_security(
        self,
        service_account: client.V1ServiceAccount,
        resource: Dict[str, Any],
        bound_workloads: Set[str],
        risk_markers: List[Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        namespace = service_account.metadata.namespace
        service_account_name = service_account.metadata.name
        automount = getattr(service_account, "automount_service_account_token", None)

        if namespace not in self.SYSTEM_NAMESPACES and automount is not False:
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Service Account Token Auto-Mount Enabled",
                "description": f"ServiceAccount {namespace}/{service_account_name} allows service account token auto-mounting by default.",
                "recommendation": "Set automountServiceAccountToken=false on service accounts that do not require Kubernetes API access.",
                "detection_tool": "kubernetes-serviceaccount-checker",
            })

        if risk_markers:
            top_risk = max(risk_markers, key=lambda item: self._severity_rank(item["severity"]))
            issue_list = ", ".join(sorted({marker["issue"] for marker in risk_markers}))
            consumers = sorted(bound_workloads)
            consumer_summary = f" It is used by {len(consumers)} workload(s): {', '.join(consumers[:5])}." if consumers else ""
            findings.append({
                "resource": resource,
                "severity": top_risk["severity"],
                "issue": "Service Account Bound to High-Risk Role",
                "description": (
                    f"ServiceAccount {namespace}/{service_account_name} is bound to role(s) with "
                    f"{issue_list}.{consumer_summary}"
                ),
                "recommendation": "Move this service account to least-privilege roles and restrict which workloads can use it.",
                "detection_tool": "kubernetes-serviceaccount-checker",
            })

        return findings

    def _check_workload_service_account_risk(
        self,
        resource: Dict[str, Any],
        service_account_name: Optional[str],
        risk_markers: List[Dict[str, str]],
    ) -> Optional[Dict[str, Any]]:
        if not risk_markers:
            return None

        top_risk = max(risk_markers, key=lambda item: self._severity_rank(item["severity"]))
        issue_list = ", ".join(sorted({marker["issue"] for marker in risk_markers}))
        namespace, _, workload_name = resource["name"].partition("/")
        return {
            "resource": resource,
            "severity": top_risk["severity"],
            "issue": "Workload Uses High-Risk Service Account",
            "description": (
                f"Workload {resource['name']} uses service account "
                f"{namespace}/{service_account_name or 'default'}, which is bound to role(s) with {issue_list}."
            ),
            "recommendation": "Move the workload to a least-privilege service account or reduce the permissions bound to the current one.",
            "detection_tool": "kubernetes-serviceaccount-checker",
        }

    def _check_secret_security(
        self,
        secret: client.V1Secret,
        resource: Dict[str, Any],
        referenced_by: Set[str],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        namespace = secret.metadata.namespace
        secret_name = secret.metadata.name
        secret_type = secret.type or "Opaque"

        if secret_type == "kubernetes.io/service-account-token":
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": "Legacy Service Account Token Secret",
                "description": f"Secret {namespace}/{secret_name} is a long-lived service account token secret.",
                "recommendation": "Prefer short-lived projected service account tokens and remove legacy token secrets where possible.",
                "detection_tool": "kubernetes-secret-checker",
            })

        if namespace in self.SYSTEM_NAMESPACES:
            return findings

        consumers = sorted(referenced_by)
        if not consumers and secret_type != "kubernetes.io/service-account-token":
            findings.append({
                "resource": resource,
                "severity": "LOW",
                "issue": "Unused Secret",
                "description": f"Secret {namespace}/{secret_name} is not referenced by any discovered workload or service account.",
                "recommendation": "Delete unused secrets or rotate them into active workloads only when required.",
                "detection_tool": "kubernetes-secret-checker",
            })
        elif len(consumers) >= self.SECRET_FANOUT_THRESHOLD:
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Secret Shared Across Multiple Consumers",
                "description": (
                    f"Secret {namespace}/{secret_name} is referenced by {len(consumers)} consumers: "
                    f"{', '.join(consumers[:5])}."
                ),
                "recommendation": "Reduce secret fan-out by scoping secrets to the smallest set of workloads or service accounts that need them.",
                "detection_tool": "kubernetes-secret-checker",
            })

        return findings

    def _is_local_storage_provisioner(self, provisioner: Optional[str]) -> bool:
        provisioner_name = (provisioner or "").lower()
        return (
            provisioner_name == "kubernetes.io/no-provisioner"
            or "hostpath" in provisioner_name
            or "local-path" in provisioner_name
        )

    def _check_persistent_volume_security(
        self,
        persistent_volume: client.V1PersistentVolume,
        resource: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        spec = persistent_volume.spec
        reclaim_policy = getattr(spec, "persistent_volume_reclaim_policy", None)

        if getattr(spec, "host_path", None):
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": "Persistent Volume Uses hostPath",
                "description": f"PersistentVolume {persistent_volume.metadata.name} mounts host path {spec.host_path.path}.",
                "recommendation": "Avoid hostPath-backed persistent volumes for application data outside tightly controlled single-node test environments.",
                "detection_tool": "kubernetes-storage-checker",
            })

        if getattr(spec, "local", None):
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Persistent Volume Uses Local Node Storage",
                "description": f"PersistentVolume {persistent_volume.metadata.name} uses node-local storage at {spec.local.path}.",
                "recommendation": "Use managed network-attached or CSI-backed storage for resilient multi-node workloads when possible.",
                "detection_tool": "kubernetes-storage-checker",
            })

        if getattr(spec, "nfs", None):
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Persistent Volume Uses NFS",
                "description": f"PersistentVolume {persistent_volume.metadata.name} is backed by NFS server {spec.nfs.server}:{spec.nfs.path}.",
                "recommendation": "Review NFS export permissions and prefer encrypted, identity-aware storage backends for sensitive data.",
                "detection_tool": "kubernetes-storage-checker",
            })

        if reclaim_policy == "Retain":
            findings.append({
                "resource": resource,
                "severity": "LOW",
                "issue": "Persistent Volume Retains Data After Release",
                "description": f"PersistentVolume {persistent_volume.metadata.name} uses reclaim policy Retain, which can leave data behind after claim deletion.",
                "recommendation": "Ensure retained volumes are securely wiped or manually reviewed before reuse.",
                "detection_tool": "kubernetes-storage-checker",
            })

        return findings

    def _check_persistent_volume_claim_security(
        self,
        persistent_volume_claim: client.V1PersistentVolumeClaim,
        resource: Dict[str, Any],
        referenced_by: Set[str],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        access_modes = set(persistent_volume_claim.spec.access_modes or [])
        namespace = persistent_volume_claim.metadata.namespace
        name = persistent_volume_claim.metadata.name
        consumers = sorted(referenced_by)

        if "ReadWriteMany" in access_modes:
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Persistent Volume Claim Allows Multi-Writer Access",
                "description": f"PersistentVolumeClaim {namespace}/{name} allows ReadWriteMany access.",
                "recommendation": "Use ReadWriteOnce where possible and restrict shared-write claims to workloads that explicitly require them.",
                "detection_tool": "kubernetes-storage-checker",
            })

        if len(consumers) >= self.PVC_FANOUT_THRESHOLD:
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Persistent Volume Claim Shared Across Multiple Workloads",
                "description": f"PersistentVolumeClaim {namespace}/{name} is referenced by {len(consumers)} workloads: {', '.join(consumers[:5])}.",
                "recommendation": "Minimize shared claim usage unless the workloads are intentionally designed to share the same persistent data.",
                "detection_tool": "kubernetes-storage-checker",
            })

        return findings

    def _check_storage_class_security(
        self,
        storage_class: client.V1StorageClass,
        resource: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        provisioner = storage_class.provisioner
        reclaim_policy = getattr(storage_class, "reclaim_policy", None)

        if self._is_local_storage_provisioner(provisioner):
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "StorageClass Uses Host-Local Provisioner",
                "description": f"StorageClass {storage_class.metadata.name} uses local provisioner {provisioner}.",
                "recommendation": "Reserve host-local storage classes for isolated development use and prefer managed CSI storage in shared environments.",
                "detection_tool": "kubernetes-storage-checker",
            })

        if reclaim_policy == "Retain":
            findings.append({
                "resource": resource,
                "severity": "LOW",
                "issue": "StorageClass Retains Data After Claim Release",
                "description": f"StorageClass {storage_class.metadata.name} uses reclaim policy Retain, which can preserve underlying data after PVC deletion.",
                "recommendation": "Add an operational process to scrub retained volumes before reassigning them to new workloads.",
                "detection_tool": "kubernetes-storage-checker",
            })

        return findings

    def _check_node_security(
        self,
        node: client.V1Node,
        resource: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        external_ips = resource.get("config", {}).get("external_ips", [])

        if external_ips:
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": "Node Has External IP",
                "description": f"Node {node.metadata.name} exposes external IPs: {', '.join(external_ips)}.",
                "recommendation": "Prefer private worker nodes and route external traffic through controlled ingress or load balancer paths.",
                "detection_tool": "kubernetes-node-checker",
            })

        if self._is_control_plane_node(node):
            if not self._node_has_control_plane_noschedule_taint(node) and not bool(getattr(node.spec, "unschedulable", False)):
                findings.append({
                    "resource": resource,
                    "severity": "MEDIUM",
                    "issue": "Control-Plane Node Accepts Workloads",
                    "description": f"Node {node.metadata.name} is labeled as a control-plane node and remains schedulable for general workloads.",
                    "recommendation": "Apply NoSchedule taints or mark control-plane nodes unschedulable unless this is an intentionally single-node test cluster.",
                    "detection_tool": "kubernetes-node-checker",
                })

        return findings

    def _service_is_internal_on_eks(self, svc: client.V1Service) -> bool:
        annotations = svc.metadata.annotations or {}
        scheme = (annotations.get("service.beta.kubernetes.io/aws-load-balancer-scheme") or "").lower()
        legacy_internal = (annotations.get("service.beta.kubernetes.io/aws-load-balancer-internal") or "").lower()
        return scheme == "internal" or legacy_internal == "true"

    def _service_is_internal_on_gke(self, svc: client.V1Service) -> bool:
        annotations = svc.metadata.annotations or {}
        lb_type = (
            annotations.get("networking.gke.io/load-balancer-type")
            or annotations.get("cloud.google.com/load-balancer-type")
            or ""
        ).lower()
        return lb_type == "internal"

    def _check_eks_service_exposure(self, svc: client.V1Service, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        if svc.spec.type != "LoadBalancer" or self._service_is_internal_on_eks(svc):
            return []
        return [{
            "resource": resource,
            "severity": "HIGH",
            "issue": "EKS Service Uses Internet-Facing Load Balancer",
            "description": f"Service {resource['name']} is a LoadBalancer service without an internal AWS load balancer annotation.",
            "recommendation": "Mark EKS load balancers as internal unless the service must be publicly reachable.",
            "detection_tool": "kubernetes-managed-cluster-checker",
        }]

    def _check_gke_service_exposure(self, svc: client.V1Service, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        if svc.spec.type != "LoadBalancer" or self._service_is_internal_on_gke(svc):
            return []
        return [{
            "resource": resource,
            "severity": "HIGH",
            "issue": "GKE Service Uses External Load Balancer",
            "description": f"Service {resource['name']} is a LoadBalancer service without a GKE internal load balancer annotation.",
            "recommendation": "Use internal load balancers for private services and expose public traffic through explicitly reviewed entry points.",
            "detection_tool": "kubernetes-managed-cluster-checker",
        }]

    def _check_eks_storage_class(self, storage_class: client.V1StorageClass, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        if (storage_class.provisioner or "").lower() != "kubernetes.io/aws-ebs":
            return []
        return [{
            "resource": resource,
            "severity": "MEDIUM",
            "issue": "EKS Uses In-Tree AWS EBS Provisioner",
            "description": f"StorageClass {storage_class.metadata.name} still uses the legacy in-tree AWS EBS provisioner.",
            "recommendation": "Migrate to the AWS EBS CSI driver to stay on the supported storage integration path.",
            "detection_tool": "kubernetes-managed-cluster-checker",
        }]

    def _check_gke_storage_class(self, storage_class: client.V1StorageClass, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        if (storage_class.provisioner or "").lower() != "kubernetes.io/gce-pd":
            return []
        return [{
            "resource": resource,
            "severity": "MEDIUM",
            "issue": "GKE Uses In-Tree GCE PD Provisioner",
            "description": f"StorageClass {storage_class.metadata.name} still uses the legacy in-tree GCE Persistent Disk provisioner.",
            "recommendation": "Migrate to the GCE PD CSI driver to use the supported GKE storage integration path.",
            "detection_tool": "kubernetes-managed-cluster-checker",
        }]

    def _check_gke_node_identity(self, node: client.V1Node, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self._is_gke_node(node):
            return []
        labels = node.metadata.labels or {}
        if labels.get("iam.gke.io/gke-metadata-server-enabled") == "true":
            return []
        return [{
            "resource": resource,
            "severity": "MEDIUM",
            "issue": "GKE Node Pool Missing Workload Identity Metadata Server",
            "description": f"Node {node.metadata.name} does not advertise iam.gke.io/gke-metadata-server-enabled=true.",
            "recommendation": "Use GKE Workload Identity-enabled node pools for workloads that need Google Cloud API access.",
            "detection_tool": "kubernetes-managed-cluster-checker",
        }]

    def _check_service_exposure(self, svc: client.V1Service, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        svc_type = svc.spec.type

        if svc_type == "LoadBalancer":
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": "Public LoadBalancer Service",
                "description": f"Service {resource['name']} is exposed through a LoadBalancer.",
                "recommendation": "Restrict exposure with ingress, source ranges, or internal load balancers where possible.",
                "detection_tool": "kubernetes-service-checker",
            })

        if svc_type == "NodePort":
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "NodePort Service Exposed",
                "description": f"Service {resource['name']} is exposed on every worker node via NodePort.",
                "recommendation": "Prefer ClusterIP with an ingress controller or tightly restrict reachable nodes.",
                "detection_tool": "kubernetes-service-checker",
            })

        if svc.spec.external_i_ps:
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": "Service With External IPs",
                "description": f"Service {resource['name']} has external IPs configured: {', '.join(svc.spec.external_i_ps)}.",
                "recommendation": "Review whether external IPs are necessary and restrict exposure if not.",
                "detection_tool": "kubernetes-service-checker",
            })

        return findings

    def _check_ingress_exposure(self, ingress: client.V1Ingress, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        spec = ingress.spec
        annotations = ingress.metadata.annotations or {}
        rules = spec.rules or []
        tls_hosts = {
            host
            for tls in (spec.tls or [])
            for host in (tls.hosts or [])
            if host
        }

        if rules and any(not getattr(rule, "host", None) for rule in rules):
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": "Ingress Rule Without Host Restriction",
                "description": f"Ingress {resource['name']} contains a rule without a host match.",
                "recommendation": "Restrict ingress rules to specific hostnames instead of accepting all hosts.",
                "detection_tool": "kubernetes-ingress-checker",
            })

        exposed_hosts = [rule.host for rule in rules if getattr(rule, "host", None)]
        hosts_without_tls = [host for host in exposed_hosts if host not in tls_hosts]
        if hosts_without_tls:
            findings.append({
                "resource": resource,
                "severity": "HIGH",
                "issue": "Ingress Host Without TLS",
                "description": f"Ingress {resource['name']} exposes hosts without TLS: {', '.join(hosts_without_tls)}.",
                "recommendation": "Configure TLS for all externally exposed ingress hosts.",
                "detection_tool": "kubernetes-ingress-checker",
            })

        if annotations.get("nginx.ingress.kubernetes.io/ssl-redirect") == "false":
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Ingress Disables SSL Redirect",
                "description": f"Ingress {resource['name']} explicitly disables SSL redirect.",
                "recommendation": "Force HTTPS redirects unless the application has a strong reason to serve plaintext HTTP.",
                "detection_tool": "kubernetes-ingress-checker",
            })

        if annotations.get("kubernetes.io/ingress.allow-http") == "true":
            findings.append({
                "resource": resource,
                "severity": "MEDIUM",
                "issue": "Ingress Allows HTTP",
                "description": f"Ingress {resource['name']} explicitly allows HTTP traffic.",
                "recommendation": "Disable HTTP on public ingress resources and require HTTPS.",
                "detection_tool": "kubernetes-ingress-checker",
            })

        return findings

    def _policy_matches_all_pods(self, policy: client.V1NetworkPolicy) -> bool:
        selector = policy.spec.pod_selector
        if not selector:
            return True
        return not (selector.match_labels or selector.match_expressions)

    def _policy_has_default_deny(self, policy: client.V1NetworkPolicy, direction: str) -> bool:
        if not self._policy_matches_all_pods(policy):
            return False

        policy_types = set(policy.spec.policy_types or [])
        if direction not in policy_types:
            return False

        if direction == "Ingress":
            return len(policy.spec.ingress or []) == 0
        return len(policy.spec.egress or []) == 0

    def _peer_is_broad(self, peer: client.V1NetworkPolicyPeer) -> bool:
        has_pod_selector = bool(peer.pod_selector and (peer.pod_selector.match_labels or peer.pod_selector.match_expressions))
        has_namespace_selector = bool(peer.namespace_selector and (peer.namespace_selector.match_labels or peer.namespace_selector.match_expressions))
        has_ip_block = bool(peer.ip_block)
        if has_ip_block:
            return False
        return not has_pod_selector and not has_namespace_selector

    def _ip_block_is_world_open(self, cidr: Optional[str], exceptions: Optional[List[str]]) -> bool:
        if not cidr:
            return False
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        if exceptions:
            return False
        return network.prefixlen == 0

    def _check_network_policy_strength(self, policy: client.V1NetworkPolicy, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        spec = policy.spec
        ingress_rules = spec.ingress or []
        egress_rules = spec.egress or []
        policy_types = set(spec.policy_types or [])

        if "Ingress" in policy_types:
            for rule in ingress_rules:
                peers = rule._from or []
                ports = rule.ports or []
                if not peers and not ports:
                    findings.append({
                        "resource": resource,
                        "severity": "HIGH",
                        "issue": "NetworkPolicy Allows All Ingress",
                        "description": f"NetworkPolicy {resource['name']} contains an ingress rule that allows traffic from any source to any port.",
                        "recommendation": "Constrain ingress rules with explicit peers and destination ports.",
                        "detection_tool": "kubernetes-networkpolicy-checker",
                    })
                    continue

                if any(self._peer_is_broad(peer) for peer in peers):
                    findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Broad Ingress Peer Selector",
                        "description": f"NetworkPolicy {resource['name']} contains an ingress peer with an unconstrained pod or namespace selector.",
                        "recommendation": "Restrict ingress peers to specific namespaces, labels, or CIDRs.",
                        "detection_tool": "kubernetes-networkpolicy-checker",
                    })
                    break

                if any(
                    self._ip_block_is_world_open(peer.ip_block.cidr, peer.ip_block._except)
                    for peer in peers
                    if peer.ip_block
                ):
                    findings.append({
                        "resource": resource,
                        "severity": "HIGH",
                        "issue": "Ingress Allowed From Entire Internet",
                        "description": f"NetworkPolicy {resource['name']} allows ingress from 0.0.0.0/0 or ::/0.",
                        "recommendation": "Replace world-open IP blocks with restricted CIDRs or namespace/pod selectors.",
                        "detection_tool": "kubernetes-networkpolicy-checker",
                    })
                    break

        if "Egress" in policy_types:
            for rule in egress_rules:
                peers = rule.to or []
                ports = rule.ports or []
                if not peers and not ports:
                    findings.append({
                        "resource": resource,
                        "severity": "HIGH",
                        "issue": "NetworkPolicy Allows All Egress",
                        "description": f"NetworkPolicy {resource['name']} contains an egress rule that allows traffic to any destination on any port.",
                        "recommendation": "Constrain egress rules with explicit destinations and ports.",
                        "detection_tool": "kubernetes-networkpolicy-checker",
                    })
                    continue

                if any(self._peer_is_broad(peer) for peer in peers):
                    findings.append({
                        "resource": resource,
                        "severity": "MEDIUM",
                        "issue": "Broad Egress Peer Selector",
                        "description": f"NetworkPolicy {resource['name']} contains an egress peer with an unconstrained pod or namespace selector.",
                        "recommendation": "Restrict egress peers to specific namespaces, labels, or CIDRs.",
                        "detection_tool": "kubernetes-networkpolicy-checker",
                    })
                    break

                if any(
                    self._ip_block_is_world_open(peer.ip_block.cidr, peer.ip_block._except)
                    for peer in peers
                    if peer.ip_block
                ):
                    findings.append({
                        "resource": resource,
                        "severity": "HIGH",
                        "issue": "Egress Allowed To Entire Internet",
                        "description": f"NetworkPolicy {resource['name']} allows egress to 0.0.0.0/0 or ::/0.",
                        "recommendation": "Restrict egress destinations to approved CIDRs, services, or namespaces.",
                        "detection_tool": "kubernetes-networkpolicy-checker",
                    })
                    break

        return findings

    def _severity_rank(self, severity: str) -> int:
        return {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }.get(severity, 0)

    def _vulnerability_sort_key(self, vuln: Vulnerability) -> Tuple[int, float, str]:
        severity_name = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
        return (
            self._severity_rank(severity_name),
            vuln.cvss_score or 0.0,
            vuln.vuln_id,
        )

    def _compliance_controls_for_finding(self, finding: Dict[str, Any]) -> List[str]:
        controls: Set[str] = set(finding.get("compliance", []))
        detection_tool = finding.get("detection_tool", "")
        issue = finding.get("issue", "")

        if detection_tool == "kubernetes-namespace-checker":
            controls.update({
                "CIS-K8S-POD-SECURITY-ENFORCEMENT",
                "NSA-CISA-K8S-ADMISSION-AND-POD-SECURITY",
            })

        if detection_tool == "kubernetes-pod-checker":
            controls.update({
                "CIS-K8S-WORKLOAD-HARDENING",
                "NSA-CISA-K8S-HARDEN-WORKLOADS",
            })

        if detection_tool == "kubernetes-node-checker":
            controls.update({
                "CIS-K8S-NODE-POSTURE",
                "NSA-CISA-K8S-HARDEN-NODES",
            })

        if detection_tool == "kubernetes-managed-cluster-checker":
            if "Load Balancer" in issue or "LoadBalancer" in issue:
                controls.update({
                    "CIS-K8S-EXPOSURE-CONTROL",
                    "NSA-CISA-K8S-MINIMIZE-EXPOSURE",
                })
            if "Provisioner" in issue:
                controls.update({
                    "CIS-K8S-STORAGE-HARDENING",
                    "NSA-CISA-K8S-SECURE-STORAGE",
                })
            if "Workload Identity" in issue:
                controls.update({
                    "CIS-K8S-SERVICEACCOUNT-MINIMIZATION",
                    "NSA-CISA-K8S-HARDEN-SERVICE-ACCOUNTS",
                })

        if detection_tool == "kubernetes-resource-checker":
            controls.update({
                "CIS-K8S-RESOURCE-GOVERNANCE",
                "NSA-CISA-K8S-HARDEN-WORKLOADS",
            })

        if detection_tool in {"kubernetes-service-checker", "kubernetes-ingress-checker"}:
            controls.update({
                "CIS-K8S-EXPOSURE-CONTROL",
                "NSA-CISA-K8S-MINIMIZE-EXPOSURE",
            })

        if detection_tool == "kubernetes-networkpolicy-checker":
            controls.update({
                "CIS-K8S-NETWORK-SEGMENTATION",
                "NSA-CISA-K8S-SEGMENT-NETWORK",
            })

        if detection_tool == "kubernetes-rbac-checker":
            controls.update({
                "CIS-K8S-RBAC-LEAST-PRIVILEGE",
                "NSA-CISA-K8S-RESTRICT-RBAC",
            })

        if detection_tool == "kubernetes-serviceaccount-checker":
            controls.update({
                "CIS-K8S-SERVICEACCOUNT-MINIMIZATION",
                "NSA-CISA-K8S-HARDEN-SERVICE-ACCOUNTS",
            })

        if detection_tool == "kubernetes-secret-checker":
            controls.update({
                "CIS-K8S-SECRETS-MANAGEMENT",
                "NSA-CISA-K8S-RESTRICT-SECRETS",
            })

        if detection_tool in {"kubernetes-image-checker", "trivy-image-scan"}:
            controls.update({
                "CIS-K8S-IMAGE-HYGIENE",
                "NSA-CISA-K8S-VERIFY-IMAGES",
            })

        if detection_tool == "kubernetes-storage-checker":
            controls.update({
                "CIS-K8S-STORAGE-HARDENING",
                "NSA-CISA-K8S-SECURE-STORAGE",
            })

        if (
            "Default Service Account" in issue
            or "Token Auto-Mount" in issue
            or "High-Risk Service Account" in issue
            or "Service Account Bound" in issue
        ):
            controls.update({
                "CIS-K8S-SERVICEACCOUNT-MINIMIZATION",
                "NSA-CISA-K8S-HARDEN-SERVICE-ACCOUNTS",
            })

        if "High-Risk Role" in issue or "Cluster Admin" in issue or "cluster-admin" in issue.lower():
            controls.update({
                "CIS-K8S-RBAC-LEAST-PRIVILEGE",
                "NSA-CISA-K8S-RESTRICT-RBAC",
            })

        return sorted(controls)

    def _annotate_findings_with_compliance(self, findings: List[Dict[str, Any]]) -> None:
        for finding in findings:
            finding["compliance"] = self._compliance_controls_for_finding(finding)

    def _build_compliance_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        framework_summaries: Dict[str, Any] = {}

        for framework, controls in self.COMPLIANCE_CONTROL_CATALOG.items():
            control_rows: List[Dict[str, Any]] = []
            findings_by_control: Dict[str, List[Dict[str, Any]]] = {}
            failed_controls = 0

            for control, title in controls.items():
                matching_findings = [finding for finding in findings if control in finding.get("compliance", [])]
                findings_by_control[control] = [
                    {
                        "severity": finding.get("severity", "INFO"),
                        "issue": finding.get("issue", "Security Issue"),
                        "resource": finding.get("resource", {}).get("name", "unknown"),
                    }
                    for finding in matching_findings[:10]
                ]
                status = "FAIL" if matching_findings else "PASS"
                if matching_findings:
                    failed_controls += 1
                control_rows.append({
                    "control": control,
                    "title": title,
                    "status": status,
                    "findings_count": len(matching_findings),
                })

            total_controls = len(controls)
            passing_controls = total_controls - failed_controls
            compliance_percentage = round((passing_controls / total_controls * 100), 2) if total_controls else 100.0
            framework_summaries[framework] = {
                "framework": framework,
                "mapping_scope": "Best-effort control-family mapping based on the Kubernetes checks implemented by this scanner.",
                "total_controls_checked": total_controls,
                "failed_controls": failed_controls,
                "passing_controls": passing_controls,
                "compliance_percentage": compliance_percentage,
                "controls": control_rows,
                "findings_by_control": findings_by_control,
            }

        return framework_summaries

    async def _scan_cluster_images(
        self,
        pods: List[client.V1Pod],
        controllers: List[Tuple[str, str, str, Optional[client.V1PodSpec]]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str], Dict[str, Any]]:
        image_resources: List[Dict[str, Any]] = []
        image_findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        image_targets = self._collect_deep_scan_images(pods, controllers)

        if not image_targets:
            return image_resources, image_findings, errors, {
                "performed": True,
                "scanned_images": 0,
                "images_with_vulnerabilities": 0,
                "vulnerabilities_found": 0,
                "skipped_images": 0,
            }

        if "trivy" not in self.vulnerability_scanner.tools_available:
            errors.append("Trivy is not available; skipping container image vulnerability scanning.")
            return image_resources, image_findings, errors, {
                "performed": False,
                "reason": "trivy unavailable",
                "candidate_images": len(image_targets),
            }

        sorted_images = sorted(image_targets.items(), key=lambda item: item[0])
        images_to_scan = sorted_images[:self.MAX_DEEP_SCAN_IMAGES]
        skipped_images = max(0, len(sorted_images) - len(images_to_scan))

        images_with_vulnerabilities = 0
        total_vulnerabilities = 0

        for image, image_info in images_to_scan:
            image_resource = self._image_resource(
                image,
                image_info["namespaces"],
                image_info["workloads"],
            )
            image_resources.append(image_resource)

            try:
                vulnerabilities = await self.vulnerability_scanner.scan_with_trivy(image, scan_type="image")
            except Exception as exc:
                logger.error("[Kubernetes] Image vulnerability scan failed for %s: %s", image, exc)
                errors.append(f"Image vulnerability scan failed for {image}: {exc}")
                continue

            if not vulnerabilities:
                continue

            images_with_vulnerabilities += 1
            total_vulnerabilities += len(vulnerabilities)
            severity_counts = Counter(
                vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
                for vuln in vulnerabilities
            )
            highest_vuln = max(vulnerabilities, key=self._vulnerability_sort_key)
            highest_severity = highest_vuln.severity.value if hasattr(highest_vuln.severity, "value") else str(highest_vuln.severity)

            image_findings.append({
                "resource": image_resource,
                "severity": highest_severity,
                "issue": "Container Image Vulnerabilities Detected",
                "description": (
                    f"Image {image} used by {len(image_info['workloads'])} workload(s) has "
                    f"{len(vulnerabilities)} known vulnerabilities "
                    f"(CRITICAL: {severity_counts.get('CRITICAL', 0)}, "
                    f"HIGH: {severity_counts.get('HIGH', 0)}, "
                    f"MEDIUM: {severity_counts.get('MEDIUM', 0)}, "
                    f"LOW: {severity_counts.get('LOW', 0)})."
                ),
                "recommendation": "Upgrade the image to a patched version or rebuild from a more secure base image.",
                "detection_tool": "trivy-image-scan",
            })

            top_vulnerabilities = sorted(
                vulnerabilities,
                key=self._vulnerability_sort_key,
                reverse=True,
            )[:self.MAX_VULNERABILITY_FINDINGS_PER_IMAGE]

            for vuln in top_vulnerabilities:
                severity = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
                detail_parts = []
                if vuln.affected_package:
                    detail_parts.append(f"package {vuln.affected_package}")
                if vuln.fixed_version:
                    detail_parts.append(f"fixed in {vuln.fixed_version}")
                detail_suffix = f" ({', '.join(detail_parts)})" if detail_parts else ""

                image_findings.append({
                    "resource": image_resource,
                    "severity": severity,
                    "issue": f"Container Image Vulnerability: {vuln.vuln_id}",
                    "description": f"{vuln.title} affects image {image}{detail_suffix}. {vuln.description[:300]}".strip(),
                    "recommendation": (
                        f"Upgrade or rebuild image {image}"
                        + (f" so that {vuln.affected_package} is at least {vuln.fixed_version}." if vuln.affected_package and vuln.fixed_version else ".")
                    ),
                    "detection_tool": "trivy-image-scan",
                    "references": vuln.references,
                    "metadata": {
                        "vuln_id": vuln.vuln_id,
                        "package": vuln.affected_package,
                        "fixed_version": vuln.fixed_version,
                        "cvss_score": vuln.cvss_score,
                        "workloads": sorted(image_info["workloads"]),
                    },
                })

            omitted = len(vulnerabilities) - len(top_vulnerabilities)
            if omitted > 0:
                image_findings.append({
                    "resource": image_resource,
                    "severity": "LOW",
                    "issue": "Additional Image Vulnerabilities Omitted",
                    "description": f"Image {image} has {omitted} additional vulnerability finding(s) not expanded individually in this report.",
                    "recommendation": "Review the full Trivy output or raise the reporting cap if you need exhaustive package-level details.",
                    "detection_tool": "trivy-image-scan",
                })

        return image_resources, image_findings, errors, {
            "performed": True,
            "scanned_images": len(images_to_scan),
            "images_with_vulnerabilities": images_with_vulnerabilities,
            "vulnerabilities_found": total_vulnerabilities,
            "skipped_images": skipped_images,
        }

    def _check_role_risk(
        self,
        role_kind: str,
        role_name: str,
        namespace: Optional[str],
        rules: List[Any],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
        findings: List[Dict[str, Any]] = []
        risk_markers: List[Dict[str, str]] = []
        resource = self._rbac_rule_resource(role_kind, role_name, namespace, len(rules or []))

        for rule in rules or []:
            verbs = set(getattr(rule, "verbs", None) or [])
            resources = set(getattr(rule, "resources", None) or [])
            api_groups = set(getattr(rule, "api_groups", None) or [])
            non_resource_urls = set(getattr(rule, "non_resource_urls", None) or [])

            if "*" in verbs and ("*" in resources or "*" in api_groups or "*" in non_resource_urls):
                findings.append({
                    "resource": resource,
                    "severity": "CRITICAL",
                    "issue": "Wildcard Administrative Permissions",
                    "description": f"{role_kind} {resource['name']} grants wildcard access across verbs, resources, or API groups.",
                    "recommendation": "Replace wildcard permissions with narrowly scoped verbs, resources, and API groups.",
                    "detection_tool": "kubernetes-rbac-checker",
                })
                risk_markers.append({"severity": "CRITICAL", "issue": "wildcard administrative permissions"})

            if {"bind", "escalate"} & verbs:
                findings.append({
                    "resource": resource,
                    "severity": "CRITICAL",
                    "issue": "RBAC Privilege Escalation Verbs",
                    "description": f"{role_kind} {resource['name']} includes bind or escalate verbs.",
                    "recommendation": "Remove bind/escalate unless this role is strictly limited to trusted administrators.",
                    "detection_tool": "kubernetes-rbac-checker",
                })
                risk_markers.append({"severity": "CRITICAL", "issue": "privilege escalation verbs"})

            if "impersonate" in verbs:
                findings.append({
                    "resource": resource,
                    "severity": "HIGH",
                    "issue": "RBAC Impersonation Permission",
                    "description": f"{role_kind} {resource['name']} can impersonate other identities.",
                    "recommendation": "Restrict impersonation privileges to tightly controlled break-glass roles.",
                    "detection_tool": "kubernetes-rbac-checker",
                })
                risk_markers.append({"severity": "HIGH", "issue": "impersonation permission"})

            if "*" in resources or "secrets" in resources:
                if verbs & {"get", "list", "watch", "create", "update", "patch", "delete", "*"}:
                    findings.append({
                        "resource": resource,
                        "severity": "HIGH",
                        "issue": "Secrets Access Permission",
                        "description": f"{role_kind} {resource['name']} can access or modify Kubernetes secrets.",
                        "recommendation": "Restrict secret access to only the identities and namespaces that require it.",
                        "detection_tool": "kubernetes-rbac-checker",
                    })
                    risk_markers.append({"severity": "HIGH", "issue": "secrets access"})

        return findings, risk_markers

    def _check_binding_to_risky_role(
        self,
        binding: Any,
        resource_type: str,
        namespace: Optional[str],
        risky_role_markers: List[Dict[str, str]],
    ) -> Optional[Dict[str, Any]]:
        if not risky_role_markers:
            return None

        top_risk = max(risky_role_markers, key=lambda item: self._severity_rank(item["severity"]))
        issue_list = ", ".join(sorted({item["issue"] for item in risky_role_markers}))

        return {
            "resource": self._binding_resource(binding, resource_type, namespace),
            "severity": top_risk["severity"],
            "issue": "High-Risk RBAC Role Bound to Subjects",
            "description": f"{resource_type.replace('_', ' ').title()} {namespace + '/' if namespace else ''}{binding.metadata.name} binds subjects to a role with {issue_list}.",
            "recommendation": "Review the bound subjects and replace the risky role with a least-privilege role where possible.",
            "detection_tool": "kubernetes-rbac-checker",
        }

    async def _check_cluster_security(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            namespaces = self.core_v1.list_namespace().items if self.core_v1 else []
            nodes = self.core_v1.list_node().items if self.core_v1 else []
            pods = self.core_v1.list_pod_for_all_namespaces().items if self.core_v1 else []
            services = self.core_v1.list_service_for_all_namespaces().items if self.core_v1 else []
            service_accounts = self.core_v1.list_service_account_for_all_namespaces().items if self.core_v1 else []
            secrets = self.core_v1.list_secret_for_all_namespaces().items if self.core_v1 else []
            persistent_volumes = self.core_v1.list_persistent_volume().items if self.core_v1 else []
            persistent_volume_claims = self.core_v1.list_persistent_volume_claim_for_all_namespaces().items if self.core_v1 else []
            ingresses = self.networking_v1.list_ingress_for_all_namespaces().items if self.networking_v1 else []
            network_policies = self.networking_v1.list_network_policy_for_all_namespaces().items if self.networking_v1 else []
            storage_classes = self.storage_v1.list_storage_class().items if self.storage_v1 else []
            deployments = self.apps_v1.list_deployment_for_all_namespaces().items if self.apps_v1 else []
            statefulsets = self.apps_v1.list_stateful_set_for_all_namespaces().items if self.apps_v1 else []
            daemonsets = self.apps_v1.list_daemon_set_for_all_namespaces().items if self.apps_v1 else []
            jobs = self.batch_v1.list_job_for_all_namespaces().items if self.batch_v1 else []
            cronjobs = self.batch_v1.list_cron_job_for_all_namespaces().items if self.batch_v1 else []
            cluster_roles = self.rbac_v1.list_cluster_role().items if self.rbac_v1 else []
            roles = self.rbac_v1.list_role_for_all_namespaces().items if self.rbac_v1 else []
            cluster_role_bindings = self.rbac_v1.list_cluster_role_binding().items if self.rbac_v1 else []
            role_bindings = self.rbac_v1.list_role_binding_for_all_namespaces().items if self.rbac_v1 else []

            namespaces_with_policies: Set[str] = {np.metadata.namespace for np in network_policies}
            namespaces_with_pods: Set[str] = {pod.metadata.namespace for pod in pods if pod.metadata and pod.metadata.namespace}
            managed_platforms = self._infer_managed_cluster_platforms(nodes, storage_classes)
            risky_roles: Dict[Tuple[str, Optional[str], str], List[Dict[str, str]]] = {}
            risky_service_accounts: Dict[Tuple[str, str], List[Dict[str, str]]] = {}
            policies_by_namespace: Dict[str, List[client.V1NetworkPolicy]] = {}
            controller_specs: List[Tuple[str, str, str, Optional[client.V1PodSpec]]] = []
            service_account_usage: Dict[Tuple[str, str], Set[str]] = {}
            secret_usage: Dict[Tuple[str, str], Set[str]] = {}
            persistent_volume_claim_usage: Dict[Tuple[str, str], Set[str]] = {}
            pod_records: List[Tuple[Dict[str, Any], str, str]] = []
            controller_records: List[Tuple[Dict[str, Any], str, str]] = []

            for policy in network_policies:
                policies_by_namespace.setdefault(policy.metadata.namespace, []).append(policy)

            for ns in namespaces:
                ns_resource = self._namespace_resource(ns)
                enforce = (ns.metadata.labels or {}).get("pod-security.kubernetes.io/enforce")
                if ns.metadata.name not in {"kube-system", "kube-public", "kube-node-lease"} and not enforce:
                    findings.append({
                        "resource": ns_resource,
                        "severity": "MEDIUM",
                        "issue": "Namespace Missing Pod Security Enforcement",
                        "description": f"Namespace {ns.metadata.name} does not declare pod-security.kubernetes.io/enforce labels.",
                        "recommendation": "Apply Pod Security Standards labels or an equivalent admission policy.",
                        "detection_tool": "kubernetes-namespace-checker",
                    })

            for node in nodes:
                node_resource = self._node_resource(node)
                findings.extend(self._check_node_security(node, node_resource))
                if "gke" in managed_platforms:
                    findings.extend(self._check_gke_node_identity(node, node_resource))

            for pod in pods:
                pod_resource = self._pod_resource(pod)
                findings.extend(self._check_pod_security(pod, pod_resource))
                service_account_name = pod.spec.service_account_name or "default"
                namespace = pod.metadata.namespace
                workload_name = f"Pod {namespace}/{pod.metadata.name}"
                self._record_service_account_usage(service_account_usage, namespace, service_account_name, workload_name)
                self._record_secret_usage_from_workload(pod.spec, namespace, workload_name, secret_usage)
                self._record_persistent_volume_claim_usage_from_workload(
                    pod.spec,
                    namespace,
                    workload_name,
                    persistent_volume_claim_usage,
                )
                pod_records.append((pod_resource, namespace, service_account_name))

            for deployment in deployments:
                controller_specs.append((
                    "Deployment",
                    deployment.metadata.namespace,
                    deployment.metadata.name,
                    deployment.spec.template.spec,
                ))
                deployment_resource = self._controller_resource(
                    "Deployment",
                    deployment.metadata.namespace,
                    deployment.metadata.name,
                    deployment.metadata.labels or {},
                    deployment.spec.template.spec,
                    desired_replicas=deployment.spec.replicas,
                    ready_replicas=getattr(deployment.status, "ready_replicas", None),
                )
                findings.extend(self._check_controller_security(deployment_resource, deployment.spec.template.spec, "Deployment"))
                namespace = deployment.metadata.namespace
                service_account_name = deployment.spec.template.spec.service_account_name or "default"
                workload_name = f"Deployment {namespace}/{deployment.metadata.name}"
                self._record_service_account_usage(service_account_usage, namespace, service_account_name, workload_name)
                self._record_secret_usage_from_workload(deployment.spec.template.spec, namespace, workload_name, secret_usage)
                self._record_persistent_volume_claim_usage_from_workload(
                    deployment.spec.template.spec,
                    namespace,
                    workload_name,
                    persistent_volume_claim_usage,
                )
                controller_records.append((deployment_resource, namespace, service_account_name))

            for statefulset in statefulsets:
                controller_specs.append((
                    "StatefulSet",
                    statefulset.metadata.namespace,
                    statefulset.metadata.name,
                    statefulset.spec.template.spec,
                ))
                statefulset_resource = self._controller_resource(
                    "StatefulSet",
                    statefulset.metadata.namespace,
                    statefulset.metadata.name,
                    statefulset.metadata.labels or {},
                    statefulset.spec.template.spec,
                    desired_replicas=statefulset.spec.replicas,
                    ready_replicas=getattr(statefulset.status, "ready_replicas", None),
                )
                findings.extend(self._check_controller_security(statefulset_resource, statefulset.spec.template.spec, "StatefulSet"))
                namespace = statefulset.metadata.namespace
                service_account_name = statefulset.spec.template.spec.service_account_name or "default"
                workload_name = f"StatefulSet {namespace}/{statefulset.metadata.name}"
                self._record_service_account_usage(service_account_usage, namespace, service_account_name, workload_name)
                self._record_secret_usage_from_workload(statefulset.spec.template.spec, namespace, workload_name, secret_usage)
                self._record_persistent_volume_claim_usage_from_workload(
                    statefulset.spec.template.spec,
                    namespace,
                    workload_name,
                    persistent_volume_claim_usage,
                )
                controller_records.append((statefulset_resource, namespace, service_account_name))

            for daemonset in daemonsets:
                controller_specs.append((
                    "DaemonSet",
                    daemonset.metadata.namespace,
                    daemonset.metadata.name,
                    daemonset.spec.template.spec,
                ))
                daemonset_resource = self._controller_resource(
                    "DaemonSet",
                    daemonset.metadata.namespace,
                    daemonset.metadata.name,
                    daemonset.metadata.labels or {},
                    daemonset.spec.template.spec,
                    desired_replicas=getattr(daemonset.status, "desired_number_scheduled", None),
                    ready_replicas=getattr(daemonset.status, "number_ready", None),
                )
                findings.extend(self._check_controller_security(daemonset_resource, daemonset.spec.template.spec, "DaemonSet"))
                namespace = daemonset.metadata.namespace
                service_account_name = daemonset.spec.template.spec.service_account_name or "default"
                workload_name = f"DaemonSet {namespace}/{daemonset.metadata.name}"
                self._record_service_account_usage(service_account_usage, namespace, service_account_name, workload_name)
                self._record_secret_usage_from_workload(daemonset.spec.template.spec, namespace, workload_name, secret_usage)
                self._record_persistent_volume_claim_usage_from_workload(
                    daemonset.spec.template.spec,
                    namespace,
                    workload_name,
                    persistent_volume_claim_usage,
                )
                controller_records.append((daemonset_resource, namespace, service_account_name))

            for job in jobs:
                controller_specs.append((
                    "Job",
                    job.metadata.namespace,
                    job.metadata.name,
                    job.spec.template.spec,
                ))
                job_resource = self._controller_resource(
                    "Job",
                    job.metadata.namespace,
                    job.metadata.name,
                    job.metadata.labels or {},
                    job.spec.template.spec,
                    desired_replicas=getattr(job.spec, "parallelism", None),
                    ready_replicas=getattr(job.status, "succeeded", None),
                )
                findings.extend(self._check_controller_security(job_resource, job.spec.template.spec, "Job"))
                namespace = job.metadata.namespace
                service_account_name = job.spec.template.spec.service_account_name or "default"
                workload_name = f"Job {namespace}/{job.metadata.name}"
                self._record_service_account_usage(service_account_usage, namespace, service_account_name, workload_name)
                self._record_secret_usage_from_workload(job.spec.template.spec, namespace, workload_name, secret_usage)
                self._record_persistent_volume_claim_usage_from_workload(
                    job.spec.template.spec,
                    namespace,
                    workload_name,
                    persistent_volume_claim_usage,
                )
                controller_records.append((job_resource, namespace, service_account_name))

            for cronjob in cronjobs:
                cronjob_template_spec = (
                    cronjob.spec.job_template.spec.template.spec
                    if cronjob.spec and cronjob.spec.job_template and cronjob.spec.job_template.spec
                    else None
                )
                controller_specs.append((
                    "CronJob",
                    cronjob.metadata.namespace,
                    cronjob.metadata.name,
                    cronjob_template_spec,
                ))
                cronjob_resource = self._controller_resource(
                    "CronJob",
                    cronjob.metadata.namespace,
                    cronjob.metadata.name,
                    cronjob.metadata.labels or {},
                    cronjob_template_spec,
                    schedule=getattr(cronjob.spec, "schedule", None),
                )
                findings.extend(self._check_controller_security(cronjob_resource, cronjob_template_spec, "CronJob"))
                namespace = cronjob.metadata.namespace
                service_account_name = (cronjob_template_spec.service_account_name if cronjob_template_spec else None) or "default"
                workload_name = f"CronJob {namespace}/{cronjob.metadata.name}"
                self._record_service_account_usage(service_account_usage, namespace, service_account_name, workload_name)
                self._record_secret_usage_from_workload(cronjob_template_spec, namespace, workload_name, secret_usage)
                self._record_persistent_volume_claim_usage_from_workload(
                    cronjob_template_spec,
                    namespace,
                    workload_name,
                    persistent_volume_claim_usage,
                )
                controller_records.append((cronjob_resource, namespace, service_account_name))

            for service_account in service_accounts:
                namespace = service_account.metadata.namespace
                consumer_name = f"ServiceAccount {namespace}/{service_account.metadata.name}"
                for secret_ref in service_account.secrets or []:
                    self._record_secret_usage(secret_usage, namespace, getattr(secret_ref, "name", None), consumer_name)
                for image_pull_secret in service_account.image_pull_secrets or []:
                    self._record_secret_usage(secret_usage, namespace, getattr(image_pull_secret, "name", None), consumer_name)

            for svc in services:
                svc_resource = self._service_resource(svc)
                findings.extend(self._check_service_exposure(svc, svc_resource))
                if "eks" in managed_platforms:
                    findings.extend(self._check_eks_service_exposure(svc, svc_resource))
                if "gke" in managed_platforms:
                    findings.extend(self._check_gke_service_exposure(svc, svc_resource))

            for ingress in ingresses:
                ingress_resource = self._ingress_resource(ingress)
                findings.extend(self._check_ingress_exposure(ingress, ingress_resource))

            for policy in network_policies:
                policy_resource = self._network_policy_resource(policy)
                findings.extend(self._check_network_policy_strength(policy, policy_resource))

            for persistent_volume in persistent_volumes:
                persistent_volume_resource = self._persistent_volume_resource(persistent_volume)
                findings.extend(self._check_persistent_volume_security(persistent_volume, persistent_volume_resource))

            for persistent_volume_claim in persistent_volume_claims:
                persistent_volume_claim_resource = self._persistent_volume_claim_resource(persistent_volume_claim)
                findings.extend(self._check_persistent_volume_claim_security(
                    persistent_volume_claim,
                    persistent_volume_claim_resource,
                    persistent_volume_claim_usage.get(
                        (persistent_volume_claim.metadata.namespace, persistent_volume_claim.metadata.name),
                        set(),
                    ),
                ))

            for storage_class in storage_classes:
                storage_class_resource = self._storage_class_resource(storage_class)
                findings.extend(self._check_storage_class_security(storage_class, storage_class_resource))
                if "eks" in managed_platforms:
                    findings.extend(self._check_eks_storage_class(storage_class, storage_class_resource))
                if "gke" in managed_platforms:
                    findings.extend(self._check_gke_storage_class(storage_class, storage_class_resource))

            for namespace in sorted(namespaces_with_pods):
                if namespace not in namespaces_with_policies and namespace not in {"kube-system", "kube-public", "kube-node-lease"}:
                    findings.append({
                        "resource": {
                            "provider": "kubernetes",
                            "resource_type": "namespace",
                            "name": namespace,
                            "region": self.cluster_name or self.active_context or "cluster",
                            "config": {},
                            "is_public": False,
                        },
                        "severity": "MEDIUM",
                        "issue": "Namespace Missing Network Policies",
                        "description": f"Namespace {namespace} has workloads but no NetworkPolicy objects.",
                        "recommendation": "Define default-deny ingress and egress NetworkPolicies for this namespace.",
                        "detection_tool": "kubernetes-networkpolicy-checker",
                    })
                elif namespace not in {"kube-system", "kube-public", "kube-node-lease"}:
                    namespace_policies = policies_by_namespace.get(namespace, [])
                    has_default_deny_ingress = any(
                        self._policy_has_default_deny(policy, "Ingress")
                        for policy in namespace_policies
                    )
                    has_default_deny_egress = any(
                        self._policy_has_default_deny(policy, "Egress")
                        for policy in namespace_policies
                    )

                    if not has_default_deny_ingress:
                        findings.append({
                            "resource": {
                                "provider": "kubernetes",
                                "resource_type": "namespace",
                                "name": namespace,
                                "region": self.cluster_name or self.active_context or "cluster",
                                "config": {},
                                "is_public": False,
                            },
                            "severity": "MEDIUM",
                            "issue": "Namespace Missing Default-Deny Ingress",
                            "description": f"Namespace {namespace} has NetworkPolicy objects but none enforce default-deny ingress for all pods.",
                            "recommendation": "Add an ingress default-deny NetworkPolicy that selects all pods before layering allow rules.",
                            "detection_tool": "kubernetes-networkpolicy-checker",
                        })

                    if not has_default_deny_egress:
                        findings.append({
                            "resource": {
                                "provider": "kubernetes",
                                "resource_type": "namespace",
                                "name": namespace,
                                "region": self.cluster_name or self.active_context or "cluster",
                                "config": {},
                                "is_public": False,
                            },
                            "severity": "MEDIUM",
                            "issue": "Namespace Missing Default-Deny Egress",
                            "description": f"Namespace {namespace} has NetworkPolicy objects but none enforce default-deny egress for all pods.",
                            "recommendation": "Add an egress default-deny NetworkPolicy that selects all pods before layering allow rules.",
                            "detection_tool": "kubernetes-networkpolicy-checker",
                        })

            for cluster_role in cluster_roles:
                role_findings, role_markers = self._check_role_risk(
                    "ClusterRole",
                    cluster_role.metadata.name,
                    None,
                    cluster_role.rules or [],
                )
                findings.extend(role_findings)
                if role_markers:
                    risky_roles[("ClusterRole", None, cluster_role.metadata.name)] = role_markers

            for role in roles:
                role_findings, role_markers = self._check_role_risk(
                    "Role",
                    role.metadata.name,
                    role.metadata.namespace,
                    role.rules or [],
                )
                findings.extend(role_findings)
                if role_markers:
                    risky_roles[("Role", role.metadata.namespace, role.metadata.name)] = role_markers

            for binding in cluster_role_bindings:
                role_ref = getattr(binding.role_ref, "name", "")
                if role_ref == "cluster-admin":
                    findings.append({
                        "resource": self._binding_resource(binding, "cluster_role_binding"),
                        "severity": "CRITICAL",
                        "issue": "Cluster Admin Binding",
                        "description": f"ClusterRoleBinding {binding.metadata.name} grants cluster-admin privileges.",
                        "recommendation": "Review subjects bound to cluster-admin and replace with least-privilege roles where possible.",
                        "detection_tool": "kubernetes-rbac-checker",
                    })
                    self._record_service_account_subject_risks(
                        binding.subjects,
                        None,
                        [{"severity": "CRITICAL", "issue": "cluster-admin privileges"}],
                        risky_service_accounts,
                    )
                self._record_service_account_subject_risks(
                    binding.subjects,
                    None,
                    risky_roles.get(("ClusterRole", None, role_ref), []),
                    risky_service_accounts,
                )
                risky_binding = self._check_binding_to_risky_role(
                    binding,
                    "cluster_role_binding",
                    None,
                    risky_roles.get(("ClusterRole", None, role_ref), []),
                )
                if risky_binding:
                    findings.append(risky_binding)

            for binding in role_bindings:
                role_ref = getattr(binding.role_ref, "name", "")
                role_kind = getattr(binding.role_ref, "kind", "Role")
                if role_ref == "cluster-admin":
                    findings.append({
                        "resource": self._binding_resource(binding, "role_binding", binding.metadata.namespace),
                        "severity": "HIGH",
                        "issue": "Namespace Binding to Cluster Admin",
                        "description": f"RoleBinding {binding.metadata.namespace}/{binding.metadata.name} references cluster-admin.",
                        "recommendation": "Replace cluster-admin with a namespace-scoped Role or ClusterRole with least privilege.",
                        "detection_tool": "kubernetes-rbac-checker",
                    })
                    self._record_service_account_subject_risks(
                        binding.subjects,
                        binding.metadata.namespace,
                        [{"severity": "HIGH", "issue": "cluster-admin privileges"}],
                        risky_service_accounts,
                    )
                if role_kind == "ClusterRole":
                    role_markers = risky_roles.get(("ClusterRole", None, role_ref), [])
                else:
                    role_markers = risky_roles.get(("Role", binding.metadata.namespace, role_ref), [])
                self._record_service_account_subject_risks(
                    binding.subjects,
                    binding.metadata.namespace,
                    role_markers,
                    risky_service_accounts,
                )
                risky_binding = self._check_binding_to_risky_role(
                    binding,
                    "role_binding",
                    binding.metadata.namespace,
                    role_markers,
                )
                if risky_binding:
                    findings.append(risky_binding)

            for service_account in service_accounts:
                sa_resource = self._service_account_resource(service_account)
                namespace = service_account.metadata.namespace
                name = service_account.metadata.name
                findings.extend(self._check_service_account_security(
                    service_account,
                    sa_resource,
                    service_account_usage.get((namespace, name), set()),
                    risky_service_accounts.get((namespace, name), []),
                ))

            for secret in secrets:
                secret_resource = self._secret_resource(secret)
                findings.extend(self._check_secret_security(
                    secret,
                    secret_resource,
                    secret_usage.get((secret.metadata.namespace, secret.metadata.name), set()),
                ))

            for resource, namespace, service_account_name in pod_records + controller_records:
                risky_service_account_finding = self._check_workload_service_account_risk(
                    resource,
                    service_account_name,
                    risky_service_accounts.get((namespace, service_account_name), []),
                )
                if risky_service_account_finding:
                    findings.append(risky_service_account_finding)

            return {
                "findings": findings,
                "errors": errors,
                "pods": pods,
                "controllers": controller_specs,
                "managed_platforms": sorted(managed_platforms),
            }
        except Exception as exc:
            logger.error("[Kubernetes] Security check failed: %s", exc)
            errors.append(str(exc))

        return {"findings": findings, "errors": errors, "pods": [], "controllers": [], "managed_platforms": []}

    async def _full_scan(
        self,
        account_id: str = "default",
        deep_scan: bool = False,
        offensive_scan: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "provider": "kubernetes",
            "account_id": account_id if account_id != "default" else (self.cluster_name or self.active_context or "default"),
            "resources": [],
            "findings": [],
            "errors": [],
            "summary": {},
            "deep_scan_enabled": deep_scan,
            "offensive_scan_requested": offensive_scan,
        }

        try:
            discovery = await self._discover_cluster_resources()
            results["resources"] = discovery.get("resources", [])

            security = await self._check_cluster_security()
            results["findings"] = security.get("findings", [])
            results["errors"].extend(security.get("errors", []))
            managed_platforms = security.get("managed_platforms", [])

            image_scan_summary = {"performed": False}
            if deep_scan:
                image_resources, image_findings, image_errors, image_scan_summary = await self._scan_cluster_images(
                    security.get("pods", []),
                    security.get("controllers", []),
                )
                results["resources"].extend(image_resources)
                results["findings"].extend(image_findings)
                results["errors"].extend(image_errors)

            self._annotate_findings_with_compliance(results["findings"])
            compliance_summary = self._build_compliance_summary(results["findings"])

            severity_counts = {key: 0 for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
            for finding in results["findings"]:
                sev = finding.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            results["summary"] = {
                "cluster_name": self.cluster_name,
                "context": self.active_context,
                "total_resources": len(results["resources"]),
                "total_findings": len(results["findings"]),
                "errors_count": len(results["errors"]),
                "by_severity": severity_counts,
                "image_vulnerability_scan": image_scan_summary,
                "managed_cluster_platforms": managed_platforms,
                "compliance": compliance_summary,
            }
            return results
        except Exception as exc:
            logger.error("[Kubernetes] Full scan failed: %s", exc)
            results["errors"].append(str(exc))
            return results


def create_kubernetes_server(cfg: Dict[str, Any]) -> KubernetesMCPServer:
    """Factory function to create a Kubernetes MCP server."""
    return KubernetesMCPServer(cfg)
