import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from kubernetes import client

from backend.mcp_servers.kubernetes_server import KubernetesMCPServer


class KubernetesLiveDocumentsTest(unittest.IsolatedAsyncioTestCase):
    async def test_sdk_list_items_without_type_meta_are_scanned(self):
        namespace = "cg-regression-lab"
        items = {
            "CoreV1Api": {
                "list_namespace": [client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace))],
                "list_pod_for_all_namespaces": [client.V1Pod(
                    metadata=client.V1ObjectMeta(name="unsafe", namespace=namespace),
                    spec=client.V1PodSpec(host_network=True, containers=[client.V1Container(
                        name="unsafe", image="nginx:latest",
                        security_context=client.V1SecurityContext(privileged=True),
                    )]),
                )],
                "list_service_for_all_namespaces": [client.V1Service(
                    metadata=client.V1ObjectMeta(name="public", namespace=namespace),
                    spec=client.V1ServiceSpec(type="NodePort", ports=[client.V1ServicePort(port=80)]),
                )],
            },
            "RbacAuthorizationV1Api": {
                "list_role_binding_for_all_namespaces": [client.V1RoleBinding(
                    metadata=client.V1ObjectMeta(name="admin", namespace=namespace),
                    role_ref=client.V1RoleRef(api_group="rbac.authorization.k8s.io", kind="ClusterRole", name="cluster-admin"),
                    subjects=[client.RbacV1Subject(kind="ServiceAccount", name="default", namespace=namespace)],
                )],
            },
        }
        api = client.ApiClient()
        with tempfile.TemporaryDirectory() as directory:
            scanner = KubernetesMCPServer({"root_path": directory})
            with ExitStack() as stack:
                stack.enter_context(patch("backend.mcp_servers.kubernetes_server.build_kubernetes_api_client", return_value=api))
                for api_name in ("CoreV1Api", "AppsV1Api", "BatchV1Api", "RbacAuthorizationV1Api", "NetworkingV1Api"):
                    mock_api = Mock()
                    scoped_items = items.get(api_name, {})
                    for method in dir(getattr(client, api_name)):
                        if method.startswith("list_") and not method.endswith("_with_http_info"):
                            getattr(mock_api, method).return_value = SimpleNamespace(items=scoped_items.get(method, []))
                    stack.enter_context(patch.object(client, api_name, return_value=mock_api))
                result = await scanner._full_live_scan()
        api.close()
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["summary"]["namespaces"], 1)
        kinds = {resource["config"].get("kind") for resource in result["resources"]}
        self.assertTrue({"Namespace", "Pod", "Service", "RoleBinding"}.issubset(kinds))
        issues = "\n".join(finding["issue"] for finding in result["findings"])
        self.assertIn("privileged", issues.lower())
        self.assertIn("hostnetwork", issues.lower())
        self.assertIn("cluster-admin", issues)
        self.assertIn("node port", issues.lower())
        self.assertIn("NetworkPolicy", issues)


if __name__ == "__main__":
    unittest.main()
