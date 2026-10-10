"""Exercise the real CloudGuard lab objects and scanner through a private SSH tunnel."""

import argparse
import ast
import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

import yaml
from kubernetes import client
from kubernetes.client.exceptions import ApiException

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.mcp_servers.kubernetes_server import KubernetesMCPServer, build_kubernetes_api_client


def lab_objects(namespace):
    source = ROOT / "backend/main.py"
    tree = ast.parse(source.read_text())
    names = {"_sandbox_iac_files", "_kubernetes_sandbox_objects"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if len(functions) != 2:
        raise RuntimeError("Could not load the project's actual Kubernetes lab template")
    scope = {"json": json, "Any": Any, "Dict": Dict, "List": List}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), scope)
    return scope["_kubernetes_sandbox_objects"](namespace)


def remote(args, command):
    return subprocess.run(
        ["ssh", "-i", args.ssh_key, "-o", "BatchMode=yes", f"root@{args.host}", command],
        check=True, capture_output=True, text=True,
    )


async def scan(args):
    namespace = f"cg-hostinger-smoke-{uuid.uuid4().hex[:8]}"
    tunnel = subprocess.Popen([
        "ssh", "-i", args.ssh_key, "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
        "-N", "-L", f"127.0.0.1:{args.local_port}:127.0.0.1:6443", f"root@{args.host}",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    core = None
    api = None
    report = {"namespace": namespace, "host": args.host, "cleanup_verified": False}
    try:
        for _ in range(60):
            if tunnel.poll() is not None:
                raise RuntimeError("SSH tunnel exited before the test")
            try:
                with socket.create_connection(("127.0.0.1", args.local_port), timeout=1):
                    break
            except OSError:
                await asyncio.sleep(0.5)
        cfg = yaml.safe_load(Path(args.kubeconfig).read_text())
        cfg["clusters"][0]["cluster"]["server"] = f"https://127.0.0.1:{args.local_port}"
        kubeconfig = yaml.safe_dump(cfg)
        api = build_kubernetes_api_client(kubeconfig, "cloudguard-lab")
        core = client.CoreV1Api(api)
        rbac = client.RbacAuthorizationV1Api(api)
        remote(args, f"systemd-run --unit={namespace}-cleanup --on-active=5m /usr/local/bin/k3s kubectl delete namespace {namespace} --ignore-not-found=true")
        objects = lab_objects(namespace)
        for obj in objects:
            kind = obj["kind"]
            if kind == "Namespace":
                core.create_namespace(obj, _request_timeout=20)
            else:
                methods = {
                    "ServiceAccount": core.create_namespaced_service_account,
                    "Pod": core.create_namespaced_pod,
                    "Service": core.create_namespaced_service,
                    "Secret": core.create_namespaced_secret,
                    "Role": rbac.create_namespaced_role,
                    "RoleBinding": rbac.create_namespaced_role_binding,
                }
                methods[kind](namespace, obj, _request_timeout=20)
        report["created_objects"] = [obj["kind"] + "/" + obj["metadata"]["name"] for obj in objects]
        print("Created actual CloudGuard vulnerable lab objects", flush=True)
        for _ in range(90):
            pod = core.read_namespaced_pod("privileged-demo", namespace, _request_timeout=20)
            if pod.status.phase == "Running":
                break
            await asyncio.sleep(1)
        report["pod_phase"] = pod.status.phase
        if pod.status.phase != "Running":
            raise RuntimeError(f"Demo pod did not start: {pod.status.phase}")
        with tempfile.TemporaryDirectory(prefix="cloudguard-empty-manifests-") as workspace:
            scanner = KubernetesMCPServer({
                "kubeconfig": kubeconfig, "context": "cloudguard-lab",
                "cluster_name": "hostinger-vulnerable-lab", "root_path": workspace,
            })
            result = await scanner._full_scan(account_id="hostinger-vulnerable-lab", mode="live")
        if result.get("errors"):
            raise RuntimeError("Scanner errors: " + json.dumps(result["errors"]))
        findings = [f for f in result["findings"] if namespace in json.dumps(f.get("resource", {}))]
        report["findings"] = [{"severity": f["severity"], "issue": f["issue"]} for f in findings]
        report["total_cluster_findings"] = len(result["findings"])
        report["scan_duration_seconds"] = result["scan_duration"]
        if len(findings) < 5:
            raise RuntimeError(f"Too few lab findings: {len(findings)}")
        issues = "\n".join(f["issue"] for f in findings)
        required_checks = (
            "runs privileged", "hostNetwork enabled", "Binding grants cluster-admin",
            "Service exposes a node port", "Service exposes an external load balancer",
            "without NetworkPolicy",
        )
        missing_checks = [check for check in required_checks if check not in issues]
        if missing_checks:
            raise RuntimeError("Missing lab checks: " + ", ".join(missing_checks))
        print(f"Live scanner found {len(findings)} lab findings without API errors", flush=True)
    finally:
        try:
            if core:
                try:
                    core.delete_namespace(namespace, _request_timeout=20)
                except ApiException as exc:
                    if exc.status != 404:
                        raise
                for _ in range(90):
                    try:
                        core.read_namespace(namespace, _request_timeout=20)
                    except ApiException as exc:
                        if exc.status == 404:
                            report["cleanup_verified"] = True
                            break
                        raise
                    await asyncio.sleep(1)
                if report["cleanup_verified"]:
                    remote(args, f"systemctl stop {namespace}-cleanup.timer")
        finally:
            if api:
                api.close()
            tunnel.terminate()
            try:
                tunnel.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait()
            report["verified_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            Path(args.report).write_text(json.dumps(report, indent=2))
            print(json.dumps(report, indent=2), flush=True)
    if not report["cleanup_verified"]:
        raise RuntimeError("Namespace cleanup was not confirmed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--ssh-key", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--local-port", type=int, default=16443)
    asyncio.run(scan(parser.parse_args()))
