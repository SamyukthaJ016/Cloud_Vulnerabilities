import base64
import os
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse, urlunparse

import yaml


class KubeconfigPreparationError(ValueError):
    """Raised when a kubeconfig cannot be made portable for containerized use."""


def _embed_file_data(
    entry: Dict[str, Any],
    path_key: str,
    data_key: str,
    missing_paths: List[str],
) -> None:
    path_value = entry.get(path_key)
    if not path_value or entry.get(data_key):
        return

    resolved_path = Path(os.path.expanduser(path_value))
    if not resolved_path.is_absolute():
        missing_paths.append(path_value)
        return

    if not resolved_path.exists():
        missing_paths.append(str(resolved_path))
        return

    entry[data_key] = base64.b64encode(resolved_path.read_bytes()).decode("ascii")
    entry.pop(path_key, None)


def _rewrite_local_server_url(cluster: Dict[str, Any]) -> None:
    server = cluster.get("server")
    if not server or not Path("/.dockerenv").exists():
        return

    parsed = urlparse(server)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        return

    cluster.setdefault("tls-server-name", parsed.hostname)

    if parsed.port:
        netloc = f"host.docker.internal:{parsed.port}"
    else:
        netloc = "host.docker.internal"

    cluster["server"] = urlunparse(parsed._replace(netloc=netloc))


def prepare_kubeconfig_text(kubeconfig_text: str) -> str:
    """
    Convert a kubeconfig into a portable form by embedding referenced cert/key files.

    This is important for containerized scanners because host file paths from
    Minikube or local kubeconfig files are otherwise not visible inside Docker.
    """
    if not kubeconfig_text or not kubeconfig_text.strip():
        raise KubeconfigPreparationError("Kubeconfig is empty.")

    try:
        kubeconfig = yaml.safe_load(kubeconfig_text)
    except yaml.YAMLError as exc:
        raise KubeconfigPreparationError(f"Invalid kubeconfig YAML: {exc}") from exc

    if not isinstance(kubeconfig, dict):
        raise KubeconfigPreparationError("Kubeconfig must be a YAML object.")

    missing_paths: List[str] = []

    for cluster_entry in kubeconfig.get("clusters") or []:
        cluster = cluster_entry.get("cluster") or {}
        _rewrite_local_server_url(cluster)
        _embed_file_data(
            cluster,
            "certificate-authority",
            "certificate-authority-data",
            missing_paths,
        )

    for user_entry in kubeconfig.get("users") or []:
        user = user_entry.get("user") or {}
        _embed_file_data(
            user,
            "client-certificate",
            "client-certificate-data",
            missing_paths,
        )
        _embed_file_data(
            user,
            "client-key",
            "client-key-data",
            missing_paths,
        )

    if missing_paths:
        unique_paths = ", ".join(sorted(set(missing_paths)))
        raise KubeconfigPreparationError(
            "Kubeconfig references local files that are not available to the scanner: "
            f"{unique_paths}. Paste the output of `kubectl config view --raw --minify` "
            "or use a kubeconfig with embedded `*-data` fields."
        )

    return yaml.safe_dump(kubeconfig, sort_keys=False)
