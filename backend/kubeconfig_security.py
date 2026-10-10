"""Validate uploaded kubeconfigs before the Kubernetes loader touches them."""

import yaml


def validate_kubeconfig(text: str) -> dict:
    config = yaml.safe_load(text)
    if not isinstance(config, dict):
        raise ValueError("kubeconfig must be a YAML object")
    for section, entry_key, forbidden in (
        ("users", "user", {"exec", "auth-provider", "tokenFile", "client-key", "client-certificate"}),
        ("clusters", "cluster", {"certificate-authority"}),
    ):
        entries = config.get(section)
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"kubeconfig must include {section}")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get(entry_key), dict):
                raise ValueError(f"Invalid kubeconfig {section} entry")
            if forbidden.intersection(entry[entry_key]):
                raise ValueError("Uploaded kubeconfigs must use embedded tokens or certificate data; authentication plugins and local file references are forbidden")
    return config
