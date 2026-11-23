"""Shared helpers for the repository tests: paths and YAML loading."""

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
TENANTS = REPO / "tenants"


def load_docs(path):
    """Return every non-empty YAML document in a file."""
    with open(path, encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc]


def tenant_names():
    """Directory names under tenants/, which are the tenant names."""
    return sorted(p.name for p in TENANTS.iterdir() if p.is_dir())
