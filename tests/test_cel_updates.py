"""Evaluates the UPDATE-only CEL rules with cel-python.

The Kyverno CLI cannot supply oldObject, so tests/kyverno covers CREATE and these
tests cover the rules that compare the old and new objects: tenant label immutability
and the ExternalSecret force-sync exemption. The expressions are read from the policy
files, so the tests exercise exactly what is deployed.
"""

import celpy
import pytest

from conftest import REPO, load_docs

KYVERNO = REPO / "platform/kyverno"
TENANT = "platform.example.com/tenant"


def _expressions(policy_file, rule_name):
    (policy,) = load_docs(KYVERNO / policy_file)
    (rule,) = [r for r in policy["spec"]["rules"] if r["name"] == rule_name]
    return [e["expression"] for e in rule["validate"]["cel"]["expressions"]]


def _allowed(expressions, operation, obj, old):
    """True when every expression passes, as Kyverno requires."""
    env = celpy.Environment()
    activation = {
        "object": celpy.json_to_cel(obj),
        "oldObject": celpy.json_to_cel(old),
        "request": celpy.json_to_cel({"operation": operation}),
    }
    return all(bool(env.program(env.compile(e)).evaluate(activation)) for e in expressions)


def _ns(labels=None):
    meta = {"name": "myapp-dev"}
    if labels is not None:
        meta["labels"] = labels
    return {"metadata": meta}


IMMUTABLE = _expressions("tenant-namespace-guard.yaml", "tenant-label-immutable")


@pytest.mark.parametrize(
    "old,new,allowed",
    [
        (None, {TENANT: "myapp"}, True),            # first labelling (Argo CD on create)
        ({}, {TENANT: "myapp"}, True),
        ({TENANT: ""}, {TENANT: "myapp"}, True),
        ({TENANT: "myapp"}, {TENANT: "myapp"}, True),
        ({TENANT: "myapp", "x": "1"}, {TENANT: "myapp"}, True),  # other labels change
        ({TENANT: "myapp"}, {TENANT: "teamb"}, False),  # takeover by another tenant
        ({TENANT: "myapp"}, {}, False),                  # label removed
        ({TENANT: "myapp"}, None, False),                # all labels removed
    ],
)
def test_tenant_label_cannot_change_once_set(old, new, allowed):
    assert _allowed(IMMUTABLE, "UPDATE", _ns(new), _ns(old)) is allowed


STORE = _expressions("restrict-cluster-secret-store.yaml", "deny-tenant-clustersecretstore-refs")


def _es(kind, key="tenants/myapp/registry", annotations=None):
    meta = {"name": "tenant-registry", "namespace": "myapp-dev"}
    if annotations:
        meta["annotations"] = annotations
    return {
        "metadata": meta,
        "spec": {
            "secretStoreRef": {"kind": kind, "name": "platform-vault"},
            "data": [{"secretKey": "password", "remoteRef": {"key": key}}],
        },
    }


def test_force_sync_annotation_on_cluster_store_secret_is_allowed():
    old = _es("ClusterSecretStore")
    new = _es("ClusterSecretStore", annotations={"force-sync": "1732000000"})
    assert _allowed(STORE, "UPDATE", new, old)


def test_changing_the_key_of_a_cluster_store_secret_is_refused():
    old = _es("ClusterSecretStore")
    new = _es("ClusterSecretStore", key="tenants/teamb/registry")
    assert not _allowed(STORE, "UPDATE", new, old)


def test_switching_to_a_cluster_store_is_refused():
    assert not _allowed(STORE, "UPDATE", _es("ClusterSecretStore"), _es("SecretStore"))


def test_creating_with_a_cluster_store_is_refused():
    assert not _allowed(STORE, "CREATE", _es("ClusterSecretStore"), None)


def test_namespaced_store_is_allowed():
    assert _allowed(STORE, "CREATE", _es("SecretStore"), None)
