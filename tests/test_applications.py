"""Static checks on the hand-written tenant Applications under tenants/<t>/applications/.

tenant-application-guard (Kyverno) enforces the security-relevant rules on the cluster;
these tests give the same answer in CI before merge, and also check things Kyverno
cannot see, such as tenant.yaml's registry.enabled and sourceRepos.
"""

import fnmatch
import re

import pytest
import yaml

from conftest import REPO, TENANTS, load_docs, tenant_names

TENANT_NAME = re.compile(r"^[a-z][a-z0-9]{1,30}$")
IN_CLUSTER = "https://kubernetes.default.svc"


def _chart_defaults():
    with open(REPO / "charts/tenant/values.yaml", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _tenant_values(tenant):
    with open(TENANTS / tenant / "tenant.yaml", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _applications():
    for tenant in tenant_names():
        for path in sorted((TENANTS / tenant / "applications").glob("*.yaml")):
            for doc in load_docs(path):
                yield tenant, path, doc


APPS = list(_applications())
IDS = [f"{t}/{p.name}" for t, p, _ in APPS]


@pytest.mark.parametrize("tenant", tenant_names())
def test_tenant_directory_layout(tenant):
    assert TENANT_NAME.match(tenant), f"{tenant}: tenant names are lowercase letters and digits only"
    assert (TENANTS / tenant / "tenant.yaml").is_file()
    assert (TENANTS / tenant / "applications" / "tenant.yaml").is_file()


@pytest.mark.parametrize("tenant,path,app", APPS, ids=IDS)
def test_application_basics(tenant, path, app):
    assert app["apiVersion"] == "argoproj.io/v1alpha1"
    assert app["kind"] == "Application"
    assert app["metadata"]["namespace"] == "argocd"
    assert app["metadata"]["labels"]["platform.example.com/tenant"] == tenant


@pytest.mark.parametrize("tenant,path,app", APPS, ids=IDS)
def test_chart_or_workload_application(tenant, path, app):
    spec = app["spec"]
    if path.name == "tenant.yaml":
        # The chart Application: platform project, name parameter = directory name.
        assert app["metadata"]["name"] == f"tenant-{tenant}"
        assert spec["project"] == "platform"
        assert spec["source"]["path"] == "charts/tenant"
        params = {p["name"]: p["value"] for p in spec["source"]["helm"]["parameters"]}
        assert params["name"] == tenant
        assert spec["source"]["helm"]["valueFiles"] == [f"../../tenants/{tenant}/tenant.yaml"]
        # Deleting the tenant must remove its access policy and RoleBindings.
        assert "resources-finalizer.argocd.argoproj.io" in app["metadata"]["finalizers"]
        return

    values = _tenant_values(tenant)
    assert "resources-finalizer.argocd.argoproj.io" in app["metadata"]["finalizers"]
    assert spec["project"] == tenant
    assert app["metadata"]["name"].startswith(f"{tenant}-")
    assert spec["destination"] == {"server": IN_CLUSTER, "namespace": spec["destination"]["namespace"]}
    namespace = spec["destination"]["namespace"]
    assert namespace == tenant or namespace.startswith(f"{tenant}-")
    # The AppProject would refuse the sync otherwise; fail in CI instead.
    assert spec["source"]["repoURL"] in values["sourceRepos"]

    sync = spec["syncPolicy"]
    assert "CreateNamespace=true" in sync["syncOptions"]
    labels = sync["managedNamespaceMetadata"]["labels"]
    assert labels["platform.example.com/tenant"] == tenant
    assert labels["platform.example.com/tenant-registry"] == str(values["registry"]["enabled"]).lower()
    for mode in ("enforce", "audit", "warn"):
        assert labels[f"pod-security.kubernetes.io/{mode}"] == "restricted"


@pytest.mark.parametrize("tenant,path,app", APPS, ids=IDS)
def test_production_is_self_healing(tenant, path, app):
    """Production namespaces only change through Git, so selfHeal must be on there."""
    if path.name == "tenant.yaml":
        return
    values = _tenant_values(tenant)
    patterns = values.get("productionNamespaces", _chart_defaults()["productionNamespaces"])
    patterns = [p.replace("TENANT", tenant) for p in patterns]
    namespace = app["spec"]["destination"]["namespace"]
    if any(fnmatch.fnmatchcase(namespace, p) for p in patterns):
        assert app["spec"]["syncPolicy"]["automated"]["selfHeal"] is True


def test_application_names_are_unique():
    names = [app["metadata"]["name"] for _, _, app in APPS]
    assert len(names) == len(set(names))


def _editor_patterns(tenant):
    values = _tenant_values(tenant)
    return [
        pattern
        for entry in values.get("access", [])
        if entry["role"] == "tenant-editor"
        for pattern in entry["namespaces"]
    ]


@pytest.mark.parametrize("tenant,path,app", APPS, ids=IDS)
def test_editor_namespaces_do_not_self_heal(tenant, path, app):
    """Where a group has tenant-editor, selfHeal would revert its direct changes."""
    if path.name == "tenant.yaml":
        return
    values = _tenant_values(tenant)
    production = values.get("productionNamespaces", _chart_defaults()["productionNamespaces"])
    production = [p.replace("TENANT", tenant) for p in production]
    namespace = app["spec"]["destination"]["namespace"]
    if any(fnmatch.fnmatchcase(namespace, p) for p in production):
        return  # editor is never bound in production
    if any(fnmatch.fnmatchcase(namespace, p) for p in _editor_patterns(tenant)):
        assert app["spec"]["syncPolicy"]["automated"]["selfHeal"] is False


def test_last_tenant_can_be_removed():
    """allowEmpty lets Argo CD prune the last tenant; .gitkeep keeps tenants/ in Git."""
    (root,) = load_docs(REPO / "platform/argocd/tenants.yaml")
    assert root["spec"]["syncPolicy"]["automated"]["allowEmpty"] is True
    assert (TENANTS / ".gitkeep").is_file()


def test_platform_roots_do_not_cascade():
    """Deleting a root orphans what it manages rather than deleting guards under tenants."""
    for path in (REPO / "bootstrap/platform-tenancy.yaml", REPO / "platform/argocd/tenants.yaml"):
        (app,) = load_docs(path)
        assert "finalizers" not in app["metadata"], path.name
