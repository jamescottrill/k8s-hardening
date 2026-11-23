"""Renders charts/tenant with the real helm binary: the example tenants, and the inputs
the chart must refuse (bad tenant names, forbidden kinds, bad access entries)."""

import json
import shutil
import subprocess

import pytest
import yaml

from conftest import REPO, TENANTS, tenant_names

CHART = REPO / "charts/tenant"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")


def render(name, values_file=None, overrides=None):
    """Run helm template; return (returncode, parsed documents or stderr)."""
    cmd = ["helm", "template", "t", str(CHART), "--set", f"name={name}"]
    if values_file:
        cmd += ["-f", str(values_file)]
    for key, value in (overrides or {}).items():
        cmd += ["--set-json", f"{key}={json.dumps(value)}"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode:
        return result.returncode, result.stderr
    return 0, [d for d in yaml.safe_load_all(result.stdout) if d]


def by_kind(docs, kind):
    return [d for d in docs if d["kind"] == kind]


MINIMAL = {
    "sourceRepos": ["https://github.com/example-org/x.git"],
    "owners": {"groups": ["g"]},
}


@pytest.mark.parametrize("tenant", tenant_names())
def test_example_tenants_render(tenant):
    code, docs = render(tenant, TENANTS / tenant / "tenant.yaml")
    assert code == 0, docs
    (project,) = by_kind(docs, "AppProject")
    assert project["metadata"]["name"] == tenant
    assert [d["namespace"] for d in project["spec"]["destinations"]] == [tenant, f"{tenant}-*"]
    assert project["spec"]["clusterResourceWhitelist"] == []
    assert "namespaceResourceBlacklist" not in project["spec"]
    groups = {r["group"] for r in project["spec"]["namespaceResourceWhitelist"]}
    assert not {g for g in groups if "kyverno" in g or g == "argoproj.io"}


def test_editor_is_never_bound_in_production():
    code, docs = render("myapp", TENANTS / "myapp" / "tenant.yaml")
    assert code == 0, docs
    (policy,) = [d for d in by_kind(docs, "ClusterPolicy") if d["metadata"]["name"] == "tenant-access-myapp"]
    editor_rules = [
        r for r in policy["spec"]["rules"]
        if r["generate"]["data"]["roleRef"]["name"] == "tenant-editor"
    ]
    assert editor_rules, "the myapp example should bind tenant-editor somewhere"
    for rule in editor_rules:
        excluded = rule["exclude"]["any"][0]["resources"]["names"]
        assert excluded == ["myapp-prod", "myapp-prod-*"]
    for rule in policy["spec"]["rules"]:
        if rule["generate"]["data"]["roleRef"]["name"] != "tenant-editor":
            assert "exclude" not in rule


@pytest.mark.parametrize(
    "name",
    ["team-b", "kube", "argocd", "tenant", "a", "Myapp", "1app", "x" * 32],
)
def test_invalid_or_reserved_tenant_names_are_refused(name):
    code, err = render(name, overrides=MINIMAL)
    assert code != 0
    assert "tenant name" in err


@pytest.mark.parametrize(
    "extra,expected",
    [
        ({"group": "kyverno.io", "kind": "Policy"}, "platform-only"),
        ({"group": "policies.kyverno.io", "kind": "ValidatingPolicy"}, "platform-only"),
        ({"group": "argoproj.io", "kind": "Application"}, "platform-only"),
        ({"group": "", "kind": "Endpoints"}, "platform-only"),
        ({"group": "discovery.k8s.io", "kind": "EndpointSlice"}, "platform-only"),
        ({"group": "", "kind": "ResourceQuota"}, "platform-only"),
        ({"group": "*", "kind": "Deployment"}, "wildcards"),
        ({"group": "apps", "kind": "*"}, "wildcards"),
        ({"kind": "Thing"}, "needs a group"),
        ({"group": "keda.sh"}, "needs a non-empty kind"),
        ({"group": "keda.sh", "kind": ""}, "needs a non-empty kind"),
    ],
)
def test_forbidden_namespace_resources_are_refused(extra, expected):
    code, err = render("myapp", overrides={**MINIMAL, "extraNamespaceResources": [extra]})
    assert code != 0
    assert expected in err


def test_extra_namespace_resources_are_appended():
    extra = {"group": "keda.sh", "kind": "ScaledObject"}
    code, docs = render("myapp", overrides={**MINIMAL, "extraNamespaceResources": [extra]})
    assert code == 0, docs
    (project,) = by_kind(docs, "AppProject")
    assert extra in project["spec"]["namespaceResourceWhitelist"]


@pytest.mark.parametrize(
    "access,expected",
    [
        ([{"group": "g", "role": "cluster-admin", "namespaces": ["myapp"]}], "must be one of"),
        ([{"group": "g", "role": "tenant-viewer", "namespaces": ["teamb"]}], "outside tenant"),
        ([{"group": "g", "role": "tenant-viewer", "namespaces": ["myappx"]}], "outside tenant"),
        ([{"group": "g", "role": "tenant-viewer", "namespaces": []}], "at least one"),
        (
            [
                {"group": "g", "role": "tenant-editor", "namespaces": ["myapp-dev"]},
                {"group": "g", "role": "tenant-editor", "namespaces": ["myapp-test"]},
            ],
            "more than once",
        ),
    ],
)
def test_bad_access_entries_are_refused(access, expected):
    code, err = render("myapp", overrides={**MINIMAL, "access": access})
    assert code != 0
    assert expected in err


@pytest.mark.parametrize("bad", ["example", "*.com", "Myapp.example.com", "a..b.com", "*", "**.x.com", "x.com."])
def test_bad_hostnames_are_refused(bad):
    code, err = render("myapp", overrides={**MINIMAL, "hostnames": [bad]})
    assert code != 0
    assert "hostnames[0]" in err


def test_hostname_policy_lists_the_tenants_hostnames():
    code, docs = render("myapp", TENANTS / "myapp" / "tenant.yaml")
    assert code == 0, docs
    (policy,) = [d for d in by_kind(docs, "ClusterPolicy") if d["metadata"]["name"] == "tenant-hosts-myapp"]
    (allowed,) = [v for v in policy["spec"]["rules"][0]["validate"]["cel"]["variables"] if v["name"] == "allowed"]
    assert json.loads(allowed["expression"]) == ["myapp.example.com", "*.myapp.example.com"]


def _owns(pattern, host):
    """Same rule as the CEL: exact, or a *.suffix entry owns every name below it."""
    return pattern == host or (pattern.startswith("*.") and host.endswith(pattern[1:]))


def test_no_two_tenants_claim_the_same_hostnames():
    claims = {
        t: yaml.safe_load((TENANTS / t / "tenant.yaml").read_text()).get("hostnames", [])
        for t in tenant_names()
    }
    for a, a_hosts in claims.items():
        for b, b_hosts in claims.items():
            if a == b:
                continue
            for pa in a_hosts:
                for pb in b_hosts:
                    # Compare the names themselves and, for wildcards, a name under them.
                    probe = pb.replace("*", "x", 1)
                    assert not _owns(pa, probe), f"{a} ({pa}) overlaps {b} ({pb})"
