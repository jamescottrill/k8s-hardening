"""Checks on the tenant user profiles in platform/rbac/tenant-roles.yaml.

The profiles are aggregated ClusterRoles, so the tests resolve aggregation the way the
API server's aggregation controller does (by label selector) and then check what each
profile can actually do.
"""

import re

import pytest

from conftest import REPO, load_docs

ROLES_FILE = REPO / "platform/rbac/tenant-roles.yaml"
PROFILES = ["tenant-viewer", "tenant-developer", "tenant-editor", "tenant-admin"]
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}


def _cluster_roles():
    return {d["metadata"]["name"]: d for d in load_docs(ROLES_FILE) if d["kind"] == "ClusterRole"}


def _resolve(profile, roles):
    """Rules a profile ends up with: every ClusterRole matching its aggregation selectors."""
    selectors = roles[profile]["aggregationRule"]["clusterRoleSelectors"]
    rules = []
    for role in roles.values():
        labels = role["metadata"].get("labels", {})
        for selector in selectors:
            if all(labels.get(k) == v for k, v in selector["matchLabels"].items()):
                rules.extend(role.get("rules", []))
                break
    return rules


def _permissions(rules):
    """Flatten rules to a set of (apiGroup, resource, verb)."""
    perms = set()
    for rule in rules:
        for group in rule.get("apiGroups", []):
            for resource in rule.get("resources", []):
                for verb in rule["verbs"]:
                    perms.add((group, resource, verb))
    return perms


@pytest.fixture(scope="module")
def perms():
    roles = _cluster_roles()
    return {p: _permissions(_resolve(p, roles)) for p in PROFILES}


def can(perms, group, resource, verb):
    return (group, resource, verb) in perms


def test_profiles_are_aggregated_and_carry_no_rules_of_their_own():
    roles = _cluster_roles()
    for profile in PROFILES:
        assert "aggregationRule" in roles[profile]
        # The aggregation controller owns .rules; anything written here would be overwritten.
        assert not roles[profile].get("rules")


def test_rule_sets_only_aggregate_into_known_profiles():
    for name, role in _cluster_roles().items():
        for label in role["metadata"].get("labels", {}):
            match = re.fullmatch(r"rbac\.platform\.example\.com/aggregate-to-(.+)", label)
            if match:
                assert match.group(1) in PROFILES, f"{name} aggregates into unknown {label}"


def test_no_wildcards_or_privilege_escalation_verbs():
    for name, role in _cluster_roles().items():
        for rule in role.get("rules", []):
            for field in ("apiGroups", "resources", "verbs"):
                assert "*" not in rule.get(field, []), f"{name}: wildcard in {field} (CIS 5.1.3)"
            assert not {"bind", "escalate", "impersonate"} & set(rule["verbs"]), f"{name} (CIS 5.1.8)"
            assert "serviceaccounts/token" not in rule.get("resources", []), f"{name} (CIS 5.1.13)"


def test_tiers_build_on_each_other(perms):
    assert perms["tenant-viewer"] < perms["tenant-developer"]
    assert perms["tenant-developer"] < perms["tenant-editor"]
    assert perms["tenant-developer"] < perms["tenant-admin"]


def test_admin_cannot_change_workloads_directly(perms):
    # Admin is bound in production, where workloads only change through Git.
    for resource in ("deployments", "statefulsets"):
        for verb in WRITE_VERBS - {"deletecollection"}:
            assert not can(perms["tenant-admin"], "apps", resource, verb)


def test_viewer_is_read_only_and_cannot_reach_secrets(perms):
    viewer = perms["tenant-viewer"]
    assert not {p for p in viewer if p[2] in WRITE_VERBS}
    assert not can(viewer, "", "pods/exec", "create")
    assert not any(resource == "secrets" for _, resource, _ in viewer)


def test_only_admin_reads_secrets_directly(perms):
    for profile in ("tenant-viewer", "tenant-developer", "tenant-editor"):
        assert not any(r == "secrets" for _, r, _ in perms[profile]), profile
    assert can(perms["tenant-admin"], "", "secrets", "get")


@pytest.mark.parametrize(
    "group,resource",
    [
        ("", "pods"),
        ("", "endpoints"),
        ("discovery.k8s.io", "endpointslices"),
        ("", "namespaces"),
        ("", "resourcequotas"),
        ("", "limitranges"),
        ("", "secrets"),
        ("apps", "daemonsets"),
        ("rbac.authorization.k8s.io", "roles"),
        ("rbac.authorization.k8s.io", "rolebindings"),
        ("networking.istio.io", "serviceentries"),
        ("gateway.networking.k8s.io", "referencegrants"),
    ],
)
def test_no_profile_creates_dangerous_kinds(perms, group, resource):
    for profile in PROFILES:
        assert not can(perms[profile], group, resource, "create"), f"{profile} can create {resource}"


def test_developer_has_debug_and_day_two_operations(perms):
    dev = perms["tenant-developer"]
    for resource in ("pods/exec", "pods/attach", "pods/portforward", "pods/eviction"):
        assert can(dev, "", resource, "create"), resource
    assert can(dev, "", "pods/ephemeralcontainers", "patch")
    assert can(dev, "", "pods", "delete")
    assert can(dev, "batch", "jobs", "create")
    assert can(dev, "external-secrets.io", "externalsecrets", "patch")
    assert not can(dev, "apps", "deployments", "patch")


def test_editor_can_operate_a_namespace_but_not_its_security(perms):
    editor = perms["tenant-editor"]
    for group, resource in [
        ("apps", "deployments"),
        ("apps", "statefulsets"),
        ("", "configmaps"),
        ("", "services"),
        ("", "persistentvolumeclaims"),
        ("batch", "cronjobs"),
        ("autoscaling", "horizontalpodautoscalers"),
        ("networking.k8s.io", "ingresses"),
        ("gateway.networking.k8s.io", "httproutes"),
        ("external-secrets.io", "externalsecrets"),
    ]:
        for verb in ("create", "update", "delete"):
            assert can(editor, group, resource, verb), (resource, verb)
    assert can(editor, "apps", "deployments/scale", "patch")
    for group, resource in [
        ("networking.k8s.io", "networkpolicies"),
        ("external-secrets.io", "secretstores"),
        ("security.istio.io", "authorizationpolicies"),
    ]:
        assert not can(editor, group, resource, "create"), resource
        assert can(perms["tenant-admin"], group, resource, "create"), resource


def test_kyverno_can_bind_exactly_the_profiles():
    docs = load_docs(REPO / "platform/kyverno/00-rbac.yaml")
    bind_rules = [
        r for d in docs for r in d.get("rules", []) if "bind" in r["verbs"]
    ]
    assert len(bind_rules) == 1
    assert sorted(bind_rules[0]["resourceNames"]) == sorted(PROFILES)


def test_chart_accepts_exactly_the_profiles():
    template = (REPO / "charts/tenant/templates/access-policy.yaml").read_text()
    match = re.search(r'\$allowedRoles := list ((?:"[^"]+" ?)+)', template)
    assert match
    assert sorted(re.findall(r'"([^"]+)"', match.group(1))) == sorted(PROFILES)


# Kind -> resource for the AppProject whitelist. Explicit rather than guessed plurals.
KIND_TO_RESOURCE = {
    "ConfigMap": "configmaps", "Secret": "secrets", "Service": "services",
    "ServiceAccount": "serviceaccounts", "PersistentVolumeClaim": "persistentvolumeclaims",
    "Deployment": "deployments", "StatefulSet": "statefulsets", "Job": "jobs",
    "CronJob": "cronjobs", "HorizontalPodAutoscaler": "horizontalpodautoscalers",
    "PodDisruptionBudget": "poddisruptionbudgets", "Ingress": "ingresses",
    "NetworkPolicy": "networkpolicies", "Role": "roles", "RoleBinding": "rolebindings",
    "ExternalSecret": "externalsecrets", "SecretStore": "secretstores",
    "HTTPRoute": "httproutes", "GRPCRoute": "grpcroutes",
    "VirtualService": "virtualservices", "DestinationRule": "destinationrules",
    "AuthorizationPolicy": "authorizationpolicies", "Certificate": "certificates",
    "ServiceMonitor": "servicemonitors", "PodMonitor": "podmonitors",
    "PrometheusRule": "prometheusrules",
}


def _role_guard_allowed_writes():
    import ast

    (policy,) = load_docs(REPO / "platform/kyverno/tenant-rbac-guard.yaml")
    (rule,) = [r for r in policy["spec"]["rules"] if r["name"] == "tenant-roles-least-privilege"]
    (var,) = [v for v in rule["validate"]["cel"]["variables"] if v["name"] == "allowedWrites"]
    # The CEL list literal of strings is also a valid Python literal.
    return set(ast.literal_eval(var["expression"]))


def test_role_guard_allows_writes_to_every_whitelisted_kind():
    """A Role may grant writes to whatever Argo CD may deploy, so the two lists agree."""
    import yaml

    with open(REPO / "charts/tenant/values.yaml", encoding="utf-8") as handle:
        whitelist = yaml.safe_load(handle)["namespaceResources"]
    allowed = _role_guard_allowed_writes()
    for entry in whitelist:
        key = f'{entry["group"]}/{KIND_TO_RESOURCE[entry["kind"]]}'
        assert key in allowed, f"{key} is in the AppProject whitelist but not in tenant-rbac-guard"


def test_role_guard_never_allows_routing_or_platform_kinds():
    allowed = _role_guard_allowed_writes()
    for key in [
        "/endpoints", "discovery.k8s.io/endpointslices", "/resourcequotas", "/limitranges",
        "apps/daemonsets", "networking.istio.io/serviceentries", "networking.istio.io/sidecars",
        "gateway.networking.k8s.io/referencegrants", "external-secrets.io/pushsecrets",
        "kyverno.io/policies", "kyverno.io/policyexceptions", "argoproj.io/applications",
        "/serviceaccounts/token",
    ]:
        assert key not in allowed, key


# Custom (non-core) kinds named in background-scanned tenancy policies -> (group, resource)
CUSTOM_KINDS = {
    "Application": ("argoproj.io", "applications"),
    "VirtualService": ("networking.istio.io", "virtualservices"),
    "HTTPRoute": ("gateway.networking.k8s.io", "httproutes"),
    "GRPCRoute": ("gateway.networking.k8s.io", "grpcroutes"),
    "Certificate": ("cert-manager.io", "certificates"),
}


def test_reports_controller_can_read_every_background_scanned_custom_kind():
    import yaml

    docs = load_docs(REPO / "platform/kyverno/00-rbac.yaml")
    (reports,) = [d for d in docs if d["metadata"]["name"] == "kyverno:reports:platform-tenancy"]
    readable = _permissions(reports["rules"])

    policies = [p for f in sorted((REPO / "platform/kyverno").glob("tenant-*.yaml")) for p in load_docs(f)]
    with open(REPO / "charts/tenant/values.yaml", encoding="utf-8") as handle:
        host_kinds = yaml.safe_load(handle)["hostPolicyKinds"]
    kinds = set(host_kinds)
    for policy in policies:
        if policy["spec"].get("background", True):
            for rule in policy["spec"]["rules"]:
                for clause in rule["match"].get("any", []) + rule["match"].get("all", []):
                    kinds.update(k.split("/")[-1] for k in clause["resources"]["kinds"])
    for kind in kinds & CUSTOM_KINDS.keys():
        group, resource = CUSTOM_KINDS[kind]
        for verb in ("get", "list", "watch"):
            assert (group, resource, verb) in readable, f"reports controller cannot {verb} {resource}"
