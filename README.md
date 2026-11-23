# Platform tenancy: Argo CD + Kyverno + External Secrets + Vault

Tenant namespaces with per-tenant registry credentials, OIDC user profiles bound by
namespace pattern, a private Vault KV space per person, and the CIS Kubernetes Benchmark
section 5 policies (Level 1 and Level 2). The platform team adds a tenant's Application
files; Argo CD creates each namespace, stamps the tenant and Pod Security labels on it,
and the pull secrets, network policies and RoleBindings turn up without anyone touching
the cluster.

## How it fits together

```
tenants/myapp/tenant.yaml                 chart values (owners, sourceRepos, registry, access)
tenants/myapp/applications/tenant.yaml ──► Application tenant-myapp (project platform)
                                              └► charts/tenant ──► AppProject myapp
                                                               └► ClusterPolicy tenant-access-myapp
tenants/myapp/applications/web-dev.yaml ─► Application myapp-web-dev
                                              │  project: myapp
                                              │  namespace: myapp-dev (CreateNamespace)
                                              └─ labels: tenant=myapp, tenant-registry=true,
                                                         pod-security enforce=restricted
                                                         │
     ┌──────────────────────┬───────────────────────────┬────────────┴───────┬─────────────────────────┐
     ▼                      ▼                           ▼                    ▼                         ▼
 Secret platform-     Secret tenant-registry      Pods get both        RoleBindings for        NetworkPolicies
 registry (shared     (Kyverno-generated          imagePullSecrets     groups in access:       default-deny +
 Quay robot, via      ExternalSecret from         (Kyverno mutate)     whose patterns match    allows (CIS 5.3.2)
 ClusterExternal-     kv/tenants/myapp/registry)                       myapp-dev
 Secret)
```

The `tenants` Application (`platform/argocd/tenants.yaml`) is an app-of-apps over every
`tenants/*/applications/*.yaml`. There are no ApplicationSets: each Application is a
plain, reviewable file.

## Trust chain

This is what stops one tenant reaching another's credentials or namespaces.

1. **The platform team writes every Application.** CODEOWNERS gives `tenants/` to platform-admins, and the tenant AppProject role only grants get, sync, actions and logs, so teams cannot create or edit Applications. The project, destination and `managedNamespaceMetadata` therefore only come from reviewed files.
2. **`tenant-application-guard`** catches mistakes in those files: an Application in project X must be labelled X, be named `X-*`, deploy to this cluster into `X` or `X-*`, use CreateNamespace, and label its namespace `tenant=X` with Pod Security `restricted`. The Argo CD controller is not excluded.
3. **Tenant names are lowercase letters and digits, without hyphens**, and not on the reserved list (the chart refuses to render otherwise). AppProject destinations are `<tenant>` and `<tenant>-*`, and with no hyphens in names, one tenant's `<tenant>-*` can never cover another tenant's namespaces.
4. **The AppProject whitelists namespaced kinds** (`namespaceResources` in `charts/tenant/values.yaml`). A team's repo cannot ship Kyverno policies or PolicyExceptions, Argo CD objects, Endpoints or EndpointSlices, quotas, or anything cluster-scoped. The chart refuses wildcards and platform-only kinds in `extraNamespaceResources`.
5. **`tenant-namespace-guard`**: only the Argo CD application controller (or platform admins) may set the tenant labels. Once a namespace has a tenant label, only platform admins can change or remove it, Argo CD included. A namespace labelled `tenant=X` must be named `X` or `X-*`.
6. **`tenant-rbac-guard`**: Argo CD applies team manifests with its own cluster-wide rights, so in tenant namespaces RoleBindings may only bind a Role to ServiceAccounts in the same namespace, and Roles may not use wildcards, bind, escalate, impersonate or create tokens, grant anything in platform-only API groups, or grant writes to the kinds the AppProject keeps out (so a repo cannot hand its own ServiceAccount what Argo CD would refuse). Human access comes only from `access:` in `tenant.yaml`.
7. **`restrict-cluster-secret-store`**: in tenant namespaces only Kyverno and ESO may create ExternalSecrets that use a ClusterSecretStore (checked in `secretStoreRef`, `data[].sourceRef` and `dataFrom[].sourceRef`). An update that leaves `spec` unchanged, such as a force-sync annotation, is allowed. Teams can bring their own namespaced SecretStore.
8. **`tenant-monitoring-guard`**: ServiceMonitors and PodMonitors may only select their own namespace, so the shared Prometheus cannot be pointed at another tenant's endpoints.
9. **`tenant-service-guard`**: no ExternalName Services and no `spec.externalIPs` (CVE-2020-8554) in tenant namespaces, and VirtualService routes, mirrors and delegates may only target the tenant's own namespaces, so a tenant cannot point the shared gateway at another tenant's Service or intercept traffic to an arbitrary IP. HTTPRoutes need a ReferenceGrant from the target namespace to cross namespaces, and tenants cannot create those.
10. **`tenant-hosts-<tenant>`** (rendered by the tenant chart): Ingresses, HTTPRoutes, GRPCRoutes, VirtualServices and Certificates in a tenant's namespaces may only claim hostnames on that tenant's `hostnames:` list in tenant.yaml. VirtualService hosts and Certificate names may also be the tenant's own Services, never another tenant's. Catch-alls are refused: Ingresses need a host on every rule and no defaultBackend, Gateway routes must list hostnames, and Certificates may not use literalSubject or be CA certificates. Other Gateway API kinds (Gateway, TLSRoute, TCPRoute, UDPRoute) are platform-only. So no tenant can take another's hostname at the shared gateway, or capture another tenant's Service traffic across the mesh (VirtualServices are exported mesh-wide by default). CI checks that no two tenants list overlapping hostnames.
11. **Vault policy for ESO is read-only** and never covers `kv/users/`, so a PushSecret through `platform-vault` cannot overwrite anyone's credential and nothing in the cluster can read personal secrets.

Kyverno's own settings (for example restricting PolicyExceptions to the `kyverno` namespace) are managed with the Kyverno installation, not here.

## User profiles (OIDC)

| Profile | Scope | Bound by | Can |
|---|---|---|---|
| `cluster-admin` (built-in) | cluster | `platform-admins` group, `platform/rbac/cluster-bindings.yaml` | Everything. The only group allowed to hold cluster-admin (CIS 5.1.1). |
| `platform-operator` | cluster | `platform-operators` group | Read everything except secrets, cordon and drain nodes, delete pods. For on-call. |
| `cluster-auditor` | cluster | `cluster-auditors` group | Read everything except secrets, including RBAC, Kyverno policies and policy reports. |
| `tenant-viewer` | namespace | `access:` in tenant.yaml | Read workloads, config maps, logs, events, policy reports, certificates, monitors. No secrets, no exec. |
| `tenant-developer` | namespace | `access:` in tenant.yaml | Viewer plus exec, attach, port-forward, `kubectl debug`, delete and evict pods, run Jobs (including from CronJobs). |
| `tenant-editor` | namespace | `access:` in tenant.yaml | Developer plus create, change and delete Deployments, StatefulSets, Services, ConfigMaps, PVCs, ServiceAccounts, Jobs, CronJobs, HPAs, PDBs, Ingresses, HTTP/GRPCRoutes, VirtualServices, DestinationRules, ExternalSecrets, Certificates and Prometheus monitors and rules; scale, restart and roll back. **Never bound in production namespaces.** |
| `tenant-admin` | namespace | `access:` in tenant.yaml | Developer plus read Secrets, force-sync ExternalSecrets, manage SecretStores, NetworkPolicies and Istio AuthorizationPolicies. No direct workload changes, because it is bound in production. |

`tenant-admin` is not a superset of `tenant-editor`: give a lead group both, editor for
the non-production namespaces and admin everywhere (see the example below).

The tenant profiles are aggregated ClusterRoles built from four rule sets in
`platform/rbac/tenant-roles.yaml` (read, debug, edit, admin), so each tier is the one
below plus one rule set and nothing is copied between them. All rules are explicit
(no wildcards). None of the profiles can create bare Pods, DaemonSets, Roles,
RoleBindings, Endpoints or EndpointSlices.

**Secret access.** Anyone who can run a Job, exec into a pod, add a debug container or
create a Deployment can read the namespace's Secrets through a pod. Treat
`tenant-developer`, `tenant-editor` and `tenant-admin` as having access to secrets; only
`tenant-viewer` does not.

**Direct changes in non-production.** `tenant-editor` changes the live namespace
without Git. Applications deploying into namespaces where a group has `tenant-editor`
set `selfHeal: false` (see `tenants/myapp/applications/web-dev.yaml`), otherwise Argo CD
reverts the change within minutes. The next sync from Git (any new commit) still
overwrites fields that Git manages, so direct changes are for trying things out;
anything worth keeping goes into the repo. Production Applications keep
`selfHeal: true`, and the tests check this.

What "production only changes through Git" covers: workload definitions (Deployments,
StatefulSets, Services, ConfigMaps, routes), because `tenant-editor` is never bound
there. It does not stop operational actions: wherever `tenant-developer` or
`tenant-admin` is bound, including production, they can exec, delete and evict pods,
run Jobs and add debug containers, and admin can change NetworkPolicies,
AuthorizationPolicies and SecretStores. Bind only `tenant-viewer` in production for
groups that should not do that.

### Binding groups to namespaces and namespace wildcards

```yaml
# tenants/myapp/tenant.yaml
access:
  - group: myapp-developers
    role: tenant-editor
    namespaces: ["myapp-dev", "myapp-test*"]
  - group: myapp-developers
    role: tenant-viewer
    namespaces: ["myapp", "myapp-prod"]
  - group: myapp-leads
    role: tenant-editor
    namespaces: ["myapp-*"]          # production is excluded automatically
  - group: myapp-leads
    role: tenant-admin
    namespaces: ["myapp", "myapp-*"]
```

The tenant chart turns this into a Kyverno ClusterPolicy (`tenant-access-myapp`). Each entry generates a RoleBinding in every namespace labelled `tenant=myapp` whose name matches one of its patterns (`*` and `?` wildcards), including namespaces created later. Removing an entry removes its RoleBindings.

`tenant-editor` entries never bind in `productionNamespaces` (default `<tenant>-prod` and `<tenant>-prod-*`; override it in tenant.yaml if a tenant names production differently), whatever their patterns say.

The chart refuses to render if a pattern is outside the tenant, the role is not one of the four tenant profiles, or a group is given the same role twice, so mistakes fail in Argo CD rather than on the cluster. Kyverno can only bind the four tenant ClusterRoles (its `bind` permission is limited to them by `resourceNames`).

Set `oidcGroupPrefix` in `charts/tenant/values.yaml` if your API server uses `--oidc-groups-prefix` (or a `claimMappings.groups.prefix` in its authentication configuration), and use the same prefix for the groups in `cluster-bindings.yaml`, `tenant-namespace-guard`, `tenant-rbac-guard` and `cis-restrict-cluster-admin-bindings`.

## Private Vault KV per person

`vault/user-private.hcl` gives everyone who logs in to Vault through OIDC their own
space at `kv/users/<entity id>/*` in the same KV mount, readable and writable only by
them (data, versions, soft delete and destroy, metadata and listing).

- The path uses the Vault **entity ID**, not a username. A username-based path would follow the OIDC role's `user_claim`; if that is an editable claim such as `email` or `preferred_username`, one person could rename themselves into another's space.
- Find your own path with `vault token lookup -format=json | jq -r .data.entity_id`, then `vault kv put kv/users/<id>/github token=...`.
- `setup.sh` writes the policy. Attach it to your OIDC role's `token_policies` so everyone gets it at login.
- Nothing in the cluster can read these paths: `external-secrets.hcl` only grants `kv/data/platform/registry` and `kv/data/tenants/+/registry`. Never widen that policy to `kv/data/*`, because the one mount holds both.

## CIS Kubernetes Benchmark, section 5

| Control | Level | Policy (`platform/kyverno/...`) | Mode |
|---|---|---|---|
| 5.1.1 cluster-admin only where required | L1 | `cis/rbac.yaml` cis-restrict-cluster-admin-bindings | Enforce |
| 5.1.2 Minimise access to secrets | L1 | Profiles in `platform/rbac/`: only `tenant-viewer` has no route to secrets (see User profiles) | Design, partial |
| 5.1.3 Minimise wildcards in Roles | L1 | `tenant-rbac-guard` (tenants), `cis/rbac.yaml` cis-rbac-hygiene (cluster) | Enforce / Audit |
| 5.1.4 Minimise access to create pods | L1 | No profile creates bare Pods; developer (Jobs) and editor (Deployments) create them through controllers | Design, partial |
| 5.1.5 Default ServiceAccounts not used | L1 | `cis/service-accounts.yaml` (automount off on every default SA, audit use) | Mutate / Audit |
| 5.1.6 SA tokens only where necessary | L1 | `cis/service-accounts.yaml` audit-token-automount | Audit |
| 5.1.7 Avoid system:masters | L1 | OIDC groups only; no client certs issued to people | Process |
| 5.1.8 Limit bind, impersonate, escalate | L1 | `tenant-rbac-guard`, cis-rbac-hygiene | Enforce / Audit |
| 5.1.9 to 5.1.13 PV create, nodes/proxy, CSR approval, webhooks, token create | L1 | cis-rbac-hygiene (5.1.13 also enforced for tenants) | Audit |
| 5.2.1 Active policy control mechanism | L1 | Kyverno plus Pod Security Admission labels on tenant namespaces | Enforce |
| 5.2.2 to 5.2.13 Privileged, host namespaces, escalation, root, NET_RAW, capabilities, HostProcess, hostPath, hostPorts | L1/L2 | `cis/pod-security.yaml` (restricted for tenants, baseline audit elsewhere) | Enforce (tenants) / Audit (elsewhere) |
| 5.3.1 CNI supports NetworkPolicies | L1 | Calico | Platform |
| 5.3.2 All namespaces have NetworkPolicies | L2 | `cis/network-policies.yaml` (tenant namespaces) | Generate |
| 5.4.1 Secrets as files, not env vars | L2 | `cis/workloads.yaml` cis-secrets-not-in-env | Audit |
| 5.4.2 External secret storage | L2 | Vault + External Secrets (this repo) | Design |
| 5.5.1 Image provenance | L2 | `cis/workloads.yaml` registry allow-list; `optional/kyverno/verify-images.yaml` for cosign | Enforce / Optional |
| 5.7.1 Namespaces as admin boundaries | L1 | Tenancy model | Design |
| 5.7.2 Seccomp RuntimeDefault | L2 | Restricted profile | Enforce |
| 5.7.3 Security contexts | L2 | Restricted profile | Enforce |
| 5.7.4 Default namespace not used | L2 | `cis/workloads.yaml` cis-disallow-default-namespace | Enforce |

The Audit items show up in `kubectl get policyreport -A` and `kubectl get clusterpolicyreport`, which is the evidence an assessor will want. Expect cis-rbac-hygiene findings for Argo CD, Kyverno, ESO, Calico and similar controllers: record them as accepted exceptions rather than excluding them silently.

### Not covered by Kyverno (sections 1 to 4)

Most of the benchmark is control plane and node configuration, which admission policies cannot reach. For a kubeadm cluster that means, among others:

- API server: audit logging with an audit policy, encryption at rest for Secrets (`--encryption-provider-config`), `--profiling=false`, `--anonymous-auth=false` where possible, admission plugins (`NodeRestriction`, `PodSecurity`), TLS cipher suites, `--service-account-lookup`.
- Controller manager and scheduler: `--profiling=false`, `--bind-address=127.0.0.1`, `RotateKubeletServerCertificate`.
- etcd: peer and client TLS with client cert auth, data directory permissions.
- Kubelet: `anonymous.enabled: false`, `authorization.mode: Webhook`, `readOnlyPort: 0`, `protectKernelDefaults: true`, `rotateCertificates`, `tlsCipherSuites`, event record QPS.
- File ownership and permissions on manifests, kubeconfigs, PKI and kubelet config.

Run kube-bench on a control-plane node and a worker to see where you stand:

```bash
kube-bench run --targets master,controlplane,etcd,policies   # on a control-plane node
kube-bench run --targets node                                 # on a worker
```

## Layout

| Path | What |
|---|---|
| `bootstrap/` | `platform` AppProject and the `platform-tenancy` app-of-apps. Apply once by hand. |
| `platform/argocd/` | `tenants` app-of-apps over every `tenants/*/applications/*.yaml`. |
| `platform/rbac/` | Tenant and cluster user profiles, and OIDC group to cluster profile bindings. |
| `platform/kyverno/` | Tenancy policies (namespace, Application, RBAC, Service and secret-store guards) and Kyverno RBAC. |
| `platform/kyverno/cis/` | CIS section 5 policies. |
| `platform/external-secrets/` | `platform-vault` ClusterSecretStore, `platform-registry` ClusterExternalSecret, TokenReview binding. |
| `charts/tenant/` | Renders each tenant's AppProject, access ClusterPolicy and hostname policy; validates the tenant name, resource whitelist, hostnames and access entries. |
| `tenants/<tenant>/tenant.yaml` | Chart values for one tenant. |
| `tenants/<tenant>/applications/` | `tenant.yaml` (the chart Application) and one Application file per workload. |
| `vault/` | ESO policy, tenant writer policy template, per-person KV policy, setup and onboarding scripts. |
| `optional/` | Not deployed: cosign image verification. |
| `tests/` | pytest (RBAC, chart, Applications, UPDATE-only CEL rules) and Kyverno CLI tests. |

## Prerequisites

- Argo CD 2.10+ (server-side diff, `managedNamespaceMetadata`), in namespace `argocd` with the standard `argocd-application-controller` ServiceAccount.
- Kyverno 1.13 to 1.19 (rule-level `failureAction`, CEL in ClusterPolicies, `generate.generateExisting`, `mutate.mutateExistingOnPolicyUpdate`), in namespace `kyverno`. **Kyverno 1.20 no longer runs `kyverno.io/v1` ClusterPolicies**, so every policy here must be migrated to the `policies.kyverno.io` types (ValidatingPolicy, GeneratingPolicy, MutatingPolicy) before upgrading. CI tests against 1.16.1.
- External Secrets Operator 0.17+ (`external-secrets.io/v1`), installed as `external-secrets` in namespace `external-secrets`.
- Vault with KV v2 and Kubernetes auth reachable from the cluster.
- If you use Istio sidecars, istio-cni (or ambient mode). Without it the injected `istio-init` container needs NET_ADMIN and NET_RAW, which the restricted profile rejects.

## Before you apply

1. Replace placeholders throughout:
   - `platform.example.com` (label prefix): `grep -rl platform.example.com . | xargs sed -i 's/platform.example.com/<your prefix>/g'`
   - `https://github.com/example-org/platform-gitops.git`, `example-org` repo globs and CODEOWNERS teams
   - `https://vault.example.com:8200` in the ClusterSecretStore
   - The KV mount, if it is not `kv`: `path: kv` in the ClusterSecretStore, and `KV_MOUNT=<mount>` when running `setup.sh` and `onboard-tenant.sh` (they render it into the policies)
   - `quay.example.com` in `cis/workloads.yaml` (approved registries)
   - OIDC group names and prefix (see User profiles)
   - System namespaces excluded from the baseline audit in `cis/pod-security.yaml`
2. Label the namespaces that must reach tenant pods (Istio gateways, Prometheus): `kubectl label ns <ns> platform.example.com/allow-tenant-ingress=true`
3. Vault: `K8S_HOST=https://<kube-vip>:6443 K8S_CA_FILE=ca.crt ./vault/setup.sh`
   Then add `user-private` to your Vault OIDC role's `token_policies` (see Private Vault KV per person).
4. Shared credential: `vault kv put kv/platform/registry registry=quay.example.com username='platform+puller' password=...`
5. List every AppProject that is not a tenant (for example your core add-ons project) in `platformProjects` in `platform/kyverno/tenant-application-guard.yaml`. Applications in any other project must follow the tenant rules.
6. Check that no namespace already carries a tenant label, because the registry credentials fan out to labelled namespaces and the guards only protect labels from now on: `kubectl get ns -l platform.example.com/tenant` should list nothing (relabel or delete anything it does list first).
7. `kubectl apply -f bootstrap/`

Consider applying with every `failureAction: Enforce` set to `Audit` first, reading the policy reports for a few days, then switching to Enforce.

## Onboarding a tenant

All of this is a platform-team pull request.

1. Pick a name: 2 to 31 lowercase letters and digits, starting with a letter, no hyphens, not reserved (see `charts/tenant/templates/_helpers.tpl`).
2. Add `tenants/<tenant>/tenant.yaml` (owners, exact sourceRepos, `hostnames`, `registry.enabled`, `access`). Add the tenant's registry to `cis-restrict-image-registries` if it is new.
3. Copy `tenants/myapp/applications/tenant.yaml` to `tenants/<tenant>/applications/tenant.yaml` and change the tenant name in it.
4. Add one Application per workload (next section).
5. If `registry.enabled: true`: `OIDC_MOUNT_ACCESSOR=... ./vault/onboard-tenant.sh <tenant> <idp-group>`, then the team writes their own robot credential:
   `vault kv put kv/tenants/<tenant>/registry registry=quay.example.com username='<org>+puller' password=...`

Rotating a credential is just `vault kv put` again; ESO refreshes hourly (or annotate the ExternalSecret with `force-sync=$(date +%s)` to do it now; tenant-editor and tenant-admin can, because RBAC cannot limit a patch to that annotation).

## Application file format

Copy an existing file in `tenants/myapp/applications/`. Per Application:

| Field | Value |
|---|---|
| `metadata.name` | `<tenant>-<app>`, unique |
| `metadata.labels` | `platform.example.com/tenant: <tenant>` |
| `spec.project` | `<tenant>` |
| `spec.source` | a repo listed in the tenant's `sourceRepos`; add `helm.valueFiles` for charts |
| `spec.destination` | `server: https://kubernetes.default.svc`, `namespace: <tenant>` or `<tenant>-<name>` |
| `syncOptions` | `CreateNamespace=true`, `ServerSideApply=true` |
| `managedNamespaceMetadata.labels` | `platform.example.com/tenant: <tenant>`, `platform.example.com/tenant-registry` matching `registry.enabled`, and the four Pod Security `restricted` labels |
| `automated.selfHeal` | `true` for production; `false` where a group has `tenant-editor` |

`tenant-application-guard` refuses an Application that gets the security-relevant fields
wrong, and `pytest tests/test_applications.py` checks the rest (registry label,
sourceRepos, selfHeal in production) before merge.

## What was and was not tested

Run `pip install -r requirements-test.txt && pytest tests`, `tests/kyverno/render.sh && kyverno test tests/kyverno` and the Vault compose test below; CI (`.github/workflows/test.yml`) runs all three plus shellcheck.

- `tests/test_rbac.py` resolves the aggregated profiles and checks tier ordering, secret access, the kinds no profile may create, wildcards and escalation verbs, and that Kyverno's `bind` list and the chart's allowed roles match the profiles.
- `tests/test_chart.py` renders the tenant chart with real `helm template` for each tenant, checks the AppProject whitelist and the production exclusion for `tenant-editor`, and checks that bad names, forbidden kinds and bad access entries fail.
- `tests/test_applications.py` checks every Application file against its tenant.
- `tests/kyverno/` runs `tenant-application-guard`, `tenant-service-guard`, `tenant-rbac-guard`, the namespace name rule, `restrict-cluster-secret-store` and the rendered `tenant-hosts-myapp` on CREATE with the Kyverno CLI, against the real Application files and deliberately bad ones (run `tests/kyverno/render.sh` first).
- `tests/test_cel_updates.py` evaluates the UPDATE-only rules (tenant label immutability, force-sync) with cel-python, because the Kyverno CLI cannot supply `oldObject`.
- `tests/vault/` runs `setup.sh` and `onboard-tenant.sh` (twice) against a Vault dev server in Docker, then checks with real tokens what the tenant writer, ESO and per-person policies allow and refuse, including a non-default `KV_MOUNT`: `docker compose -f tests/vault/docker-compose.yml run --rm --build test`.
- **Not tested on a cluster:** the generate, mutate and podSecurity rules, aggregation of the profiles, the `\{{ }}` escape, and subject-based exclusions. Check after the first sync:

```bash
kubectl get clusterpolicy                       # all READY
kubectl get clusterrole tenant-editor -o yaml   # rules filled in by aggregation

# After the first tenant app syncs
kubectl get ns myapp-dev --show-labels
kubectl -n myapp-dev get externalsecret,secret,networkpolicy,rolebinding
kubectl -n myapp-dev get externalsecret tenant-registry -o jsonpath='{.spec.target.template.data}'   # literal {{ .registry }}
kubectl auth can-i patch deployments -n myapp-dev  --as=x --as-group=myapp-developers   # yes (editor)
kubectl auth can-i patch deployments -n myapp-prod --as=x --as-group=myapp-leads        # no (prod: admin, not editor)
kubectl auth can-i get secrets      -n myapp-prod --as=x --as-group=myapp-leads         # yes
kubectl auth can-i create pods/exec -n myapp-prod --as=x --as-group=myapp-developers    # no (viewer)

# A namespace cannot be moved to another tenant, even by Argo CD
kubectl label ns myapp-dev platform.example.com/tenant=teamb --overwrite --as=x --as-group=myapp-leads
# expect: denied by tenant-namespace-guard
kubectl get policyreport -A; kubectl get clusterpolicyreport
```

## Known caveats

- **`\{{ }}` escaping** in `tenant-registry-externalsecret.yaml` keeps Kyverno from substituting ESO's template expressions. Those policies are applied as a plain directory; the tenant chart uses Helm-quoted strings for Kyverno variables instead.
- **Default ServiceAccounts lose their token** (CIS 5.1.5). Workloads that call the Kubernetes API must use their own ServiceAccount.
- **cis-restrict-cluster-admin-bindings is enforced**, so third-party charts that bind cluster-admin will fail to install. Give them a scoped ClusterRole or add a Kyverno PolicyException.
- **Egress is open.** CIS 5.3.2 is met with ingress policies; add default-deny egress once tenant egress needs are known.
- **`clusterResourceWhitelist: []` with CreateNamespace.** Argo CD creates the namespace itself, which in current versions does not need Namespace in the project whitelist. Do not add Namespace to a tenant project: a team could then ship its own Namespace manifest and drop its Pod Security labels.
- **New kinds for a tenant** (for example KEDA ScaledObjects) go in `extraNamespaceResources` in tenant.yaml; the chart refuses platform-only kinds.
- **External hosts in VirtualServices** are refused (only this tenant's Services are allowed as destinations); route to external services with a platform-owned VirtualService.
- **Hostnames are owned per tenant** (`hostnames:` in tenant.yaml). Certificate IP and URI SANs are not checked; keep the ClusterIssuer's own policy tight as well (for Vault PKI, the role's `allowed_domains` and `allow_ip_sans`).
- **Monitoring.** `tenant-monitoring-guard` keeps ServiceMonitors and PodMonitors to their own namespace (delete it if you do not run the Prometheus Operator). PrometheusRules are not limited: a tenant rule can query any series in the shared Prometheus and be expensive to evaluate. Remove PrometheusRule from `namespaceResources` and the edit rule set if that matters for you.
- **Kyverno's own rights.** Kyverno's background controller can create RoleBindings anywhere and bind the four tenant profiles, so a compromised Kyverno, or a malicious platform-owned policy, could grant itself tenant-admin outside tenant namespaces. Tenants cannot ship Kyverno policies (AppProject whitelist, tenant-rbac-guard), so this rests on Kyverno and the platform repo.
- **Kinds without a CRD.** Kyverno refuses a policy naming a kind whose CRD is not installed. Remove such kinds from `hostPolicyKinds` in `charts/tenant/values.yaml`, and drop the VirtualService rule from `tenant-service-guard` if you do not run Istio.
- **Pods created before the ExternalSecret syncs** briefly fail to pull, then succeed on kubelet retry.
- **Namespaces are not deleted** when an Application file is removed.
- **Kyverno and ESO ServiceAccount names** are the Helm defaults (`kyverno/kyverno-background-controller`, `external-secrets/external-secrets`). Adjust the exclusions if yours differ.
- **Using GCP Secret Manager instead of Vault:** swap the provider block in the ClusterSecretStore and change the keys, since Secret Manager names cannot contain `/` (for example `tenants-myapp-registry`).
