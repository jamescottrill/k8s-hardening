# Platform tenancy: Argo CD + Kyverno + External Secrets + Vault

Self-service tenant namespaces with per-tenant registry credentials, OIDC user
profiles bound by namespace pattern, and the CIS Kubernetes Benchmark section 5
policies (Level 1 and Level 2). Teams add an app file; Argo CD creates the namespace,
stamps the tenant and Pod Security labels on it, and the pull secrets, network
policies and RoleBindings turn up without anyone touching the cluster.

## How it fits together

```
tenants/myapp/tenant.yaml        (platform owned) ──► tenants ApplicationSet ──► AppProject myapp
                                                                              └► ClusterPolicy tenant-access-myapp
tenants/myapp/apps/web-dev.yaml  (team owned)     ──► tenant-apps ApplicationSet
                                                        │  project: myapp
                                                        │  namespace: myapp-dev (CreateNamespace)
                                                        └─ labels: tenant=myapp, tenant-registry=true,
                                                                   pod-security enforce=restricted
                                                                   │
     ┌──────────────────────┬───────────────────────────┬─────────┴──────────┬─────────────────────────┐
     ▼                      ▼                           ▼                    ▼                         ▼
 Secret platform-     Secret tenant-registry      Pods get both        RoleBindings for        NetworkPolicies
 registry (shared     (Kyverno-generated          imagePullSecrets     groups in access:       default-deny +
 Quay robot, via      ExternalSecret from         (Kyverno mutate)     whose patterns match    allows (CIS 5.3.2)
 ClusterExternal-     kv/tenants/myapp/registry)                       myapp-dev
 Secret)
```

## Trust chain

This is what stops one tenant reaching another's credentials or namespaces.

1. **Tenant name = directory name.** Both ApplicationSets derive it from `tenants/<name>/`; nothing in a file can override it. CODEOWNERS keeps `tenant.yaml` with the platform team and `apps/` with the team.
2. **Teams cannot author Applications.** The tenant AppProject role only grants get, sync, actions and logs, so `managedNamespaceMetadata` only ever comes from the platform-owned ApplicationSet.
3. **AppProject destinations are `<tenant>` and `<tenant>-*`.**
4. **`tenant-namespace-guard`**: only the Argo CD application controller (or platform admins) may set, change or remove the tenant labels, and a namespace labelled `tenant=X` must be named `X` or `X-*`.
5. **`tenant-rbac-guard`**: Argo CD applies team manifests with its own cluster-wide rights, so in tenant namespaces RoleBindings may only bind a Role to ServiceAccounts in the same namespace, and Roles may not use wildcards, bind, escalate, impersonate or create tokens. Human access comes only from `access:` in `tenant.yaml`.
6. **`restrict-cluster-secret-store`**: in tenant namespaces only Kyverno and ESO may create ExternalSecrets that use a ClusterSecretStore (checked in `secretStoreRef`, `data[].sourceRef` and `dataFrom[].sourceRef`). Teams can bring their own namespaced SecretStore.
7. **Vault policy for ESO is read-only**, so a PushSecret through `platform-vault` cannot overwrite anyone's credential.

## User profiles (OIDC)

| Profile | Scope | Bound by | Can |
|---|---|---|---|
| `cluster-admin` (built-in) | cluster | `platform-admins` group, `platform/rbac/cluster-bindings.yaml` | Everything. The only group allowed to hold cluster-admin (CIS 5.1.1). |
| `platform-operator` | cluster | `platform-operators` group | Read everything except secrets, cordon and drain nodes, delete pods. For on-call. |
| `cluster-auditor` | cluster | `cluster-auditors` group | Read everything except secrets, including RBAC, Kyverno policies and policy reports. |
| `tenant-admin` | namespace | `access:` in tenant.yaml | `tenant-developer` plus read secrets, scale, evict, force-sync ExternalSecrets. |
| `tenant-developer` | namespace | `access:` in tenant.yaml | `tenant-viewer` plus exec, port-forward, delete pods, create and delete Jobs. |
| `tenant-viewer` | namespace | `access:` in tenant.yaml | Read workloads, config maps, logs, events, policy reports. No secrets, no exec. |

All profiles use explicit rules (no wildcards) and none below `tenant-admin` can read secrets (CIS 5.1.2). None can create pods directly (CIS 5.1.4): changes go through Git and Argo CD, and the Argo CD project role gives the tenant's `owners.groups` sync and restart actions.

### Binding groups to namespaces and namespace wildcards

```yaml
# tenants/myapp/tenant.yaml
access:
  - group: myapp-developers
    role: tenant-developer
    namespaces: ["myapp-dev", "myapp-test*"]
  - group: myapp-developers
    role: tenant-viewer
    namespaces: ["myapp", "myapp-prod"]
  - group: myapp-leads
    role: tenant-admin
    namespaces: ["myapp", "myapp-*"]
```

The tenant chart turns this into a Kyverno ClusterPolicy (`tenant-access-myapp`). Each entry generates a RoleBinding in every namespace labelled `tenant=myapp` whose name matches one of its patterns (`*` and `?` wildcards), including namespaces created later. Removing an entry removes its RoleBindings. The chart refuses to render if a pattern is outside the tenant, the role is not one of the three tenant profiles, or a group is given the same role twice, so mistakes fail in Argo CD rather than on the cluster. Kyverno can only bind the three tenant ClusterRoles (its `bind` permission is limited to them by `resourceNames`).

Set `oidcGroupPrefix` in `charts/tenant/values.yaml` if your API server uses `--oidc-groups-prefix`, and use the same prefix for the groups in `cluster-bindings.yaml`, `tenant-namespace-guard`, `tenant-rbac-guard` and `cis-restrict-cluster-admin-bindings`.

## CIS Kubernetes Benchmark, section 5

| Control | Level | Policy (`platform/kyverno/...`) | Mode |
|---|---|---|---|
| 5.1.1 cluster-admin only where required | L1 | `cis/rbac.yaml` cis-restrict-cluster-admin-bindings | Enforce |
| 5.1.2 Minimise access to secrets | L1 | Profiles in `platform/rbac/` | Design |
| 5.1.3 Minimise wildcards in Roles | L1 | `tenant-rbac-guard` (tenants), `cis/rbac.yaml` cis-rbac-hygiene (cluster) | Enforce / Audit |
| 5.1.4 Minimise access to create pods | L1 | Profiles in `platform/rbac/` | Design |
| 5.1.5 Default ServiceAccounts not used | L1 | `cis/service-accounts.yaml` (automount off on every default SA, audit use) | Mutate / Audit |
| 5.1.6 SA tokens only where necessary | L1 | `cis/service-accounts.yaml` audit-token-automount | Audit |
| 5.1.7 Avoid system:masters | L1 | OIDC groups only; no client certs issued to people | Process |
| 5.1.8 Limit bind, impersonate, escalate | L1 | `tenant-rbac-guard`, cis-rbac-hygiene | Enforce / Audit |
| 5.1.9 to 5.1.13 PV create, nodes/proxy, CSR approval, webhooks, token create | L1 | cis-rbac-hygiene (5.1.13 also enforced for tenants) | Audit |
| 5.2.1 Active policy control mechanism | L1 | Kyverno plus Pod Security Admission labels on tenant namespaces | Enforce |
| 5.2.2 to 5.2.13 Privileged, host namespaces, escalation, root, NET_RAW, capabilities, HostProcess, hostPath, hostPorts | L1/L2 | `cis/pod-security.yaml` (restricted for tenants, baseline audit elsewhere) | Enforce / Audit |
| 5.3.1 CNI supports NetworkPolicies | L1 | Calico | Platform |
| 5.3.2 All namespaces have NetworkPolicies | L2 | `cis/network-policies.yaml` | Generate |
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
| `platform/argocd/` | `tenants` ApplicationSet (AppProjects, access policies) and `tenant-apps` ApplicationSet (workloads). |
| `platform/rbac/` | Tenant and cluster user profiles, and OIDC group to cluster profile bindings. |
| `platform/kyverno/` | Tenancy policies and Kyverno RBAC. |
| `platform/kyverno/cis/` | CIS section 5 policies. |
| `platform/external-secrets/` | `platform-vault` ClusterSecretStore, `platform-registry` ClusterExternalSecret, TokenReview binding. |
| `charts/tenant/` | Renders each tenant's AppProject and access ClusterPolicy. |
| `tenants/` | One directory per tenant: `tenant.yaml` + `apps/*.yaml`. |
| `vault/` | ESO policy, tenant writer policy template, setup and onboarding scripts. |
| `optional/` | Not deployed: cosign image verification. |

## Prerequisites

- Argo CD 2.9+ (matrix of two Git generators with `pathParamPrefix`, `templatePatch`, server-side diff), in namespace `argocd` with the standard `argocd-application-controller` ServiceAccount.
- Kyverno 1.13+ (rule-level `failureAction`, CEL in ClusterPolicies, `generate.generateExisting`, `mutate.mutateExistingOnPolicyUpdate`), in namespace `kyverno`.
- External Secrets Operator 0.17+ (`external-secrets.io/v1`), installed as `external-secrets` in namespace `external-secrets`.
- Vault with KV v2 and Kubernetes auth reachable from the cluster.
- If you use Istio sidecars, istio-cni (or ambient mode). Without it the injected `istio-init` container needs NET_ADMIN and NET_RAW, which the restricted profile rejects.

## Before you apply

1. Replace placeholders throughout:
   - `platform.example.com` (label prefix): `grep -rl platform.example.com . | xargs sed -i 's/platform.example.com/<your prefix>/g'`
   - `https://github.com/example-org/platform-gitops.git`, `example-org` repo globs and CODEOWNERS teams
   - `https://vault.example.com:8200` in the ClusterSecretStore
   - `quay.example.com` in `cis/workloads.yaml` (approved registries)
   - OIDC group names and prefix (see User profiles)
   - System namespaces excluded from the baseline audit in `cis/pod-security.yaml`
2. Label the namespaces that must reach tenant pods (Istio gateways, Prometheus): `kubectl label ns <ns> platform.example.com/allow-tenant-ingress=true`
3. Vault: `K8S_HOST=https://<kube-vip>:6443 K8S_CA_FILE=ca.crt ./vault/setup.sh`
4. Shared credential: `vault kv put kv/platform/registry registry=quay.example.com username='platform+puller' password=...`
5. `kubectl apply -f bootstrap/`

Consider applying with every `failureAction: Enforce` set to `Audit` first, reading the policy reports for a few days, then switching to Enforce.

## Onboarding a tenant

1. Platform team: add `tenants/<tenant>/tenant.yaml` (owners, sourceRepos, `registry.enabled`, `access`) and a CODEOWNERS line for `tenants/<tenant>/apps/`. Add the tenant's registry to `cis-restrict-image-registries` if it is new.
2. If `registry.enabled: true`: `OIDC_MOUNT_ACCESSOR=... ./vault/onboard-tenant.sh <tenant> <idp-group>`, then the team writes their own robot credential:
   `vault kv put kv/tenants/<tenant>/registry registry=quay.example.com username='<org>+puller' password=...`
3. Team: add `tenants/<tenant>/apps/<app>.yaml`.

Rotating a credential is just `vault kv put` again; ESO refreshes hourly (or annotate the ExternalSecret with `force-sync` to do it now).

## App file format

```yaml
namespace: myapp-dev           # required: full name, must be <tenant> or <tenant>-<something>
source:                        # required
  repoURL: https://github.com/example-org/myapp-web.git
  path: deploy/chart
  targetRevision: main
helm:                          # optional; omit for plain manifests or Kustomize
  valueFiles: [values.yaml, values-dev.yaml]
```

`tenant.yaml` must always include `registry.enabled` (true or false); the ApplicationSet uses `missingkey=error` so a typo fails loudly rather than producing an unlabelled namespace. A namespace outside the tenant is refused by the AppProject at sync time.

## What was and was not tested

- Every CEL rule (22 expressions across 10 rules) was evaluated against 54 allow and deny cases: label spoofing and removal, `myapp` versus `myappx` prefix collisions, ClusterSecretStore references hidden in `data[]` and `dataFrom[]`, Roles with wildcards or escalate, RoleBindings to groups or other namespaces, cluster-admin bindings, secrets in env vars. The repo's own five RBAC profiles were run through cis-rbac-hygiene and pass. All passed.
- The tenant chart was rendered for both example tenants with a stand-in for `helm template` (Go text/template plus the Sprig functions it uses), including the failure cases for bad patterns, roles, duplicates and empty lists. Run real `helm template charts/tenant -f tenants/myapp/tenant.yaml --set name=myapp` in CI.
- YAML lint and shellcheck pass.
- The Kyverno CLI and a cluster were **not** available, so the generate, mutate and podSecurity rules, the `\{{ }}` escape and the ApplicationSet templating need checking on a cluster:

```bash
kubectl get clusterpolicy                       # all READY

# Label spoofing is blocked (impersonating a non-admin)
kubectl apply --dry-run=server --as=someone --as-group=myapp-developers -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: myapp-test
  labels:
    platform.example.com/tenant: myapp
EOF
# expect: denied by tenant-namespace-guard

# After the first tenant app syncs
kubectl get ns myapp-dev --show-labels
kubectl -n myapp-dev get externalsecret,secret,networkpolicy,rolebinding
kubectl -n myapp-dev get externalsecret tenant-registry -o jsonpath='{.spec.target.template.data}'   # literal {{ .registry }}
kubectl auth can-i create pods/exec -n myapp-dev  --as=x --as-group=myapp-developers   # yes
kubectl auth can-i create pods/exec -n myapp-prod --as=x --as-group=myapp-developers   # no
kubectl auth can-i get secrets      -n myapp-prod --as=x --as-group=myapp-leads        # yes
kubectl get policyreport -A; kubectl get clusterpolicyreport
```

## Known caveats

- **`\{{ }}` escaping** in `tenant-registry-externalsecret.yaml` keeps Kyverno from substituting ESO's template expressions. Those policies are applied as a plain directory; the tenant chart uses Helm-quoted strings for Kyverno variables instead.
- **Default ServiceAccounts lose their token** (CIS 5.1.5). Workloads that call the Kubernetes API must use their own ServiceAccount.
- **cis-restrict-cluster-admin-bindings is enforced**, so third-party charts that bind cluster-admin will fail to install. Give them a scoped ClusterRole or add a Kyverno PolicyException.
- **Egress is open.** CIS 5.3.2 is met with ingress policies; add default-deny egress once tenant egress needs are known.
- **`clusterResourceWhitelist: []` with CreateNamespace.** Argo CD creates the namespace itself, which in current versions does not need Namespace in the project whitelist. If a sync fails with "Namespace is not permitted" on your version, add `{group: "", kind: Namespace}`; the Kyverno guard still stops a mislabelled namespace.
- **Pods created before the ExternalSecret syncs** briefly fail to pull, then succeed on kubelet retry.
- **Namespaces are not deleted** when an app file is removed.
- **Kyverno and ESO ServiceAccount names** are the Helm defaults (`kyverno/kyverno-background-controller`, `external-secrets/external-secrets`). Adjust the exclusions if yours differ.
- **Using GCP Secret Manager instead of Vault:** swap the provider block in the ClusterSecretStore and change the keys, since Secret Manager names cannot contain `/` (for example `tenants-myapp-registry`).
