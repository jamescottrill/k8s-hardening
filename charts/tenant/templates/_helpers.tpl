{{- /*
tenant.name: the validated tenant name. Every template uses this instead of
.Values.name, so a bad name fails the whole render.

No hyphens, because namespace ownership is "<tenant>" or "<tenant>-*": with hyphens
allowed, tenant "myapp" would also own every namespace of a tenant called "myapp-x".
Reserved names would give a tenant system namespaces (kube -> kube-system) or collide
with platform objects (tenant -> the tenant-<name> Applications).
*/ -}}
{{- define "tenant.name" -}}
{{- $name := required "name is required (set by the tenant's chart Application)" .Values.name -}}
{{- if not (regexMatch "^[a-z][a-z0-9]{1,30}$" $name) -}}
{{- fail (printf "tenant name %q must be 2-31 lowercase letters and digits, starting with a letter, with no hyphens" $name) -}}
{{- end -}}
{{- $reserved := list "kube" "default" "argocd" "argo" "kyverno" "external" "externalsecrets" "cert" "certmanager" "calico" "tigera" "istio" "gateway" "metallb" "monitoring" "prometheus" "grafana" "loki" "vault" "platform" "tenant" "tenants" "system" "openshift" -}}
{{- if has $name $reserved -}}
{{- fail (printf "tenant name %q is reserved for the platform" $name) -}}
{{- end -}}
{{- $name -}}
{{- end -}}

{{- /*
tenant.namespaceResources: the AppProject namespaceResourceWhitelist as YAML.
Refuses wildcards and kinds that would let a tenant's repo change cluster policy or
Argo CD, lift quotas, or route traffic to other tenants' pods.
*/ -}}
{{- define "tenant.namespaceResources" -}}
{{- $forbiddenGroups := list "kyverno.io" "policies.kyverno.io" "reports.kyverno.io" "wgpolicyk8s.io" "argoproj.io" "generators.external-secrets.io" "admissionregistration.k8s.io" "apiextensions.k8s.io" -}}
{{- $forbiddenKinds := list "Namespace" "ResourceQuota" "LimitRange" "Endpoints" "EndpointSlice" "PushSecret" "ServiceEntry" "Sidecar" "ReferenceGrant" "Pod" "DaemonSet" "Gateway" "TLSRoute" "TCPRoute" "UDPRoute" "ListenerSet" "BackendTLSPolicy" -}}
{{- $all := concat .Values.namespaceResources (.Values.extraNamespaceResources | default list) -}}
{{- range $i, $r := $all -}}
{{- if not (hasKey $r "group") -}}
{{- fail (printf "namespace resource %d (%v) needs a group (\"\" for the core group)" $i $r) -}}
{{- end -}}
{{- if not (and (hasKey $r "kind") (kindIs "string" $r.kind) $r.kind) -}}
{{- fail (printf "namespace resource %d (%v) needs a non-empty kind" $i $r) -}}
{{- end -}}
{{- if or (eq (toString $r.group) "*") (eq (toString $r.kind) "*") (eq (toString $r.kind) "") -}}
{{- fail (printf "namespace resource %d: wildcards and empty kinds are not allowed (%v)" $i $r) -}}
{{- end -}}
{{- if has (toString $r.group) $forbiddenGroups -}}
{{- fail (printf "namespace resource %d: group %q is platform-only" $i $r.group) -}}
{{- end -}}
{{- if has (toString $r.kind) $forbiddenKinds -}}
{{- fail (printf "namespace resource %d: kind %q is platform-only" $i $r.kind) -}}
{{- end -}}
{{- end -}}
{{- range $all }}
- group: {{ .group | quote }}
  kind: {{ .kind }}
{{- end -}}
{{- end -}}

{{- /*
tenant.ownedHost: CEL that is true when the host expression passed in is on this
tenant's hostnames list (variables.allowed), exactly or under a "*.suffix" entry.
A "*.suffix" entry owns every name below the suffix.
*/ -}}
{{- define "tenant.ownedHost" -}}
variables.allowed.exists(p, p == {{ . }} || (p.startsWith('*.') && {{ . }}.endsWith(p.substring(1))))
{{- end -}}
