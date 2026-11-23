#!/usr/bin/env bash
# One-off Vault setup for the tenancy layer. Run as a Vault admin with VAULT_ADDR set.
#
#   K8S_HOST         API server URL as Vault should reach it (kube-vip address for kubeadm)
#   K8S_CA_FILE      path to the cluster CA certificate
#   KV_MOUNT         defaults to kv
#   AUTH_MOUNT       defaults to kubernetes (must match mountPath in the ClusterSecretStore)
set -euo pipefail

: "${K8S_HOST:?set K8S_HOST, e.g. https://10.0.0.10:6443}"
: "${K8S_CA_FILE:?set K8S_CA_FILE to the cluster CA cert path}"
KV_MOUNT="${KV_MOUNT:-kv}"
AUTH_MOUNT="${AUTH_MOUNT:-kubernetes}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# KV v2 mount
if ! vault secrets list -format=json | jq -e --arg m "${KV_MOUNT}/" 'has($m)' >/dev/null; then
  vault secrets enable -path="${KV_MOUNT}" kv-v2
fi

# Kubernetes auth. With Vault outside the cluster and no token_reviewer_jwt, Vault
# uses the client's own JWT for the TokenReview, so ESO's ServiceAccount needs the
# system:auth-delegator ClusterRole (see README).
if ! vault auth list -format=json | jq -e --arg m "${AUTH_MOUNT}/" 'has($m)' >/dev/null; then
  vault auth enable -path="${AUTH_MOUNT}" kubernetes
fi
vault write "auth/${AUTH_MOUNT}/config" \
  kubernetes_host="${K8S_HOST}" \
  kubernetes_ca_cert=@"${K8S_CA_FILE}"

# ESO policy and role, bound to the ESO ServiceAccount only
vault policy write external-secrets "${HERE}/external-secrets.hcl"
vault write "auth/${AUTH_MOUNT}/role/external-secrets" \
  bound_service_account_names=external-secrets \
  bound_service_account_namespaces=external-secrets \
  token_policies=external-secrets \
  token_ttl=1h

echo "Done. Now store the shared registry credential, for example:"
echo "  vault kv put ${KV_MOUNT}/platform/registry registry=quay.example.com username='platform+puller' password=..."
