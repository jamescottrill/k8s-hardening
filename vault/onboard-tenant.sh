#!/usr/bin/env bash
# Give a tenant's IdP group write access to kv/tenants/<tenant>/* so the team can
# store (and rotate) its own registry credential.
#
# Usage: OIDC_MOUNT_ACCESSOR=auth_oidc_xxxx ./onboard-tenant.sh myapp myapp-developers
#   OIDC_MOUNT_ACCESSOR  from: vault auth list -format=json | jq -r '."oidc/".accessor'
set -euo pipefail

TENANT="${1:?tenant name, e.g. myapp}"
GROUP="${2:?IdP group name, e.g. myapp-developers}"
: "${OIDC_MOUNT_ACCESSOR:?set OIDC_MOUNT_ACCESSOR}"
KV_MOUNT="${KV_MOUNT:-kv}"   # must match setup.sh
HERE="$(cd "$(dirname "$0")" && pwd)"

# The name is substituted into a Vault policy path, where * and + are globs: an
# unchecked name could grant access to every tenant. Same rule as the tenant chart.
if [[ ! "${TENANT}" =~ ^[a-z][a-z0-9]{1,30}$ ]]; then
  echo "tenant name '${TENANT}' must be 2-31 lowercase letters and digits, no hyphens" >&2
  exit 1
fi

if [[ ! "${KV_MOUNT}" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "KV_MOUNT '${KV_MOUNT}' must be a single path segment" >&2
  exit 1
fi

sed -e "s/TENANT/${TENANT}/g" -e "s#^path \"kv/#path \"${KV_MOUNT}/#" "${HERE}/tenant-writer.hcl.tpl" \
  | vault policy write "tenant-${TENANT}-writer" -

# Re-runnable: writing an existing group by name updates it and returns no id, so read
# the id back by name.
vault write identity/group \
  name="tenant-${TENANT}" type=external policies="tenant-${TENANT}-writer" >/dev/null
GROUP_ID="$(vault read -field=id "identity/group/name/tenant-${TENANT}")"

vault write identity/group-alias \
  name="${GROUP}" mount_accessor="${OIDC_MOUNT_ACCESSOR}" canonical_id="${GROUP_ID}" >/dev/null

echo "tenant-${TENANT} can now run, for example:"
echo "  vault kv put ${KV_MOUNT}/tenants/${TENANT}/registry registry=quay.example.com username='${TENANT}+puller' password=..."
