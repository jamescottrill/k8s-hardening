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
HERE="$(cd "$(dirname "$0")" && pwd)"

sed "s/TENANT/${TENANT}/g" "${HERE}/tenant-writer.hcl.tpl" | vault policy write "tenant-${TENANT}-writer" -

GROUP_ID="$(vault write -field=id identity/group \
  name="tenant-${TENANT}" type=external policies="tenant-${TENANT}-writer")"

vault write identity/group-alias \
  name="${GROUP}" mount_accessor="${OIDC_MOUNT_ACCESSOR}" canonical_id="${GROUP_ID}" >/dev/null

echo "tenant-${TENANT} can now run, for example:"
echo "  vault kv put kv/tenants/${TENANT}/registry registry=quay.example.com username='${TENANT}+puller' password=..."
