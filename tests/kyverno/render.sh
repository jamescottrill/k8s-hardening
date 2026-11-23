#!/usr/bin/env bash
# Renders each tenant's chart into tests/kyverno/rendered/ so the Kyverno CLI tests can
# exercise the per-tenant policies (access, hostnames). Run before `kyverno test`.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p tests/kyverno/rendered
for dir in tenants/*/; do
  tenant="$(basename "${dir}")"
  helm template "tenant-${tenant}" charts/tenant -f "${dir}tenant.yaml" --set name="${tenant}" \
    > "tests/kyverno/rendered/${tenant}.yaml"
done
