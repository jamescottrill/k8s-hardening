#!/usr/bin/env bash
# Runs setup.sh and onboard-tenant.sh against a Vault dev server, then checks what each
# policy actually allows. Expects VAULT_ADDR and a root VAULT_TOKEN (see
# docker-compose.yml).
set -euo pipefail

failures=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }

# expect_ok <description> <command...>: must succeed (run as the current VAULT_TOKEN).
expect_ok() {
  local what="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then pass "${what}"; else fail "${what} (expected success): ${out}"; fi
}
# expect_denied <description> <command...>: must fail with Vault's 403, not any error,
# so a typo, missing secret or dead server cannot make a security check pass.
expect_denied() {
  local what="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    fail "${what} (expected permission denied)"
  elif grep -qE 'Code: 403|permission denied' <<<"${out}"; then
    pass "${what}"
  else
    fail "${what} (failed, but not with permission denied): ${out}"
  fi
}
# expect_refused <description> <command...>: a script must reject its input (any failure).
expect_refused() {
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "${what} (expected the script to refuse)"; else pass "${what}"; fi
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
ROOT_TOKEN="${VAULT_TOKEN}"

# --- setup.sh needs a CA certificate for the Kubernetes auth config ----------------
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test-ca \
  -keyout "${work}/ca.key" -out "${work}/ca.crt" 2>/dev/null
K8S_HOST=https://10.0.0.10:6443 K8S_CA_FILE="${work}/ca.crt" bash vault/setup.sh >/dev/null
pass "setup.sh"

# --- onboarding is re-runnable -------------------------------------------------------
vault auth enable oidc >/dev/null
ACCESSOR="$(vault auth list -format=json | jq -r '."oidc/".accessor')"
OIDC_MOUNT_ACCESSOR="${ACCESSOR}" bash vault/onboard-tenant.sh myapp myapp-developers >/dev/null
OIDC_MOUNT_ACCESSOR="${ACCESSOR}" bash vault/onboard-tenant.sh myapp myapp-developers >/dev/null
pass "onboard-tenant.sh twice"
OIDC_MOUNT_ACCESSOR="${ACCESSOR}" bash vault/onboard-tenant.sh myapp "Myapp Developers@corp" >/dev/null
alias_name="$(vault read -format=json identity/group/name/tenant-myapp | jq -r .data.alias.name)"
if [[ "${alias_name}" == "Myapp Developers@corp" ]]; then
  pass "alias renamed in place"
else
  fail "alias rename (${alias_name})"
fi
expect_refused "onboarding refuses a globbing tenant name" \
  env OIDC_MOUNT_ACCESSOR="${ACCESSOR}" bash vault/onboard-tenant.sh '+' g
expect_refused "onboarding refuses a hyphenated tenant name" \
  env OIDC_MOUNT_ACCESSOR="${ACCESSOR}" bash vault/onboard-tenant.sh my-app g

vault kv put kv/tenants/teamb/registry password=teamb-secret >/dev/null
vault kv put kv/tenants/teamb/other password=other >/dev/null
vault kv put kv/platform/registry password=shared >/dev/null

# --- tenant writer policy ------------------------------------------------------------
export VAULT_TOKEN
VAULT_TOKEN="$(vault token create -policy=tenant-myapp-writer -field=token)"
expect_ok "tenant writer: put own registry" vault kv put kv/tenants/myapp/registry password=x
expect_ok "tenant writer: patch own registry" vault kv patch kv/tenants/myapp/registry username=y
expect_ok "tenant writer: read own registry" vault kv get kv/tenants/myapp/registry
expect_denied "tenant writer: read another tenant" vault kv get kv/tenants/teamb/registry
expect_denied "tenant writer: write another tenant" vault kv put kv/tenants/teamb/registry password=x
expect_denied "tenant writer: read the shared credential" vault kv get kv/platform/registry
VAULT_TOKEN="${ROOT_TOKEN}"

# --- per-person private KV, with real entities (userpass stands in for OIDC) ---------
vault auth enable userpass >/dev/null
for user in alice bob; do
  vault write "auth/userpass/users/${user}" password=pw token_policies=user-private >/dev/null
done
login() { vault login -method=userpass -token-only username="$1" password=pw; }
ALICE="$(login alice)"
BOB="$(login bob)"
ALICE_ID="$(VAULT_TOKEN="${ALICE}" vault token lookup -format=json | jq -r .data.entity_id)"
BOB_ID="$(VAULT_TOKEN="${BOB}" vault token lookup -format=json | jq -r .data.entity_id)"

VAULT_TOKEN="${ALICE}"
expect_ok "alice: write own space" vault kv put "kv/users/${ALICE_ID}/github" token=a
expect_ok "alice: read own space" vault kv get "kv/users/${ALICE_ID}/github"
expect_ok "alice: list own space" vault kv list "kv/users/${ALICE_ID}"
expect_ok "alice: soft delete and undelete" bash -c \
  "vault kv delete kv/users/${ALICE_ID}/github && vault kv undelete -versions=1 kv/users/${ALICE_ID}/github"
VAULT_TOKEN="${BOB}"
expect_ok "bob: write own space" vault kv put "kv/users/${BOB_ID}/github" token=b
expect_denied "bob: read alice's space" vault kv get "kv/users/${ALICE_ID}/github"
expect_denied "bob: write alice's space" vault kv put "kv/users/${ALICE_ID}/github" token=evil
expect_denied "bob: list everyone" vault kv list kv/users
expect_denied "bob: read tenant secrets" vault kv get kv/tenants/teamb/registry
VAULT_TOKEN="${ROOT_TOKEN}"

# --- External Secrets Operator policy ------------------------------------------------
VAULT_TOKEN="$(vault token create -policy=external-secrets -field=token)"
expect_ok "eso: read a tenant registry" vault kv get kv/tenants/teamb/registry
expect_ok "eso: read the shared credential" vault kv get kv/platform/registry
expect_denied "eso: write (PushSecret)" vault kv put kv/tenants/teamb/registry password=x
expect_denied "eso: read a personal space" vault kv get "kv/users/${ALICE_ID}/github"
expect_denied "eso: read other tenant paths" vault kv get kv/tenants/teamb/other
VAULT_TOKEN="${ROOT_TOKEN}"

# --- a non-default KV mount is rendered into the policies ----------------------------
KV_MOUNT=secret2 K8S_HOST=https://10.0.0.10:6443 K8S_CA_FILE="${work}/ca.crt" bash vault/setup.sh >/dev/null
vault kv put secret2/platform/registry password=shared >/dev/null
VAULT_TOKEN="$(vault token create -policy=external-secrets -field=token)"
expect_ok "KV_MOUNT=secret2: eso reads secret2/platform/registry" vault kv get secret2/platform/registry
VAULT_TOKEN="${ROOT_TOKEN}"
if vault policy read user-private | grep -q '^path "secret2/data/users/'; then
  pass "KV_MOUNT=secret2: user-private rendered"
else
  fail "KV_MOUNT=secret2: user-private not rendered"
fi
vault secrets enable -path=kvone -version=1 kv >/dev/null
vault secrets enable -path=notkv transit >/dev/null
expect_refused "setup.sh refuses an existing KV v1 mount" \
  env KV_MOUNT=kvone K8S_HOST=https://10.0.0.10:6443 K8S_CA_FILE="${work}/ca.crt" bash vault/setup.sh
expect_refused "setup.sh refuses an existing non-KV mount" \
  env KV_MOUNT=notkv K8S_HOST=https://10.0.0.10:6443 K8S_CA_FILE="${work}/ca.crt" bash vault/setup.sh
expect_refused "setup.sh refuses a multi-segment KV_MOUNT" \
  env KV_MOUNT='a/b' K8S_HOST=https://10.0.0.10:6443 K8S_CA_FILE="${work}/ca.crt" bash vault/setup.sh

echo
if (( failures )); then
  echo "${failures} check(s) failed"
  exit 1
fi
echo "All Vault checks passed"
