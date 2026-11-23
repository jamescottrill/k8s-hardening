# Rendered per tenant by onboard-tenant.sh (the upper-case placeholder becomes a validated
# tenant name). Lets the tenant's own group manage its secrets so the platform team never
# handles their registry passwords.
path "kv/data/tenants/TENANT/*" {
  capabilities = ["create", "update", "patch", "read"]
}

path "kv/delete/tenants/TENANT/*" {
  capabilities = ["update"]
}

path "kv/undelete/tenants/TENANT/*" {
  capabilities = ["update"]
}

path "kv/metadata/tenants/TENANT/*" {
  capabilities = ["read", "list", "delete"]
}

path "kv/metadata/tenants/TENANT" {
  capabilities = ["list"]
}
