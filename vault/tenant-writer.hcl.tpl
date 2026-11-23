# Rendered per tenant by onboard-tenant.sh (TENANT is replaced).
# Lets the tenant's own group manage its secrets so the platform team never
# handles their registry passwords.
path "kv/data/tenants/TENANT/*" {
  capabilities = ["create", "update", "read"]
}

path "kv/metadata/tenants/TENANT/*" {
  capabilities = ["read", "list", "delete"]
}

path "kv/metadata/tenants/TENANT" {
  capabilities = ["list"]
}
