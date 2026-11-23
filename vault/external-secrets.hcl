# Policy for the External Secrets Operator. Read-only by design: even if a tenant
# found a way to send a PushSecret through platform-vault, Vault would refuse the write.

# Shared platform registry credential
path "kv/data/platform/registry" {
  capabilities = ["read"]
}

# Each tenant's own registry credential (+ matches exactly one path segment)
path "kv/data/tenants/+/registry" {
  capabilities = ["read"]
}
