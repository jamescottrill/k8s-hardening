# Private KV space for every person who logs in to Vault through OIDC (Keycloak):
# kv/users/<entity id>/*, readable and writable only by that person.
#
# Keyed on the Vault entity ID rather than a username, because the entity ID cannot be
# changed by the user. A path built from the OIDC alias name would follow whatever
# claim the OIDC role's user_claim names; if that is email or preferred_username and
# Keycloak lets users edit it, one person could rename themselves into another's space.
#
# Find your own path:  vault token lookup -format=json | jq -r .data.entity_id
#
# Attach this policy to the OIDC role (token_policies) so everyone gets it on login.
# Nothing in the cluster can read these paths: external-secrets.hcl does not grant
# kv/data/users/*, and must never be widened to kv/data/* (one KV mount holds both).

path "kv/data/users/{{identity.entity.id}}/*" {
  capabilities = ["create", "read", "update", "patch", "delete"]
}

# Soft delete, undelete and permanent destroy of versions
path "kv/delete/users/{{identity.entity.id}}/*" {
  capabilities = ["update"]
}
path "kv/undelete/users/{{identity.entity.id}}/*" {
  capabilities = ["update"]
}
path "kv/destroy/users/{{identity.entity.id}}/*" {
  capabilities = ["update"]
}

# Listing and metadata (versions, custom metadata), and deleting a key with all versions
path "kv/metadata/users/{{identity.entity.id}}/*" {
  capabilities = ["read", "list", "update", "patch", "delete"]
}
path "kv/metadata/users/{{identity.entity.id}}" {
  capabilities = ["list"]
}
