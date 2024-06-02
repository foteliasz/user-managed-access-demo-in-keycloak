"""
docker run \
    --detach \
    --publish 6100:8080 \
    --env KEYCLOAK_ADMIN=admin \
    --env KEYCLOAK_ADMIN_PASSWORD=admin-password \
    quay.io/keycloak/keycloak:21.1.2 start-dev
"""

import requests
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection


# ---------------------------------------------------------------------------- #
# Configure the Keycloak connection to master realm
# ---------------------------------------------------------------------------- #
server_url = "http://localhost:6100/"
username = "admin"
password = "admin-password"
keycloak_connection = KeycloakOpenIDConnection(server_url=server_url,
                                               username=username,
                                               password=password)
keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

# ---------------------------------------------------------------------------- #
# Create a new realm
# ---------------------------------------------------------------------------- #
# Remove realm when exists
realm_name = "auth-services-demo"
realms = keycloak_admin.get_realms()
for realm in realms:
    if realm.get("realm") == realm_name:
        keycloak_admin.delete_realm("auth-services-demo")
        break

realm_payload = {
    "realm": realm_name,
    "enabled": True
}
realm = keycloak_admin.create_realm(payload=realm_payload)

# Reconfigure the Keycloak connection to the new realm
keycloak_admin.connection.user_realm_name = keycloak_admin.connection.realm_name
keycloak_admin.connection.realm_name = realm_name

# ---------------------------------------------------------------------------- #
# Create a new user
# ---------------------------------------------------------------------------- #
# Create alpha user
alpha_username = "alpha-user"
user_payload = {
    "username": alpha_username,
    "enabled": True,
}
alpha_user_uuid = keycloak_admin.create_user(payload=user_payload)

# Create beta user
beta_username = "beta-user"
user_payload['username'] = beta_username
keycloak_admin.create_user(payload=user_payload)

# ---------------------------------------------------------------------------- #
# Create client
# ---------------------------------------------------------------------------- #
client_id = "demo-client"
client_payload = {
    "clientId": client_id,
    "name": "Demo client for User-Managed Access authorization",
    "enabled": True,
    "publicClient": False,
    "serviceAccountsEnabled": True,
    "authorizationServicesEnabled": True
}
client_uuid = keycloak_admin.create_client(payload=client_payload)

# ---------------------------------------------------------------------------- #
# Create resource
# ---------------------------------------------------------------------------- #
resource_name = "alpha-resource"
resource_payload = {
    "name": resource_name,
    "displayName": "Alpha resource",
    "ownerManagedAccess": True
}
resource = keycloak_admin.create_client_authz_resource(client_id=client_uuid,
                                                       payload=resource_payload)

# ---------------------------------------------------------------------------- #
# Create scope
# ---------------------------------------------------------------------------- #
scope_name = "read"
scope_payload = {
    "name": scope_name,
    "displayName": "Allows read access to resource"
}
scope = keycloak_admin.create_client_authz_scopes(client_id=client_uuid,
                                                  payload=scope_payload)

# ---------------------------------------------------------------------------- #
# Create policy
#   Has to be done using requests library,
#   because the KeycloakAdmin class does not support it yet
# ---------------------------------------------------------------------------- #
url = (f"{server_url}admin/realms/{realm_name}/clients/"
       f"{client_uuid}/authz/resource-server/policy/user")
policy_name = "alpha-user-can"
headers = {
    'Authorization': f"Bearer {keycloak_admin.connection.token.get('access_token')}",
    'Content-Type': 'application/json'
}
policy_payload = {
    "name": policy_name,
    "description": "Policy that allows alpha user to access alpha resource",
    "logic": "POSITIVE",
    "users": [
        alpha_user_uuid
    ]
}
response = requests.request(method="POST",
                            url=url,
                            headers=headers,
                            json=policy_payload)
policy = response.json()

# ---------------------------------------------------------------------------- #
# Create permission
# ---------------------------------------------------------------------------- #
permission_name = "read-alpha-resource"
permission_payload = {
    "name": "read-alpha-resource",
    "description": "",
    "resources": [resource.get('_id')],
    "policies": [policy.get('id')],
    "decisionStrategy": "UNANIMOUS"
}
permission = keycloak_admin.create_client_authz_resource_based_permission(client_id=client_uuid,
                                                                          payload=permission_payload)
