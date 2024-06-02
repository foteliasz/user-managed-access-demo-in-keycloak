from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection


server_url = "http://localhost:6100/"
username = "admin"
password = "admin-password"
keycloak_connection = KeycloakOpenIDConnection(server_url=server_url,
                                               username=username,
                                               password=password)

keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

# ---------------------------------------------------------------------------- #
# Delete the realm if exists
# ---------------------------------------------------------------------------- #
realm_name = "auth-services-demo"
realms = keycloak_admin.get_realms()
for realm in realms:
    if realm["realm"] == realm_name:
        keycloak_admin.delete_realm(realm_name)
        break
