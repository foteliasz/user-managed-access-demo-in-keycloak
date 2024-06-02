from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenID
import requests

# ---------------------------------------------------------------------------- #
# Configure the Keycloak admin connection to master realm
# ---------------------------------------------------------------------------- #
server_url = "http://localhost:6100/"
realm_name = "auth-services-demo"
admin_username = "admin"
admin_password = "admin-password"
user_realm_name = "master"
keycloak_admin = KeycloakAdmin(server_url=server_url,
                               username=admin_username,
                               password=admin_password,
                               realm_name=realm_name,
                               user_realm_name=user_realm_name)

# ---------------------------------------------------------------------------- #
# Initialize Keycloak OpenID and Admin clients
# ---------------------------------------------------------------------------- #
user_agent_client_id = "user-agent-client"
keycloak_openid = KeycloakOpenID(server_url=server_url,
                                 realm_name=realm_name,
                                 client_id=user_agent_client_id)

# ---------------------------------------------------------------------------- #
# Authenticate user and get token
# ---------------------------------------------------------------------------- #
alpha_username = "alpha-username"
alpha_password = "alpha-password"
token = keycloak_openid.token(username=alpha_username,
                              password=alpha_password,
                              grant_type='password')
access_token = token['access_token']


# Requesting a UMA RPT (Requesting Party Token)
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

resource_server_client_id = "resource-server-client"
uma_url = f"{server_url}realms/{realm_name}/protocol/openid-connect/token"
uma_payload = {
    "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
    "audience": resource_server_client_id
}

response = requests.post(uma_url, json=uma_payload, headers=headers)
uma_token = response.json()
print(f"UMA RPT: {uma_token}")

# Access protected resource with UMA RPT
resource_url = "http://localhost:8080/resource"
resource_headers = {
    "Authorization": f"Bearer {uma_token['access_token']}"
}

resource_response = requests.get(resource_url, headers=resource_headers)
print(f"Resource Access Response: {resource_response.json()}")
