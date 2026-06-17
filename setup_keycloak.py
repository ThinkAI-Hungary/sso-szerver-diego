import argparse
import getpass
import os
import sys
import httpx

# Protocol Mappers config for LearnWorlds client custom claims
CUSTOM_MAPPERS = [
    {
        "name": "teljesnev",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "teljesnev",
            "claim.name": "teljesnev",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "multivalued": "false"
        }
    },
    {
        "name": "munkakor",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "munkakor",
            "claim.name": "munkakor",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "multivalued": "false"
        }
    },
    {
        "name": "aruhaz",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "aruhaz",
            "claim.name": "aruhaz",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "multivalued": "false"
        }
    },
    {
        "name": "munkakezdet",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "munkakezdet",
            "claim.name": "munkakezdet",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "multivalued": "false"
        }
    },
    {
        "name": "ujkollega",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "ujkollega",
            "claim.name": "ujkollega",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "multivalued": "false"
        }
    }
]

def main():
    parser = argparse.ArgumentParser(description="Configure Keycloak 'diego' realm and clients.")
    parser.add_argument("--keycloak-url", help="Keycloak Base URL (fallback: KEYCLOAK_BASE_URL env var)")
    parser.add_argument("--admin-user", default="admin", help="Admin username (fallback: KEYCLOAK_ADMIN_USER env var)")
    parser.add_argument("--redirect-uri", help="LearnWorlds redirect URI (fallback: LEARNWORLDS_REDIRECT_URI env var)")
    
    args = parser.parse_args()
    
    # Resolve parameters from CLI or environment
    keycloak_url = args.keycloak_url or os.environ.get("KEYCLOAK_BASE_URL")
    admin_user = args.admin_user or os.environ.get("KEYCLOAK_ADMIN_USER") or "admin"
    redirect_uri = args.redirect_uri or os.environ.get("LEARNWORLDS_REDIRECT_URI")
    
    if not keycloak_url:
        print("Error: Keycloak URL is required. Provide --keycloak-url or set KEYCLOAK_BASE_URL.")
        sys.exit(1)
        
    if not redirect_uri:
        print("Error: Redirect URI is required. Provide --redirect-uri or set LEARNWORLDS_REDIRECT_URI.")
        sys.exit(1)
        
    keycloak_url = keycloak_url.rstrip("/")
    
    # Securely fetch password
    admin_password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD")
    if not admin_password:
        admin_password = getpass.getpass("Keycloak admin password: ")
        
    if not admin_password:
        print("Error: Password cannot be empty.")
        sys.exit(1)
        
    print(f"Connecting to Keycloak at {keycloak_url}...")
    
    client = httpx.Client(verify=False, timeout=60.0)
    
    # 1. Authenticate with admin credentials
    token_url = f"{keycloak_url}/realms/master/protocol/openid-connect/token"
    try:
        resp = client.post(token_url, data={
            "client_id": "admin-cli",
            "username": admin_user,
            "password": admin_password,
            "grant_type": "password"
        })
        if resp.status_code != 200:
            print(f"Authentication failed (status: {resp.status_code}): {resp.text}")
            sys.exit(1)
            
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
    except Exception as e:
        print(f"Failed to authenticate: {e}")
        sys.exit(1)
        
    print("Successfully authenticated as admin.")
    
    # 2. Check if webhook-http provider is installed
    has_webhook = False
    try:
        info_resp = client.get(f"{keycloak_url}/admin/serverinfo", headers=headers)
        info_resp.raise_for_status()
        providers = info_resp.json().get("providers", {})
        event_listeners = providers.get("eventsListener", {}).get("providers", {})
        if "webhook-http" in event_listeners:
            print("Confirmed: 'webhook-http' event listener plugin is installed.")
            has_webhook = True
        else:
            print("WARNING: 'webhook-http' event listener plugin is NOT installed on the Keycloak server!")
            print("Webhook events (login, registration, update) will NOT trigger syncs automatically.")
    except Exception as e:
        print(f"Could not retrieve server providers info: {e}. Proceeding assuming no webhook listener...")
        
    # 3. Create or update the 'diego' realm
    realm_name = "diego"
    try:
        realms_resp = client.get(f"{keycloak_url}/admin/realms", headers=headers)
        realms_resp.raise_for_status()
        realms = [r["realm"] for r in realms_resp.json()]
    except Exception as e:
        print(f"Failed to fetch realms: {e}")
        sys.exit(1)
        
    realm_data = {
        "realm": realm_name,
        "enabled": True,
        "eventsEnabled": True,
        "enabledEventTypes": ["LOGIN", "REGISTER", "UPDATE_PROFILE"],
        "eventsListeners": ["jboss-logging"]
    }
    if has_webhook:
        realm_data["eventsListeners"].append("webhook-http")
        
    if realm_name not in realms:
        print(f"Creating realm '{realm_name}'...")
        try:
            resp = client.post(f"{keycloak_url}/admin/realms", json=realm_data, headers=headers)
            resp.raise_for_status()
            print(f"Realm '{realm_name}' created successfully.")
        except Exception as e:
            print(f"Failed to create realm: {e}")
            sys.exit(1)
    else:
        print(f"Realm '{realm_name}' already exists. Updating settings...")
        try:
            # Get existing settings first to preserve other configurations
            existing_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}", headers=headers)
            existing_resp.raise_for_status()
            existing_data = existing_resp.json()
            
            # Update event listeners and enabled events
            listeners = existing_data.get("eventsListeners", [])
            for listener in realm_data["eventsListeners"]:
                if listener not in listeners:
                    listeners.append(listener)
                    
            enabled_events = existing_data.get("enabledEventTypes", [])
            for evt in realm_data["enabledEventTypes"]:
                if evt not in enabled_events:
                    enabled_events.append(evt)
                    
            existing_data["eventsListeners"] = listeners
            existing_data["enabledEventTypes"] = enabled_events
            existing_data["eventsEnabled"] = True
            
            resp = client.put(f"{keycloak_url}/admin/realms/{realm_name}", json=existing_data, headers=headers)
            resp.raise_for_status()
            print(f"Realm '{realm_name}' settings updated successfully.")
        except Exception as e:
            print(f"Failed to update realm settings: {e}")
            sys.exit(1)
            
    # 4. Create or update 'learnworlds' confidential OIDC client
    learnworlds_client_rep = {
        "clientId": "learnworlds",
        "name": "LearnWorlds SSO",
        "description": "Diego LearnWorlds SSO Client",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [redirect_uri],
        "protocolMappers": CUSTOM_MAPPERS
    }
    
    # Query client
    try:
        clients_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients?clientId=learnworlds", headers=headers)
        clients_resp.raise_for_status()
        learnworlds_clients = clients_resp.json()
    except Exception as e:
        print(f"Failed to query learnworlds client: {e}")
        sys.exit(1)
        
    lw_id = None
    if not learnworlds_clients:
        print("Creating confidential 'learnworlds' client...")
        try:
            resp = client.post(f"{keycloak_url}/admin/realms/{realm_name}/clients", json=learnworlds_client_rep, headers=headers)
            resp.raise_for_status()
            # Query it again to get the auto-generated id
            clients_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients?clientId=learnworlds", headers=headers)
            lw_id = clients_resp.json()[0]["id"]
            print("Client 'learnworlds' created.")
        except Exception as e:
            print(f"Failed to create client 'learnworlds': {e}")
            sys.exit(1)
    else:
        lw_client_existing = learnworlds_clients[0]
        lw_id = lw_client_existing["id"]
        print(f"Updating confidential 'learnworlds' client (id: {lw_id})...")
        try:
            # Merge protocol mappers and redirect URIs
            lw_client_existing["redirectUris"] = [redirect_uri]
            lw_client_existing["publicClient"] = False
            lw_client_existing["standardFlowEnabled"] = True
            
            # Map existing protocol mappers by name
            existing_mappers = lw_client_existing.get("protocolMappers", [])
            existing_mapper_names = {m["name"] for m in existing_mappers}
            
            for m in CUSTOM_MAPPERS:
                if m["name"] not in existing_mapper_names:
                    existing_mappers.append(m)
                else:
                    # Update configuration of existing one
                    for em in existing_mappers:
                        if em["name"] == m["name"]:
                            em["config"] = m["config"]
                            
            lw_client_existing["protocolMappers"] = existing_mappers
            
            resp = client.put(f"{keycloak_url}/admin/realms/{realm_name}/clients/{lw_id}", json=lw_client_existing, headers=headers)
            resp.raise_for_status()
            print("Client 'learnworlds' updated.")
        except Exception as e:
            print(f"Failed to update client 'learnworlds': {e}")
            sys.exit(1)
            
    # Retrieve learnworlds client secret
    try:
        secret_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients/{lw_id}/client-secret", headers=headers)
        secret_resp.raise_for_status()
        learnworlds_secret = secret_resp.json()["value"]
    except Exception as e:
        print(f"Failed to get secret for 'learnworlds': {e}")
        sys.exit(1)
        
    # 5. Create or update 'sync-backend' client with service accounts
    sync_backend_rep = {
        "clientId": "sync-backend",
        "name": "SSO Sync Backend",
        "description": "Service Account client for Sync Backend",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True
    }
    
    try:
        clients_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients?clientId=sync-backend", headers=headers)
        clients_resp.raise_for_status()
        sync_backend_clients = clients_resp.json()
    except Exception as e:
        print(f"Failed to query sync-backend client: {e}")
        sys.exit(1)
        
    sb_id = None
    if not sync_backend_clients:
        print("Creating confidential 'sync-backend' client...")
        try:
            resp = client.post(f"{keycloak_url}/admin/realms/{realm_name}/clients", json=sync_backend_rep, headers=headers)
            resp.raise_for_status()
            clients_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients?clientId=sync-backend", headers=headers)
            sb_id = clients_resp.json()[0]["id"]
            print("Client 'sync-backend' created.")
        except Exception as e:
            print(f"Failed to create client 'sync-backend': {e}")
            sys.exit(1)
    else:
        sb_id = sync_backend_clients[0]["id"]
        print(f"Updating confidential 'sync-backend' client (id: {sb_id})...")
        try:
            existing_sb = sync_backend_clients[0]
            existing_sb["serviceAccountsEnabled"] = True
            existing_sb["publicClient"] = False
            existing_sb["standardFlowEnabled"] = False
            resp = client.put(f"{keycloak_url}/admin/realms/{realm_name}/clients/{sb_id}", json=existing_sb, headers=headers)
            resp.raise_for_status()
            print("Client 'sync-backend' updated.")
        except Exception as e:
            print(f"Failed to update client 'sync-backend': {e}")
            sys.exit(1)
            
    # Retrieve sync-backend client secret
    try:
        secret_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients/{sb_id}/client-secret", headers=headers)
        secret_resp.raise_for_status()
        sync_backend_secret = secret_resp.json()["value"]
    except Exception as e:
        print(f"Failed to get secret for 'sync-backend': {e}")
        sys.exit(1)
        
    # 6. Service account role mapping
    print("Assigning 'view-users' and 'query-users' roles to the sync-backend service account...")
    try:
        # Get service account user ID
        sa_user_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients/{sb_id}/service-account-user", headers=headers)
        sa_user_resp.raise_for_status()
        sa_user = sa_user_resp.json()
        sa_user_id = sa_user["id"]
        
        # Get realm-management client UUID
        rm_client_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients?clientId=realm-management", headers=headers)
        rm_client_resp.raise_for_status()
        rm_client_id = rm_client_resp.json()[0]["id"]
        
        # Get available roles for realm-management
        roles_resp = client.get(f"{keycloak_url}/admin/realms/{realm_name}/clients/{rm_client_id}/roles", headers=headers)
        roles_resp.raise_for_status()
        rm_roles = roles_resp.json()
        
        roles_to_map = []
        for role in rm_roles:
            if role["name"] in ["view-users", "query-users"]:
                roles_to_map.append(role)
                
        if not roles_to_map:
            print("WARNING: 'view-users' and 'query-users' roles not found in realm-management client.")
        else:
            # Map roles to service account user
            map_resp = client.post(
                f"{keycloak_url}/admin/realms/{realm_name}/users/{sa_user_id}/role-mappings/clients/{rm_client_id}",
                json=roles_to_map,
                headers=headers
            )
            map_resp.raise_for_status()
            print(f"Successfully mapped roles {[r['name'] for r in roles_to_map]} to service account user {sa_user['username']}.")
    except Exception as e:
        print(f"Failed to configure service account roles: {e}")
        sys.exit(1)
        
    # 7. Write to sync-backend/.env.generated
    env_content = f"""# Keycloak Configuration (Auto-generated by setup_keycloak.py)
KEYCLOAK_BASE_URL={keycloak_url}
KEYCLOAK_REALM={realm_name}
KEYCLOAK_CLIENT_ID=sync-backend
KEYCLOAK_CLIENT_SECRET={sync_backend_secret}

# LearnWorlds client secret for reference (if needed in your OIDC integration)
LEARNWORLDS_CLIENT_SECRET={learnworlds_secret}

# Note: Add the webhook secret (WEBHOOK_SECRET) and LearnWorlds API keys to your environment values manually.
"""
    try:
        generated_env_path = os.path.join("sync-backend", ".env.generated")
        with open(generated_env_path, "w", encoding="utf-8") as f:
            f.write(env_content)
        print(f"\nConfiguration successfully written to: {os.path.abspath(generated_env_path)}")
    except Exception as e:
        print(f"Failed to write generated environment file: {e}")
        
    discovery_url = f"{keycloak_url}/realms/{realm_name}/.well-known/openid-configuration"
    
    print("\n" + "="*80)
    print("KEYCLOAK SETUP COMPLETE")
    print("="*80)
    print(f"Realm:                     {realm_name}")
    print(f"OIDC Discovery Document:   {discovery_url}")
    print(f"learnworlds client secret: {learnworlds_secret}")
    print(f"sync-backend client secret: {sync_backend_secret}")
    print("="*80)
    print("Next steps:")
    print("1. Copy the discovery document URL above into LearnWorlds OIDC settings.")
    print("2. Set learnworlds client secret in the LearnWorlds authentication config.")
    print("3. Add custom mappings in LearnWorlds to map the claims: teljesnev, munkakor, aruhaz, munkakezdet, ujkollega")
    print("   * Note: 'munkakezdet' MUST be configured as a Text field, not a Date field in LearnWorlds.")
    print("4. Configure the sync-backend service on Railway using the values in sync-backend/.env.generated")
    print("="*80)

if __name__ == "__main__":
    main()
