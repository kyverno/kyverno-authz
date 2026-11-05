"""Generate local-only demo identities; never persist passwords in the checkout."""

import json
import secrets


def identity_secret():
    password = secrets.token_urlsafe(32)
    realm = {
        "realm": "demo",
        "enabled": True,
        "sslRequired": "none",
        "accessTokenLifespan": 1800,
        "clients": [{
            "clientId": "demo-cli",
            "enabled": True,
            "publicClient": True,
            "directAccessGrantsEnabled": True,
            "standardFlowEnabled": False,
            "protocol": "openid-connect",
            "protocolMappers": [{
                "name": "demo-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": "agentrouter-demo",
                    "access.token.claim": "true",
                },
            }],
        }],
        "users": [{
            "username": name,
            "enabled": True,
            "firstName": name.title(),
            "lastName": "Demo",
            "email": f"{name}@example.invalid",
            "emailVerified": True,
            "credentials": [{
                "type": "password", "value": password, "temporary": False,
            }],
        } for name in ("alice", "bob")],
    }
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "demo-identity", "namespace": "agentrouter-demo"},
        "type": "Opaque",
        "stringData": {"password": password, "realm.json": json.dumps(realm)},
    }


if __name__ == "__main__":
    print(json.dumps(identity_secret()))
