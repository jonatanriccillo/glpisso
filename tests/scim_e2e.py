#!/usr/bin/env python3
"""Suite E2E SCIM M6 contra un GLPI desplegado (stdlib, sin dependencias)."""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("SCIM_BASE", "http://localhost/plugins/sso/front/scim.php/v2").rstrip("/")
TOKEN_2 = os.environ.get("SCIM_TOKEN_2", "")
TOKEN_3 = os.environ.get("SCIM_TOKEN_3", "")
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
stamp = str(int(time.time()))


def request(method, path, token="", body=None, query=None):
    url = BASE + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/scim+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/scim+json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=20)
        raw = response.read()
        return response.status, dict(response.headers), json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, dict(exc.headers), json.loads(raw) if raw else None


def expect(label, expected, result):
    status, headers, body = result
    if status != expected:
        raise AssertionError(f"{label}: HTTP {status}, esperado {expected}, body={body}")
    content_type = headers.get("Content-Type", "")
    if expected != 204 and "application/scim+json" not in content_type:
        raise AssertionError(f"{label}: Content-Type inesperado {content_type}")
    print(f"PASS {label}: {status}")
    return body


def header_value(headers, name):
    """Return a response header without depending on its canonical casing."""
    wanted = name.lower()
    return next((value for key, value in headers.items() if key.lower() == wanted), "")


def delete_quiet(path, token):
    try:
        request("DELETE", path, token)
    except Exception:
        pass


def main():
    if not TOKEN_2 or not TOKEN_3:
        raise RuntimeError("SCIM_TOKEN_2 y SCIM_TOKEN_3 son obligatorios")

    user3a = user3b = user2 = group3 = None
    try:
        unauthenticated = request("GET", "/ServiceProviderConfig")
        expect("sin Bearer", 401, unauthenticated)
        assert header_value(unauthenticated[1], "WWW-Authenticate").startswith("Bearer")
        expect("Bearer inválido", 401, request("GET", "/ServiceProviderConfig", "invalid-token"))
        discovery = expect("discovery autenticado", 200, request("GET", "/ServiceProviderConfig", TOKEN_3))
        assert discovery["patch"]["supported"] is True
        expect("resource types", 200, request("GET", "/ResourceTypes", TOKEN_3))
        schemas = expect("schemas", 200, request("GET", "/Schemas", TOKEN_3))
        assert schemas["Resources"] and all(schema.get("attributes") for schema in schemas["Resources"])

        payload3a = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "externalId": "m6-ext-3a-" + stamp,
            "userName": "m6_scim_3a_" + stamp,
            "name": {"givenName": "M6", "familyName": "ThreeA"},
            "emails": [{"value": f"m6-3a-{stamp}@example.invalid", "primary": True}],
            "phoneNumbers": [{"value": "+54-11-3000-0001"}],
            "active": True,
        }
        doc = expect("crear User IdP 3/A", 201, request("POST", "/Users", TOKEN_3, payload3a))
        user3a = doc["id"]
        assert doc["externalId"] == payload3a["externalId"] and doc["active"] is True
        expect("GET User IdP 3/A", 200, request("GET", f"/Users/{user3a}", TOKEN_3))

        listing = expect("filtro userName", 200, request("GET", "/Users", TOKEN_3,
            query={"filter": f'userName eq "{payload3a["userName"]}"'}))
        assert listing["totalResults"] == 1 and listing["Resources"][0]["id"] == user3a
        expect("filtro inválido fail-closed", 400, request("GET", "/Users", TOKEN_3,
            query={"filter": 'displayName co "x"'}))

        put = dict(payload3a)
        put["name"] = {"givenName": "Updated", "familyName": "ThreeA"}
        put["active"] = "False"
        updated = expect("PUT User + active=false", 200, request("PUT", f"/Users/{user3a}", TOKEN_3, put))
        assert updated["active"] is False and updated["name"]["givenName"] == "Updated"
        patched = expect("PATCH User reactivate", 200, request("PATCH", f"/Users/{user3a}", TOKEN_3, {
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": "True"}],
        }))
        assert patched["active"] is True

        payload3b = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "externalId": "m6-ext-3b-" + stamp,
            "userName": "m6_scim_3b_" + stamp,
            "name": {"givenName": "M6", "familyName": "ThreeB"},
            "active": True,
        }
        user3b = expect("crear User IdP 3/B", 201, request("POST", "/Users", TOKEN_3, payload3b))["id"]

        payload2 = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "externalId": "m6-ext-2-" + stamp,
            "userName": "m6_scim_2_" + stamp,
            "name": {"givenName": "M6", "familyName": "Two"},
            "active": True,
        }
        user2 = expect("crear User IdP 2", 201, request("POST", "/Users", TOKEN_2, payload2))["id"]
        expect("aislamiento User 3 frente token 2", 404, request("GET", f"/Users/{user3a}", TOKEN_2))

        group_payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "externalId": "m6-group-3-" + stamp,
            "displayName": "M6 SCIM Group " + stamp,
            "members": [{"value": user3a}],
        }
        group_doc = expect("crear Group IdP 3", 201, request("POST", "/Groups", TOKEN_3, group_payload))
        group3 = group_doc["id"]
        assert [member["value"] for member in group_doc["members"]] == [user3a]
        expect("aislamiento Group 3 frente token 2", 404, request("GET", f"/Groups/{group3}", TOKEN_2))
        expect("rechazar member de otro IdP", 400, request("PATCH", f"/Groups/{group3}", TOKEN_3, {
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": user2}]}],
        }))

        group_doc = expect("PATCH add member", 200, request("PATCH", f"/Groups/{group3}", TOKEN_3, {
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": user3b}]}],
        }))
        assert {member["value"] for member in group_doc["members"]} == {user3a, user3b}
        group_doc = expect("PATCH remove member filter", 200, request("PATCH", f"/Groups/{group3}", TOKEN_3, {
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": f'members[value eq "{user3a}"]'}],
        }))
        assert [member["value"] for member in group_doc["members"]] == [user3b]

        replacement = dict(group_payload)
        replacement["displayName"] = "M6 SCIM Group Updated " + stamp
        replacement["members"] = [{"value": user3a}]
        group_doc = expect("PUT Group replace", 200, request("PUT", f"/Groups/{group3}", TOKEN_3, replacement))
        assert group_doc["displayName"] == replacement["displayName"]
        assert [member["value"] for member in group_doc["members"]] == [user3a]

        expect("DELETE Group", 204, request("DELETE", f"/Groups/{group3}", TOKEN_3))
        expect("GET Group eliminado", 404, request("GET", f"/Groups/{group3}", TOKEN_3))
        group3 = None

        expect("DELETE User soft 3/A", 204, request("DELETE", f"/Users/{user3a}", TOKEN_3))
        expect("GET User soft-deleted", 404, request("GET", f"/Users/{user3a}", TOKEN_3))
        user3a = None
        expect("DELETE User soft 3/B", 204, request("DELETE", f"/Users/{user3b}", TOKEN_3))
        user3b = None
        expect("DELETE User soft 2", 204, request("DELETE", f"/Users/{user2}", TOKEN_2))
        user2 = None

        print("SCIM E2E COMPLETO: Users/Groups/security en verde")
    finally:
        if group3:
            delete_quiet(f"/Groups/{group3}", TOKEN_3)
        if user3a:
            delete_quiet(f"/Users/{user3a}", TOKEN_3)
        if user3b:
            delete_quiet(f"/Users/{user3b}", TOKEN_3)
        if user2:
            delete_quiet(f"/Users/{user2}", TOKEN_2)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
