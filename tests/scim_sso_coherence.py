#!/usr/bin/env python3
"""E2E de coherencia SCIM→OIDC y revocación de sesión en active=false."""

import html
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

GLPI = os.environ.get("GLPI_BASE", "http://localhost").rstrip("/")
SCIM = GLPI + "/plugins/sso/front/scim.php/v2"
TOKEN = os.environ.get("SCIM_TOKEN_3", "")
USERNAME = os.environ.get("OIDC_USERNAME", "")
PASSWORD = os.environ.get("OIDC_PASSWORD", "")
SUBJECT = os.environ.get("OIDC_SUBJECT", "")
EMAIL = os.environ.get("OIDC_EMAIL", "")
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client(with_cookies=True):
    handlers = [NoRedirect()]
    if with_cookies:
        handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    result = urllib.request.build_opener(*handlers)
    result.addheaders = [("User-Agent", "sso-scim-coherence/1.0")]
    return result


def fetch(opener, url, data=None, method=None, headers=None):
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        response = opener.open(request, timeout=20)
        return response.status, dict(response.headers), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")


def follow(opener, result):
    code, headers, body = result
    while code in (301, 302, 303):
        code, headers, body = fetch(opener, headers["Location"])
    return code, headers, body


def scim(method, path, body=None):
    raw = None if body is None else json.dumps(body).encode()
    headers = {"Authorization": "Bearer " + TOKEN, "Accept": "application/scim+json"}
    if raw is not None:
        headers["Content-Type"] = "application/scim+json"
    code, response_headers, text = fetch(client(False), SCIM + path, raw, method, headers)
    return code, response_headers, json.loads(text) if text else None


def main():
    if not all([TOKEN, USERNAME, PASSWORD, SUBJECT, EMAIL]):
        raise RuntimeError("faltan variables SCIM_TOKEN_3/OIDC_USERNAME/OIDC_PASSWORD/OIDC_SUBJECT/OIDC_EMAIL")
    users_id = None
    try:
        code, _, doc = scim("POST", "/Users", {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "externalId": SUBJECT, "userName": USERNAME,
            "name": {"givenName": "M6", "familyName": "Coherence"},
            "emails": [{"value": EMAIL, "primary": True}], "active": True,
        })
        if code != 201:
            raise AssertionError(f"SCIM create: HTTP {code}, body={doc}")
        users_id = doc["id"]
        print(f"PASS SCIM creó User id={users_id} con subject OIDC real")

        browser = client(True)
        code, headers, body = fetch(browser, GLPI + "/plugins/sso/front/login.php?idp=3")
        if code not in (301, 302, 303) or "code_challenge_method=S256" not in headers.get("Location", ""):
            raise AssertionError("OIDC no inició con PKCE")
        code, headers, body = follow(browser, fetch(browser, headers["Location"]))
        match = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', body)
        if not match:
            raise AssertionError("Keycloak no entregó formulario de login")
        action = html.unescape(match.group(1))
        form = urllib.parse.urlencode({"username": USERNAME, "password": PASSWORD, "credentialId": ""}).encode()
        code, headers, body = fetch(browser, action, form)
        callback = headers.get("Location", "")
        if code not in (301, 302, 303) or "callback.php" not in callback or "code=" not in callback:
            raise AssertionError(f"Keycloak no volvió al callback: HTTP {code} {callback} body={body[:500]}")
        code, headers, body = fetch(browser, callback)
        finish = headers.get("Location", "")
        if code not in (301, 302, 303) or "finish.php?t=" not in finish:
            raise AssertionError(f"callback no emitió ticket: HTTP {code} {body[:300]}")
        code, headers, body = fetch(browser, finish)
        if code not in (301, 302, 303):
            raise AssertionError(f"finish no creó sesión: HTTP {code} {body[:300]}")
        code, _, body = fetch(browser, GLPI + "/front/preference.php")
        if code != 200:
            raise AssertionError(f"sesión OIDC no válida: HTTP {code}")
        print("PASS login OIDC resolvió el User provisionado por SCIM")

        code, _, doc = scim("PATCH", f"/Users/{users_id}", {
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        })
        if code != 200 or doc.get("active") is not False:
            raise AssertionError(f"active=false falló: HTTP {code}, body={doc}")
        code, headers, _ = fetch(browser, GLPI + "/front/preference.php")
        if code == 200:
            raise AssertionError("la sesión siguió viva después de active=false")
        print(f"PASS active=false invalidó la sesión viva (HTTP posterior {code})")

        code, _, _ = scim("DELETE", f"/Users/{users_id}")
        if code != 204:
            raise AssertionError(f"cleanup SCIM User: HTTP {code}")
        users_id = None
        print("SCIM↔OIDC COHERENCE E2E COMPLETO")
    finally:
        if users_id is not None:
            scim("DELETE", f"/Users/{users_id}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
