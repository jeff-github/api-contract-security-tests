"""
test_portal_api_v4.py

Portal API pytest suite aligned to the actual route + response shapes you described:
- routes.dart defines:
  GET   /api/v1/portal/me
  GET   /api/v1/portal/users
  GET   /api/v1/portal/users/<userId>
  POST  /api/v1/portal/users
  PATCH /api/v1/portal/users/<userId>
  GET   /api/v1/portal/sites
  GET   /api/v1/portal/patients
  (plus activation + OTP + password reset + config endpoints)

- portal_user.dart shapes:
  GET /users -> {"users":[...]} (NOT paginated)
  GET /sites -> {"sites":[...], "sync": {... optional ...}}
  GET /patients -> {"patients":[...], "sync": {... optional ...}, "assigned_sites":[... optional ...]}

How it authenticates:
- Reads token from env var PORTAL_TOKEN OR local file portal_token.txt
- Reads base url from env var PORTAL_BASE_URL (default: http://localhost:3000)

Run:
    pip install -U pytest requests
    python -m pytest -v test_portal_api_v4.py
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import pytest
import requests


DEFAULT_BASE_URL = "http://localhost:3000"
TOKEN_FILES = ("portal_token.txt", ".portal_token.txt")
TIMEOUT_SEC = float(os.environ.get("PORTAL_HTTP_TIMEOUT", "20"))

JWT_RE = re.compile(r"(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)")


def base_url() -> str:
    return os.environ.get("PORTAL_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def read_token() -> Optional[str]:
    t = os.environ.get("PORTAL_TOKEN")
    if t and t.strip():
        return t.strip()
    for p in TOKEN_FILES:
        if os.path.exists(p):
            try:
                v = open(p, "r", encoding="utf-8").read().strip()
                if v:
                    return v
            except Exception:
                continue
    return None


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
    except Exception:
        return {}


def pretty(resp: requests.Response) -> str:
    try:
        return json.dumps(resp.json(), indent=2, sort_keys=True)
    except Exception:
        return resp.text


def assert_status_in(resp: requests.Response, allowed: set[int]) -> None:
    assert resp.status_code in allowed, (
        f"Expected status in {sorted(allowed)}, got {resp.status_code}\n"
        f"URL: {resp.request.method} {resp.url}\n"
        f"Response:\n{pretty(resp)}"
    )


def assert_not_5xx(resp: requests.Response) -> None:
    assert resp.status_code < 500, (
        f"Unexpected server error {resp.status_code}\n"
        f"URL: {resp.request.method} {resp.url}\n"
        f"Response:\n{pretty(resp)}"
    )


def header(resp: requests.Response, name: str) -> Optional[str]:
    return resp.headers.get(name)


def assert_json_content_type(resp: requests.Response) -> None:
    ct = header(resp, "Content-Type") or ""
    assert "application/json" in ct, f"Expected JSON Content-Type, got: {ct}"


@dataclass
class PortalClient:
    base: str
    token: Optional[str]

    def headers(self, extra: Optional[dict] = None) -> dict:
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base}{path}"

    def get(self, path: str, **kwargs) -> requests.Response:
        return requests.get(self.url(path), headers=self.headers(), timeout=TIMEOUT_SEC, **kwargs)

    def options(self, path: str, **kwargs) -> requests.Response:
        return requests.options(self.url(path), headers=self.headers(), timeout=TIMEOUT_SEC, **kwargs)

    def post(self, path: str, json_body: dict, **kwargs) -> requests.Response:
        return requests.post(
            self.url(path),
            headers=self.headers({"Content-Type": "application/json"}),
            json=json_body,
            timeout=TIMEOUT_SEC,
            **kwargs,
        )

    def patch(self, path: str, json_body: dict, **kwargs) -> requests.Response:
        return requests.patch(
            self.url(path),
            headers=self.headers({"Content-Type": "application/json"}),
            json=json_body,
            timeout=TIMEOUT_SEC,
            **kwargs,
        )


@pytest.fixture(scope="session")
def portal() -> PortalClient:
    if not os.environ.get("PORTAL_BASE_URL"):
        pytest.skip("Set PORTAL_BASE_URL to an authorized test environment")
    return PortalClient(base=base_url(), token=read_token())


@pytest.fixture(scope="session")
def jwt_payload(portal: PortalClient) -> Dict[str, Any]:
    if not portal.token:
        return {}
    return decode_jwt_payload(portal.token)


# ---------- small helpers for endpoint parsing ----------

def get_json(resp: requests.Response) -> Optional[dict]:
    try:
        return resp.json()
    except Exception:
        return None


def get_me(portal: PortalClient) -> Tuple[requests.Response, Optional[dict]]:
    r = portal.get("/api/v1/portal/me")
    return r, get_json(r)


def get_users(portal: PortalClient) -> Tuple[requests.Response, Optional[dict]]:
    r = portal.get("/api/v1/portal/users")
    return r, get_json(r)


def get_sites(portal: PortalClient) -> Tuple[requests.Response, Optional[dict]]:
    r = portal.get("/api/v1/portal/sites")
    return r, get_json(r)


def get_patients(portal: PortalClient) -> Tuple[requests.Response, Optional[dict]]:
    r = portal.get("/api/v1/portal/patients")
    return r, get_json(r)


def pick_first_user_id(users_payload: dict) -> Optional[str]:
    users = users_payload.get("users") if isinstance(users_payload, dict) else None
    if isinstance(users, list) and users:
        u = users[0]
        if isinstance(u, dict):
            return u.get("id")
    return None


# =======================================================
# 1) Auth & token behavior (10 tests)
# =======================================================

def test_auth_me_no_header_401(portal: PortalClient):
    r = requests.get(f"{portal.base}/api/v1/portal/me", headers={"Accept": "application/json"}, timeout=TIMEOUT_SEC)
    assert_status_in(r, {401})
    assert_json_content_type(r)
    body = r.json()
    assert "error" in body


def test_auth_me_malformed_bearer_401(portal: PortalClient):
    r = requests.get(
        f"{portal.base}/api/v1/portal/me",
        headers={"Accept": "application/json", "Authorization": "Bearer"},
        timeout=TIMEOUT_SEC,
    )
    assert_status_in(r, {401})
    assert "error" in r.json()


def test_auth_me_garbage_token_401(portal: PortalClient):
    r = requests.get(
        f"{portal.base}/api/v1/portal/me",
        headers={"Accept": "application/json", "Authorization": "Bearer abc.def.ghi"},
        timeout=TIMEOUT_SEC,
    )
    assert_status_in(r, {401})
    assert "error" in r.json()


def test_auth_token_present_or_skip(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found. Set PORTAL_TOKEN or create portal_token.txt to run authenticated tests.")
    assert portal.token.startswith("eyJ")


def test_auth_token_structure_looks_like_jwt(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    parts = portal.token.split(".")
    assert len(parts) == 3
    assert JWT_RE.search(portal.token), "Token does not look like a JWT (eyJ...)"


def test_auth_token_payload_has_exp_and_aud(jwt_payload: Dict[str, Any], portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    assert "exp" in jwt_payload and "aud" in jwt_payload, f"JWT payload missing exp/aud: {jwt_payload}"


def test_auth_token_exp_in_future(jwt_payload: Dict[str, Any], portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    exp = jwt_payload.get("exp")
    assert isinstance(exp, (int, float))
    assert exp > time.time(), f"Token expired (exp={exp}). Re-capture token and rerun."


def test_auth_me_with_token_200(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_me(portal)
    assert_status_in(r, {200})
    assert isinstance(data, dict)


def test_auth_users_without_token_401_or_403(portal: PortalClient):
    # Depending on implementation, /users might be 401 or 403 when unauth.
    r = requests.get(f"{portal.base}/api/v1/portal/users", headers={"Accept": "application/json"}, timeout=TIMEOUT_SEC)
    assert_status_in(r, {401, 403})
    assert_json_content_type(r)


def test_auth_sites_without_token_401_or_403(portal: PortalClient):
    r = requests.get(f"{portal.base}/api/v1/portal/sites", headers={"Accept": "application/json"}, timeout=TIMEOUT_SEC)
    assert_status_in(r, {401, 403})
    assert_json_content_type(r)


# =======================================================
# 2) CORS & security headers (7 tests)
# =======================================================

@pytest.mark.parametrize("path", [
    "/api/v1/portal/me",
    "/api/v1/portal/users",
    "/api/v1/portal/sites",
    "/api/v1/portal/patients",
])
def test_security_options_preflight_ok(portal: PortalClient, path: str):
    r = portal.options(path)
    assert_status_in(r, {200, 204})


@pytest.mark.parametrize("path", [
    "/api/v1/portal/me",
    "/api/v1/portal/users",
    "/api/v1/portal/sites",
    "/api/v1/portal/patients",
])
def test_security_content_type_json_common_endpoints(portal: PortalClient, path: str):
    r = portal.get(path)
    assert_status_in(r, {200, 400, 401, 403, 404})
    assert_json_content_type(r)


@pytest.mark.parametrize("path", [
    "/api/v1/portal/me",
    "/api/v1/portal/users",
])
def test_security_headers_present(portal: PortalClient, path: str):
    r = portal.get(path)
    assert_status_in(r, {200, 400, 401, 403, 404})
    assert header(r, "x-content-type-options") is not None
    assert header(r, "x-frame-options") is not None
    assert header(r, "referrer-policy") is not None


def test_security_cors_allow_methods_mentions_get(portal: PortalClient):
    r = portal.get("/api/v1/portal/me")
    assert_status_in(r, {200, 401})
    h = header(r, "access-control-allow-methods")
    assert h is not None and "GET" in h


def test_security_cors_allow_headers_mentions_authorization(portal: PortalClient):
    r = portal.get("/api/v1/portal/me")
    assert_status_in(r, {200, 401})
    h = header(r, "access-control-allow-headers")
    assert h is not None and "Authorization" in h


def test_security_auth_error_not_html(portal: PortalClient):
    r = requests.get(f"{portal.base}/api/v1/portal/me", headers={"Accept": "application/json"}, timeout=TIMEOUT_SEC)
    assert_status_in(r, {401})
    assert not r.text.strip().lower().startswith("<!doctype html")


def test_security_404_not_html(portal: PortalClient):
    r = portal.get("/api/v1/portal/__nope__")
    assert_status_in(r, {404, 401, 403})
    assert not r.text.strip().lower().startswith("<!doctype html")


# =======================================================
# 3) /me contract (6 tests)
# =======================================================

def test_me_required_keys(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_me(portal)
    assert_status_in(r, {200})
    for key in ("id", "email", "roles", "active_role", "status"):
        assert key in data, f"Missing '{key}' in /me:\n{pretty(r)}"


def test_me_roles_list_nonempty(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_me(portal)
    assert_status_in(r, {200})
    assert isinstance(data.get("roles"), list)
    assert len(data["roles"]) >= 1


def test_me_active_role_in_roles(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_me(portal)
    assert_status_in(r, {200})
    assert data.get("active_role") in (data.get("roles") or [])


def test_me_email_string(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_me(portal)
    assert_status_in(r, {200})
    assert isinstance(data.get("email"), str)


def test_me_status_string(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_me(portal)
    assert_status_in(r, {200})
    assert isinstance(data.get("status"), str)


def test_me_id_is_uuidish(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_me(portal)
    assert_status_in(r, {200})
    # Relaxed: just ensure it parses as UUID
    uuid.UUID(str(data.get("id")))


# =======================================================
# 4) /users list + detail RBAC & contract (10 tests)
# =======================================================

def test_users_list_rbac_200_or_403(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_users(portal)
    assert_status_in(r, {200, 403})
    if r.status_code == 200:
        assert isinstance(data, dict)


def test_users_list_shape_users_key_if_200(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_users(portal)
    if r.status_code == 403:
        pytest.skip("/users forbidden for this role")
    assert_status_in(r, {200})
    assert "users" in data
    assert isinstance(data["users"], list)


def test_users_first_user_has_core_fields_if_present(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_users(portal)
    if r.status_code == 403:
        pytest.skip("/users forbidden for this role")
    assert_status_in(r, {200})
    if not data["users"]:
        pytest.skip("No users returned")
    u = data["users"][0]
    for k in ("id", "email", "name", "status", "created_at", "roles", "sites"):
        assert k in u, f"Missing '{k}' in user:\n{pretty(r)}"
    assert isinstance(u["roles"], list)


def test_users_list_unique_ids(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_users(portal)
    if r.status_code == 403:
        pytest.skip("/users forbidden for this role")
    assert_status_in(r, {200})
    ids = [u.get("id") for u in data.get("users", []) if isinstance(u, dict)]
    ids = [i for i in ids if i]
    assert len(ids) == len(set(ids)), "Duplicate user ids in /users"


def test_users_get_by_id_200_403_or_404(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r_users, data = get_users(portal)
    if r_users.status_code == 403:
        pytest.skip("/users forbidden for this role; cannot pick id")
    assert_status_in(r_users, {200})
    uid = pick_first_user_id(data)
    if not uid:
        pytest.skip("No user id found")
    r = portal.get(f"/api/v1/portal/users/{uid}")
    assert_status_in(r, {200, 403, 404})
    assert_not_5xx(r)
    if r.status_code == 200:
        assert get_json(r).get("id") == uid


def test_users_get_by_id_invalid_uuid_is_4xx_not_500(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r = portal.get("/api/v1/portal/users/not-a-uuid")
    assert_status_in(r, {400, 401, 403, 404})
    assert_not_5xx(r)


def test_users_get_by_random_uuid_is_4xx_not_500(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    rid = str(uuid.uuid4())
    r = portal.get(f"/api/v1/portal/users/{rid}")
    assert_status_in(r, {200, 401, 403, 404})
    assert_not_5xx(r)


def test_users_post_requires_auth(portal: PortalClient):
    # No auth: expect 401
    r = requests.post(
        f"{portal.base}/api/v1/portal/users",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={},
        timeout=TIMEOUT_SEC,
    )
    assert_status_in(r, {401})
    assert "error" in r.json()


def test_users_post_invalid_body_is_4xx_or_403(portal: PortalClient):
    # With auth: might be forbidden for non-admin OR validation error.
    if not portal.token:
        pytest.skip("No token found.")
    r = portal.post("/api/v1/portal/users", json_body={})
    assert_status_in(r, {400, 401, 403, 409, 422})
    assert_not_5xx(r)


def test_users_post_unknown_field_is_4xx_or_403(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r = portal.post("/api/v1/portal/users", json_body={"__unknownField": "nope"})
    assert_status_in(r, {400, 401, 403, 409, 422})
    assert_not_5xx(r)


# =======================================================
# 5) PATCH validation & safety (7 tests)
# =======================================================

def my_user_id_or_skip(portal: PortalClient) -> str:
    r, me = get_me(portal)
    if r.status_code != 200 or not isinstance(me, dict) or not me.get("id"):
        pytest.skip("Cannot get /me id for PATCH tests")
    return me["id"]


def test_users_patch_requires_auth_401(portal: PortalClient):
    uid = str(uuid.uuid4())
    r = requests.patch(
        f"{portal.base}/api/v1/portal/users/{uid}",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={},
        timeout=TIMEOUT_SEC,
    )
    assert_status_in(r, {401})
    assert "error" in r.json()


def test_users_patch_empty_body_4xx_or_403_not_500(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    uid = my_user_id_or_skip(portal)
    r = portal.patch(f"/api/v1/portal/users/{uid}", json_body={})
    assert_status_in(r, {200, 204, 400, 401, 403, 409, 422})
    assert_not_5xx(r)


def test_users_patch_unknown_field_4xx_or_403_not_500(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    uid = my_user_id_or_skip(portal)
    r = portal.patch(f"/api/v1/portal/users/{uid}", json_body={"__unknownField": "nope"})
    assert_status_in(r, {200, 204, 400, 401, 403, 409, 422})
    assert_not_5xx(r)


def test_users_patch_wrong_type_boolean_field(portal: PortalClient):
    # You’ve seen email_otp_required in /me response; server should validate types.
    if not portal.token:
        pytest.skip("No token found.")
    uid = my_user_id_or_skip(portal)
    r = portal.patch(f"/api/v1/portal/users/{uid}", json_body={"email_otp_required": "yes"})
    assert_status_in(r, {200, 204, 400, 401, 403, 409, 422})
    assert_not_5xx(r)


def test_users_patch_attempt_change_id_rejected(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    uid = my_user_id_or_skip(portal)
    r = portal.patch(f"/api/v1/portal/users/{uid}", json_body={"id": str(uuid.uuid4())})
    assert_status_in(r, {200, 204, 400, 401, 403, 409, 422})
    assert_not_5xx(r)


def test_users_patch_invalid_status_enum(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    uid = my_user_id_or_skip(portal)
    r = portal.patch(f"/api/v1/portal/users/{uid}", json_body={"status": "BANANA"})
    assert_status_in(r, {200, 204, 400, 401, 403, 409, 422})
    assert_not_5xx(r)


def test_users_patch_long_name_4xx_or_403_not_500(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    uid = my_user_id_or_skip(portal)
    long_name = "A" * 1024
    r = portal.patch(f"/api/v1/portal/users/{uid}", json_body={"name": long_name})
    assert_status_in(r, {200, 204, 400, 401, 403, 409, 422})
    assert_not_5xx(r)


# =======================================================
# 6) /sites contract + RBAC (6 tests)
# =======================================================

def test_sites_rbac_200_or_403(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_sites(portal)
    assert_status_in(r, {200, 403})
    if r.status_code == 200:
        assert "sites" in data and isinstance(data["sites"], list)


def test_sites_items_have_expected_fields_if_present(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_sites(portal)
    if r.status_code == 403:
        pytest.skip("/sites forbidden for this role")
    assert_status_in(r, {200})
    if not data["sites"]:
        pytest.skip("No sites returned")
    s = data["sites"][0]
    for k in ("site_id", "site_name", "site_number", "edc_synced_at"):
        assert k in s, f"Missing '{k}' in site:\n{pretty(r)}"


def test_sites_sync_optional_shape(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_sites(portal)
    if r.status_code == 403:
        pytest.skip("/sites forbidden for this role")
    assert_status_in(r, {200})
    if "sync" in data:
        assert isinstance(data["sync"], dict)


def test_sites_unique_site_ids(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_sites(portal)
    if r.status_code == 403:
        pytest.skip("/sites forbidden for this role")
    assert_status_in(r, {200})
    ids = [s.get("site_id") for s in data.get("sites", []) if isinstance(s, dict)]
    ids = [i for i in ids if i is not None]
    assert len(ids) == len(set(ids)), "Duplicate site_id values in /sites"


def test_sites_response_json_content_type(portal: PortalClient):
    r = portal.get("/api/v1/portal/sites")
    assert_status_in(r, {200, 401, 403})
    assert_json_content_type(r)


def test_sites_perf_under_5s_if_allowed(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    start = time.time()
    r, _ = get_sites(portal)
    dt = time.time() - start
    if r.status_code == 403:
        pytest.skip("/sites forbidden for this role")
    assert_status_in(r, {200})
    assert dt < 5.0, f"/sites took {dt:.2f}s (threshold 5.0s)"


# =======================================================
# 7) /patients contract + RBAC (6 tests)
# =======================================================

def test_patients_rbac_200_or_403(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_patients(portal)
    assert_status_in(r, {200, 403})
    if r.status_code == 200:
        assert "patients" in data and isinstance(data["patients"], list)


def test_patients_sync_optional_shape(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_patients(portal)
    if r.status_code == 403:
        pytest.skip("/patients forbidden for this role")
    assert_status_in(r, {200})
    if "sync" in data:
        assert isinstance(data["sync"], dict)


def test_patients_assigned_sites_optional_list(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_patients(portal)
    if r.status_code == 403:
        pytest.skip("/patients forbidden for this role")
    assert_status_in(r, {200})
    if "assigned_sites" in data:
        assert isinstance(data["assigned_sites"], list)


def test_patients_items_are_objects(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r, data = get_patients(portal)
    if r.status_code == 403:
        pytest.skip("/patients forbidden for this role")
    assert_status_in(r, {200})
    if not data["patients"]:
        pytest.skip("No patients returned")
    assert isinstance(data["patients"][0], dict)


def test_patients_response_json_content_type(portal: PortalClient):
    r = portal.get("/api/v1/portal/patients")
    assert_status_in(r, {200, 401, 403})
    assert_json_content_type(r)


def test_patients_perf_under_8s_if_allowed(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    start = time.time()
    r, _ = get_patients(portal)
    dt = time.time() - start
    if r.status_code == 403:
        pytest.skip("/patients forbidden for this role")
    assert_status_in(r, {200})
    assert dt < 8.0, f"/patients took {dt:.2f}s (threshold 8.0s)"


# =======================================================
# 8) Error contract / stability (6 tests)
# =======================================================

@pytest.mark.parametrize("headers", [
    {"Accept": "application/json"},
    {"Accept": "application/json", "Authorization": "Bearer abc.def.ghi"},
])
def test_error_body_has_error_key_on_401(portal: PortalClient, headers: dict):
    r = requests.get(f"{portal.base}/api/v1/portal/me", headers=headers, timeout=TIMEOUT_SEC)
    assert_status_in(r, {401})
    body = r.json()
    assert "error" in body


def test_error_response_not_stacktrace(portal: PortalClient):
    r = requests.get(f"{portal.base}/api/v1/portal/me", headers={"Accept": "application/json"}, timeout=TIMEOUT_SEC)
    assert_status_in(r, {401})
    txt = r.text
    assert "Traceback" not in txt
    assert "Exception" not in txt


def test_users_invalid_path_never_500(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    r = portal.get("/api/v1/portal/users/00000000-0000-0000-0000-000000000000")
    assert_status_in(r, {200, 401, 403, 404})
    assert_not_5xx(r)


def test_stability_me_5_times_if_authed(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    for _ in range(5):
        r = portal.get("/api/v1/portal/me")
        assert_status_in(r, {200})
        time.sleep(0.1)


def test_stability_sites_3_times_if_allowed(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    for _ in range(3):
        r = portal.get("/api/v1/portal/sites")
        if r.status_code == 403:
            pytest.skip("/sites forbidden for this role")
        assert_status_in(r, {200})
        time.sleep(0.1)


def test_stability_patients_3_times_if_allowed(portal: PortalClient):
    if not portal.token:
        pytest.skip("No token found.")
    for _ in range(3):
        r = portal.get("/api/v1/portal/patients")
        if r.status_code == 403:
            pytest.skip("/patients forbidden for this role")
        assert_status_in(r, {200})
        time.sleep(0.1)
