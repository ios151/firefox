"""Guardian (Firefox IP Protection) API client.

Handles the runtime credential chain:

    refresh_token  --(FxA /oauth/token)-->  access_token (~24h)
    access_token   --(GET /api/v1/fpn/token)-->  proxy pass JWT (~10min)

and exposes the public Fastly server list. The proxy pass JWT is what the
local proxy presents to a Fastly node via ``Proxy-Authorization: Bearer``.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from typing import Optional

import requests

# Firefox desktop public (PKCE-capable) client. The VPN client
# (e6eb0d1e856335fc) is confidential and cannot be used for token refresh.
FIREFOX_CLIENT_ID = "5882386c6d801776"
VPN_SCOPE = "profile https://identity.mozilla.com/apps/vpn"

FXA_OAUTH_TOKEN_URL = "https://oauth.accounts.firefox.com/v1/token"
GUARDIAN_BASE = "https://vpn.mozilla.org"
SERVERLIST_URL = (
    "https://firefox.settings.services.mozilla.com"
    "/v1/buckets/main/collections/vpn-serverlist/records"
)

# Refresh the short-lived proxy pass this many seconds before it expires.
PASS_REFRESH_MARGIN = 60
# Refresh the access token this many seconds before it expires.
ACCESS_REFRESH_MARGIN = 300


def _b64url_json(seg: str) -> dict:
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def _int_or_none(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def jwt_exp(token: str) -> int:
    """Return the ``exp`` (unix seconds) of a JWT, or 0 if absent."""
    try:
        payload = _b64url_json(token.split(".")[1])
        return int(payload.get("exp", 0))
    except Exception:
        return 0


class GuardianError(RuntimeError):
    pass


class NotEnrolledError(GuardianError):
    """Raised when the account is valid but not enrolled (HTTP 403).

    Run the one-time ``login``/``enroll`` bootstrap to enroll the account.
    """


class GuardianClient:
    def __init__(
        self,
        refresh_token: str,
        client_id: str = FIREFOX_CLIENT_ID,
        scope: str = VPN_SCOPE,
        session: Optional[requests.Session] = None,
    ):
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.scope = scope
        self._s = session or requests.Session()
        self._lock = threading.Lock()

        self._access_token: Optional[str] = None
        self._access_exp: float = 0.0

        self._pass: Optional[str] = None
        self._pass_exp: float = 0.0
        self._quota_hdr: dict = {}

    # ---- access token -------------------------------------------------
    def _refresh_access_token(self) -> str:
        r = self._s.post(
            FXA_OAUTH_TOKEN_URL,
            json={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": self.refresh_token,
                "scope": self.scope,
            },
            timeout=20,
        )
        if r.status_code != 200:
            raise GuardianError(
                f"oauth refresh failed: {r.status_code} {r.text[:200]}"
            )
        d = r.json()
        self._access_token = d["access_token"]
        self._access_exp = time.time() + int(d.get("expires_in", 86400))
        return self._access_token

    @property
    def access_token(self) -> str:
        if not self._access_token or time.time() >= self._access_exp - ACCESS_REFRESH_MARGIN:
            self._refresh_access_token()
        return self._access_token  # type: ignore[return-value]

    def _auth_header(self) -> dict:
        return {"Authorization": "Bearer " + self.access_token}

    # ---- account status / quota --------------------------------------
    def status(self) -> dict:
        r = self._s.get(
            GUARDIAN_BASE + "/api/v1/fpn/status",
            headers=self._auth_header(),
            timeout=20,
        )
        if r.status_code == 403:
            raise NotEnrolledError(
                "account not enrolled (HTTP 403) — run the `login` bootstrap"
            )
        if r.status_code != 200:
            raise GuardianError(f"status failed: {r.status_code} {r.text[:200]}")
        return r.json()

    def quota(self) -> dict:
        """Return account status merged with live quota usage.

        Keys: uid, max_bytes, subscribed, limited_bandwidth,
              remaining_bytes, used_bytes, reset (ISO), unlimited.
        """
        s = self.status()
        max_bytes = int(s.get("maxBytes", 0))
        # populate quota headers by minting a proxy pass
        try:
            self.proxy_pass()
        except GuardianError:
            pass
        q = self._quota_hdr
        limit = q.get("limit") or max_bytes
        remaining = q.get("remaining")
        used = (limit - remaining) if (limit and remaining is not None) else None
        return {
            "uid": s.get("uid"),
            "max_bytes": max_bytes,
            "subscribed": bool(s.get("subscribed", False)),
            "limited_bandwidth": bool(s.get("limited_bandwidth", False)),
            "remaining_bytes": remaining,
            "used_bytes": used,
            "reset": q.get("reset"),
            "unlimited": q.get("unlimited", False),
        }

    # ---- proxy pass ---------------------------------------------------
    def _fetch_pass(self) -> str:
        r = self._s.get(
            GUARDIAN_BASE + "/api/v1/fpn/token",
            headers=self._auth_header(),
            timeout=20,
        )
        if r.status_code == 403:
            raise NotEnrolledError(
                "account not enrolled (HTTP 403) — run the `login` bootstrap"
            )
        if r.status_code != 200:
            raise GuardianError(
                f"proxy pass fetch failed: {r.status_code} {r.text[:200]}"
            )
        token = r.json().get("token")
        if not token:
            raise GuardianError("proxy pass response missing 'token'")
        self._pass = token
        self._pass_exp = jwt_exp(token) or (time.time() + 600)
        h = r.headers
        self._quota_hdr = {
            "limit": _int_or_none(h.get("x-quota-limit")),
            "remaining": _int_or_none(h.get("x-quota-remaining")),
            "reset": h.get("x-quota-reset"),
            "unlimited": (h.get("x-quota-unlimited", "").lower() == "true"),
        }
        return token

    def proxy_pass(self) -> str:
        """Return a currently-valid proxy pass JWT, refreshing as needed."""
        with self._lock:
            if not self._pass or time.time() >= self._pass_exp - PASS_REFRESH_MARGIN:
                self._fetch_pass()
            return self._pass  # type: ignore[return-value]

    # ---- server list --------------------------------------------------
    def servers(self) -> list[dict]:
        r = self._s.get(SERVERLIST_URL, timeout=20)
        if r.status_code != 200:
            raise GuardianError(f"serverlist failed: {r.status_code}")
        return r.json()["data"]

    def nodes_by_country(self) -> dict[str, dict]:
        """Return {country_code: {'name', 'nodes': [(host, port), ...]}}."""
        out: dict[str, dict] = {}
        for rec in self.servers():
            nodes = []
            for city in rec.get("cities", []):
                for srv in city.get("servers", []):
                    nodes.append((srv["hostname"], int(srv["port"])))
            if nodes:
                out[rec["code"]] = {"name": rec.get("name", rec["code"]), "nodes": nodes}
        return out
