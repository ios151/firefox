"""One-time credential bootstrap for Firefox IP Protection.

Turns a Firefox Account (email+password, or a pre-extracted sessionToken)
into a durable apps/vpn ``refresh_token`` and makes sure the account is
enrolled into the proxy service.

Notes on network:
* FxA ``/account/login`` is bot-walled from datacenter IPs (HTTP 406). Run
  ``login`` from a residential IP, or extract a sessionToken from a real
  Firefox and pass ``--session-token``.
* ``/oauth/authorization``, ``/oauth/token`` and ``/api/v1/fpn/*`` are NOT
  IP-walled, so the resulting refresh_token works from anywhere (e.g. a VPS).
* The enrollment redirect ``/api/v1/fpn/auth`` trips the bot-wall for some
  User-Agents, so we drive it with a Chrome-impersonating client.
"""
from __future__ import annotations

import base64
import hashlib
import os
import urllib.parse as up

from curl_cffi import requests as creq
from fxa._utils import APIClient, HawkTokenAuth
from fxa.core import Client as CoreClient
from fxa.oauth import Client as OAuthClient

from .guardian import (
    FIREFOX_CLIENT_ID,
    GUARDIAN_BASE,
    VPN_SCOPE,
    GuardianClient,
)

FXA_API_URL = "https://api.accounts.firefox.com/v1"
FXA_OAUTH_URL = "https://oauth.accounts.firefox.com/v1"
ENROLL_EXPERIMENT = "ip-protection"


def _pkce() -> dict:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    return {"verifier": verifier, "challenge": challenge, "state": state}


def login_to_session_token(email: str, password: str) -> str:
    """email+password -> sessionToken (residential IP required)."""
    client = CoreClient(server_url=FXA_API_URL)
    session = client.login(email, password)
    return session.token  # sessionToken (hex)


def session_to_tokens(session_token: str) -> dict:
    """sessionToken -> {access_token, refresh_token, expires_in, scope} for apps/vpn."""
    p = _pkce()
    api = APIClient(FXA_API_URL)
    auth = HawkTokenAuth(session_token, "sessionToken", api)
    body = {
        "client_id": FIREFOX_CLIENT_ID,
        "response_type": "code",
        "scope": VPN_SCOPE,
        "state": p["state"],
        "code_challenge": p["challenge"],
        "code_challenge_method": "S256",
        "access_type": "offline",
    }
    resp = api.post("/oauth/authorization", body, auth=auth)
    oc = OAuthClient(client_id=FIREFOX_CLIENT_ID, server_url=FXA_OAUTH_URL)
    tok = oc.trade_code(resp["code"], code_verifier=p["verifier"])
    return tok


def enroll(session_token: str, access_token: str) -> dict:
    """Enroll the account into the proxy service (idempotent).

    Drives the Guardian enrollment OAuth flow:
      GET /api/v1/fpn/auth  -> 302 to FxA authorize (VPN client, subs scope)
      Hawk-authorize        -> code (confidential client, no PKCE)
      GET /oauth/success    -> Guardian trades code with its secret & enrolls
    """
    s = creq.Session(impersonate="chrome")
    r = s.get(
        f"{GUARDIAN_BASE}/api/v1/fpn/auth?experiment={ENROLL_EXPERIMENT}",
        headers={"Authorization": "Bearer " + access_token},
        allow_redirects=False,
        timeout=20,
    )
    if r.status_code != 302 or "Location" not in r.headers:
        raise RuntimeError(f"enroll start failed: {r.status_code} {r.text[:160]}")
    q = dict(up.parse_qsl(up.urlparse(r.headers["Location"]).query))

    api = APIClient(FXA_API_URL)
    auth = HawkTokenAuth(session_token, "sessionToken", api)
    resp = api.post(
        "/oauth/authorization",
        {
            "client_id": q["client_id"],
            "response_type": "code",
            "scope": q["scope"],
            "state": q["state"],
            "redirect_uri": q["redirect_uri"],
            "access_type": q.get("access_type", "offline"),
        },
        auth=auth,
    )
    cb = resp.get("redirect")
    if not cb or "code=" not in cb:
        base = q["redirect_uri"]
        sep = "&" if "?" in base else "?"
        cb = f"{base}{sep}code={resp['code']}&state={resp['state']}"
    done = s.get(cb, allow_redirects=False, timeout=20)
    if done.status_code != 200:
        raise RuntimeError(f"enroll callback failed: {done.status_code} {done.text[:160]}")
    return done.json()


def browser_login(*, timeout: int = 300, status_cb=None) -> str:
    """Open a real browser, let the user sign in, and capture the sessionToken.

    The FxA login/registration endpoints are bot-walled (CAPTCHA / 406) for
    scripted requests, but a real browser passes. We launch a headed Chromium,
    let the human complete email/password/2FA/CAPTCHA (or even register a new
    account — the official page mails the verification code), and sniff the
    ``sessionToken`` out of the ``/account/login`` or ``/account/create``
    response. Returns the sessionToken (hex).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "浏览器登录需要 playwright：先运行 "
            "`pip install playwright` 再 `python -m playwright install chromium`"
        ) from e

    def _say(msg):
        if status_cb:
            try:
                status_cb(msg)
            except Exception:
                pass

    captured: dict = {}

    def _on_response(resp):
        try:
            url = resp.url
            if ("/account/login" in url or "/account/create" in url) and \
                    resp.request.method == "POST":
                data = resp.json()
                st = data.get("sessionToken")
                if st:
                    captured["sessionToken"] = st
        except Exception:
            pass

    _say("正在打开浏览器 …")
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=False)
        except Exception:
            browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.on("response", _on_response)
        page.goto("https://accounts.firefox.com/", wait_until="domcontentloaded",
                  timeout=60000)
        _say("请在弹出的浏览器窗口里登录（或注册）你的 Firefox 账号 …")
        waited = 0
        while "sessionToken" not in captured and waited < timeout:
            page.wait_for_timeout(1000)
            waited += 1
            if browser.contexts == []:  # window closed
                break
        try:
            browser.close()
        except Exception:
            pass

    st = captured.get("sessionToken")
    if not st:
        raise RuntimeError("没抓到登录凭证（可能未完成登录或超时）")
    _say("登录成功，正在换取长期凭证 …")
    return st


def bootstrap(
    *,
    session_token: str | None = None,
    email: str | None = None,
    password: str | None = None,
) -> dict:
    """Full bootstrap -> {refresh_token, quota}. Enrolls if needed."""
    if not session_token:
        if not (email and password):
            raise ValueError("provide session_token, or email and password")
        session_token = login_to_session_token(email, password)

    tok = session_to_tokens(session_token)
    refresh_token = tok.get("refresh_token")
    if not refresh_token:
        raise RuntimeError("no refresh_token returned (need access_type=offline)")

    gc = GuardianClient(refresh_token)
    try:
        quota = gc.quota()
    except Exception:
        enroll(session_token, tok["access_token"])
        quota = gc.quota()
    return {"refresh_token": refresh_token, "quota": quota}
