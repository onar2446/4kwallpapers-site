#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""4kwallpapers_source — hardened single-file server.

Serves the local design plus a live read-only proxy to 4kwallpapers.com.

Run:  python server.py [port]
Env:
  PORT               listen port            (default 8000, or argv[1])
  BIND               listen address         (default 127.0.0.1)
  SITE_HOST          extra allowed Host value (your tunnel domain)
  ALLOWED_HOSTS      comma list, or "*" to disable Host checking
  RATE_LIMIT_PER_MIN per-IP cap on the expensive API routes (0 = off, default 90)
  IMG_RATE_PER_MIN   per-IP cap on image delivery  (0 = off, default 900)
  MAX_CONCURRENCY    max simultaneous connections (default 64)
  CSP_RELAX          1 = add 'unsafe-inline' to script-src (escape hatch only)
  NO_GZIP            1 = never compress responses
  TURNSTILE_MODE     off | gate | api   (default gate)
  TURNSTILE_SITE_KEY public site key (safe to ship in the page)
  TURNSTILE_SECRET   secret key. Prefer the file over the env var; see below.
  TURNSTILE_TTL      seconds a solved challenge stays valid (default 43200)
  TURNSTILE_PROBE    0 = skip the boot check that validates the secret
  GATE_RATE_PER_MIN  per-IP cap on challenge pages (default 120)
  SECRETS_DIR        where turnstile.secret / gate.key live
                     (default: ../4kwallpapers_source-secrets)

Secrets never touch the web root: TURNSTILE_SECRET comes from the environment
or from <SECRETS_DIR>/turnstile.secret, and the cookie-signing key from
<SECRETS_DIR>/gate.key (generated once, on first run).

Security properties enforced here
---------------------------------
* Every request is routed through ONE normalised path, used by both GET and HEAD.
* Static files are gated by an extension ALLOW-LIST plus a realpath containment
  check against the served root, so the server source, dot-files and stale
  duplicate assets are not reachable by any spelling.
* Directory listings are never generated.
* No `Server` banner (no interpreter / version disclosure).
* Security headers on every single response, including error responses.
* Socket timeout + bounded concurrency (slowloris / thread-exhaustion).
* API responses are same-origin only — no `Access-Control-Allow-Origin: *`.
* Upstream fetches are bounded in size and time, and their target path is
  re-validated after normalisation so the proxy cannot be pointed elsewhere.
* The Turnstile gate runs before anything is produced, and its pass cookie is
  HMAC-signed, so it cannot be forged or replayed past its expiry.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import html as html_mod
import json
import mimetypes
import os
import posixpath
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

WEB_ROOT = os.path.dirname(os.path.abspath(__file__))
ORIGIN = "https://4kwallpapers.com"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

SERVER_NAME = "4kwallpapers"          # sent as `Server:` — no version on purpose

# ---------------------------------------------------------------- limits ----
UPSTREAM_TIMEOUT = 20
MAX_UPSTREAM_BYTES = 12 * 1024 * 1024   # hard cap on any single upstream body
MAX_PATH_LEN = 2048
MAX_QUERY_LEN = 1024
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "90") or 0)
# Images are a browsing-critical, high-volume endpoint: one gallery page pulls
# ~24 of them. They get their own, much more generous bucket so normal use is
# never throttled while still capping abuse.
IMG_RATE_PER_MIN = int(os.environ.get("IMG_RATE_PER_MIN", "900") or 0)

# gzip. Obfuscated JS compresses extremely well (~80 KB -> ~15 KB), so this is
# the single cheapest bandwidth win on the site. Set NO_GZIP=1 to disable.
GZIP_ENABLED = os.environ.get("NO_GZIP") != "1"
GZIP_MIN_BYTES = 512
GZIP_TYPES = (
    "text/", "application/json", "application/javascript",
    "application/xml", "application/manifest+json", "image/svg+xml",
)

# ------------------------------------------------------ Cloudflare Turnstile --
# MODE:
#   off   -> nothing is challenged
#   gate  -> every visitor solves Turnstile once, then carries a signed cookie
#            (default; this is the only mode that actually stops bots)
#   api   -> only /api/* and /search-api are challenged
#
# The secret key must NEVER be readable from the web root. Order of resolution:
#   TURNSTILE_SECRET env  ->  <secrets dir>/turnstile.secret
SECRETS_DIR = os.environ.get(
    "SECRETS_DIR",
    os.path.join(os.path.dirname(WEB_ROOT), "4kwallpapers_source-secrets"),
)
TURNSTILE_MODE = (os.environ.get("TURNSTILE_MODE") or "gate").strip().lower()
TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY", "0x4AAAAAAAFSyGIrU4EB-w-Yj")
TURNSTILE_VERIFY_URL = os.environ.get(
    "TURNSTILE_VERIFY_URL",
    "https://challenges.cloudflare.com/turnstile/v0/siteverify")
TURNSTILE_TTL = int(os.environ.get("TURNSTILE_TTL", str(12 * 3600)) or 43200)
PASS_COOKIE = "ts_pass"
MAX_FORM_BYTES = 8 * 1024

# Error codes that mean "your server is misconfigured", not "this visitor is a
# bot". Failing closed on these would lock every real visitor out of the site,
# so they fail OPEN and shout in the log instead.
#
# NOTE: "missing-input-response" is deliberately NOT in here. It means the
# visitor submitted an empty token — a client problem. Treating it as our
# misconfiguration would let anyone through the gate by posting a blank form.
CONFIG_ERROR_CODES = {
    "missing-input-secret", "invalid-input-secret", "bad-request",
}
GATE_EXEMPT = {"/__cf/verify", "/assets/turnstile.js",
               "/assets/favicon.ico", "/favicon.ico"}
VERIFY_PATH = "/__cf/verify"
# A bot that never solves the challenge still costs us a challenge page every
# hit, so the gate gets its own bucket. Generous enough that a human reloading
# a few times never notices, tight enough to stop challenge-page amplification.
GATE_RATE_PER_MIN = int(os.environ.get("GATE_RATE_PER_MIN", "120") or 0)


def _load_secret_file(name: str) -> str:
    try:
        with open(os.path.join(SECRETS_DIR, name), "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _load_turnstile_secret() -> str:
    val = (os.environ.get("TURNSTILE_SECRET") or "").strip()
    if val:
        return val
    return _load_secret_file("turnstile.secret")


def _load_gate_key() -> bytes:
    """HMAC key for signing the pass cookie. Generated once, kept off the web
    root, so a restart does not invalidate everyone's pass."""
    val = (os.environ.get("GATE_KEY") or "").strip()
    if val:
        return val.encode()
    path = os.path.join(SECRETS_DIR, "gate.key")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            existing = fh.read().strip()
        if existing:
            return existing.encode()
    except OSError:
        pass
    fresh = secrets.token_urlsafe(48)
    try:
        os.makedirs(SECRETS_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(fresh + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        print("  ! could not persist gate key (%s) — passes reset on restart" % exc)
    return fresh.encode()


TURNSTILE_SECRET = _load_turnstile_secret()
GATE_KEY = _load_gate_key()
GATE_ON = TURNSTILE_MODE in ("gate", "api")


def sign_pass(expiry: int) -> str:
    mac = hmac.new(GATE_KEY, str(expiry).encode(), hashlib.sha256).hexdigest()
    return "%d.%s" % (expiry, mac)


def check_pass(raw: str) -> bool:
    if not raw or "." not in raw:
        return False
    exp_s, _, mac = raw.partition(".")
    if not exp_s.isdigit():
        return False
    expiry = int(exp_s)
    if expiry < int(time.time()):
        return False
    expect = hmac.new(GATE_KEY, exp_s.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, mac)


def turnstile_verify(token: str, ip: str):
    """Ask Cloudflare whether a Turnstile token is genuine.

    Returns (ok, error_codes, misconfigured). `misconfigured` is True only when
    the failure is OUR fault (bad secret, unreachable Cloudflare) rather than
    the visitor's — the caller fails OPEN on those and CLOSED on the rest.
    """
    if not TURNSTILE_SECRET:
        return False, ["missing-input-secret"], True
    if not token or len(token) > 4096:
        # No token at all is the visitor's problem, never ours: fail CLOSED so
        # that posting an empty form cannot walk straight through the gate.
        return False, ["missing-input-response"], False
    payload = {"secret": TURNSTILE_SECRET, "response": token}
    if ip:
        payload["remoteip"] = ip
    body = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(
        TURNSTILE_VERIFY_URL, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "4kwallpapers-server"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read(MAX_FORM_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # siteverify answers 4xx with a JSON body saying *why*. urlopen raises
        # on 4xx, so read the reason off the exception — otherwise
        # `invalid-input-secret` gets logged as a useless "network error".
        try:
            raw = exc.read(MAX_FORM_BYTES + 1)
        except Exception:                                     # noqa: BLE001
            return False, ["http-%s" % exc.code], True
    except Exception as exc:                                  # noqa: BLE001
        # Could not reach Cloudflare at all. Never lock the whole site out
        # because our egress is down.
        return False, ["network-error:%s" % type(exc).__name__], True
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return False, ["bad-json"], True
    codes = list(data.get("error-codes") or [])
    misconfigured = any(c in CONFIG_ERROR_CODES for c in codes)
    return bool(data.get("success")), codes, misconfigured


def probe_secret():
    """One-shot boot check: does Cloudflare actually accept our secret?

    Returns (verdict, detail) with verdict in {"ok", "bad", "unknown"}.

    A dummy token is enough. Cloudflare validates the *secret* before it ever
    looks at the response, so:
      * `invalid-input-secret` / `missing-input-secret` -> the key is wrong
      * anything else (typically `invalid-input-response`) -> the key was
        accepted and only the dummy token was rejected
    That distinction is the whole point: without it a typo'd secret looks
    exactly like a working one until you read the per-request log.
    """
    if not TURNSTILE_SECRET:
        return "bad", "no secret configured"
    _ok, codes, _misc = turnstile_verify("0" * 32, "")
    if any(c in ("missing-input-secret", "invalid-input-secret") for c in codes):
        return "bad", ",".join(codes)
    if any(c.startswith(("network-error", "http-", "bad-json")) for c in codes):
        return "unknown", ",".join(codes)
    return "ok", ",".join(codes) or "accepted"
MAX_CONCURRENCY = int(os.environ.get("MAX_CONCURRENCY", "64") or 64)

# ------------------------------------------------------------ CSP / headers --
# Two tiers. `script-src 'self'` is strict on purpose: every page this server
# emits (local file or localised upstream page) has its inline scripts moved to
# external files, so 'unsafe-inline' is not needed. CSP_RELAX=1 is the escape
# hatch if the upstream site ever starts injecting an inline script again.
# The upstream search page sometimes embeds Google Programmable Search
# (`cse.google.com/cse.js` + a results iframe). Blank this out to lock the CSP
# down completely if you stop using it.
THIRD_PARTY_SCRIPT = "https://cse.google.com https://www.google.com"
THIRD_PARTY_FRAME = "https://cse.google.com https://www.google.com"
THIRD_PARTY_CONNECT = "https://cse.google.com https://www.googleapis.com"

# Turnstile loads its widget script from here and renders the challenge inside an
# iframe on the same origin. Without these three the widget silently never shows.
TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"


def build_csp() -> str:
    script = "script-src 'self'"
    if THIRD_PARTY_SCRIPT:
        script += " " + THIRD_PARTY_SCRIPT
    if GATE_ON:
        script += " " + TURNSTILE_ORIGIN
    if os.environ.get("CSP_RELAX") == "1":
        script += " 'unsafe-inline'"
    frame = "frame-src " + " ".join(
        x for x in ([THIRD_PARTY_FRAME, TURNSTILE_ORIGIN if GATE_ON else ""]) if x
    ) or "frame-src 'none'"
    connect = "connect-src 'self'"
    if THIRD_PARTY_CONNECT:
        connect += " " + THIRD_PARTY_CONNECT
    if GATE_ON:
        connect += " " + TURNSTILE_ORIGIN
    return "; ".join([
        "default-src 'self'",
        script,
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob: %s" % ORIGIN,
        "font-src 'self' data:",
        connect,
        "media-src 'self'",
        "manifest-src 'self'",
        "object-src 'none'",
        frame,
        "worker-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "upgrade-insecure-requests",
    ])


CSP = build_csp()

BASE_SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=(), "
        "interest-cohort=(), browsing-topics=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
    "X-Download-Options": "noopen",
}

# --------------------------------------------------------- static allow-list --
ALLOWED_EXT = {
    ".html", ".htm", ".css", ".js", ".mjs", ".json", ".webmanifest",
    ".txt", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".map",
}
# Stale duplicates from the original scrape (`_assets_*`, `_manifest.json`) and
# any other underscore-prefixed artefact: never served.
BLOCKED_BASENAME_PREFIX = ("_", ".")
BLOCKED_EXT = {".py", ".pyc", ".pyo", ".pyd", ".db", ".sqlite", ".log",
               ".bak", ".old", ".orig", ".env", ".ini", ".cfg", ".conf",
               ".sh", ".bat", ".ps1", ".yml", ".yaml", ".toml", ".lock"}

PAGE_RE = re.compile(r"^/[a-z0-9\-]+/[a-z0-9\-]+\-\d+\.html$")
CAT_RE = re.compile(r"^/[a-z0-9\-():]+/?$")
IMG_PREFIX = "/images/"
SEARCH_ACTIONS = {"tagsearch"}


def norm_path(raw: str) -> str:
    """One canonical path, shared by every method and every check.

    Percent-decoding happens exactly once, here, and `..` is resolved before any
    decision is taken — so `/server%2Epy`, `/%73erver.py`, `/./server.py` and
    `/assets/../server.py` all collapse to the same string.
    """
    p = raw.split("?", 1)[0].split("#", 1)[0]
    p = unquote(p, errors="replace").replace("\\", "/")
    if "\x00" in p:
        return "\x00"
    if not p.startswith("/"):
        p = "/" + p
    trailing = p.endswith("/")          # posixpath.normpath eats this
    p = posixpath.normpath(p)
    if not p.startswith("/"):
        p = "/" + p
    if trailing and not p.endswith("/"):
        p += "/"
    return p


def safe_join(root: str, url_path: str) -> str | None:
    """Map a normalised URL path onto a file inside `root`, or None."""
    rel = url_path.lstrip("/")
    if not rel:
        return None
    candidate = os.path.realpath(os.path.join(root, rel.replace("/", os.sep)))
    root_real = os.path.realpath(root)
    if candidate != root_real and not candidate.startswith(root_real + os.sep):
        return None
    return candidate


def is_servable_file(url_path: str) -> bool:
    """Allow-list gate. Everything not explicitly permitted is a 404.

    Comparisons are case-insensitive so that `SERVER.PY` and `_ASSETS_X.JS`
    cannot slip past on a case-insensitive filesystem.
    """
    base = posixpath.basename(url_path)
    if not base:
        return False
    low = base.lower()
    if low.startswith(BLOCKED_BASENAME_PREFIX):
        return False
    ext = posixpath.splitext(low)[1]
    if ext in BLOCKED_EXT or ext not in ALLOWED_EXT:
        return False
    return True


# ------------------------------------------------------------ rate limiting --
_RATE: dict[str, list] = {}
_RATE_LOCK = threading.Lock()


def rate_limited(ip: str, bucket: str, limit: int) -> bool:
    if limit <= 0:
        return False
    key = bucket + "|" + ip
    now = time.monotonic()
    with _RATE_LOCK:
        if len(_RATE) > 4096:            # keep the table bounded
            for k in [k for k, v in _RATE.items() if now - v[0] > 120]:
                _RATE.pop(k, None)
        slot = _RATE.get(key)
        if slot is None or now - slot[0] >= 60:
            _RATE[key] = [now, 1]
            return False
        slot[1] += 1
        return slot[1] > limit


# ----------------------------------------------------------- upstream fetch --
_TLS = threading.local()

# Only the site's own functional prefs are ever forwarded upstream — never
# tracking cookies, never the gate pass cookie. The origin needs these two
# to render the right variant (infinite-scroll markup, 4K-only filter).
_PREF_NAMES = ("infinitescrolling", "4k")


def _pref_cookie_header() -> str:
    raw = getattr(_TLS, "cookies", "") or ""
    out = []
    for part in raw.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k.strip() in _PREF_NAMES:
            v = v.strip()
            if len(v) <= 32 and re.match(r"^[A-Za-z0-9_\-]+$", v):
                out.append("%s=%s" % (k.strip(), v))
    return "; ".join(out)


def http_get(url: str, timeout: int = UPSTREAM_TIMEOUT):
    headers = dict(UA)
    prefs = _pref_cookie_header()
    if prefs:
        headers["Cookie"] = prefs
    req = urllib.request.Request(url, headers=headers)
    resp = urllib.request.urlopen(req, timeout=timeout)
    data = resp.read(MAX_UPSTREAM_BYTES + 1)
    if len(data) > MAX_UPSTREAM_BYTES:
        raise ValueError("upstream response too large")
    return resp, data


def fetch_latest(limit: int = 24):
    _, body = http_get(ORIGIN + "/")
    html = body.decode("utf-8", errors="ignore")
    seen: dict[str, str] = {}
    for page, wid in re.findall(r'href="(/[a-z\-]+/[a-z0-9\-]+\-(\d+)\.html)"', html):
        if wid not in seen:
            seen[wid] = page
        if len(seen) >= limit:
            break
    return [{"id": w, "page": p,
             "thumb": "/api/img?url=%s" % urllib.parse.quote("/images/walls/thumbs_2t/%s.jpg" % w),
             "origin_page": ORIGIN + p} for w, p in seen.items()]


def fetch_wallpaper(page_path: str):
    if not (PAGE_RE.match(page_path) or CAT_RE.match(page_path)):
        raise ValueError("bad url")
    _, body = http_get(ORIGIN + page_path)
    html = body.decode("utf-8", errors="ignore")
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S)
    title = re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else page_path
    res = []
    for href, label in re.findall(r'href="(/images/wallpapers/[^"]+)"[^>]*>([^<]+?)\s*<span', html):
        res.append({"label": label.strip(),
                    "file": href,
                    "direct": ORIGIN + href,
                    "proxy": "/api/img?url=%s&dl=1" % urllib.parse.quote(href)})
    uniq, seen_f = [], set()
    for r in res:
        if r["file"] not in seen_f:
            seen_f.add(r["file"])
            uniq.append(r)
    return {"title": title, "page": ORIGIN + page_path, "resolutions": uniq}


def img_variants(f: str):
    yield f
    if "/thumbs_2t/" in f:
        yield f.replace("/thumbs_2t/", "/thumbs/")
    if "/thumbs_3t/" in f:
        yield f.replace("/thumbs_3t/", "/thumbs/")
    base, dot, ext = f.rpartition(".")
    if dot and base and ext:
        for e in ("jpg", "jpeg", "png", "webp"):
            if e != ext:
                yield base + "." + e


def fetch_img(f: str):
    last = None
    for v in img_variants(f):
        try:
            resp, data = http_get(ORIGIN + v, timeout=30)
            return resp, v, data
        except Exception as exc:                     # noqa: BLE001
            last = exc
    raise last if last else ValueError("no variant")


def clean_img_path(raw: str) -> str:
    """Normalise and re-validate so the proxy can only ever read /images/*."""
    p = unquote(raw, errors="replace").replace("\\", "/")
    if not p.startswith(IMG_PREFIX):
        raise ValueError("bad file")
    p = posixpath.normpath(p)
    if not p.startswith(IMG_PREFIX) or ".." in p.split("/"):
        raise ValueError("bad file")
    if not re.match(r"^/images/[A-Za-z0-9._/\-]+$", p):
        raise ValueError("bad file")
    return p


# ------------------------------------------------------------- localisation --
THEME_INLINE = (
    "<script>try{if(localStorage.getItem('theme')==='light')"
    "document.documentElement.setAttribute('data-theme','light')}catch(e){}</script>"
)

_ADS = [
    r'<script[^>]*googletagmanager[^>]*>.*?</script>',
    r'<script[^>]*>(?:(?!</script>).)*?gtag\(\s*[\'"]config[\'"].*?</script>',
    r'<script[^>]*pagead2[^>]*>\s*</script>',
    r'<script[^>]*fundingchoices[^>]*>\s*</script>',
    r'<script[^>]*>(?:(?!</script>).)*?signalGooglefcPresent.*?</script>',
    r'<script[^>]*cloudflareinsights[^>]*>\s*</script>',
    r'<ins class="adsbygoogle".*?</ins>',
    r'<script>\s*\(adsbygoogle.*?</script>',
    r'<div class="banner">\s*(?:<!--.*?-->\s*)*</div>',
]


_ANCHOR_BLANK_RE = re.compile(r'<a\b[^>]*target=["\']_blank["\'][^>]*>', re.I)


def add_noopener(html: str) -> str:
    """Give every target="_blank" anchor a rel, so the opened page cannot reach
    back through window.opener (reverse tabnabbing)."""
    def repl(m):
        tag = m.group(0)
        if re.search(r"\brel\s*=", tag, re.I):
            return tag
        return tag[:-1].rstrip() + ' rel="noopener noreferrer">'
    return _ANCHOR_BLANK_RE.sub(repl, html)


def localize(page_html: str) -> str:
    h = page_html
    h = re.sub(r'<span class="stores">.*?</span>', '', h, flags=re.S)
    for pat in _ADS:
        h = re.sub(pat, '', h, flags=re.S)
    # Inline scripts -> external file, so the strict CSP actually holds.
    h = h.replace(THEME_INLINE, '<script src="/assets/theme-init.js"></script>')
    h = add_noopener(h)
    h = h.replace('<p class="footer">', '<p class="footer">Made by <a href="https://t.me/b_tor" target="_blank" rel="noopener noreferrer" title="Telegram">@b_tor</a> | ')
    h = h.replace("https://4kwallpapers.com/images/walls/", "/api/img?url=/images/walls/")
    h = h.replace("https://4kwallpapers.com/images/wallpapers/", "/api/img?url=/images/wallpapers/")
    h = re.sub(r"(?<!url=)/images/(walls|wallpapers)/", r"/api/img?url=/images/\1/", h)
    h = re.sub(r"(?<![\w/])images/(walls|wallpapers)/", r"/api/img?url=/images/\1/", h)
    h = re.sub(r"https://4kwallpapers\.com(/[a-z0-9\-]+/[a-z0-9\-]+\-\d+\.html)", r"\1", h)
    h = re.sub(r"(/api/img\?url=/images/wallpapers/[^\"&]+)\"", r"\1&dl=1\"", h)
    h = h.replace("fa.min.css?v=12092026", "fa.min.css?v=local2")
    h = h.replace("styles.min.css?v=16092026o", "styles.min.css?v=local2")
    h = h.replace("functions.js?v=16092026", "functions.js?v=local2")
    h = h.replace("ui.js?v=16092026b", "ui.js?v=local2")
    h = h.replace("custom.js?v=16092026b", "custom.js?v=local2")
    return h


def serve_origin(path_qs: str) -> bytes:
    _, body = http_get(ORIGIN + path_qs)
    return localize(body.decode("utf-8", errors="ignore")).encode("utf-8")


# ---------------------------------------------------- Turnstile gate page ----
# No web fonts and no inline script: everything here has to survive the strict
# CSP the server sends with it.
_CHALLENGE_CSS = """
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#14161a;color:#eee;
       font-family:system-ui,"Segoe UI",Tahoma,Arial,sans-serif;
       line-height:1.8;padding:24px}
  .card{width:100%;max-width:440px;background:#1c1c1c;border:1px solid #2a2e35;border-radius:14px;padding:36px 34px}
  .mark{font-size:20px;font-weight:800;letter-spacing:.06em;margin:0 0 18px;color:#fff}
  .mark b{color:#7cfc00}
  h1{font-size:20px;font-weight:700;margin:0 0 10px;color:#fff}
  p{margin:0 0 22px;color:#b9bec7;font-size:14px}
  .err{border-inline-start:3px solid #ff5d5d;padding:10px 14px;background:#26262b;color:#ff8080;font-size:14px;margin:0 0 20px}
  button{margin-top:18px;width:100%;padding:12px 16px;background:#7cfc00;color:#111;border:0;border-radius:10px;font-size:15px;font-weight:800;font-family:inherit;cursor:pointer}
  button:disabled{opacity:.4;cursor:not-allowed}
  .cf-turnstile{margin-top:4px;min-height:65px}
  .msg{display:none;font-size:13px;margin:14px 0 0;color:#8a9099}
"""


def challenge_page(next_path: str, error: str = "") -> bytes:
    safe_next = html_mod.escape(next_path, quote=True)
    site_key = html_mod.escape(TURNSTILE_SITE_KEY, quote=True)
    err = ('<p class="err">%s</p>' % html_mod.escape(error)) if error else ""
    page = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex">'
        '<title>Quick Verification</title>'
        '<style>%s</style>'
        '<script src="/assets/turnstile.js"></script>'
        '</head><body><div class="card">'
        '<p class="mark"><b>4K</b> Wallpapers</p>'
        '<h1>Quick Verification</h1>'
        '<p>Please verify you are human to continue.'
        '%s'
        '<form id="tsform" method="POST" action="/__cf/verify">'
        '<input type="hidden" name="next" value="%s">'
        '<div class="cf-turnstile" data-sitekey="%s" data-callback="__tsOk" '
        'data-expired-callback="__tsExpired" data-error-callback="__tsError" '
        'data-theme="dark"></div>'
        '<button type="submit" disabled>Continue</button>'
        '<p id="tsnote" class="msg"></p>'
        '</form>'
        '</div>'
        '<script src="%s/turnstile/v0/api.js" async defer></script>'
        '</body></html>'
        % (_CHALLENGE_CSS, err, safe_next, site_key, TURNSTILE_ORIGIN)
    )
    return page.encode("utf-8")


def safe_next_path(raw: str) -> str:
    """Only ever bounce back to a path on this site."""
    p = (raw or "/").strip()
    if not p.startswith("/") or p.startswith("//") or "\\" in p or "\r" in p or "\n" in p:
        return "/"
    if len(p) > MAX_PATH_LEN:
        return "/"
    return p


# ------------------------------------------------------------------- server --
class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = True

    def __init__(self, *args, max_workers: int = MAX_CONCURRENCY, **kwargs):
        super().__init__(*args, **kwargs)
        self._sem = threading.Semaphore(max(4, max_workers))

    def process_request(self, request, client_address):
        if not self._sem.acquire(timeout=5):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Connection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._sem.release()
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self._sem.release()


class H(BaseHTTPRequestHandler):
    server_version = SERVER_NAME
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 20                       # slowloris guard

    # -- plumbing ------------------------------------------------------------
    def send_response(self, code, message=None):
        # Same as the stdlib version minus the `Server:` banner.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def log_error(self, fmt, *args):
        self.log_message(fmt, *args)

    def _client_ip(self) -> str:
        peer = self.client_address[0] if self.client_address else ""
        if peer in ("127.0.0.1", "::1"):
            fwd = (self.headers.get("CF-Connecting-IP") or "").strip()
            if fwd and len(fwd) <= 45 and all(c.isalnum() or c in ".:" for c in fwd):
                return fwd
        return peer

    def _via_tls(self) -> bool:
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
        return bool(self.headers.get("CF-Connecting-IP")) or proto == "https"

    # -- Turnstile gate ------------------------------------------------------
    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, sep, v = part.strip().partition("=")
            if sep and k == name:
                return v
        return ""

    def _has_pass(self) -> bool:
        return check_pass(self._cookie(PASS_COOKIE))

    def _gate_applies(self, path: str) -> bool:
        if not GATE_ON:
            return False
        # Case-insensitively, so `/assets/TURNSTILE.JS` cannot silently become
        # gated (and therefore unloadable) if the file is ever renamed with a
        # different case. Exempting a public asset is not a weakening: the
        # static handler would serve it anyway.
        if path.lower() in GATE_EXEMPT:
            return False
        if TURNSTILE_MODE == "api":
            return path.startswith("/api/") or path == "/search-api"
        return True

    def _wants_html(self) -> bool:
        return "text/html" in (self.headers.get("Accept") or "")

    def _serve_challenge(self, next_path: str, error: str = "", status=403):
        body = challenge_page(next_path, error)
        self._respond(status, "text/html; charset=utf-8", body,
                      extra={"X-Robots-Tag": "noindex"})

    def _set_pass_cookie(self):
        expiry = int(time.time()) + TURNSTILE_TTL
        value = sign_pass(expiry)
        cookie = ("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax"
                  % (PASS_COOKIE, value, TURNSTILE_TTL))
        if self._via_tls():
            cookie += "; Secure"
        return cookie

    def _handle_turnstile_post(self):
        """POST /__cf/verify — the challenge form target."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_FORM_BYTES:
            self._error(413, "Payload too large.", close=True)
            return
        raw = self.rfile.read(length) if length else b""
        form = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        token = (form.get("cf-turnstile-response", [""])[0] or "").strip()
        next_path = safe_next_path(form.get("next", ["/"])[0])

        ok, codes, misconfigured = turnstile_verify(token, self._client_ip())

        if ok:
            self.log_message('turnstile PASS ip=%s -> %s',
                             self._client_ip(), next_path)
            self.send_response(303)
            self.send_header("Location", next_path)
            self.send_header("Set-Cookie", self._set_pass_cookie())
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            for k, v in BASE_SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            return

        if misconfigured:
            # Our fault, not the visitor's. Never lock the whole site out over a
            # bad secret — let them through and scream in the log.
            self.log_message('! TURNSTILE MISCONFIGURED (%s) — failing OPEN, '
                             'fix TURNSTILE_SECRET', ",".join(codes) or "unknown")
            self.send_response(303)
            self.send_header("Location", next_path)
            self.send_header("Set-Cookie", self._set_pass_cookie())
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            for k, v in BASE_SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            return

        self.log_message('turnstile FAIL ip=%s codes=%s',
                         self._client_ip(), ",".join(codes))
        hint = ("Verification expired, please try again."
                if "timeout-or-duplicate" in codes
                else "Verification failed, please try again.")
        self._serve_challenge(next_path, error=hint)

    def _host_ok(self) -> bool:
        allowed = os.environ.get("ALLOWED_HOSTS", "").strip()
        if allowed == "*":
            return True
        host = (self.headers.get("Host") or "").strip()
        hostname = host.rsplit(":", 1)[0].strip("[]").lower()
        base = {"127.0.0.1", "localhost", "::1", "[::1]", ""}
        extra = os.environ.get("SITE_HOST", "").strip().lower()
        if extra:
            base.add(extra)
        if allowed:
            base |= {h.strip().lower() for h in allowed.split(",") if h.strip()}
        if hostname in base:
            return True
        # Reached through the tunnel: the Host is the public domain.
        peer = self.client_address[0] if self.client_address else ""
        return peer in ("127.0.0.1", "::1") and bool(self.headers.get("CF-Connecting-IP"))

    def _accepts_gzip(self) -> bool:
        if not GZIP_ENABLED:
            return False
        ae = (self.headers.get("Accept-Encoding") or "").lower()
        return "gzip" in ae and "gzip;q=0" not in ae.replace(" ", "")

    def _respond(self, status, ctype, body: bytes, extra=None, cache="no-store",
                 head_only=False, close=False):
        headers = dict(extra or {})
        compressible = ctype.startswith(GZIP_TYPES)
        if compressible:
            # Advertised on every compressible response, compressed or not, so
            # caches never hand a gzipped body to a client that cannot read it.
            headers["Vary"] = "Accept-Encoding"
            if body and len(body) >= GZIP_MIN_BYTES and self._accepts_gzip():
                body = gzip.compress(body, 6)
                headers["Content-Encoding"] = "gzip"

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        for k, v in BASE_SECURITY_HEADERS.items():
            self.send_header(k, v)
        if self._via_tls():
            self.send_header("Strict-Transport-Security",
                             "max-age=31536000; includeSubDomains")
        for k, v in headers.items():
            self.send_header(k, v)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        # HEAD gets the identical headers (including the compressed
        # Content-Length) but no body, which is exactly what the RFC wants.
        if not head_only and body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                self.close_connection = True

    def _error(self, status, message, close=False, head_only=False):
        body = ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<title>%d</title></head><body><h1>%d</h1><p>%s</p></body></html>"
                % (status, status, message)).encode("utf-8")
        self._respond(status, "text/html; charset=utf-8", body,
                      cache="no-store", head_only=head_only, close=close)

    def _json(self, obj, status=200, head_only=False):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        # Deliberately NO Access-Control-Allow-Origin: same-origin only.
        self._respond(status, "application/json; charset=utf-8", body,
                      head_only=head_only)

    # -- one dispatch for every method --------------------------------------
    def do_GET(self):
        self._dispatch(head_only=False)

    def do_HEAD(self):
        self._dispatch(head_only=True)

    def do_POST(self):
        # The only POST this server ever accepts is the Turnstile challenge
        # form. Everything else is a method error, not a 404, so a scanner
        # learns nothing about which paths exist.
        raw = self.path or "/"
        if len(raw) > MAX_PATH_LEN:
            self._error(414, "Request URI too long.", close=True)
            return
        if not self._host_ok():
            self._error(421, "Misdirected request.", close=True)
            return
        if norm_path(raw) == VERIFY_PATH:
            self._handle_turnstile_post()
            return
        self._reject_method()

    def do_PUT(self):
        self._reject_method()

    def do_DELETE(self):
        self._reject_method()

    def do_PATCH(self):
        self._reject_method()

    def do_OPTIONS(self):
        self._reject_method()

    def _reject_method(self):
        self._error(405, "Method not allowed.", close=True)

    def _dispatch(self, head_only: bool):
        raw = self.path or "/"
        if len(raw) > MAX_PATH_LEN:
            self._error(414, "Request URI too long.", close=True, head_only=head_only)
            return

        # A GET/HEAD carrying a body would desync keep-alive: refuse and close.
        try:
            clen = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            clen = -1
        if clen != 0:
            self._error(400, "Unexpected request body.", close=True, head_only=head_only)
            return

        if not self._host_ok():
            self._error(421, "Misdirected request.", close=True, head_only=head_only)
            return

        split = urlsplit(raw)
        query = split.query
        if len(query) > MAX_QUERY_LEN:
            self._error(414, "Query string too long.", close=True, head_only=head_only)
            return

        path = norm_path(raw)
        if path == "\x00":
            self._error(400, "Bad request.", close=True, head_only=head_only)
            return
        q = parse_qs(query)
        _TLS.cookies = self.headers.get("Cookie") or ""

        # ---- Turnstile gate -----------------------------------------------
        # Runs before *any* content is produced, so nothing — not a page, not
        # an image, not an API error message — leaks to an unverified client.
        # HTML navigations get the challenge; everything else (XHR/fetch,
        # <img>, HEAD) gets a flat JSON 403 so a bot cannot tell a gated
        # endpoint from a missing one.
        if self._gate_applies(path) and not self._has_pass():
            if rate_limited(self._client_ip(), "gate", GATE_RATE_PER_MIN):
                self._error(429, "Too many requests.", close=True,
                            head_only=head_only)
                return
            if head_only or not self._wants_html():
                self._respond(403, "application/json; charset=utf-8",
                              b'{"error":"verification required"}',
                              extra={"X-Robots-Tag": "noindex"},
                              head_only=head_only)
                return
            self._serve_challenge(path)
            return

        # ---- API ----------------------------------------------------------
        if path.startswith("/api/") or path == "/search-api":
            if head_only:
                self._error(405, "HEAD not supported on API endpoints.",
                            close=True, head_only=True)
                return
            limit = IMG_RATE_PER_MIN if path == "/api/img" else RATE_LIMIT_PER_MIN
            bucket = "img" if path == "/api/img" else "api"
            if rate_limited(self._client_ip(), bucket, limit):
                self._respond(429, "application/json; charset=utf-8",
                              b'{"error":"rate limited"}',
                              extra={"Retry-After": "60"})
                return
            if path == "/api/latest":
                try:
                    self._json(fetch_latest())
                except Exception as exc:                      # noqa: BLE001
                    self._json({"error": str(exc)[:200]}, 502)
                return
            if path == "/api/wallpaper":
                try:
                    self._json(fetch_wallpaper(q.get("url", [""])[0]))
                except Exception as exc:                      # noqa: BLE001
                    self._json({"error": str(exc)[:200]}, 400)
                return
            if path == "/api/img":
                self._serve_img(q, head_only)
                return
            if path == "/search-api":
                self._serve_search_api(q)
                return
            self._error(404, "Not found.", head_only=head_only)
            return

        # ---- upstream-proxied HTML ---------------------------------------
        if path == "/" or path == "/search/" or CAT_RE.match(path):
            if path.rstrip("/").startswith(("/api", "/assets", "/images")):
                self._error(404, "Not found.", head_only=head_only)
                return
            qs = ("?" + query) if query else ""
            try:
                body = serve_origin(path + qs)
            except Exception as exc:                          # noqa: BLE001
                self._error(502, "Upstream error: %s" % str(exc)[:120],
                            head_only=head_only)
                return
            self._respond(200, "text/html; charset=utf-8", body, head_only=head_only)
            return

        if PAGE_RE.match(path):
            try:
                body = serve_origin(path)
            except Exception as exc:                          # noqa: BLE001
                self._error(502, "Upstream error: %s" % str(exc)[:120],
                            head_only=head_only)
                return
            self._respond(200, "text/html; charset=utf-8", body, head_only=head_only)
            return

        # ---- images -------------------------------------------------------
        if path.startswith(IMG_PREFIX):
            if rate_limited(self._client_ip(), "img", IMG_RATE_PER_MIN):
                self._error(429, "Rate limited.", head_only=head_only)
                return
            # Direct requests (`/images/...`) carry no ?url= — the path *is* the
            # target. Only the normalised path is ever trusted here.
            if not q.get("url"):
                q["url"] = [path]
            self._serve_img(q, head_only)
            return

        # ---- static files -------------------------------------------------
        self._serve_static(path, head_only)

    def _serve_static(self, path: str, head_only: bool):
        if path.endswith("/"):
            index = safe_join(WEB_ROOT, path + "index.html")
            if index and os.path.isfile(index):
                path = path + "index.html"
            else:
                # No directory listings, ever.
                self._error(404, "Not found.", head_only=head_only)
                return
        if not is_servable_file(path):
            self._error(404, "Not found.", head_only=head_only)
            return
        local = safe_join(WEB_ROOT, path)
        if not local or not os.path.isfile(local):
            self._error(404, "Not found.", head_only=head_only)
            return
        try:
            with open(local, "rb") as fh:
                data = fh.read(MAX_UPSTREAM_BYTES + 1)
        except OSError:
            self._error(404, "Not found.", head_only=head_only)
            return
        if len(data) > MAX_UPSTREAM_BYTES:
            self._error(413, "File too large.", head_only=head_only)
            return
        ext = posixpath.splitext(path)[1].lower()
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ext in (".html", ".htm"):
            ctype = "text/html; charset=utf-8"
            cache = "no-store"
        elif ext in (".js", ".mjs", ".css", ".json", ".webmanifest", ".svg",
                     ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico",
                     ".woff", ".woff2", ".ttf", ".otf"):
            ctype = (ctype + "; charset=utf-8") if ctype.startswith("text/") else ctype
            cache = "public, max-age=86400"
        else:
            cache = "no-store"
        self._respond(200, ctype, data, cache=cache, head_only=head_only)

    def _serve_img(self, q, head_only: bool):
        raw = q.get("url", [""])[0]
        try:
            f = clean_img_path(raw)
        except ValueError as exc:
            self._error(400, str(exc), head_only=head_only)
            return

        # Prefer a real file already on disk (localised copies).
        local = safe_join(WEB_ROOT, f)
        if local and os.path.isfile(local):
            try:
                with open(local, "rb") as fh:
                    data = fh.read(MAX_UPSTREAM_BYTES + 1)
            except OSError:
                data = None
            if data is not None:
                ctype = mimetypes.guess_type(local)[0] or "image/jpeg"
                extra = {}
                if q.get("dl"):
                    extra["Content-Disposition"] = (
                        'attachment; filename="%s"' % posixpath.basename(local))
                self._respond(200, ctype, data, extra=extra,
                              cache="public, max-age=86400", head_only=head_only)
                return

        try:
            resp, real, data = fetch_img(f)
        except Exception:                                     # noqa: BLE001
            self._error(502, "Upstream image unavailable.", head_only=head_only)
            return
        ctype = (resp.headers.get_content_type()
                 or mimetypes.guess_type(real)[0] or "image/jpeg")
        extra = {}
        if q.get("dl"):
            extra["Content-Disposition"] = (
                'attachment; filename="%s"' % posixpath.basename(real))
        self._respond(200, ctype, data, extra=extra,
                      cache="public, max-age=86400", head_only=head_only)

    def _serve_search_api(self, q):
        action = q.get("action", [""])[0]
        term = q.get("mainsearchtext", [""])[0][:100]
        if action not in SEARCH_ACTIONS:
            self._error(400, "Unsupported action.")
            return
        try:
            qs = "?" + urllib.parse.urlencode(
                {"action": action, "mainsearchtext": term})
            resp, data = http_get(ORIGIN + "/search-api" + qs)
        except Exception:                                     # noqa: BLE001
            self._error(502, "Upstream search unavailable.")
            return
        ctype = resp.headers.get_content_type() or "application/json"
        if not (ctype.startswith("application/json") or ctype.startswith("text/")):
            ctype = "application/json"
        self._respond(200, ctype, data)


def main():
    port = int(os.environ.get("PORT") or (sys.argv[1] if len(sys.argv) > 1 else 8000))
    bind = os.environ.get("BIND", "127.0.0.1")
    print("Serving %s on http://%s:%d  (hardened)" % (WEB_ROOT, bind, port))
    if RATE_LIMIT_PER_MIN or IMG_RATE_PER_MIN:
        print("  rate limit: %d/min per IP on JSON API, %d/min on images"
              % (RATE_LIMIT_PER_MIN, IMG_RATE_PER_MIN))
    print("  concurrency cap: %d" % MAX_CONCURRENCY)
    print("  gzip: %s" % ("on" if GZIP_ENABLED else "off"))
    if TURNSTILE_MODE == "off":
        print("  turnstile: off (no challenge)")
    else:
        print("  turnstile: %s (site key %s)" % (TURNSTILE_MODE, TURNSTILE_SITE_KEY))
        if os.environ.get("TURNSTILE_PROBE") != "0":
            verdict, detail = probe_secret()
            if verdict == "ok":
                print("  turnstile: secret ACCEPTED by Cloudflare (%s)" % detail)
            elif verdict == "bad":
                bar = "!" * 68
                print("  " + bar)
                print("  !! TURNSTILE SECRET REJECTED BY CLOUDFLARE: %s" % detail)
                print("  !! Visitors will still get a challenge page, but the")
                print("  !! verification can never succeed — it is pointless")
                print("  !! friction. The gate FAILS OPEN, so the site keeps")
                print("  !! working and nobody is locked out.")
                print("  !! Fix: open the Cloudflare dashboard, Turnstile, your")
                print("  !! widget, and use the COPY button on the Secret Key")
                print("  !! (do not retype it). Paste it into:")
                print("  !!   %s" % os.path.join(SECRETS_DIR, "turnstile.secret"))
                print("  !! Or set TURNSTILE_MODE=off until it is fixed.")
                print("  " + bar)
            else:
                print("  turnstile: could not reach Cloudflare to validate the "
                      "secret (%s)" % detail)
                print("             the gate will fail OPEN while it is down")
        else:
            print("  turnstile: secret loaded (len %d), boot probe skipped"
                  % len(TURNSTILE_SECRET or ""))
    BoundedThreadingHTTPServer((bind, port), H).serve_forever()


if __name__ == "__main__":
    main()
