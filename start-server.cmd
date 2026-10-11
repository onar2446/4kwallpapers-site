@echo off
REM ---------------------------------------------------------------
REM  Start the hardened 4kwallpapers server.
REM  Double-click this file, or run it from a terminal.
REM ---------------------------------------------------------------
cd /d "%~dp0"

REM Port to listen on (change if you need to).
if "%~1"=="" (set PORT=8000) else (set PORT=%~1)

REM Uncomment and set this once you put the site behind a tunnel,
REM so the Host-header check accepts your public domain.
REM set SITE_HOST=your-domain.example.com

REM ---------------------------------------------------------------
REM  Cloudflare Turnstile (CAPTCHA)
REM    off  = no challenge at all
REM    gate = every visitor solves it once, then carries a signed cookie
REM    api  = only /api/* and /search-api are challenged
REM ---------------------------------------------------------------
set TURNSTILE_MODE=gate
set TURNSTILE_SITE_KEY=0x4AAAAAAAFSyGIrU4EB-w-Yj

REM The SECRET is deliberately NOT written here: this .cmd is easy to share
REM by accident. It lives, one line on its own, in:
REM     ..\4kwallpapers_source-secrets\turnstile.secret
REM Set TURNSTILE_SECRET below to override the file.
REM set TURNSTILE_SECRET=

REM How long a solved challenge stays valid, in seconds. Default 43200 (12h).
REM set TURNSTILE_TTL=43200

REM Extra per-IP allowance for the challenge page itself (per minute).
REM set GATE_RATE_PER_MIN=120

REM On startup the server asks Cloudflare whether your Secret Key is actually
REM accepted, and prints a loud warning if it is not. Set this to 0 to skip
REM that one request (e.g. on an offline machine).
REM set TURNSTILE_PROBE=0

echo Starting hardened server on http://127.0.0.1:%PORT%
echo Press Ctrl+C to stop.
echo.

python server.py %PORT%
pause
