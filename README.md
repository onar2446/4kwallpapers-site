# 4K Wallpapers Site

Static mirror + live Python proxy of a 4K-wallpapers frontend (same look, local serving).

## Run locally

```bash
python server.py 8000
# open http://localhost:8000/
```

- `/` — homepage (Recent + Trending, live)
- Any `/category/page-123.html` — wallpaper detail with all resolutions, downloads served locally
- `/search/?q=...` — live search
- Toggle `∞` enables infinite scroll (cookie is forwarded upstream)

## Deploy notes

- **GitHub Pages (static):** serves the design + cached images. The live
  `/api/*` proxy needs Python, so use a Python host (Render / Railway / Fly.io)
  for full functionality: `python server.py $PORT` with `BIND=0.0.0.0`.
- Secrets (`turnstile.secret`, `gate.key`) live in
  `../4kwallpapers_source-secrets/` and are **never committed**
  (see `.gitignore`). Set them via env vars on your host:
  `TURNSTILE_SECRET`, `TURNSTILE_MODE=off` to disable the gate.

Made by [@b_tor](https://t.me/b_tor)
