# webproxy 🛰️

Persian RTL web browsing proxy (mini CroxyProxy) at https://webproxy.miors.art

- Python backend: stdlib http.server + curl_cffi (Chrome TLS fingerprint) with urllib fallback
- URL rewriting: href/src/action/poster/data-src, CSS url(), frame-buster stripping, CSP/X-Frame-Options removal
- SSRF guard: blocks loopback/private/link-local IPs + blocklist.txt
- Proxied GET & POST support
- Atlas dark-gold theme homepage, localStorage history (last 5)

Run: `webproxy.service` (systemd) → 127.0.0.1:7450, exposed via Cloudflare Tunnel.
