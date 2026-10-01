#!/usr/bin/env python3
"""Mini web proxy (CroxyProxy-style) — Python stdlib only. Port 7450."""
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 7450
TIMEOUT = 15
MAX_BYTES = 8 * 1024 * 1024
BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.txt")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

STRIP_HEADERS = {
    "content-security-policy", "x-frame-options", "strict-transport-security",
    "content-encoding", "transfer-encoding", "content-length", "set-cookie",
    "x-xss-protection", "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "report-to", "permissions-policy",
}

_extra_block_hosts = set()
if os.path.exists(BLOCKLIST_FILE):
    with open(BLOCKLIST_FILE) as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                _extra_block_hosts.add(line)


def _ip_is_blocked(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
            or a.is_multicast or a.is_unspecified)


class Blocked(Exception):
    pass


def check_target(url: str) -> str:
    """Normalize & validate target URL; returns absolute URL."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise Blocked("طرقه پشتیبانی نمی‌شود")
    host = (p.hostname or "").lower().strip(".")
    if not host:
        raise Blocked("آدرس نامعتبر")
    if host in _extra_block_hosts or host.endswith(".local") or host.endswith(".internal"):
        raise Blocked("این آدرس مسدود است")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise Blocked("نام دامنه پیدا نشد")
    for info in infos:
        ip = info[4][0]
        if _ip_is_blocked(ip):
            raise Blocked("دسترسی به آدرس‌های داخلی مجاز نیست")
    return url


def proxy_url(target: str) -> str:
    return "/proxy?url=" + urllib.parse.quote(target, safe="")


URL_RE = re.compile(r"""(?ix)
    \b(?:src|href|action|poster|data-src|formaction)\s*=\s*
    (?:"([^"]*)"|'([^']*)'|([^\s>]+)) |
    url\(\s*(['"]?)([^'")]+)\5\s*\)
""")


class Rewriter:
    def __init__(self, base: str):
        self.base = base

    def abs_url(self, u: str) -> str:
        u = u.strip()
        if not u or u.startswith(("#", "javascript:", "data:", "mailto:", "tel:", "about:")):
            return None
        if u.startswith("//"):
            u = "https:" + u
        try:
            return urllib.parse.urljoin(self.base, u)
        except ValueError:
            return None

    def to_proxy(self, u: str) -> str:
        a = self.abs_url(u)
        return proxy_url(a) if a else u

    def rewrite(self, html: str) -> str:
        def repl(m):
            if m.group(1) is not None or m.group(2) is not None or m.group(3) is not None:
                val = m.group(1) or m.group(2) or m.group(3) or ""
                attr = m.group(0).split("=")[0]
                return f'{attr}="{self.to_proxy(val)}"'
            # css url()
            return f"url({m.group(6)!r}-CSS)"  # placeholder; handled below
        # handle attribute form only; css url() separately
        html = URL_ATTR_RE.sub(self._attr_repl, html)
        html = CSS_URL_RE.sub(self._css_repl, html)
        # strip frame-busting scripts
        html = re.sub(r"<script[^>]*>[^<]*?(?:top\.location|self\.location(?!\s*=)|parent\.location)[\s\S]*?</script>", "", html, flags=re.I)
        return html

    def _attr_repl(self, m):
        val = m.group(2) or m.group(3) or m.group(4) or ""
        if val.lower().startswith(("data:", "javascript:", "mailto:", "tel:")):
            return m.group(0)
        attr = m.group(1)
        return f'{attr}="{self.to_proxy(val)}"'

    def _css_repl(self, m):
        return "url('%s')" % self.to_proxy(m.group(2))


URL_ATTR_RE = re.compile(
    r"""(?i)\b(src|href|action|poster|data-src|formaction)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
CSS_URL_RE = re.compile(r"""url\(\s*(['"]?)([^'")]+)\1\s*\)""", re.I)

ERROR_PAGE = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>خطا</title>
<style>body{{background:#121212;color:#f0e9d8;font-family:sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center}}
.box{{background:#1a1a1a;border:1px solid #2e2c26;border-radius:14px;padding:2rem 3rem;text-align:center}}
h1{{color:#c9a962;font-size:1.4rem}}p{{color:#9a937f;margin-top:.8rem}}a{{color:#c9a962}}</style></head>
<body><div class="box"><h1>⚠️ خطا در بارگذاری سایت</h1><p>{msg}</p><p><a href="/">بازگشت به صفحه اصلی</a></p></div></body></html>"""


class _CurlHTTPError(Exception):
    def __init__(self, code, body, content_type, url):
        self.code = code
        self.body = body
        self.content_type = content_type
        self.url = url


class _CurlResp:
    """Adapter so the rest of _fetch works with both curl_cffi and urllib responses."""

    def __init__(self, r):
        self._r = r
        self.status = r.status_code
        self._headers = r.headers

    class _Hdrs:
        def __init__(self, h):
            self._h = h

        def get(self, k, default=None):
            v = self._h.get(k)
            return v if v is not None else default

        def items(self):
            return self._h.items()

    @property
    def headers(self):
        return _CurlResp._Hdrs(self._headers)

    def geturl(self):
        return getattr(self._r, "url", "")

    def read(self, n=-1):
        return self._r.content


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path in ("/", "/index.html"):
            return self._homepage()
        if parsed.path != "/proxy":
            return self._send(404, ERROR_PAGE.format(msg="صفحه پیدا نشد").encode())
        q = urllib.parse.parse_qs(parsed.query)
        target = (q.get("url") or [""])[0]
        if not target:
            return self._send(400, ERROR_PAGE.format(msg="آدرسی وارد نشده است").encode())
        try:
            target = check_target(target)
        except Blocked as e:
            return self._send(403, ERROR_PAGE.format(msg=str(e)).encode())
        return self._fetch(target)

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/proxy":
            return self._send(404, ERROR_PAGE.format(msg="صفحه پیدا نشد").encode())
        q = urllib.parse.parse_qs(parsed.query)
        target = (q.get("url") or [""])[0]
        try:
            target = check_target(target)
        except Blocked as e:
            return self._send(403, ERROR_PAGE.format(msg=str(e)).encode())
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, MAX_BYTES)) if length else b""
        return self._fetch(target, method="POST", body=body if body else None,
                           ctype=self.headers.get("Content-Type", "application/x-www-form-urlencoded"))

    def _fetch(self, target, method="GET", body=None, ctype=None):
        # Prefer curl_cffi (browser TLS fingerprint — bypasses JA3 bot blocks), fallback to urllib
        resp = None
        try:
            import curl_cffi.requests as creq
            hdrs = {"Accept-Language": "fa,en;q=0.8", "Referer": target}
            if body is not None:
                hdrs["Content-Type"] = ctype
            try:
                r = creq.request(method, target, data=body, headers=hdrs, timeout=TIMEOUT,
                                 impersonate="chrome", allow_redirects=True)
            except creq.errors.HTTPError as he:
                rr = he.response
                raise _CurlHTTPError(he.response.status_code if rr is not None else 502,
                                     (rr.content if rr is not None else b""),
                                     (rr.headers.get("Content-Type", "") if rr is not None else ""),
                                     (rr.url if rr is not None else target)) from he
            resp = _CurlResp(r)
        except _CurlHTTPError as e:
            data = e.body or b""
            ct = e.content_type or ""
            if data and "html" in ct:
                data = Rewriter(e.url or target).rewrite(data.decode("utf-8", "replace")).encode("utf-8")
            if data and ("html" in ct or "json" in ct):
                return self._send(e.code, data, ctype=ct or "text/html; charset=utf-8")
            return self._send(e.code, ERROR_PAGE.format(msg=f"سایت پاسخ {e.code} داد").encode())
        except Exception:
            req = urllib.request.Request(target, data=body, method=method,
                                         headers={"User-Agent": UA,
                                                  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                                  "Accept-Language": "fa,en;q=0.8",
                                                  "Referer": target})
            try:
                resp = urllib.request.urlopen(req, timeout=TIMEOUT)
            except urllib.error.HTTPError as e:
                try:
                    data = e.read()
                except Exception:
                    data = b""
                ct = (e.headers.get("Content-Type", "") if e.headers else "")
                if data and "html" in ct:
                    data = Rewriter(str(e.url or target)).rewrite(data.decode("utf-8", "replace")).encode("utf-8")
                if data and ("html" in ct or "json" in ct):
                    return self._send(e.code, data, ctype=ct or "text/html; charset=utf-8")
                return self._send(e.code, ERROR_PAGE.format(msg=f"سایت پاسخ {e.code} داد").encode())
            except Exception as e:
                return self._send(502, ERROR_PAGE.format(msg="سایت در دسترس نیست: " + str(e)[:200]).encode())
        cdata = resp.headers.get("Content-Type", "")
        if "text/html" not in cdata and "text/css" not in cdata and "javascript" not in cdata:
            data = resp.read(MAX_BYTES)
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in STRIP_HEADERS and k.lower() != "link":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        data = resp.read(MAX_BYTES)
        final_url = resp.geturl()
        charset = "utf-8"
        m = re.search(r"charset=([\w-]+)", cdata)
        if m:
            charset = m.group(1)
        try:
            text = data.decode(charset, errors="replace")
        except LookupError:
            text = data.decode("utf-8", errors="replace")
        rw = Rewriter(final_url)
        if "text/html" in cdata:
            text = rw.rewrite(text)
            # inject proxied form handler support: force GET-less forms? leave as-is; action already rewritten to /proxy
        elif "text/css" in cdata:
            text = CSS_URL_RE.sub(rw._css_repl, text)
        else:
            # javascript: rewrite absolute urls cautiously (skip)
            pass
        out = text.encode("utf-8")
        extra = {"X-Proxied-For": urllib.parse.urlsplit(final_url).netloc}
        self._send(resp.status, out, ctype="text/html; charset=utf-8" if "html" in cdata else cdata, extra=extra)

    def _homepage(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
        with open(path, "rb") as f:
            self._send(200, f.read())


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"webproxy listening on {PORT}", flush=True)
    srv.serve_forever()
