"""[F72][SAFETY: read-only target — bind 127.0.0.1] Aplikasi benchmark:
dua mode, satu kode.

  vulnerable : kondisi keamanan DITANAM (tanpa header keamanan, cookie
               tanpa flag, directory listing, halaman debug, robots
               membocorkan panel, Server header ber-versi, error oracle,
               CORS wildcard, swagger, api-docs)
  hardened   : kondisi yang sama SEMUA diperbaiki — scanner yang benar
               harus DIAM (nol temuan) di mode ini

Dipakai tools/benchmark_accuracy.py sebagai target scan. Bukan produksi;
bind 127.0.0.1, port ephemeral.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILES_PAGE = """<html><head><title>Index of /files</title></head><body>
<h1>Directory listing</h1>
<ul><li><a href="backup-2025.sql">backup-2025.sql</a></li>
<li><a href="notes.txt">notes.txt</a></li></ul></body></html>"""

DEBUG_PAGE = """<html><body><h1>Debug</h1>
<pre>benchmark-target v1.2.3
python 3.12.8 | db: sqlite://benchmark
stack: handle_request -> render_debug -> boom</pre></body></html>"""

SEARCH_ERROR = """<html><body><h1>500</h1>
<pre>sqlite3.OperationalError: no such column: q'{q}'</pre>
</body></html>"""

SWAGGER_PAGE = """<html><head><title>Swagger UI</title></head>
<body><div id="swagger-ui"></div>
<script src="/openapi.json"></script></body></html>"""

API_DOCS_PAGE = """<html><head><title>API Documentation</title></head>
<body><h1>API Reference</h1><ul><li>GET /api/v1/contacts</li>
<li>POST /api/v1/deals</li></ul></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "BenchmarkServer/1.2.3"  # terlihat di Server header
    mode = "vulnerable"

    def log_message(self, *a):  # senyap — benchmark
        pass

    # header dasar: hardened = lengkap; vulnerable = kosong
    def _base_headers(self) -> dict[str, str]:
        if self.mode == "hardened":
            return {
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            }
        return {}

    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8",
              extra: dict | None = None) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in self._base_headers().items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/robots.txt":
            body = ("User-agent: *\n"
                    + ("Disallow: /admin/\nDisallow: /secret-panel/\n"
                       if self.mode == "vulnerable" else "Disallow:\n"))
            self._send(200, body, "text/plain")
        elif path == "/" and self.mode == "vulnerable":
            self._send(200, "<html><body><h1>Benchmark</h1></body></html>",
                       extra={"Set-Cookie":
                              "session=abc123; Path=/  # tanpa Secure/HttpOnly"})
        elif path == "/" and self.mode == "hardened":
            self._send(200, "<html><body><h1>Benchmark</h1></body></html>",
                       extra={"Set-Cookie":
                              "session=abc123; Path=/; Secure; HttpOnly; "
                              "SameSite=Strict"})
        elif path == "/files/" and self.mode == "vulnerable":
            self._send(200, FILES_PAGE)
        elif path.startswith("/files/"):
            self._send(403, "forbidden")
        elif path == "/debug" and self.mode == "vulnerable":
            self._send(200, DEBUG_PAGE)
        elif path == "/debug":
            self._send(404, "not found")
        elif path == "/search":
            q = self.path.split("q=", 1)[-1]
            if self.mode == "vulnerable":
                self._send(500, SEARCH_ERROR.format(q=q))
            else:
                self._send(400, "bad request")
        elif path == "/swagger" and self.mode == "vulnerable":
            self._send(200, SWAGGER_PAGE)
        elif path == "/swagger":
            self._send(404, "not found")
        elif path == "/api-docs" and self.mode == "vulnerable":
            self._send(200, API_DOCS_PAGE)
        elif path == "/api-docs":
            self._send(404, "not found")
        elif path == "/api/public" and self.mode == "vulnerable":
            self._send(200, '{"ok": true}',
                       extra={"Access-Control-Allow-Origin": "*",
                              "Access-Control-Allow-Credentials": "true"})
        elif path == "/api/public":
            self._send(200, '{"ok": true}')
        else:
            self._send(404, "not found")


def serve(mode: str, port: int = 0) -> tuple[ThreadingHTTPServer, int]:
    handler = type("H", (Handler,), {"mode": mode})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    return httpd, httpd.server_address[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("vulnerable", "hardened"),
                    default="vulnerable")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    httpd, port = serve(args.mode, args.port)
    print(f"benchmark-target: {args.mode} di http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
