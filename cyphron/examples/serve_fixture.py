"""Standalone vulnerable lab server for Cyphron demos (SELF-OWNED, localhost only).

Run:  python examples/serve_fixture.py [port]   (default 8000, in scope of
examples/authorization.localhost.json)

Endpoints: / (hub), /search?q= (reflected XSS), /item?id= (SQLi), /.env and
/.git/HEAD (exposure). Bind is 127.0.0.1 only — never exposes to the network."""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = """<html><head><title>Cyphron Lab</title></head><body>
<h1>Cyphron vulnerable fixture</h1>
<a href="/search?q=laptop">Search</a>
<a href="/item?id=3">Item 3</a>
<form action="/login" method="POST">
  <input type="text" name="username"><input type="password" name="password">
  <button type="submit">Login</button>
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/search":
            q = (parse_qs(p.query).get("q") or [""])[0]
            self._send(200, f"<html><body>Results for {q}</body></html>")  # no encoding (vuln)
        elif p.path == "/item":
            item_id = (parse_qs(p.query).get("id") or [""])[0]
            if "'" in item_id:
                if "1'='1" in item_id:
                    self._send(200, "<html><body><table><tr><td>Row A</td></tr>"
                                    "<tr><td>Row B</td></tr></table></body></html>")
                elif "1'='2" in item_id:
                    self._send(200, "<html><body><table></table></body></html>")
                else:
                    self._send(500, "<html><body>SQLiteException: incomplete input</body></html>")
            else:
                self._send(200, f"<html><body><table><tr><td>Item {item_id}</td></tr></table></body></html>")
        elif p.path == "/.env":
            self._send(200, "DB_PASSWORD=supersecret123\nAPI_KEY=abcd1234efgh5678\n",
                       content_type="text/plain")
        elif p.path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", content_type="text/plain")
        elif p.path in ("", "/"):
            self._send(200, PAGE)
        else:
            self._send(404, "<html><body>not found</body></html>")

    def do_POST(self):
        self._send(200, "<html><body>login failed</body></html>")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"[fixture] vulnerable lab on http://127.0.0.1:{port} (Ctrl+C to stop)")
    server.serve_forever()
