"""Loopback-only vulnerable/patched application controls. No real user data."""
import http.server
import json
import pathlib
import re
import sqlite3
import sys
import tempfile
import threading
import urllib.parse
import xml.parsers.expat

try:
    import jinja2
except ImportError:
    jinja2 = None

scratch = tempfile.TemporaryDirectory(prefix="xalgorix-verifier-oracle-")
passwd = pathlib.Path(scratch.name, "passwd")
passwd.write_text("root:x:0:0:isolated fixture:/nonexistent:/bin/false\n")
custom = pathlib.Path(scratch.name, "canary")
custom.write_text("fixture-only-canary-8490362715\n")
unstable_counter = 0


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, body, content_type="text/plain"):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        value = query.get("q", [""])[0]
        if parsed.path == "/shutdown":
            self.respond(200, "closed")
            threading.Thread(target=server.shutdown, daemon=True).start()
        elif parsed.path == "/capabilities":
            self.respond(200, json.dumps(dict(jinja=jinja2 is not None)), "application/json")
        elif parsed.path.startswith("/sql/"):
            connection = sqlite3.connect(":memory:")
            try:
                connection.execute("create table users (id text, label text)")
                connection.execute("insert into users values ('1', 'fixture account')")
                if parsed.path == "/sql/vulnerable":
                    rows = connection.execute("select label from users where id = '" + value + "'").fetchall()
                elif parsed.path == "/sql/patched":
                    rows = connection.execute("select label from users where id = ?", (value,)).fetchall()
                elif parsed.path == "/sql/validator":
                    if "'" in value:
                        self.respond(400, "SQLSTATE: quotes are prohibited by validation; no query was run")
                        return
                    rows = []
                else:
                    self.respond(200, value)
                    return
                self.respond(200, json.dumps(rows))
            except sqlite3.Error as error:
                self.respond(500, "sqlite3." + type(error).__name__ + ": " + str(error))
            finally:
                connection.close()
        elif parsed.path.startswith("/ssti/"):
            if jinja2 is None:
                self.respond(503, "Jinja2 is not installed")
                return
            if parsed.path == "/ssti/vulnerable":
                rendered = jinja2.Environment().from_string("Hello " + value).render()
            else:
                rendered = jinja2.Environment(autoescape=True).from_string("Hello {{ value }}").render(value=value)
            self.respond(200, rendered)
        else:
            self.respond(404, "No fixture route")

    def do_POST(self):
        global unstable_counter
        payload = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not self.path.startswith("/xxe/"):
            self.respond(404, "No fixture route")
            return

        raw = payload.decode(errors="replace")
        if self.path == "/xxe/echo":
            self.respond(200, raw, "application/xml")
            return
        if self.path == "/xxe/static":
            self.respond(200, "Documentation example: fixture-only-canary-8490362715")
            return
        if self.path in {"/xxe/substitute", "/xxe/unstable"}:
            match = re.search(r"<data>(.*)</data>", raw, re.DOTALL)
            if match is None:
                self.respond(400, "invalid fixture document")
                return
            value = match.group(1)
            if "&xxe;" in value:
                if self.path == "/xxe/unstable" and "xalgorix-xxe-missing-" not in raw:
                    unstable_counter += 1
                    replacement = "volatile-substitution-" + str(unstable_counter)
                else:
                    replacement = "external-entity-blocked"
                value = value.replace("&xxe;", replacement)
            self.respond(200, value)
            return

        parser = xml.parsers.expat.ParserCreate()
        output = []
        parser.CharacterDataHandler = output.append

        def resolve(context, base, system_id, public_id):
            # A real external-entity parser callback, confined to two owned files.
            fixture = {"file:///oracle/passwd": passwd, "file:///oracle/canary": custom}.get(system_id)
            if fixture is None:
                return 0
            child = parser.ExternalEntityParserCreate(context)
            child.CharacterDataHandler = output.append
            child.Parse(fixture.read_bytes(), True)
            return 1

        if self.path == "/xxe/vulnerable":
            parser.ExternalEntityRefHandler = resolve
        else:
            parser.ExternalEntityRefHandler = lambda *unused: 1
        try:
            parser.Parse(payload, True)
            self.respond(200, "".join(output))
        except xml.parsers.expat.ExpatError as error:
            self.respond(400, str(error))


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print("http://127.0.0.1:" + str(server.server_port), flush=True)
try:
    server.serve_forever()
finally:
    server.server_close()
    scratch.cleanup()
