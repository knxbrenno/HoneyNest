"""Servidor HTTP falso: painel de login, arquivos isca e classificação de ataques web."""
import logging
import re
from urllib.parse import parse_qsl, unquote_plus

from aiohttp import web

log = logging.getLogger("honeynest.http")

SERVICE = "http"
MAX_BODY = 4096

# Padrões simples para categorizar o que o atacante está tentando.
ATTACK_PATTERNS = {
    "sqli": re.compile(r"union\s+(all\s+)?select|'\s*or\s*'?\d|\bor\s+1\s*=\s*1|sleep\(\d|benchmark\(|"
                       r"information_schema|load_file\(|into\s+outfile|'\s*--", re.I),
    "xss": re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|alert\(|<svg|<img[^>]+src", re.I),
    "lfi": re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|php://|file://|win\.ini|/proc/self", re.I),
    "rce": re.compile(r"[;|`]\s*(id|whoami|uname|cat|wget|curl|nc|bash|sh|chmod)\b|\$\(|\$\{jndi:|"
                      r"cmd=|exec=|shell_exec|system\(|passthru|/bin/(ba)?sh", re.I),
    "scanner": re.compile(r"/\.env|/\.git/|wp-login|wp-admin|xmlrpc\.php|phpmyadmin|/actuator|/cgi-bin/|"
                          r"/\.aws/|/config\.json|/vendor/phpunit|/boaform|/hnap1|/solr/|/console|"
                          r"/server-status|/\.ds_store|/manager/html|/owa/|/autodiscover", re.I),
}

TOOLS_RE = re.compile(r"(nmap|sqlmap|nikto|masscan|zgrab|nuclei|gobuster|dirbuster|dirb|ffuf|wpscan|"
                      r"hydra|curl|wget|python-requests|go-http-client|libwww-perl|censys|shodan)", re.I)

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Admin Panel - Login</title>
<style>
body{font-family:Arial,sans-serif;background:#eef1f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#fff;padding:32px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:300px}
h2{margin-top:0;color:#333}input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:10px;background:#2d6cdf;color:#fff;border:0;border-radius:4px;cursor:pointer}
.err{color:#c0392b;font-size:14px}
</style></head><body>
<form method="post" action="/login">
<h2>Admin Panel</h2>{error}
<input name="username" placeholder="Username" autofocus>
<input name="password" type="password" placeholder="Password">
<button type="submit">Sign in</button>
</form></body></html>"""

NOT_FOUND = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body>
<h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>{server} Server at {host} Port {port}</address></body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.env\n"

FAKE_ENV = """APP_ENV=production
APP_DEBUG=false
DB_HOST=127.0.0.1
DB_DATABASE=app_prod
DB_USERNAME=app_user
DB_PASSWORD=Pr0d#Db!2024
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://deploy:ghp_FakeTokenForHoneypot000000000000000@github.example.com/company/app.git
"""

BAIT_PATHS = {"/.env": FAKE_ENV, "/.git/config": FAKE_GIT_CONFIG, "/backup/db.sql": "-- MySQL dump\n"}

USER_FIELDS = ("username", "user", "login", "log", "email", "usr")
PASS_FIELDS = ("password", "pass", "pwd", "passwd", "senha")


def classify(text, user_agent=""):
    """Retorna as categorias de ataque encontradas e a ferramenta usada (se identificável)."""
    decoded = unquote_plus(unquote_plus(text))
    tags = [name for name, pattern in ATTACK_PATTERNS.items() if pattern.search(decoded)]
    tool = TOOLS_RE.search(user_agent or "")
    return tags, tool.group(1).lower() if tool else None


def _pick(form, fields):
    for name in fields:
        if form.get(name):
            return form[name]
    return None


def build_app(honeypot, cfg):
    rec = honeypot.recorder

    async def handler(request):
        ip = request.remote or "desconhecido"
        peer = request.transport.get_extra_info("peername") if request.transport else None
        port = peer[1] if peer else None
        body = (await request.content.read(MAX_BODY)).decode("utf-8", errors="replace") if request.can_read_body else ""
        ua = request.headers.get("User-Agent", "")
        tags, tool = classify(request.path_qs + " " + body, ua)

        rec.record(SERVICE, "http_request", ip, port, detail=f"{request.method} {request.path_qs}",
                   user_agent=ua, host=request.headers.get("Host", ""), tags=tags, tool=tool,
                   body=body[:1000] if body else None)

        headers = {"Server": cfg["server_header"]}
        path = request.path.rstrip("/") or "/"

        if path in ("/", "/admin", "/login") and request.method == "GET":
            return web.Response(text=LOGIN_PAGE.replace("{error}", ""), content_type="text/html", headers=headers)

        if path == "/login" and request.method == "POST":
            form = dict(parse_qsl(body))
            rec.record(SERVICE, "login_failed", ip, port,
                       username=_pick(form, USER_FIELDS), password=_pick(form, PASS_FIELDS))
            error = '<p class="err">Invalid username or password.</p>'
            return web.Response(text=LOGIN_PAGE.replace("{error}", error), content_type="text/html",
                                status=401, headers=headers)

        if path == "/robots.txt":
            return web.Response(text=ROBOTS, headers=headers)

        if path in BAIT_PATHS:
            rec.record(SERVICE, "bait_accessed", ip, port, detail=path, user_agent=ua)
            return web.Response(text=BAIT_PATHS[path], headers=headers)

        host = request.headers.get("Host", "localhost").split(":")[0]
        page = NOT_FOUND.format(server=cfg["server_header"], host=host, port=cfg["port"])
        return web.Response(text=page, content_type="text/html", status=404, headers=headers)

    app = web.Application(client_max_size=MAX_BODY * 4)
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


async def start(honeypot, cfg):
    runner = web.AppRunner(build_app(honeypot, cfg), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, cfg["host"], cfg["port"], reuse_address=True)
    await site.start()
    return runner
