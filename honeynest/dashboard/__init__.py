"""Painel web: API JSON + página com gráficos, mapa e eventos em tempo real."""
import base64
import hmac
from pathlib import Path

from aiohttp import web

STATIC_DIR = Path(__file__).parent / "static"
MAX_EVENTS = 500


def _basic_auth_middleware(username, password):
    expected = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    @web.middleware
    async def middleware(request, handler):
        if not hmac.compare_digest(request.headers.get("Authorization", ""), expected):
            return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="HoneyNest"'})
        response = await handler(request)
        # O painel exibe dados enviados por atacantes; estes cabeçalhos reduzem o risco de XSS.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https://tile.openstreetmap.org https://cdnjs.cloudflare.com")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    return middleware


def build_app(db, cfg):
    async def index(request):
        return web.FileResponse(STATIC_DIR / "index.html")

    async def stats(request):
        return web.json_response(db.stats())

    async def events(request):
        q = request.query
        try:
            limit = max(1, min(int(q.get("limit", 100)), MAX_EVENTS))
        except ValueError:
            limit = 100
        rows = db.recent_events(limit, service=q.get("service"), event=q.get("event"), ip=q.get("ip"))
        return web.json_response(rows)

    async def map_points(request):
        return web.json_response(db.map_points())

    app = web.Application(middlewares=[_basic_auth_middleware(cfg["username"], cfg["password"])])
    app.router.add_get("/", index)
    app.router.add_get("/api/stats", stats)
    app.router.add_get("/api/events", events)
    app.router.add_get("/api/map", map_points)
    app.router.add_static("/static", STATIC_DIR)
    return app


async def start_dashboard(db, cfg):
    runner = web.AppRunner(build_app(db, cfg), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, cfg["host"], cfg["port"]).start()
    return runner
