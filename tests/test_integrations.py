"""Telegram, downloader e geolocalização testados contra servidores HTTP locais que imitam as APIs reais."""
import asyncio
import hashlib

from aiohttp import web

from honeynest import downloader as downloader_module
from honeynest import geoip
from honeynest.alerts import TelegramAlerter
from honeynest.database import Database
from honeynest.downloader import Downloader, is_public_url
from honeynest.recorder import Recorder


async def start_server(routes):
    app = web.Application()
    for method, path, handler in routes:
        app.router.add_route(method, path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


def test_telegram_alerts_with_cooldown():
    async def scenario():
        messages = []

        async def send_message(request):
            messages.append(await request.json())
            return web.json_response({"ok": True})

        runner, base = await start_server([("POST", "/sendMessage", send_message)])
        alerter = TelegramAlerter({"token": "x", "chat_id": "42", "events": ["login_success"], "cooldown": 300})
        alerter.url = base + "/sendMessage"
        rec = Recorder(Database(":memory:"), alerter=alerter)

        rec.record("ssh", "login_success", "203.0.113.9", username="root", password="123456")
        rec.record("ssh", "login_success", "203.0.113.9", username="root", password="123456")  # cooldown
        rec.record("ssh", "login_failed", "203.0.113.9", username="root", password="x")       # não monitorado
        rec.record("telnet", "login_success", "198.51.100.1", username="admin", password="admin")
        await asyncio.gather(*alerter.tasks)
        await alerter.close()
        await runner.cleanup()
        return messages

    messages = asyncio.run(scenario())
    # As mensagens são enviadas em paralelo, então podem chegar em qualquer ordem.
    assert len(messages) == 2
    assert all(m["chat_id"] == "42" for m in messages)
    texts = sorted(m["text"] for m in messages)
    assert any("203.0.113.9" in t and "root:123456" in t and "[SSH]" in t for t in texts)
    assert any("198.51.100.1" in t and "[TELNET]" in t for t in texts)


def test_downloader_blocks_internal_addresses():
    async def scenario():
        return [await is_public_url(u) for u in (
            "http://127.0.0.1/x", "http://localhost/x", "http://10.0.0.5/x", "http://169.254.169.254/latest/",
            "ftp://8.8.8.8/x", "http://[::1]/x", "http://192.168.0.1/x")]

    assert asyncio.run(scenario()) == [False] * 7


def test_downloader_saves_sample(tmp_path, monkeypatch):
    payload = b"#!/bin/sh\necho malware de teste\n"

    async def scenario():
        async def sample(request):
            return web.Response(body=payload)

        async def huge(request):
            return web.Response(body=b"x" * (2 * 1024 * 1024))

        runner, base = await start_server([("GET", "/bot.sh", sample), ("GET", "/huge.bin", huge)])

        async def always_public(url):
            return True

        monkeypatch.setattr(downloader_module, "is_public_url", always_public)
        db = Database(":memory:")
        dl = Downloader({"dir": str(tmp_path), "max_size_mb": 1}, Recorder(db))
        dl.schedule(base + "/bot.sh", "ssh", "203.0.113.9", 1234, "sess1")
        dl.schedule(base + "/bot.sh", "ssh", "203.0.113.9", 1234, "sess1")  # Repetida: ignorada
        dl.schedule(base + "/huge.bin", "ssh", "203.0.113.9", 1234, "sess1")
        await asyncio.gather(*dl.tasks)
        await runner.cleanup()
        return db.recent_events(10, event="file_saved")

    events = asyncio.run(scenario())
    digest = hashlib.sha256(payload).hexdigest()
    assert len(events) == 1
    assert events[0]["data"]["sha256"] == digest
    assert (tmp_path / f"{digest}.bin").read_bytes() == payload
    assert len(list(tmp_path.iterdir())) == 1  # O arquivo grande demais não foi salvo


def test_geoip_update(monkeypatch):
    async def scenario():
        async def batch(request):
            ips = await request.json()
            return web.json_response([{"status": "success", "query": ip, "country": "Brazil", "countryCode": "BR",
                                       "city": "São Paulo", "lat": -23.5, "lon": -46.6, "isp": "ISP"} for ip in ips])

        runner, base = await start_server([("POST", "/batch", batch)])
        monkeypatch.setattr(geoip, "API_URL", base + "/batch")
        db = Database(":memory:")
        rec = Recorder(db)
        rec.record("ssh", "connect", "8.8.8.8")
        rec.record("ssh", "connect", "192.168.0.10")
        import aiohttp
        async with aiohttp.ClientSession() as http:
            updated = await geoip.update_once(db, http)
            again = await geoip.update_once(db, http)
        await runner.cleanup()
        return db, updated, again

    db, updated, again = asyncio.run(scenario())
    assert (updated, again) == (2, 0)
    points = db.map_points()
    assert len(points) == 1 and points[0]["ip"] == "8.8.8.8" and points[0]["country"] == "Brazil"
    countries = {r["label"] for r in db.stats()["top_countries"]}
    assert countries == {"Brazil", "Rede local"}


def test_geoip_api_error_keeps_ips_for_retry(monkeypatch):
    async def scenario():
        async def limited(request):
            return web.json_response({"message": "too many requests"}, status=429)

        runner, base = await start_server([("POST", "/batch", limited)])
        monkeypatch.setattr(geoip, "API_URL", base + "/batch")
        db = Database(":memory:")
        Recorder(db).record("ssh", "connect", "8.8.8.8")
        import aiohttp
        async with aiohttp.ClientSession() as http:
            await geoip.update_once(db, http)
        await runner.cleanup()
        return db.ips_without_geo()

    assert asyncio.run(scenario()) == ["8.8.8.8"]
