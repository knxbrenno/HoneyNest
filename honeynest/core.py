"""Objeto principal: junta configuração, banco, autenticação e serviços."""
import asyncio
import logging

from .alerts import TelegramAlerter
from .auth import AuthPolicy
from .dashboard import start_dashboard
from .database import Database
from .downloader import Downloader
from .geoip import run_forever as geoip_loop
from .recorder import Recorder
from .services import SERVICES
from .shell import FakeShell

log = logging.getLogger("honeynest")


class HoneyNest:
    def __init__(self, config):
        self.config = config
        self.hostname = config["hostname"]
        self.idle_timeout = config["idle_timeout"]
        self.db = Database(config["database"])

        self.alerter = None
        if config["telegram"]["enabled"]:
            if config["telegram"]["token"] and config["telegram"]["chat_id"]:
                self.alerter = TelegramAlerter(config["telegram"])
            else:
                log.warning("Telegram habilitado, mas token/chat_id não configurados.")

        self.recorder = Recorder(self.db, config["log_file"], self.alerter)
        self.auth = AuthPolicy(config["auth"]["accept_credentials"], config["auth"]["accept_after_attempts"])
        self.downloader = Downloader(config["downloads"], self.recorder) if config["downloads"]["enabled"] else None
        self.servers = []
        self.background = []

    def make_shell(self, service, ip, port, session, username):
        def on_event(event, detail=None, **data):
            self.recorder.record(service, event, ip, port, session=session, username=username,
                                 detail=detail, **data)

        on_download = None
        if self.downloader:
            def on_download(url):
                self.downloader.schedule(url, service, ip, port, session)

        return FakeShell(self.hostname, username, on_event, on_download)

    async def start(self):
        for name, module in SERVICES.items():
            cfg = self.config["services"][name]
            if not cfg["enabled"]:
                continue
            self.servers.append(await module.start(self, cfg))
            log.info("Serviço %-6s escutando em %s:%s", name.upper(), cfg["host"], cfg["port"])

        dash = self.config["dashboard"]
        if dash["enabled"]:
            self.servers.append(await start_dashboard(self.db, dash))
            log.info("Painel disponível em http://%s:%s", dash["host"], dash["port"])
            if dash["password"] == "troque-esta-senha":
                log.warning("O painel está usando a senha padrão. Altere 'dashboard.password' no config.yaml!")

        if self.config["geoip"]["enabled"]:
            self.background.append(asyncio.create_task(geoip_loop(self.db)))

    async def stop(self):
        for task in self.background:
            task.cancel()
        for server in self.servers:
            if hasattr(server, "cleanup"):      # aiohttp AppRunner
                await server.cleanup()
            else:                               # asyncio / asyncssh
                server.close()
        if self.alerter:
            await self.alerter.close()
        self.recorder.close()
