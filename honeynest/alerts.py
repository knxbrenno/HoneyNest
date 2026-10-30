"""Alertas no Telegram para os eventos mais importantes."""
import asyncio
import logging
import time

import aiohttp

log = logging.getLogger("honeynest.alerts")

EVENT_TITLES = {
    "login_success": "Login aceito",
    "download": "Tentativa de download",
    "bait_accessed": "Arquivo isca acessado",
    "command": "Comando executado",
    "login_failed": "Tentativa de login",
    "http_request": "Requisição HTTP",
}


class TelegramAlerter:
    def __init__(self, cfg):
        self.url = f"https://api.telegram.org/bot{cfg['token']}/sendMessage"
        self.chat_id = cfg["chat_id"]
        self.events = set(cfg["events"])
        self.cooldown = cfg["cooldown"]
        self.last_sent = {}
        self.tasks = set()
        self.session = None

    def notify(self, ev):
        if ev["event"] not in self.events:
            return

        # Evita uma enxurrada de mensagens: no máximo 1 alerta por IP/tipo de evento a cada `cooldown` segundos.
        key = (ev["src_ip"], ev["event"])
        now = time.monotonic()
        if now - self.last_sent.get(key, -self.cooldown) < self.cooldown:
            return
        self.last_sent[key] = now

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self._send(self.format(ev)))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    @staticmethod
    def format(ev):
        lines = [f"{EVENT_TITLES.get(ev['event'], ev['event'])} [{ev['service'].upper()}]",
                 f"IP: {ev['src_ip']}"]
        if ev.get("username") is not None:
            lines.append(f"Credencial: {ev['username']}:{ev.get('password')}")
        if ev.get("detail"):
            lines.append(f"Detalhe: {ev['detail'][:300]}")
        lines.append(f"Horário (UTC): {ev['ts']}")
        return "\n".join(lines)

    async def _send(self, text):
        try:
            if self.session is None:
                self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
            async with self.session.post(self.url, json={"chat_id": self.chat_id, "text": text,
                                                         "disable_web_page_preview": True}) as resp:
                if resp.status != 200:
                    log.warning("Telegram respondeu %s: %s", resp.status, await resp.text())
        except Exception as err:
            log.warning("Falha ao enviar alerta para o Telegram: %s", err)

    async def close(self):
        if self.session:
            await self.session.close()
