"""
Coleta de amostras: baixa os arquivos que os atacantes tentam obter com wget/curl.

Os arquivos são salvos com o nome igual ao SHA-256 e sem permissão de execução; nunca são executados.
Para impedir que o honeypot seja usado para acessar a rede interna (SSRF), só endereços públicos são aceitos.
"""
import asyncio
import hashlib
import ipaddress
import logging
import socket
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

log = logging.getLogger("honeynest.downloader")


async def is_public_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(parsed.hostname, parsed.port or 80,
                                                             type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(info[4][0]).is_global for info in infos)


class Downloader:
    def __init__(self, cfg, recorder):
        self.dir = Path(cfg["dir"])
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = int(cfg["max_size_mb"] * 1024 * 1024)
        self.recorder = recorder
        self.seen_urls = set()
        self.tasks = set()

    def schedule(self, url, service, ip, port, session):
        if url in self.seen_urls:
            return
        self.seen_urls.add(url)
        task = asyncio.get_running_loop().create_task(self._fetch(url, service, ip, port, session))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _fetch(self, url, service, ip, port, session):
        if not await is_public_url(url):
            log.info("Download ignorado (endereço não público ou inválido): %s", url)
            return

        sha256 = hashlib.sha256()
        chunks, size = [], 0
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.get(url, allow_redirects=False, headers={"User-Agent": "Wget/1.21.2"}) as resp:
                    if resp.status != 200:
                        log.info("Download de %s retornou HTTP %s", url, resp.status)
                        return
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        size += len(chunk)
                        if size > self.max_bytes:
                            log.info("Download de %s excedeu o limite de tamanho", url)
                            return
                        sha256.update(chunk)
                        chunks.append(chunk)
        except Exception as err:
            log.info("Falha ao baixar %s: %s", url, err)
            return

        digest = sha256.hexdigest()
        path = self.dir / f"{digest}.bin"
        if not path.exists():
            path.write_bytes(b"".join(chunks))
            path.chmod(0o440)
        self.recorder.record(service, "file_saved", ip, port, session=session, detail=url,
                             sha256=digest, size=size, path=str(path))
