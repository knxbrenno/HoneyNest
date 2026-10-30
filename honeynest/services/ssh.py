"""Servidor SSH falso (protocolo real via asyncssh) com shell simulado."""
import asyncio
import logging
import uuid
from pathlib import Path

import asyncssh

log = logging.getLogger("honeynest.ssh")

SERVICE = "ssh"


def load_host_keys(key_dir):
    """Carrega (ou gera na primeira execução) as chaves do servidor, para que a impressão digital não mude."""
    key_dir = Path(key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    keys = []
    for alg, filename in (("ssh-ed25519", "ssh_host_ed25519_key"), ("ssh-rsa", "ssh_host_rsa_key")):
        path = key_dir / filename
        if not path.exists():
            asyncssh.generate_private_key(alg).write_private_key(str(path))
        keys.append(asyncssh.read_private_key(str(path)))
    return keys


class _SSHServer(asyncssh.SSHServer):
    def __init__(self, honeypot):
        self.hp = honeypot
        self.session = uuid.uuid4().hex[:12]
        self.ip = self.port = None
        self.version_logged = False

    def connection_made(self, conn):
        self.conn = conn
        self.ip, self.port = conn.get_extra_info("peername")[:2]
        conn.set_extra_info(honeynest_session=self.session)
        self.hp.recorder.record(SERVICE, "connect", self.ip, self.port, session=self.session)

    def connection_lost(self, exc):
        self.hp.recorder.record(SERVICE, "disconnect", self.ip, self.port, session=self.session)

    def begin_auth(self, username):
        if not self.version_logged:
            self.version_logged = True
            version = self.conn.get_extra_info("client_version")
            self.hp.recorder.record(SERVICE, "client_version", self.ip, self.port,
                                    session=self.session, detail=version)
        return True  # Sempre exige autenticação

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        ok = self.hp.auth.check(self.ip, username, password)
        self.hp.recorder.record(SERVICE, "login_success" if ok else "login_failed", self.ip, self.port,
                                session=self.session, username=username, password=password)
        return ok


async def _handle_process(honeypot, process):
    ip, port = process.get_extra_info("peername")[:2]
    session = process.get_extra_info("honeynest_session")
    shell = honeypot.make_shell(SERVICE, ip, port, session, process.get_extra_info("username"))

    try:
        # "ssh usuario@host comando": executa um único comando e sai.
        if process.command:
            process.stdout.write(shell.execute(process.command)[0])
            return

        process.stdout.write(shell.motd())
        while True:
            process.stdout.write(shell.prompt())
            try:
                line = await asyncio.wait_for(process.stdin.readline(), timeout=honeypot.idle_timeout)
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                process.stdout.write("^C\n")
                continue
            except asyncssh.TerminalSizeChanged:
                continue
            if not line:
                break
            output, should_exit = shell.execute(line)
            if output:
                process.stdout.write(output)
            if should_exit:
                process.stdout.write("logout\n")
                break
    except (asyncio.TimeoutError, asyncssh.Error, ConnectionError, BrokenPipeError):
        pass
    finally:
        try:
            process.exit(0)
        except Exception:
            pass


async def start(honeypot, cfg):
    return await asyncssh.create_server(
        lambda: _SSHServer(honeypot),
        cfg["host"], cfg["port"],
        server_host_keys=load_host_keys(cfg["host_key_dir"]),
        server_version=cfg["version"],
        process_factory=lambda process: _handle_process(honeypot, process),
        reuse_address=True,
    )
