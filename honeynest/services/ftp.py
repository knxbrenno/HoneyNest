"""Servidor FTP falso: registra credenciais e comandos."""
import asyncio
import logging
import uuid

log = logging.getLogger("honeynest.ftp")

SERVICE = "ftp"
MAX_COMMANDS = 200


async def _handle(honeypot, reader, writer):
    ip, port = writer.get_extra_info("peername")[:2]
    session = uuid.uuid4().hex[:12]
    rec = honeypot.recorder
    rec.record(SERVICE, "connect", ip, port, session=session)

    def reply(text):
        writer.write((text + "\r\n").encode())

    username = None
    logged_in = False
    cwd = "/"

    try:
        reply(f"220 {honeypot.config['services']['ftp']['banner']}")
        for _ in range(MAX_COMMANDS):
            await writer.drain()
            raw = await asyncio.wait_for(reader.readline(), timeout=honeypot.idle_timeout)
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()

            if cmd == "USER":
                username = arg
                reply("331 Please specify the password.")
            elif cmd == "PASS":
                if username is None:
                    reply("503 Login with USER first.")
                    continue
                logged_in = honeypot.auth.check(ip, username, arg)
                rec.record(SERVICE, "login_success" if logged_in else "login_failed", ip, port,
                           session=session, username=username, password=arg)
                reply("230 Login successful." if logged_in else "530 Login incorrect.")
            elif cmd == "QUIT":
                reply("221 Goodbye.")
                break
            elif cmd in ("SYST", "FEAT", "AUTH") and not logged_in:
                reply({"SYST": "215 UNIX Type: L8", "FEAT": "211-Features:\r\n PASV\r\n UTF8\r\n211 End",
                       "AUTH": "530 Please login with USER and PASS."}[cmd])
            elif not logged_in:
                reply("530 Please login with USER and PASS.")
            else:
                rec.record(SERVICE, "command", ip, port, session=session, username=username, detail=line)
                if cmd == "PWD":
                    reply(f'257 "{cwd}" is the current directory')
                elif cmd == "CWD":
                    cwd = arg or "/"
                    reply("250 Directory successfully changed.")
                elif cmd == "SYST":
                    reply("215 UNIX Type: L8")
                elif cmd == "TYPE":
                    reply("200 Switching to Binary mode.")
                elif cmd in ("PASV", "EPSV", "PORT", "EPRT"):
                    reply("500 Illegal PORT command.")
                elif cmd in ("LIST", "NLST", "RETR", "STOR", "MLSD"):
                    reply("425 Use PORT or PASV first.")
                else:
                    reply("502 Command not implemented.")
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        rec.record(SERVICE, "disconnect", ip, port, session=session)
        try:
            await writer.drain()
            writer.close()
        except Exception:
            pass


async def start(honeypot, cfg):
    return await asyncio.start_server(lambda r, w: _handle(honeypot, r, w), cfg["host"], cfg["port"],
                                      reuse_address=True)
