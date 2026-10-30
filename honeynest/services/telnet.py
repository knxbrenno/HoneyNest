"""Servidor Telnet falso. Muito atacado por botnets de IoT (ex.: Mirai)."""
import asyncio
import logging
import uuid

log = logging.getLogger("honeynest.telnet")

SERVICE = "telnet"
MAX_LOGIN_TRIES = 3

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO = 1
WILL_ECHO = bytes([IAC, WILL, ECHO])
WONT_ECHO = bytes([IAC, WONT, ECHO])


def strip_iac(data):
    """Remove as negociações do protocolo Telnet (bytes IAC), deixando apenas o texto digitado."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b != IAC:
            out.append(b)
            i += 1
        elif i + 1 < len(data) and data[i + 1] == IAC:
            out.append(IAC)
            i += 2
        elif i + 1 < len(data) and data[i + 1] == SB:
            end = data.find(bytes([IAC, SE]), i)
            i = len(data) if end == -1 else end + 2
        elif i + 1 < len(data) and data[i + 1] in (WILL, WONT, DO, DONT):
            i += 3
        else:
            i += 2
    return bytes(out)


class TelnetLineReader:
    def __init__(self, reader, timeout):
        self.reader = reader
        self.timeout = timeout
        self.buf = bytearray()
        self.last_cr = False

    def _pop_line(self):
        # "\r\n" e "\r\0" contam como uma única quebra de linha, mesmo se chegarem em pacotes separados.
        if self.last_cr and self.buf and self.buf[0] in (0, 10):
            del self.buf[0]
        if self.buf:
            self.last_cr = False

        for i, b in enumerate(self.buf):
            if b in (10, 13):
                raw = bytes(self.buf[:i])
                del self.buf[:i + 1]
                self.last_cr = b == 13
                return self._apply_backspace(raw.decode("utf-8", errors="replace"))
        return None

    @staticmethod
    def _apply_backspace(text):
        chars = []
        for c in text:
            if c in ("\x08", "\x7f"):
                if chars:
                    chars.pop()
            elif c.isprintable() or c == "\t":
                chars.append(c)
        return "".join(chars)

    async def readline(self):
        while True:
            line = self._pop_line()
            if line is not None:
                return line
            data = await asyncio.wait_for(self.reader.read(1024), timeout=self.timeout)
            if not data:
                return None
            self.buf += strip_iac(data)


def _send(writer, text):
    writer.write(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())


async def _handle(honeypot, reader, writer):
    ip, port = writer.get_extra_info("peername")[:2]
    session = uuid.uuid4().hex[:12]
    rec = honeypot.recorder
    rec.record(SERVICE, "connect", ip, port, session=session)
    lines = TelnetLineReader(reader, honeypot.idle_timeout)

    try:
        _send(writer, f"\nUbuntu 22.04.4 LTS\n")
        username = None
        for _ in range(MAX_LOGIN_TRIES):
            _send(writer, f"{honeypot.hostname} login: ")
            username = await lines.readline()
            if username is None:
                return

            _send(writer, "Password: ")
            writer.write(WILL_ECHO)  # Pede ao cliente para não mostrar a senha
            password = await lines.readline()
            writer.write(WONT_ECHO)
            if password is None:
                return
            _send(writer, "\n")

            ok = honeypot.auth.check(ip, username, password)
            rec.record(SERVICE, "login_success" if ok else "login_failed", ip, port,
                       session=session, username=username, password=password)
            if ok:
                break
            await asyncio.sleep(1)
            _send(writer, "\nLogin incorrect\n")
        else:
            return

        shell = honeypot.make_shell(SERVICE, ip, port, session, username)
        _send(writer, shell.motd())
        while True:
            _send(writer, shell.prompt())
            await writer.drain()
            line = await lines.readline()
            if line is None:
                break
            output, should_exit = shell.execute(line)
            if output:
                _send(writer, output)
            if should_exit:
                _send(writer, "logout\n")
                break
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
