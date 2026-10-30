"""
Shell falso que imita um servidor Ubuntu.

Nenhum comando é executado de verdade: as respostas são simuladas e cada comando é registrado.
"""
import posixpath
import random
import re
import shlex
from datetime import datetime, timezone

URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"|;&<>]+", re.IGNORECASE)

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
"""

OS_RELEASE = """PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
"""

CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu MHz\t\t: 2399.998
cache size\t: 35840 KB
cpu cores\t: 2
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov sse sse2 ht syscall nx lm avx avx2
"""

# Arquivos isca: parecem valiosos e qualquer acesso a eles gera o evento "bait_accessed".
BAIT_FILES = {
    "/var/www/html/.env": """APP_ENV=production
APP_KEY=base64:Q2hhbmdlTWVQbGVhc2VUaGlzSXNGYWtlS2V5MTIzNDU2
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=app_prod
DB_USERNAME=app_user
DB_PASSWORD=Pr0d#Db!2024
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""",
    "/root/.aws/credentials": """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
""",
    "/home/deploy/backup_db.sql": "-- MySQL dump 10.13\n-- Host: localhost    Database: app_prod\n"
                                  "INSERT INTO users VALUES (1,'admin','$2y$10$abcdefghijklmnopqrstuv');\n",
    "/root/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                         "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                         "-----END OPENSSH PRIVATE KEY-----\n",
}

BASE_DIRS = [
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/home/ubuntu", "/home/deploy", "/lib", "/media", "/mnt",
    "/opt", "/proc", "/root", "/root/.ssh", "/root/.aws", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr",
    "/usr/bin", "/usr/local", "/var", "/var/log", "/var/www", "/var/www/html",
]

BASE_FILES = {
    "/etc/passwd": PASSWD,
    "/etc/os-release": OS_RELEASE,
    "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
    "/proc/cpuinfo": CPUINFO,
    "/proc/version": "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-007) (gcc 11.4.0) #115-Ubuntu SMP\n",
    "/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
    "/var/log/auth.log": "",
    "/var/log/syslog": "",
    "/home/ubuntu/.bashrc": "# ~/.bashrc\n",
    "/root/.bashrc": "# ~/.bashrc\n",
    "/root/.ssh/authorized_keys": "",
    **BAIT_FILES,
}


class FakeShell:
    def __init__(self, hostname, username, on_event, on_download=None):
        """
        hostname, username: identidade exibida no prompt.
        on_event(event, detail=None, **data): chamado para cada ação registrável.
        on_download(url): chamado quando o atacante tenta baixar algo (opcional).
        """
        self.hostname = hostname
        self.username = username or "root"
        self.home = "/root" if self.username == "root" else f"/home/{self.username}"
        self.cwd = self.home
        self.on_event = on_event
        self.on_download = on_download
        self.history = []
        self.env = {"HOME": self.home, "USER": self.username, "SHELL": "/bin/bash",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

        self.dirs = set(BASE_DIRS) | {self.home}
        self.files = {path: content.replace("{hostname}", hostname) for path, content in BASE_FILES.items()}
        self.files["/etc/hostname"] = hostname + "\n"

        self.commands = {
            "ls": self.cmd_ls, "ll": self.cmd_ll, "cd": self.cmd_cd, "pwd": self.cmd_pwd,
            "cat": self.cmd_cat, "echo": self.cmd_echo, "whoami": self.cmd_whoami, "id": self.cmd_id,
            "uname": self.cmd_uname, "hostname": self.cmd_hostname, "uptime": self.cmd_uptime,
            "w": self.cmd_w, "ps": self.cmd_ps, "free": self.cmd_free, "df": self.cmd_df,
            "ifconfig": self.cmd_ifconfig, "ip": self.cmd_ip, "nproc": lambda a: "2\n",
            "history": self.cmd_history, "wget": self.cmd_download, "curl": self.cmd_curl,
            "tftp": self.cmd_download, "mkdir": self.cmd_mkdir, "touch": self.cmd_touch,
            "rm": lambda a: "", "chmod": lambda a: "", "chown": lambda a: "", "chattr": lambda a: "",
            "export": self.cmd_export, "env": self.cmd_env, "which": self.cmd_which,
            "clear": lambda a: "\x1b[H\x1b[2J", "crontab": self.cmd_crontab, "passwd": self.cmd_passwd,
            "lscpu": self.cmd_lscpu, "netstat": self.cmd_netstat, "ss": self.cmd_netstat,
            "last": lambda a: "\nwtmp begins Mon Jan  1 00:00:01 2024\n", "date": self.cmd_date,
            "true": lambda a: "", "cp": lambda a: "", "mv": lambda a: "", "kill": lambda a: "",
            "pkill": lambda a: "", "killall": lambda a: "", "nohup": self.cmd_nohup,
        }

    # ------------------------------------------------------------------ interface

    def prompt(self):
        path = self.cwd.replace(self.home, "~", 1) if self.cwd.startswith(self.home) else self.cwd
        return f"{self.username}@{self.hostname}:{path}{'#' if self.username == 'root' else '$'} "

    def motd(self):
        now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        return (
            "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n"
            " * Support:        https://ubuntu.com/pro\n\n"
            f"  System information as of {now}\n\n"
            "  System load:  0.08               Processes:             132\n"
            "  Usage of /:   41.3% of 38.58GB   Users logged in:       0\n"
            "  Memory usage: 23%                IPv4 address for eth0: 10.0.0.12\n\n"
            f"Last login: {now} from 10.0.0.2\n"
        )

    def execute(self, line):
        """Executa uma linha de comando. Retorna (saída, deve_encerrar)."""
        line = line.strip()
        if not line:
            return "", False

        self.history.append(line)
        self.on_event("command", detail=line)

        output = []
        # Comandos encadeados: cmd1; cmd2 && cmd3 || cmd4
        for segment in re.split(r"\s*(?:;|&&|\|\|)\s*", line):
            if not segment:
                continue
            if segment.split()[0] in ("exit", "logout", "quit"):
                return "".join(output), True
            output.append(self._run_segment(segment))
        return "".join(output), False

    # ------------------------------------------------------------------ execução

    def _run_segment(self, segment):
        # Redirecionamentos: "echo x > arquivo" grava no sistema de arquivos falso;
        # "2>/dev/null" e "2>&1" são só removidos.
        segment = re.sub(r"\s*\d?>&\d?", "", segment)
        redirect = None
        for match in re.finditer(r"\s*(\d?)(>>?)\s*([^\s>]+)", segment):
            if match.group(1) in ("", "1"):
                redirect = (match.group(2), match.group(3))
        segment = re.sub(r"\s*\d?>>?\s*[^\s>]+", "", segment)
        segment = re.sub(r"\s*<\s*\S+", "", segment)

        # Pipes: só o primeiro comando produz saída (suficiente para enganar scripts automatizados).
        first = segment.split("|")[0].strip()
        output = self._run_command(first) if first else ""

        # URLs aparecem em qualquer lugar da linha (ex.: "cd /tmp; wget http://x/bot.sh | sh").
        if not first.split() or first.split()[0] not in ("wget", "curl", "tftp"):
            for url in URL_RE.findall(segment):
                self._register_download(url)

        if redirect:
            mode, target = redirect
            if target != "/dev/null":
                path = self._resolve(target)
                self.files[path] = (self.files.get(path, "") if mode == ">>" else "") + output
            return ""
        return output

    def _run_command(self, command):
        try:
            args = shlex.split(command)
        except ValueError:
            args = command.split()
        if not args:
            return ""

        # Remove prefixos que não mudam o comando.
        while args and args[0] in ("sudo", "busybox", "command", "exec", "time") or (args and "=" in args[0]):
            args = args[1:]
        if not args:
            return ""

        name = posixpath.basename(args[0])
        handler = self.commands.get(name)
        if handler:
            return handler(args[1:])
        if name in ("sh", "bash") and len(args) > 2 and args[1] == "-c":
            return self.execute(args[2])[0]
        if name in ("sh", "bash", "python", "python3", "perl"):
            return ""
        if args[0].startswith(("./", "/")):
            path = self._resolve(args[0])
            if path in self.files:
                return f"-bash: {args[0]}: Permission denied\n"
            return f"-bash: {args[0]}: No such file or directory\n"
        return f"{name}: command not found\n"

    def _resolve(self, path):
        path = path.replace("~", self.home, 1) if path.startswith("~") else path
        return posixpath.normpath(posixpath.join(self.cwd, path))

    def _read(self, path):
        if path in BAIT_FILES:
            self.on_event("bait_accessed", detail=path)
        return self.files.get(path)

    def _register_download(self, url):
        self.on_event("download", detail=url)
        if self.on_download:
            self.on_download(url)

    # ------------------------------------------------------------------ comandos

    def cmd_ls(self, args):
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        targets = [a for a in args if not a.startswith("-")] or ["."]
        lines = []
        for target in targets:
            path = self._resolve(target)
            if path in self.files:
                lines.append(self._ls_entry(path, flags))
                continue
            if path not in self.dirs:
                lines.append(f"ls: cannot access '{target}': No such file or directory")
                continue
            children = sorted(self._children(path))
            if "a" not in flags:
                children = [c for c in children if not c.startswith(".")]
            if "l" in flags:
                lines.append(f"total {len(children) * 4}")
                lines.extend(self._ls_entry(posixpath.join(path, c), flags) for c in children)
            elif children:
                lines.append("  ".join(children))
        return "\n".join(lines) + "\n" if lines else ""

    def cmd_ll(self, args):
        return self.cmd_ls(["-la", *args])

    def _children(self, path):
        prefix = path.rstrip("/") + "/"
        names = set()
        for p in list(self.dirs) + list(self.files):
            if p.startswith(prefix) and p != path:
                names.add(p[len(prefix):].split("/")[0])
        return names

    def _ls_entry(self, path, flags):
        name = posixpath.basename(path)
        if "l" not in flags:
            return name
        if path in self.dirs:
            return f"drwxr-xr-x 2 root root 4096 Mar 12 09:41 {name}"
        size = len(self.files.get(path, ""))
        return f"-rw-r--r-- 1 root root {size:>5} Mar 12 09:41 {name}"

    def cmd_cd(self, args):
        target = args[0] if args else self.home
        path = self._resolve(target)
        if path in self.dirs:
            self.cwd = path
            return ""
        if path in self.files:
            return f"-bash: cd: {target}: Not a directory\n"
        return f"-bash: cd: {target}: No such file or directory\n"

    def cmd_pwd(self, args):
        return self.cwd + "\n"

    def cmd_cat(self, args):
        out = []
        for target in (a for a in args if not a.startswith("-")):
            path = self._resolve(target)
            content = self._read(path)
            if content is not None:
                out.append(content)
            elif path in self.dirs:
                out.append(f"cat: {target}: Is a directory\n")
            else:
                out.append(f"cat: {target}: No such file or directory\n")
        return "".join(out)

    def cmd_echo(self, args):
        if args and args[0] == "-n":
            return " ".join(args[1:])
        text = " ".join(self.env.get(a[1:], "") if a.startswith("$") else a for a in args)
        if args and args[0] == "-e":
            text = text[3:].encode().decode("unicode_escape", errors="ignore")
        return text + "\n"

    def cmd_whoami(self, args):
        return self.username + "\n"

    def cmd_id(self, args):
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\n"

    def cmd_uname(self, args):
        if not args:
            return "Linux\n"
        if "-a" in args:
            return (f"Linux {self.hostname} 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 "
                    "x86_64 x86_64 x86_64 GNU/Linux\n")
        parts = {"-s": "Linux", "-n": self.hostname, "-r": "5.15.0-105-generic", "-m": "x86_64",
                 "-p": "x86_64", "-o": "GNU/Linux", "-v": "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024"}
        return " ".join(parts[a] for a in args if a in parts) + "\n"

    def cmd_hostname(self, args):
        return self.hostname + "\n"

    def cmd_uptime(self, args):
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return f" {now} up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n"

    def cmd_w(self, args):
        return (self.cmd_uptime(args) + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{self.username:<8} pts/0    10.0.0.2         09:41    0.00s  0.02s  0.00s w\n")

    def cmd_ps(self, args):
        return ("    PID TTY          TIME CMD\n"
                "      1 ?        00:00:12 systemd\n"
                "    612 ?        00:00:03 sshd\n"
                "    845 ?        00:01:47 mysqld\n"
                "    903 ?        00:00:21 apache2\n"
                f"   {random.randint(2000, 9000)} pts/0    00:00:00 bash\n"
                f"   {random.randint(9001, 9999)} pts/0    00:00:00 ps\n")

    def cmd_free(self, args):
        return ("               total        used        free      shared  buff/cache   available\n"
                "Mem:         4026512      932140     1801236        1236     1293136     2826980\n"
                "Swap:              0           0           0\n")

    def cmd_df(self, args):
        return ("Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                "/dev/sda1       40454740 16708452  23729904  42% /\n"
                "tmpfs            2013256        0   2013256   0% /dev/shm\n")

    def cmd_ifconfig(self, args):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.0.12  netmask 255.255.255.0  broadcast 10.0.0.255\n"
                "        ether 52:54:00:8a:3c:1f  txqueuelen 1000  (Ethernet)\n\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\n")

    def cmd_ip(self, args):
        if args and args[0] in ("a", "addr", "address"):
            return ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                    "    inet 127.0.0.1/8 scope host lo\n"
                    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                    "    inet 10.0.0.12/24 brd 10.0.0.255 scope global eth0\n")
        return 'Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n'

    def cmd_history(self, args):
        return "".join(f"  {i:>3}  {cmd}\n" for i, cmd in enumerate(self.history, 1))

    def cmd_download(self, args):
        urls = [a for a in args if URL_RE.match(a)]
        if not urls:
            hosts = [a for a in args if not a.startswith("-")]
            urls = [f"http://{h}" for h in hosts[:1]]
        for url in urls:
            self._register_download(url)
        if not urls:
            return "wget: missing URL\n"

        host = re.sub(r"^\w+://", "", urls[0]).split("/")[0]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return (f"--{now}--  {urls[0]}\n"
                f"Resolving {host}... failed: Temporary failure in name resolution.\n"
                f"wget: unable to resolve host address '{host}'\n")

    def cmd_curl(self, args):
        output = self.cmd_download(args)
        if output.startswith("wget: missing"):
            return "curl: try 'curl --help' or 'curl --manual' for more information\n"
        host = re.search(r"address '([^']*)'", output).group(1)
        return f"curl: (6) Could not resolve host: {host}\n"

    def cmd_mkdir(self, args):
        for target in (a for a in args if not a.startswith("-")):
            self.dirs.add(self._resolve(target))
        return ""

    def cmd_touch(self, args):
        for target in (a for a in args if not a.startswith("-")):
            self.files.setdefault(self._resolve(target), "")
        return ""

    def cmd_export(self, args):
        for arg in args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                self.env[key] = value
        return ""

    def cmd_env(self, args):
        return "".join(f"{k}={v}\n" for k, v in self.env.items())

    def cmd_which(self, args):
        return "".join(f"/usr/bin/{a}\n" for a in args if a in self.commands)

    def cmd_crontab(self, args):
        if "-l" in args:
            return f"no crontab for {self.username}\n"
        return ""

    def cmd_passwd(self, args):
        self.on_event("password_change", detail=" ".join(args))
        return "passwd: password updated successfully\n"

    def cmd_lscpu(self, args):
        return ("Architecture:            x86_64\n"
                "CPU(s):                  2\n"
                "Model name:              Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n")

    def cmd_netstat(self, args):
        return ("Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
                "tcp6       0      0 :::80                   :::*                    LISTEN\n")

    def cmd_date(self, args):
        return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"

    def cmd_nohup(self, args):
        return self._run_command(" ".join(shlex.quote(a) for a in args)) if args else ""
