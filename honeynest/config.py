"""Carregamento da configuração (YAML) com valores padrão."""
import copy
from pathlib import Path

import yaml

DEFAULTS = {
    "hostname": "srv-web-01",
    "database": "data/honeynest.db",
    "log_file": "logs/honeynest.jsonl",
    "idle_timeout": 300,
    "services": {
        "ssh": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 2222,
            "version": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            "host_key_dir": "data/keys",
        },
        "telnet": {"enabled": True, "host": "0.0.0.0", "port": 2323},
        "http": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 8080,
            "server_header": "Apache/2.4.52 (Ubuntu)",
        },
        "ftp": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 2121,
            "banner": "(vsFTPd 3.0.5)",
        },
    },
    "auth": {
        # Credenciais que sempre funcionam (formato usuario:senha).
        "accept_credentials": ["root:root", "root:123456", "admin:admin", "ubuntu:ubuntu", "pi:raspberry"],
        # Depois de N tentativas erradas do mesmo IP, a próxima é aceita (0 desativa).
        "accept_after_attempts": 4,
    },
    "downloads": {
        # Baixa os arquivos que os atacantes tentam obter com wget/curl (nunca são executados).
        "enabled": False,
        "dir": "data/downloads",
        "max_size_mb": 10,
    },
    "dashboard": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 5000,
        "username": "admin",
        "password": "troque-esta-senha",
    },
    "geoip": {"enabled": True},
    "telegram": {
        "enabled": False,
        "token": "",
        "chat_id": "",
        "events": ["login_success", "download", "bait_accessed"],
        "cooldown": 300,
    },
}


def deep_merge(base, override):
    """Mescla dicionários recursivamente; valores de `override` têm prioridade."""
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path=None):
    if path and Path(path).exists():
        with open(path, encoding="utf-8") as f:
            return deep_merge(DEFAULTS, yaml.safe_load(f))
    return copy.deepcopy(DEFAULTS)
