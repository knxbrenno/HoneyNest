"""Ponto central de registro: todo evento passa por aqui (banco, arquivo JSONL, console e alertas)."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("honeynest")


class Recorder:
    def __init__(self, db, log_file=None, alerter=None):
        self.db = db
        self.alerter = alerter
        self.log_file = None
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            self.log_file = open(log_file, "a", encoding="utf-8")

    def record(self, service, event, src_ip, src_port=None, session=None,
               username=None, password=None, detail=None, **data):
        ev = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "session": session,
            "service": service,
            "event": event,
            "src_ip": src_ip,
            "src_port": src_port,
            "username": username,
            "password": password,
            "detail": detail,
            "data": data,
        }
        ev["id"] = self.db.insert_event(ev)

        if self.log_file:
            self.log_file.write(json.dumps(ev, ensure_ascii=False) + "\n")
            self.log_file.flush()

        extra = " ".join(f"{k}={v!r}" for k, v in (("user", username), ("pass", password), ("detail", detail)) if v)
        log.info("[%s] %-14s %s %s", service, event, src_ip, extra)

        if self.alerter:
            self.alerter.notify(ev)
        return ev

    def close(self):
        if self.log_file:
            self.log_file.close()
