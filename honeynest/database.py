"""Armazenamento dos eventos em SQLite e consultas usadas pelo painel."""
import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,      -- ISO 8601 em UTC
    session   TEXT,
    service   TEXT NOT NULL,      -- ssh, telnet, http, ftp
    event     TEXT NOT NULL,      -- connect, login_failed, login_success, command...
    src_ip    TEXT NOT NULL,
    src_port  INTEGER,
    username  TEXT,
    password  TEXT,
    detail    TEXT,               -- comando, URL ou caminho HTTP
    data      TEXT                -- campos extras em JSON
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_event ON events (event);

CREATE TABLE IF NOT EXISTS geo (
    ip            TEXT PRIMARY KEY,
    country       TEXT,
    country_code  TEXT,
    city          TEXT,
    lat           REAL,
    lon           REAL,
    isp           TEXT
);
"""

LOGIN_EVENTS = ("login_failed", "login_success")


class Database:
    def __init__(self, path):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def insert_event(self, ev):
        cur = self.conn.execute(
            "INSERT INTO events (ts, session, service, event, src_ip, src_port, username, password, detail, data)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ev["ts"], ev.get("session"), ev["service"], ev["event"], ev["src_ip"], ev.get("src_port"),
             ev.get("username"), ev.get("password"), ev.get("detail"),
             json.dumps(ev.get("data") or {}, ensure_ascii=False)),
        )
        self.conn.commit()
        return cur.lastrowid

    def _all(self, sql, params=()):
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def _scalar(self, sql, params=()):
        return self.conn.execute(sql, params).fetchone()[0]

    def recent_events(self, limit=100, service=None, event=None, ip=None):
        where, params = [], []
        for column, value in (("service", service), ("event", event), ("src_ip", ip)):
            if value:
                where.append(f"e.{column} = ?")
                params.append(value)
        sql = ("SELECT e.*, g.country, g.country_code FROM events e LEFT JOIN geo g ON g.ip = e.src_ip"
               + (" WHERE " + " AND ".join(where) if where else "")
               + " ORDER BY e.id DESC LIMIT ?")
        rows = self._all(sql, (*params, limit))
        for row in rows:
            row["data"] = json.loads(row["data"] or "{}")
        return rows

    def stats(self, top=10):
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
        login = f"event IN {LOGIN_EVENTS}"

        # Ataques HTTP: as categorias ficam numa lista dentro do JSON.
        http_tags = Counter()
        for (raw,) in self.conn.execute("SELECT data FROM events WHERE event = 'http_request'"):
            http_tags.update(json.loads(raw or "{}").get("tags", []))

        return {
            "totals": {
                "events": self._scalar("SELECT COUNT(*) FROM events"),
                "unique_ips": self._scalar("SELECT COUNT(DISTINCT src_ip) FROM events"),
                "login_attempts": self._scalar(f"SELECT COUNT(*) FROM events WHERE {login}"),
                "login_success": self._scalar("SELECT COUNT(*) FROM events WHERE event = 'login_success'"),
                "commands": self._scalar("SELECT COUNT(*) FROM events WHERE event = 'command'"),
                "downloads": self._scalar("SELECT COUNT(*) FROM events WHERE event = 'download'"),
                "http_requests": self._scalar("SELECT COUNT(*) FROM events WHERE event = 'http_request'"),
                "last_24h": self._scalar("SELECT COUNT(*) FROM events WHERE ts >= ?", (since,)),
            },
            "by_service": self._all("SELECT service AS label, COUNT(DISTINCT src_ip) AS count FROM events"
                                    " GROUP BY service ORDER BY count DESC"),
            "timeline": self._all("SELECT substr(ts, 1, 13) AS label, COUNT(*) AS count FROM events"
                                  " WHERE ts >= ? GROUP BY label ORDER BY label", (since,)),
            "top_usernames": self._all(f"SELECT username AS label, COUNT(*) AS count FROM events WHERE {login}"
                                       " GROUP BY username ORDER BY count DESC LIMIT ?", (top,)),
            "top_passwords": self._all(f"SELECT password AS label, COUNT(*) AS count FROM events WHERE {login}"
                                       " GROUP BY password ORDER BY count DESC LIMIT ?", (top,)),
            "top_credentials": self._all(f"SELECT username || ':' || password AS label, COUNT(*) AS count"
                                         f" FROM events WHERE {login} GROUP BY label ORDER BY count DESC LIMIT ?",
                                         (top,)),
            "top_commands": self._all("SELECT detail AS label, COUNT(*) AS count FROM events WHERE event = 'command'"
                                      " GROUP BY detail ORDER BY count DESC LIMIT ?", (top,)),
            "top_downloads": self._all("SELECT detail AS label, COUNT(*) AS count FROM events WHERE event = 'download'"
                                       " GROUP BY detail ORDER BY count DESC LIMIT ?", (top,)),
            "top_ips": self._all("SELECT e.src_ip AS label, COUNT(*) AS count, g.country, g.country_code"
                                 " FROM events e LEFT JOIN geo g ON g.ip = e.src_ip"
                                 " GROUP BY e.src_ip ORDER BY count DESC LIMIT ?", (top,)),
            "top_countries": self._all("SELECT COALESCE(g.country, 'Desconhecido') AS label,"
                                       " COUNT(DISTINCT e.src_ip) AS count FROM events e"
                                       " LEFT JOIN geo g ON g.ip = e.src_ip"
                                       " GROUP BY label ORDER BY count DESC LIMIT ?", (top,)),
            "http_attacks": [{"label": k, "count": v} for k, v in http_tags.most_common(top)],
        }

    def ips_without_geo(self, limit=100):
        rows = self.conn.execute(
            "SELECT DISTINCT src_ip FROM events WHERE src_ip NOT IN (SELECT ip FROM geo) LIMIT ?", (limit,))
        return [r[0] for r in rows]

    def save_geo(self, rows):
        self.conn.executemany(
            "INSERT OR REPLACE INTO geo (ip, country, country_code, city, lat, lon, isp)"
            " VALUES (:ip, :country, :country_code, :city, :lat, :lon, :isp)", rows)
        self.conn.commit()

    def map_points(self):
        return self._all("SELECT e.src_ip AS ip, g.country, g.city, g.lat, g.lon, COUNT(*) AS count"
                         " FROM events e JOIN geo g ON g.ip = e.src_ip"
                         " WHERE g.lat IS NOT NULL GROUP BY e.src_ip")
