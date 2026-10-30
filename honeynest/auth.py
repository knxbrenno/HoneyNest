"""Política de autenticação falsa, compartilhada por SSH, Telnet e FTP."""
from collections import defaultdict

MAX_TRACKED_IPS = 100_000


class AuthPolicy:
    """
    Decide se uma tentativa de login "funciona".

    Aceitar alguns logins é o que faz o atacante entrar no shell falso e revelar o que pretende fazer.
    """

    def __init__(self, accept_credentials=(), accept_after_attempts=0):
        self.accepted = set(accept_credentials)
        self.accept_after = accept_after_attempts
        self.attempts = defaultdict(int)

    def check(self, ip, username, password):
        if len(self.attempts) > MAX_TRACKED_IPS:
            self.attempts.clear()

        self.attempts[ip] += 1
        if f"{username}:{password}" in self.accepted:
            return True
        return bool(self.accept_after) and self.attempts[ip] > self.accept_after
