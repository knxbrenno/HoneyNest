"""
HoneyNest - honeypot multi-serviço (SSH, Telnet, HTTP, FTP) com painel web.

Uso:
    python3 -m honeynest                 # usa config.yaml (ou os valores padrão)
    python3 -m honeynest -c outro.yaml
"""
import argparse
import asyncio
import logging
import sys

from . import __version__
from .config import load_config
from .core import HoneyNest


async def run(config):
    honeypot = HoneyNest(config)
    await honeypot.start()
    try:
        await asyncio.Event().wait()
    finally:
        await honeypot.stop()


def main():
    parser = argparse.ArgumentParser(description="HoneyNest - honeypot multi-serviço com painel web.")
    parser.add_argument("-c", "--config", default="config.yaml", help="arquivo de configuração (padrão: config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", help="mostra mensagens de depuração")
    parser.add_argument("--version", action="version", version=f"HoneyNest {__version__}")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # As bibliotecas de rede são muito verbosas; mostramos só avisos delas.
    for noisy in ("asyncssh", "aiohttp.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    config = load_config(args.config)
    logging.getLogger("honeynest").info("HoneyNest %s iniciando (hostname falso: %s)",
                                        __version__, config["hostname"])
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        print("\nEncerrando HoneyNest.")
    except OSError as err:
        print(f"Erro ao abrir uma porta: {err}. Verifique se ela já está em uso ou se precisa de root.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
