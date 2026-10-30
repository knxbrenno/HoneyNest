# 🍯 HoneyNest

[![Testes](https://github.com/knxbrenno/HoneyNest/actions/workflows/tests.yml/badge.svg)](https://github.com/knxbrenno/HoneyNest/actions/workflows/tests.yml)

Honeypot multi-serviço escrito em Python (asyncio) que simula um servidor Ubuntu vulnerável para **atrair, registrar e analisar ataques reais** vindos da internet. Todas as interações (tentativas de login, comandos digitados, malwares baixados, varreduras web) são gravadas e exibidas em um **painel web em tempo real**, com mapa de origem dos ataques e alertas no Telegram.

## Funcionalidades

### Serviços falsos
| Serviço | Porta padrão | O que registra |
|---|---|---|
| **SSH** | 2222 | Protocolo SSH real (asyncssh), versão do cliente, usuário/senha, comandos, shell interativo |
| **Telnet** | 2323 | Logins e comandos, muito usado por botnets de IoT (Mirai e variantes) |
| **HTTP** | 8080 | Requisições, User-Agent, logins no painel falso e acesso a arquivos isca |
| **FTP** | 2121 | Credenciais e comandos |

### Shell falso
- Imita um Ubuntu 22.04: `ls`, `cd`, `cat`, `uname`, `id`, `ps`, `free`, `df`, `ifconfig`, `netstat`, `history` e mais 30 comandos
- Sistema de arquivos fictício, com suporte a redirecionamento (`echo x > arquivo`), encadeamento (`;`, `&&`, `||`), `sudo` e `bash -c`
- **Arquivos isca** (`.env`, `.aws/credentials`, `id_rsa`, dump SQL): qualquer leitura gera o evento `bait_accessed`
- Detecta URLs em `wget`, `curl`, `tftp` e em qualquer parte do comando

### Análise
- **Classificação de ataques HTTP**: SQL Injection, XSS, LFI/Path Traversal, RCE (incluindo Log4Shell) e varreduras automáticas
- **Identificação de ferramentas** pelo User-Agent: sqlmap, nmap, nikto, nuclei, gobuster, masscan...
- **Geolocalização** dos IPs (ip-api.com, sem chave de API)
- **Coleta de amostras** (opcional): baixa os malwares que os atacantes tentam obter, salvos pelo SHA-256 e **nunca executados**, com proteção contra SSRF (só endereços públicos)

### Painel e alertas
- Painel web com indicadores, gráfico das últimas 24h, mapa mundial, rankings (credenciais, senhas, comandos, IPs, países, ataques HTTP) e tabela de eventos com filtros
- Protegido por senha, com Content-Security-Policy (os dados exibidos vêm de atacantes)
- **Alertas no Telegram** para logins aceitos, downloads e arquivos isca, com limite anti-spam
- Eventos salvos em **SQLite** e em **JSONL** (fácil de enviar para ELK, Splunk, Wazuh...)

## Arquitetura

```
                         Atacantes
                             │
      ┌──────────┬───────────┼───────────┬──────────┐
      ▼          ▼           ▼           ▼          │
    SSH       Telnet        FTP        HTTP         │
      └────┬─────┘           │      (classificador  │
           ▼                 │       de ataques)    │
      Shell falso ──► Downloader (opcional)         │
           │                 │           │          │
           └─────────────────┴─────┬─────┘          │
                                   ▼
                               Recorder
                   ┌───────────────┼───────────────┐
                   ▼               ▼               ▼
                 SQLite          JSONL         Telegram
                   │
                   ▼
           Painel web (:5000)
```

```
honeynest/
├── __main__.py      # Ponto de entrada (python -m honeynest)
├── core.py          # Inicializa e conecta todos os componentes
├── config.py        # Configuração YAML com valores padrão
├── shell.py         # Shell e sistema de arquivos falsos
├── auth.py          # Política de logins aceitos
├── recorder.py      # Registro central de eventos
├── database.py      # SQLite e consultas do painel
├── alerts.py        # Alertas no Telegram
├── downloader.py    # Coleta de amostras com proteção contra SSRF
├── geoip.py         # Geolocalização dos IPs
├── services/        # ssh.py, telnet.py, http.py, ftp.py
└── dashboard/       # API + página web (HTML/CSS/JS)
```

## Instalação

```bash
git clone https://github.com/knxbrenno/HoneyNest.git
cd HoneyNest
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml   # edite a senha do painel!
python3 -m honeynest
```

Para acessar o painel, abra `http://127.0.0.1:5000` (usuário e senha definidos no `config.yaml`).

### Com Docker

```bash
cp config.example.yaml config.yaml
docker compose up -d --build
docker compose logs -f
```

## Colocando na internet

Para receber ataques reais, rode em uma VPS e exponha as portas padrão (22, 23, 80, 21).

1. **Mova o seu SSH real** para outra porta (ex.: 22222) em `/etc/ssh/sshd_config` e reinicie o `sshd`. Teste a nova porta antes de fechar a sessão atual!
2. **Redirecione as portas** padrão para o honeypot, sem precisar rodá-lo como root:
   ```bash
   sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
   sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
   sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
   sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
   ```
   (com o `docker-compose.yml` o mapeamento já é feito.)
3. **Acesse o painel por túnel SSH**, sem expô-lo na internet:
   ```bash
   ssh -p 22222 -L 5000:127.0.0.1:5000 usuario@sua-vps
   ```

Em poucos minutos os primeiros bots começam a aparecer no painel.

## Alertas no Telegram

1. Crie um bot com o [@BotFather](https://t.me/BotFather) e copie o token.
2. Descubra seu chat ID com o [@userinfobot](https://t.me/userinfobot).
3. No `config.yaml`:
   ```yaml
   telegram:
     enabled: true
     token: "123456:ABC..."
     chat_id: "987654321"
   ```

## Testes

```bash
pip install pytest
python3 -m pytest
```

## Consultas úteis

Os eventos ficam em `data/honeynest.db` (SQLite) e em `logs/honeynest.jsonl`. Com Docker, eles ficam nos volumes `honeynest-data` e `honeynest-logs`; para copiar o banco: `docker cp honeynest:/app/data/honeynest.db .`

```bash
# Senhas mais testadas
sqlite3 data/honeynest.db "SELECT password, COUNT(*) c FROM events WHERE event='login_failed' GROUP BY 1 ORDER BY c DESC LIMIT 20"

# Todos os comandos de uma sessão
sqlite3 data/honeynest.db "SELECT ts, detail FROM events WHERE session='<id>' AND event='command'"

# URLs de malware com jq
jq -r 'select(.event=="download") | .detail' logs/honeynest.jsonl | sort -u
```

## Segurança

- Nenhum comando do atacante é executado de verdade: tudo é simulado.
- Rode o honeypot em uma máquina **dedicada e isolada** (VPS ou VM), nunca na sua rede pessoal ou em um servidor de produção.
- As amostras baixadas são malwares reais. Não as execute e trate a pasta `data/downloads` com cuidado.
- As credenciais dos arquivos isca são falsas.

## Aviso

Projeto para fins educacionais e de pesquisa em segurança. Verifique se hospedar um honeypot é permitido pelo seu provedor de hospedagem.
