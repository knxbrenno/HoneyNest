"""Geolocalização dos IPs atacantes usando a API gratuita do ip-api.com (sem chave)."""
import asyncio
import ipaddress
import logging

import aiohttp

log = logging.getLogger("honeynest.geoip")

API_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,isp"
BATCH_SIZE = 100       # Limite da API por requisição
INTERVAL = 60          # Segundos entre atualizações (a API permite 15 lotes por minuto)


async def update_once(db, http):
    ips = db.ips_without_geo(BATCH_SIZE)
    if not ips:
        return 0

    rows = []
    public = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_global:
                public.append(ip)
                continue
        except ValueError:
            pass
        rows.append({"ip": ip, "country": "Rede local", "country_code": None, "city": None,
                     "lat": None, "lon": None, "isp": None})

    if public:
        async with http.post(API_URL, json=public) as resp:
            if resp.status != 200:  # Ex.: 429 quando o limite de requisições é atingido
                log.warning("ip-api.com respondeu HTTP %s; nova tentativa no próximo ciclo.", resp.status)
                public = []
            for item in (await resp.json() if public else []):
                ok = item.get("status") == "success"
                rows.append({"ip": item["query"], "country": item.get("country") if ok else "Desconhecido",
                             "country_code": item.get("countryCode"), "city": item.get("city"),
                             "lat": item.get("lat"), "lon": item.get("lon"), "isp": item.get("isp")})

    db.save_geo(rows)
    return len(rows)


async def run_forever(db):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as http:
        while True:
            try:
                count = await update_once(db, http)
                if count:
                    log.info("Geolocalização atualizada para %d IP(s)", count)
            except Exception as err:
                log.warning("Falha ao consultar a geolocalização: %s", err)
            await asyncio.sleep(INTERVAL)
