import asyncio
import httpx
import re
import base64
import json
import os
import ipaddress
import math
import time
import statistics
from collections import defaultdict
from urllib.parse import urlparse
from typing import List, Tuple, Optional
from datetime import datetime

#НАСТРОЙКИ
TIMEOUT = 0.5
CONCURRENT_LIMIT = 50
SERVERS_PER_FILE = 200
MAX_PING_MS = 800
MIN_PING_MS = 10
PING_SAMPLES = 2

ALLOWED_PROTOCOLS = ['vless', 'vmess', 'ss']

#ИСТОЧНИКИ
SOURCES = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt", 
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt", 
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt", 
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt", 
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt", 
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt", 
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt", 
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt", 
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt", #9
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless", 
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt", 
    "https://github.com/expressalaki/ExpressVPN/blob/main/configs3.txt", 
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt", 
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes", 
    "https://github.com/miladtahanian/Config-Collector/raw/refs/heads/main/vless_iran.txt", 
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub", 
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt", 
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", 
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix", 
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt", 
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt", 
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri", 
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/protocols/vless.txt", 
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE", 
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt"


]

# -------------------- ЛОГИРОВАНИЕ --------------------
thistime = datetime.now()
offset = thistime.strftime("%H:%M | %d.%m.%Y")


def log(message: str):
    """Простое логирование в консоль"""
    print(f"[{offset}] {message}")


# -------------------- HTTP КЛИЕНТ --------------------
class HTTPFetcher:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.client = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            headers=self.headers,
            timeout=30.0
        )
        return self

    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()

    async def fetch(self, url: str) -> Optional[str]:
        """Асинхронная загрузка"""
        try:
            log(f"🌐 Загрузка {url}")
            r = await self.client.get(url, timeout=20.0)
            if r.status_code == 200:
                log(f"✅ Успешно: {len(r.text)} байт")
                return r.text
            else:
                log(f"⚠️ Статус {r.status_code}")
        except Exception as e:
            log(f"❌ Ошибка: {str(e)[:100]}")
        return None


# -------------------- ПАРСЕР КОНФИГОВ --------------------
class ConfigParser:
    @staticmethod
    def decode_base64(text: str) -> str:
        try:
            text = re.sub(r'\s+', '', text)
            missing = len(text) % 4
            if missing:
                text += '=' * (4 - missing)
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except:
            return ""

    @staticmethod
    def extract_keys(text: str) -> List[str]:
        if not text:
            return []
        patterns = [
            r'(vmess://[a-zA-Z0-9+/=]+)',
            r'(vless://[a-f0-9-]+@[a-zA-Z0-9.-]+:\d+)',
            r'(ss://[a-zA-Z0-9+/=]+[@#])',
            r'(ss://[a-zA-Z0-9+/=]+)',
        ]
        found = []
        for p in patterns:
            found.extend(re.findall(p, text, re.IGNORECASE))
        return list(set(found))

    @staticmethod
    def extract_host_port(config: str) -> Tuple[Optional[str], Optional[int]]:
        try:
            if config.startswith('vmess://'):
                try:
                    data = config[8:]
                    decoded = ConfigParser.decode_base64(data)
                    if decoded and decoded.startswith('{'):
                        j = json.loads(decoded)
                        return j.get('add'), int(j.get('port', 0))
                except:
                    pass

            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port

            parts = config.split('://')[1].split('@')
            addr = parts[-1].split('/')[0].split('?')[0]
            if ':' in addr:
                h, p = addr.split(':')
                return h, int(p)
        except:
            pass
        return None, None


# -------------------- ПРОВЕРКА ПИНГА --------------------
async def check_server_ping(config: str, semaphore: asyncio.Semaphore) -> Tuple[Optional[str], Optional[float]]:
    """Проверяет сервер и возвращает пинг"""
    host, port = ConfigParser.extract_host_port(config)
    if not host or not port:
        return None, None

    async with semaphore:
        pings = []
        for sample in range(PING_SAMPLES):
            try:
                start = time.time()

                # DNS check если нужно
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    await asyncio.get_event_loop().getaddrinfo(host, port)

                # TCP connect
                conn = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)

                elapsed = (time.time() - start) * 1000
                pings.append(elapsed)

                writer.close()
                await writer.wait_closed()

                if sample < PING_SAMPLES - 1:
                    await asyncio.sleep(0.1)

            except:
                return None, None

        if not pings:
            return None, None

        final_ping = statistics.median(pings)
        if final_ping < MIN_PING_MS or final_ping > 2000:
            return None, None

        return config, final_ping


# -------------------- ФИЛЬТРАЦИЯ --------------------
def filter_by_protocol(configs: List[str]) -> List[str]:
    """Оставляет только разрешённые протоколы"""
    filtered = []
    for c in configs:
        proto = c.split('://')[0].lower()
        if proto in ALLOWED_PROTOCOLS:
            filtered.append(c)
    log(f"🔍 После фильтрации протоколов: {len(filtered)} из {len(configs)}")
    return filtered


def filter_by_ping(servers_with_ping: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
    """Умная фильтрация по пингу"""
    if not servers_with_ping:
        return []

    pings = [p for _, p in servers_with_ping]

    if len(pings) < 10:
        return servers_with_ping

    median = statistics.median(pings)
    threshold = min(median * 2, MAX_PING_MS)

    filtered = [(c, p) for c, p in servers_with_ping if p <= threshold]
    log(f"📊 Пинг: медиана={median:.1f}ms, порог={threshold:.1f}ms, осталось={len(filtered)}")

    return filtered


# -------------------- СОХРАНЕНИЕ ФАЙЛОВ --------------------
def save_results(servers_with_ping: List[Tuple[str, float]]):
    """Сохраняет результаты в файлы"""
    if not servers_with_ping:
        log("❌ Нет данных для сохранения")
        return

    # Сортируем по пингу
    sorted_servers = sorted(servers_with_ping, key=lambda x: x[1])
    sorted_configs = [c for c, _ in sorted_servers]

    # Создаём папку deploy
    os.makedirs('../deploy', exist_ok=True)

    # 1. Полный список (текст)
    with open('../deploy/sub.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_configs))
    log(f"💾 Сохранён deploy/sub.txt ({len(sorted_configs)} серверов)")

    # 2. Полный список (base64 для V2Ray)
    with open('../deploy/sub_base64.txt', 'w', encoding='utf-8') as f:
        b64 = base64.b64encode('\n'.join(sorted_configs).encode()).decode()
        f.write(b64)
    log(f"💾 Сохранён deploy/sub_base64.txt")

    # 3. Статистика по пингу
    pings = [p for _, p in sorted_servers]
    stats = {
        'total': len(sorted_servers),
        'min_ping': round(min(pings), 1),
        'max_ping': round(max(pings), 1),
        'avg_ping': round(statistics.mean(pings), 1),
        'median_ping': round(statistics.median(pings), 1),
        'fast_servers': len([p for p in pings if p < 200]),
        'slow_servers': len([p for p in pings if p >= 400]),
        'updated': offset
    }

    with open('../deploy/ping_stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    log(f"💾 Сохранён deploy/ping_stats.json")

    # 4. Разбивка на маленькие файлы
    split_into_files(sorted_configs)

    return sorted_configs


def split_into_files(configs: List[str], base_name: str = "sub", per_file: int = SERVERS_PER_FILE):
    """Разбивает на маленькие файлы по per_file штук"""
    if not configs:
        return

    subs_dir = os.path.join('../deploy', 'subscriptions')
    os.makedirs(subs_dir, exist_ok=True)

    total = len(configs)
    num_files = math.ceil(total / per_file)

    for i in range(num_files):
        start = i * per_file
        end = min((i + 1) * per_file, total)
        chunk = configs[start:end]

        # Текстовый файл
        txt_path = os.path.join(subs_dir, f"{base_name}_{i + 1:03d}.txt")
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(chunk))

        # Base64 файл для V2Ray
        b64_path = os.path.join(subs_dir, f"{base_name}_{i + 1:03d}_b64.txt")
        b64 = base64.b64encode('\n'.join(chunk).encode()).decode()
        with open(b64_path, 'w', encoding='utf-8') as f:
            f.write(b64)

    log(f"📁 Создано {num_files} маленьких файлов в {subs_dir}")


# -------------------- ОСНОВНАЯ ФУНКЦИЯ --------------------
async def main():
    """Основная функция"""
    start_time = time.time()

    try:
        async with HTTPFetcher() as fetcher:
            log("🚀 Начало работы...")

            # ШАГ 1: Скачиваем источники
            all_configs = []
            for url in SOURCES:
                data = await fetcher.fetch(url)
                if data:
                    configs = ConfigParser.extract_keys(data)
                    all_configs.extend(configs)
                    log(f"📥 Получено {len(configs)} конфигов")

            if not all_configs:
                log("❌ Нет конфигов для обработки")
                return

            log(f"📊 Всего конфигов: {len(all_configs)}")

            # ШАГ 2: Фильтруем по протоколу
            filtered = filter_by_protocol(all_configs)

            # ШАГ 3: Проверяем пинг (первые 500 для скорости)
            log("⚡ Проверка пинга...")
            sem = asyncio.Semaphore(CONCURRENT_LIMIT)

            servers_with_ping = []
            check_limit = min(len(filtered), 500)

            for i in range(0, check_limit, 50):
                chunk = filtered[i:i + 50]
                tasks = [check_server_ping(c, sem) for c in chunk]
                results = await asyncio.gather(*tasks)

                for config, ping in results:
                    if config:
                        servers_with_ping.append((config, ping))

                log(f"⏳ Прогресс: {i + len(chunk)}/{check_limit}")

            log(f"📊 Доступно с пингом: {len(servers_with_ping)}")

            # ШАГ 4: Фильтруем по пингу
            filtered_with_ping = filter_by_ping(servers_with_ping)

            # ШАГ 5: Сохраняем результаты
            if filtered_with_ping:
                save_results(filtered_with_ping)

            # Итог
            elapsed = time.time() - start_time
            log(f"✅ Готово за {elapsed:.1f}с")
            print(f"\n📁 Результаты в папке 'deploy'")

    except KeyboardInterrupt:
        log("⏸️ Прервано пользователем")
    except Exception as e:
        log(f"❌ Ошибка: {str(e)}")


# -------------------- ЗАПУСК --------------------
if __name__ == "__main__":

    asyncio.run(main())
