import asyncio
import aiohttp
import re
import base64
import json
import os
import ipaddress
import math
import time
from collections import defaultdict
from urllib.parse import urlparse
from typing import List, Tuple, Optional
from datetime import datetime

# -------------------- НАСТРОЙКИ --------------------
PING_TIMEOUT = 3.0
MAX_PING_MS = 1000  # Максимальный пинг
CONCURRENT_PINGS = 30
SERVERS_PER_SOURCE = 200  # По 200 лучших с каждого источника

ALLOWED_PROTOCOLS = ['vless', 'vmess', 'ss']

# -------------------- ИСТОЧНИКИ --------------------
URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",  # 1
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",  # 2
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",  # 3
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",  # 4
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",  # 5
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",  # 6
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",  # 7
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",  # 8
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    # 9
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",  # 10
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",  # 11
    "https://github.com/expressalaki/ExpressVPN/blob/main/configs3.txt",  # 12
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",  # 13
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",  # 14
    "https://github.com/miladtahanian/Config-Collector/raw/refs/heads/main/vless_iran.txt",  # 15
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",  # 16
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",  # 17
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",  # 18
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",  # 19
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",  # 20
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",  # 21
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",  # 22
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/protocols/vless.txt",  # 23
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE",  # 24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",  # 25
]


# -------------------- ЛОГИРОВАНИЕ --------------------
def log(message: str):
    """Добавляет сообщение в лог"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")


# -------------------- HTTP КЛИЕНТ --------------------
class HTTPFetcher:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def fetch(self, url: str) -> Optional[str]:
        """Загрузка с retry"""
        for attempt in range(1, 4):
            try:
                async with self.session.get(url, timeout=20, ssl=False) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    else:
                        if attempt < 3:
                            await asyncio.sleep(1)
            except Exception as e:
                if attempt < 3:
                    await asyncio.sleep(1)
        return None


# -------------------- ПАРСЕР КОНФИГОВ --------------------
class ConfigParser:
    INSECURE_PATTERN = re.compile(
        r'(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)(?:[&;#]|$|(?=\s|$))',
        re.IGNORECASE
    )

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
        """Извлекает все конфиги из текста"""
        if not text:
            return []
        patterns = [
            r'(vmess://[a-zA-Z0-9+/=]+)',
            r'(vless://[a-f0-9-]+@[a-zA-Z0-9.-]+:\d+)',
            r'(ss://[a-zA-Z0-9+/=]+[@#])',
            r'(trojan://[a-zA-Z0-9-]+@[a-zA-Z0-9.-]+:\d+)',
            r'(ss://[a-zA-Z0-9+/=]+)',
        ]
        found = []
        for p in patterns:
            found.extend(re.findall(p, text, re.IGNORECASE))
        return list(set(found))

    @staticmethod
    def extract_host_port(config: str) -> Tuple[Optional[str], Optional[int]]:
        """Извлекает хост и порт из конфига"""
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

    @staticmethod
    def filter_insecure(data: str) -> Tuple[str, int]:
        """Фильтрует небезопасные конфиги"""
        lines = data.splitlines()
        result = []
        filtered = 0

        for line in lines:
            if ConfigParser.INSECURE_PATTERN.search(line):
                filtered += 1
                continue
            result.append(line)

        return "\n".join(result), filtered


# -------------------- ПРОВЕРКА ПИНГА --------------------
async def check_server_ping(config: str, semaphore: asyncio.Semaphore) -> Tuple[Optional[str], Optional[float]]:
    """Проверяет пинг и возвращает (конфиг, пинг) если пинг <= MAX_PING_MS"""
    host, port = ConfigParser.extract_host_port(config)
    if not host or not port:
        return None, None

    async with semaphore:
        try:
            start = time.time()

            # DNS check
            try:
                ipaddress.ip_address(host)
            except ValueError:
                await asyncio.get_event_loop().getaddrinfo(host, port)

            # TCP connect
            conn = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(conn, timeout=PING_TIMEOUT)

            elapsed = (time.time() - start) * 1000
            writer.close()
            await writer.wait_closed()

            if elapsed <= MAX_PING_MS:
                return config, elapsed
            else:
                return None, elapsed  # Слишком медленный

        except:
            return None, None


# -------------------- ОБРАБОТКА ОДНОГО ИСТОЧНИКА --------------------
async def process_source(idx: int, url: str, fetcher: HTTPFetcher) -> Tuple[int, List[str]]:
    """
    Обрабатывает один источник:
    1. Скачивает
    2. Фильтрует небезопасные
    3. Фильтрует по протоколу
    4. Проверяет пинг
    5. Возвращает 200 лучших
    """
    log(f"\n🔍 Источник {idx + 1}: {url[:50]}...")

    # ШАГ 1: Скачиваем
    data = await fetcher.fetch(url)
    if not data:
        log(f"  ❌ Источник {idx + 1}: не удалось загрузить")
        return idx, []

    # ШАГ 2: Фильтруем небезопасные
    data, filtered_insecure = ConfigParser.filter_insecure(data)
    if filtered_insecure > 0:
        log(f"  ℹ️ Источник {idx + 1}: отфильтровано {filtered_insecure} небезопасных")

    # ШАГ 3: Извлекаем конфиги
    all_configs = ConfigParser.extract_keys(data)
    log(f"  📊 Источник {idx + 1}: всего конфигов {len(all_configs)}")

    # ШАГ 4: Фильтруем по протоколу
    valid_configs = []
    for c in all_configs:
        proto = c.split('://')[0].lower()
        if proto in ALLOWED_PROTOCOLS:
            valid_configs.append(c)

    log(f"  🔬 Источник {idx + 1}: после фильтрации протоколов {len(valid_configs)}")

    if not valid_configs:
        log(f"  ⚠️ Источник {idx + 1}: нет подходящих протоколов")
        return idx, []

    # ШАГ 5: Проверяем пинг (но не больше 500, чтобы не зависать надолго)
    log(f"  ⚡ Источник {idx + 1}: проверка пинга...")

    check_limit = min(len(valid_configs), 500)
    sem = asyncio.Semaphore(CONCURRENT_PINGS)
    ping_tasks = []

    for config in valid_configs[:check_limit]:
        ping_tasks.append(check_server_ping(config, sem))

    ping_results = await asyncio.gather(*ping_tasks)

    # Собираем хорошие с пингом
    good_servers = []
    for config, ping in ping_results:
        if config:
            good_servers.append((config, ping))

    log(f"  ✅ Источник {idx + 1}: хороший пинг у {len(good_servers)} серверов")

    if not good_servers:
        return idx, []

    # ШАГ 6: Сортируем по пингу и берём лучшие SERVERS_PER_SOURCE
    good_servers.sort(key=lambda x: x[1])  # Сортировка по пингу
    best_servers = [c for c, _ in good_servers[:SERVERS_PER_SOURCE]]

    log(f"  🏆 Источник {idx + 1}: выбрано {len(best_servers)} лучших (пинг от {good_servers[0][1]:.1f}ms)")

    return idx, best_servers


# -------------------- СОХРАНЕНИЕ РЕЗУЛЬТАТОВ --------------------
def save_results(source_results: List[Tuple[int, List[str]]]):
    """Сохраняет результаты в папку deploy"""
    os.makedirs('deploy/subscriptions', exist_ok=True)

    total_servers = 0
    sources_with_data = 0

    # Сначала удаляем старые файлы, если есть
    for idx in range(len(URLS)):
        file_path = f"deploy/subscriptions/{idx + 1}.txt"
        b64_path = f"deploy/subscriptions/{idx + 1}_b64.txt"

        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(b64_path):
            os.remove(b64_path)

    # Сохраняем новые
    for idx, servers in source_results:
        if servers:
            file_path = f"deploy/subscriptions/{idx + 1}.txt"
            b64_path = f"deploy/subscriptions/{idx + 1}_b64.txt"

            # Текстовый файл
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(servers))

            # Base64 файл
            b64 = base64.b64encode('\n'.join(servers).encode()).decode()
            with open(b64_path, 'w', encoding='utf-8') as f:
                f.write(b64)

            total_servers += len(servers)
            sources_with_data += 1
            log(f"  💾 Сохранён {idx + 1}.txt: {len(servers)} серверов")

    # Создаём общий файл со всеми серверами
    all_servers = []
    for _, servers in source_results:
        all_servers.extend(servers)

    if all_servers:
        # Текстовый
        with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_servers))

        # Base64
        with open('deploy/sub_base64.txt', 'w', encoding='utf-8') as f:
            f.write(base64.b64encode('\n'.join(all_servers).encode()).decode())

    return sources_with_data, total_servers


# -------------------- ОСНОВНАЯ ФУНКЦИЯ --------------------
async def main():
    start_time = time.time()

    log("=" * 60)
    log("🚀 ПАРСЕР VPN КОНФИГОВ")
    log("=" * 60)
    log(f"📊 Всего источников: {len(URLS)}")
    log(f"⚡ Берём по {SERVERS_PER_SOURCE} лучших с каждого")
    log(f"⏱ Макс. пинг: {MAX_PING_MS}ms")

    # ШАГ 1: Обрабатываем все источники параллельно
    log("\n📥 ЗАГРУЗКА И ОБРАБОТКА ИСТОЧНИКОВ")

    async with HTTPFetcher() as fetcher:
        tasks = []
        for i, url in enumerate(URLS):
            task = process_source(i, url, fetcher)
            tasks.append(task)

        results = await asyncio.gather(*tasks)

    # ШАГ 2: Сортируем результаты по номеру источника
    results.sort(key=lambda x: x[0])

    # ШАГ 3: Сохраняем
    log("\n💾 СОХРАНЕНИЕ РЕЗУЛЬТАТОВ")
    sources_with_data, total_servers = save_results(results)

    # ИТОГ
    elapsed = time.time() - start_time

    log("\n" + "=" * 60)
    log("✅ РАБОТА ЗАВЕРШЕНА")
    log("=" * 60)
    log(f"📊 ИТОГОВАЯ СТАТИСТИКА:")
    log(f"   • Источников с данными: {sources_with_data}/{len(URLS)}")
    log(f"   • Всего сохранено серверов: {total_servers}")
    log(f"   • В среднем на источник: {total_servers / sources_with_data:.1f} если есть данные")
    log(f"⏱ Время выполнения: {elapsed:.1f}с")
    log("=" * 60)


log("\n🔍 ПРОВЕРКА СОХРАНЁННЫХ ФАЙЛОВ:")
if os.path.exists('deploy/subscriptions'):
    files = os.listdir('deploy/subscriptions')
    log(f"   📁 Папка существует, файлов: {len(files)}")
    for f in sorted(files)[:10]:  # Первые 10 файлов
        log(f"      • {f}")
else:
    log(f"   ❌ Папка deploy/subscriptions НЕ создана!")

    # Проверим, создалась ли вообще папка deploy
    if os.path.exists('deploy'):
        log(f"   📁 Папка deploy существует, но subscriptions - нет")
    else:
        log(f"   ❌ Папка deploy тоже не создана!")

if __name__ == "__main__":
    asyncio.run(main())