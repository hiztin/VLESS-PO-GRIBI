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
MAX_PING_MS = 1000
CONCURRENT_PINGS = 30
SERVERS_PER_SOURCE = 200

ALLOWED_PROTOCOLS = ['vless', 'vmess', 'ss']

# -------------------- ПУТИ (ОТНОСИТЕЛЬНО КОРНЯ РЕПО) --------------------
DEPLOY_PATH = "deploy"
SUBSCRIPTIONS_PATH = f"{DEPLOY_PATH}/subscriptions"

# -------------------- ИСТОЧНИКИ --------------------
URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
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
    host, port = ConfigParser.extract_host_port(config)
    if not host or not port:
        return None, None

    async with semaphore:
        try:
            start = time.time()

            try:
                ipaddress.ip_address(host)
            except ValueError:
                await asyncio.get_event_loop().getaddrinfo(host, port)

            conn = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(conn, timeout=PING_TIMEOUT)

            elapsed = (time.time() - start) * 1000
            writer.close()
            await writer.wait_closed()

            if elapsed <= MAX_PING_MS:
                return config, elapsed
            else:
                return None, elapsed

        except:
            return None, None


# -------------------- ОБРАБОТКА ИСТОЧНИКА --------------------
async def process_source(idx: int, url: str, fetcher: HTTPFetcher) -> Tuple[int, List[str]]:
    log(f"\n🔍 Источник {idx + 1}")

    data = await fetcher.fetch(url)
    if not data:
        log(f"  ❌ Не удалось загрузить")
        return idx, []

    data, filtered_insecure = ConfigParser.filter_insecure(data)
    if filtered_insecure > 0:
        log(f"  ℹ️ Отфильтровано небезопасных: {filtered_insecure}")

    all_configs = ConfigParser.extract_keys(data)
    log(f"  📊 Всего конфигов: {len(all_configs)}")

    valid_configs = []
    for c in all_configs:
        proto = c.split('://')[0].lower()
        if proto in ALLOWED_PROTOCOLS:
            valid_configs.append(c)

    log(f"  🔬 После фильтрации протоколов: {len(valid_configs)}")

    if not valid_configs:
        return idx, []

    log(f"  ⚡ Проверка пинга...")

    check_limit = min(len(valid_configs), 500)
    sem = asyncio.Semaphore(CONCURRENT_PINGS)
    ping_tasks = []

    for config in valid_configs[:check_limit]:
        ping_tasks.append(check_server_ping(config, sem))

    ping_results = await asyncio.gather(*ping_tasks)

    good_servers = []
    for config, ping in ping_results:
        if config:
            good_servers.append((config, ping))

    log(f"  ✅ Хороший пинг у {len(good_servers)}")

    if not good_servers:
        return idx, []

    good_servers.sort(key=lambda x: x[1])
    best_servers = [c for c, _ in good_servers[:SERVERS_PER_SOURCE]]

    if best_servers:
        log(f"  🏆 Отобрано {len(best_servers)} лучших")

    return idx, best_servers


# -------------------- СОХРАНЕНИЕ НА ГИТХАБ --------------------
def save_results(source_results: List[Tuple[int, List[str]]]):
    """Сохраняет файлы прямо в папку репозитория"""

    # СОЗДАЁМ ПАПКИ ПРЯМО ЗДЕСЬ
    os.makedirs(SUBSCRIPTIONS_PATH, exist_ok=True)

    log(f"\n💾 СОХРАНЕНИЕ В {DEPLOY_PATH}")
    log(f"   Папка создана: {os.path.exists(DEPLOY_PATH)}")
    log(f"   Подпапка создана: {os.path.exists(SUBSCRIPTIONS_PATH)}")

    total_servers = 0
    sources_with_data = 0

    # Сохраняем по одному файлу на источник
    for idx, servers in source_results:
        if servers:
            # Текстовый файл
            txt_path = os.path.join(SUBSCRIPTIONS_PATH, f"{idx + 1}.txt")
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(servers))

            # Base64 файл
            b64_path = os.path.join(SUBSCRIPTIONS_PATH, f"{idx + 1}_b64.txt")
            b64 = base64.b64encode('\n'.join(servers).encode()).decode()
            with open(b64_path, 'w', encoding='utf-8') as f:
                f.write(b64)

            log(f"  ✅ {idx + 1}.txt: {len(servers)} серверов")
            total_servers += len(servers)
            sources_with_data += 1

    # Общий файл
    all_servers = []
    for _, servers in source_results:
        all_servers.extend(servers)

    if all_servers:
        txt_path = os.path.join(DEPLOY_PATH, "sub.txt")
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_servers))

        b64_path = os.path.join(DEPLOY_PATH, "sub_base64.txt")
        b64 = base64.b64encode('\n'.join(all_servers).encode()).decode()
        with open(b64_path, 'w', encoding='utf-8') as f:
            f.write(b64)

        log(f"  ✅ sub.txt: {len(all_servers)} всего серверов")

    # ПРОВЕРЯЕМ, ЧТО ФАЙЛЫ РЕАЛЬНО СОЗДАЛИСЬ
    log("\n🔍 ПРОВЕРКА:")
    if os.path.exists(DEPLOY_PATH):
        files = os.listdir(DEPLOY_PATH)
        log(f"   В {DEPLOY_PATH} найдено: {files}")
    else:
        log(f"   ❌ {DEPLOY_PATH} НЕ СУЩЕСТВУЕТ!")

    if os.path.exists(SUBSCRIPTIONS_PATH):
        files = os.listdir(SUBSCRIPTIONS_PATH)
        log(f"   В {SUBSCRIPTIONS_PATH} найдено: {sorted(files)[:5]}")
    else:
        log(f"   ❌ {SUBSCRIPTIONS_PATH} НЕ СУЩЕСТВУЕТ!")

    return sources_with_data, total_servers


# -------------------- ОСНОВНАЯ ФУНКЦИЯ --------------------
async def main():
    start_time = time.time()

    print("\n" + "=" * 60)
    print("🚀 ПАРСЕР ДЛЯ ГИТХАБА")
    print("=" * 60)
    print(f"📁 Будет сохранено в: {DEPLOY_PATH}")

    # Принудительно создаём папки ещё раз
    os.makedirs(DEPLOY_PATH, exist_ok=True)
    os.makedirs(SUBSCRIPTIONS_PATH, exist_ok=True)

    async with HTTPFetcher() as fetcher:
        tasks = [process_source(i, url, fetcher) for i, url in enumerate(URLS)]
        results = await asyncio.gather(*tasks)

    results.sort(key=lambda x: x[0])
    sources_with_data, total_servers = save_results(results)

    elapsed = time.time() - start_time
    print("\n" + "=" * 60)
    print("✅ РАБОТА ЗАВЕРШЕНА")
    print("=" * 60)
    print(f"📊 Источников с данными: {sources_with_data}/{len(URLS)}")
    print(f"📊 Всего серверов: {total_servers}")
    print(f"⏱ Время: {elapsed:.1f}с")
    print("=" * 60)


def generate_readme():
    """Автоматически генерирует README.md с таблицей статусов и рабочими ссылками"""
    
    from datetime import datetime
    import zoneinfo
    
    # Текущее время по Москве
    zone = zoneinfo.ZoneInfo("Europe/Moscow")
    current_time = datetime.now(zone)
    time_str = current_time.strftime("%H:%M")
    date_str = current_time.strftime("%d.%m.%Y")
    
    # Получаем список источников
    sources = [
        "sakha1370/OpenRay",
        "sevcator/5ubscrpt10n",
        "yitong2333/proxy-minging",
        "acymz/AutoVPN",
        "miladtahanian/V2RayCFGDumper",
        "roosterkid/openproxylist",
        "Epodonios/v2ray-configs",
        "CidVpn/cid-vpn-config",
        "mohamadfg-dev/telegram-v2ray-configs-collector",
        "mheidari98/.proxy",
        "youfoundamin/V2rayCollector",
        "expressalaki/ExpressVPN",
        "MahsaNetConfigTopic/config",
        "LalatinaHub/Mineral",
        "miladtahanian/Config-Collector",
        "Pawdroid/Free-servers",
        "MhdiTaheri/V2rayCollector_Py",
        "free18/v2ray",
        "MhdiTaheri/V2rayCollector",
        "Argh94/Proxy-List",
        "shabane/kamaji",
        "wuqb2i4f/xray-config-toolkit",
        "Delta-Kronecker/V2ray-Config",
        "STR97/STRUGOV",
        "V2RayRoot/V2RayConfig",
    ]
    
    # Проверяем, какие файлы реально существуют
    subs_dir = "deploy/subscriptions"
    existing_files = set()
    if os.path.exists(subs_dir):
        for f in os.listdir(subs_dir):
            match = re.match(r'(\d+)\.txt', f)
            if match:
                existing_files.add(int(match.group(1)))
    
    # Генерируем таблицу статусов
    status_table = ""
    for i, source in enumerate(sources, 1):
        filename = f"{i}.txt"
        if i in existing_files:
            status_table += f"| {i} | `{filename}` | {source} | {time_str} | {date_str} |\n"
        else:
            status_table += f"| {i} | `{filename}` | {source} | ⏳ Нет данных | ⏳ Нет данных |\n"
    
    # Добавляем 26-й файл если есть
    if os.path.exists("deploy/subscriptions/26.txt"):
        status_table += f"| 26 | `26.txt` | Обход SNI/CIDR белых списков | {time_str} | {date_str} |\n"
    
    # Генерируем рабочие ссылки (как в предыдущей версии)
    android_table = ""
    ios_table = ""
    windows_table = ""
    linux_table = ""
    
    BASE_RAW_URL = "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions"
    
    for i in range(1, 27):
        if os.path.exists(f"deploy/subscriptions/{i}_b64.txt"):
            android_table += f"| {i} | [`{i}_b64.txt`]({BASE_RAW_URL}/{i}_b64.txt) |\n"
            ios_table += f"| {i} | [`{i}_b64.txt`]({BASE_RAW_URL}/{i}_b64.txt) |\n"
        
        if os.path.exists(f"deploy/subscriptions/{i}.txt"):
            windows_table += f"| {i} | [`{i}.txt`]({BASE_RAW_URL}/{i}.txt) |\n"
            linux_table += f"| {i} | [`{i}.txt`]({BASE_RAW_URL}/{i}.txt) |\n"
    
    # Подсчёт серверов
    total_servers = 0
    if os.path.exists("deploy/sub.txt"):
        with open("deploy/sub.txt", "r", encoding="utf-8") as f:
            total_servers = len(f.readlines())
    
    # Полный README
    readme_content = f"""# 🍄 VLESS ПО ГРИБЫ - Бесплатные VPN подписки 

<div align="center">
  
### 🍄‍🟫 Ежедневно обновляемая коллекция рабочих VPN-серверов

[![GitHub last commit](https://img.shields.io/github/last-commit/hiztin/VLESS-PO-GRIBI)](https://github.com/hiztin/VLESS-PO-GRIBI/commits/main)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/hiztin/VLESS-PO-GRIBI/update-subscriptions.yml)](https://github.com/hiztin/VLESS-PO-GRIBI/actions)
[![License](https://img.shields.io/github/license/hiztin/VLESS-PO-GRIBI)](LICENSE)
![Серверов](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/debug.json&query=alive&label=рабочих&color=green)

</div>

## 🍄‍🟫 О проекте

Этот проект автоматически собирает и проверяет **бесплатные VPN-серверы** из открытых источников. Обновление происходит **каждый день** через GitHub Actions, поэтому подписки всегда актуальны. Проект ещё в разработке,
поэтому подписки не подписаны и\или что-то может не работать

---

## 📊 Статус конфигов

> ⚠️ **Внимание!** Эта таблица показывает только источники и статус обновления конфигов. **Не копируйте ссылки отсюда!**  
> Для использования копируйте ссылки из раздела **«🍄 Общий список всех вечно актуальных конфигов»** ниже.

| № | Файл | Источник | Время | Дата |
|---|------|----------|-------|------|
{status_table}

**[🍄 Открыть папку со всеми файлами](https://github.com/hiztin/VLESS-PO-GRIBI/tree/main/deploy/subscriptions)**

---

## 🍄 Общий список всех вечно актуальных конфигов

### 📦 Основные подписки (все серверы сразу)

| Формат | Описание | Прямая ссылка для копирования |
|--------|----------|-------------------------------|
| **Base64** | Для V2Ray/V2Box (Android/iOS) | `https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/sub_base64.txt` |
| **Текст** | Для Throne/NekoRay (Windows/Linux) | `https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/sub.txt` |
| **Статистика** | Данные о количестве серверов | `https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/debug.json` |

---

## 📁 Конфиги по источникам (по 200 лучших с каждого)

<details>
<summary><b>📱 Android — v2rayNG</b></summary>

**Как добавить подписку:**
1. Открой v2rayNG
2. Нажми `+` → **"Импорт подписки из буфера"**
3. Вставь ссылку из таблицы ниже:

| № | Base64 ссылка (копировать) |
|---|---------------------------|
{android_table}

**[📂 Все файлы](https://github.com/hiztin/VLESS-PO-GRIBI/tree/main/deploy/subscriptions)**

</details>

<details>
<summary><b>📱 iOS — V2Box</b></summary>

**Как добавить подписку:**
1. Открой V2Box
2. Перейди в **"Конфигурации"** → `+` → **"Импортировать V2Ray URL из буфера"**
3. Вставь ссылку из таблицы ниже:

| № | Base64 ссылка |
|---|--------------|
{ios_table}

**[📂 Все файлы](https://github.com/hiztin/VLESS-PO-GRIBI/tree/main/deploy/subscriptions)**

</details>

<details>
<summary><b>💻 Windows — Throne</b></summary>

**Как добавить подписку:**
1. Открой Throne
2. Нажми **"Профили"** → **"Добавить профиль из буфера"**
3. Вставь ссылку из таблицы ниже:

| № | Текстовая ссылка |
|---|-----------------|
{windows_table}

**[📂 Все файлы](https://github.com/hiztin/VLESS-PO-GRIBI/tree/main/deploy/subscriptions)**

</details>

<details>
<summary><b>🐧 Linux — NekoRay</b></summary>

**Как добавить подписку:**
1. Открой NekoRay
2. Нажми **"Программа"** → **"Добавить подписку"**
3. Вставь ссылку из таблицы ниже:

| № | Текстовая ссылка |
|---|-----------------|
{linux_table}

**[📂 Все файлы](https://github.com/hiztin/VLESS-PO-GRIBI/tree/main/deploy/subscriptions)**

</details>

---

## 📊 Статистика

- **Всего серверов**: ~{total_servers}+
- **Активных источников**: {len([i for i in range(1,27) if os.path.exists(f'deploy/subscriptions/{i}.txt')])}
- **Протоколы**: VMess, VLESS, Shadowsocks
- **Обновление**: каждые 3 часа UTC
- **Последнее обновление**: {time_str} {date_str}

---

## 🍄 Контакты и поддержка

- **Discord**: `h1zz`
- **GitHub Issues**: [Создать issue](https://github.com/hiztin/VLESS-PO-GRIBI/issues)

---

<div align="center">

### ⭐ Если проект полезен, поставь звезду! ⭐

[![GitHub stars](https://img.shields.io/github/stars/hiztin/VLESS-PO-GRIBI?style=social)](https://github.com/hiztin/VLESS-PO-GRIBI/stargazers)

</div>
"""
    
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    
    print(f"✅ README.md обновлён!")
    print(f"📊 Таблица статусов: {len([i for i in range(1,27) if os.path.exists(f'deploy/subscriptions/{i}.txt')])} активных источников")
# В конце main(), после save_results():
if __name__ == "__main__":
    asyncio.run(main())

