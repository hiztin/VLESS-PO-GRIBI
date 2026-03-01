import asyncio
import aiohttp
import re
import base64
import json
import os
import math
from collections import defaultdict
from urllib.parse import urlparse
from typing import List, Tuple, Optional
from datetime import datetime
import time
from typing import List, Tuple, Optional, Dict, Any
# НАСТРОЙКИ 
SERVERS_PER_FILE = 200  # Количество серверов в одном файле

ALLOWED_PROTOCOLS = ['vless', 'vmess', 'ss']

# ИСТОЧНИКИ 
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
]


LOGS: Dict[int, List[str]] = defaultdict(list)


def log(message: str, file_idx: int = 0):
    """Добавляет сообщение в лог"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    LOGS[file_idx].append(f"[{timestamp}] {message}")
    print(f"[{file_idx}] {message}")



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

    async def fetch(self, url: str, attempt: int = 1) -> Optional[str]:
        """Загрузка с retry"""
        try:
            log(f"🌐 Загрузка {url}", 0)
            async with self.session.get(url, timeout=20, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    log(f"✅ Успешно: {len(text)} байт", 0)
                    return text
                else:
                    log(f"⚠️ Статус {resp.status}", 0)
                    if attempt < 3:
                        await asyncio.sleep(1)
                        return await self.fetch(url, attempt + 1)
        except Exception as e:
            log(f"❌ Ошибка: {str(e)[:100]}", 0)
            if attempt < 3:
                await asyncio.sleep(1)
                return await self.fetch(url, attempt + 1)
        return None



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
    def filter_insecure(data: str) -> Tuple[str, int]:
        """Фильтрует небезопасные конфиги"""
        lines = data.splitlines()
        result = []
        filtered = 0

        for line in lines:
            original = line
            processed = line.strip()

            if ConfigParser.INSECURE_PATTERN.search(processed):
                filtered += 1
                continue

            result.append(original)

        return "\n".join(result), filtered



async def download_source(idx: int, url: str, fetcher: HTTPFetcher) -> Optional[str]:
    """Скачивает один источник и сохраняет в githubmirror/"""
    try:
        data = await fetcher.fetch(url)
        if not data:
            return None

        # Фильтруем небезопасные
        data, filtered = ConfigParser.filter_insecure(data)
        if filtered > 0:
            log(f"ℹ️ Отфильтровано {filtered} небезопасных", idx + 1)

        # Сохраняем
        os.makedirs("githubmirror", exist_ok=True)
        local_path = f"githubmirror/{idx + 1}.txt"

        with open(local_path, 'w', encoding='utf-8') as f:
            f.write(data)

        log(f"💾 Сохранено в {local_path}", idx + 1)
        return local_path

    except Exception as e:
        log(f"❌ Ошибка: {str(e)[:100]}", idx + 1)
        return None



def filter_by_protocol(configs: List[str]) -> List[str]:
    """Оставляет только VLESS, VMess, SS"""
    filtered = []
    for c in configs:
        proto = c.split('://')[0].lower()
        if proto in ALLOWED_PROTOCOLS:
            filtered.append(c)
    log(f"🔍 После фильтрации протоколов: {len(filtered)} из {len(configs)}", 0)
    return filtered



def save_results(configs: List[str]):
    """Сохраняет все конфиги в папку deploy"""
    if not configs:
        log("❌ Нет данных для сохранения", 0)
        return

    # Дедупликация
    unique_configs = list(set(configs))
    log(f"📊 После дедупликации: {len(unique_configs)} уникальных", 0)

    # Создаём папку deploy
    os.makedirs('deploy', exist_ok=True)

    # 1. Полный список (текст)
    with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique_configs))
    log(f"💾 Сохранён deploy/sub.txt ({len(unique_configs)} серверов)", 0)

    # 2. Полный список (base64 для V2Ray)
    with open('deploy/sub_base64.txt', 'w', encoding='utf-8') as f:
        b64 = base64.b64encode('\n'.join(unique_configs).encode()).decode()
        f.write(b64)
    log(f"💾 Сохранён deploy/sub_base64.txt", 0)

    # 3. Статистика
    protocols = {}
    for c in unique_configs[:100]:
        proto = c.split('://')[0]
        protocols[proto] = protocols.get(proto, 0) + 1

    stats = {
        'total': len(unique_configs),
        'protocols': protocols,
        'updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    with open('deploy/debug.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    log(f"💾 Сохранён deploy/debug.json", 0)


    split_into_files(unique_configs)


def split_into_files(configs: List[str], base_name: str = "sub", per_file: int = SERVERS_PER_FILE):
    """Разбивает на маленькие файлы по per_file штук"""
    if not configs:
        return

    subs_dir = os.path.join('deploy', 'subscriptions')
    os.makedirs(subs_dir, exist_ok=True)

    total = len(configs)
    num_files = math.ceil(total / per_file)

    log(f"📁 Разбивка на {num_files} файлов по {per_file} серверов", 0)

    for i in range(num_files):
        start = i * per_file
        end = min((i + 1) * per_file, total)
        chunk = configs[start:end]


        txt_path = os.path.join(subs_dir, f"{base_name}_{i + 1:03d}.txt")
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(chunk))


        b64_path = os.path.join(subs_dir, f"{base_name}_{i + 1:03d}_b64.txt")
        b64 = base64.b64encode('\n'.join(chunk).encode()).decode()
        with open(b64_path, 'w', encoding='utf-8') as f:
            f.write(b64)

        log(f"  [{i + 1:03d}] {txt_path}: {len(chunk)} серверов", 0)


async def main():
    """Основная функция"""
    start_time = time.time()

    try:
        async with HTTPFetcher() as fetcher:
            log("🚀 Начало работы...", 0)


            download_tasks = []
            for i, url in enumerate(URLS):
                task = download_source(i, url, fetcher)
                download_tasks.append(task)

            downloaded = await asyncio.gather(*download_tasks)

            all_configs = []
            for i, path in enumerate(downloaded):
                if path and os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        configs = ConfigParser.extract_keys(content)
                        all_configs.extend(configs)
                        log(f"📥 Загружено {len(configs)} конфигов из {i + 1}.txt", i + 1)

            log(f"📊 Всего конфигов: {len(all_configs)}", 0)

            if not all_configs:
                log("❌ Нет конфигов для обработки", 0)
                return


            filtered = filter_by_protocol(all_configs)


            if filtered:
                save_results(filtered)
                log(f"✅ Сохранено {len(filtered)} серверов", 0)
            else:
                log("❌ Нет серверов после фильтрации", 0)

            elapsed = time.time() - start_time
            log(f"✅ Готово за {elapsed:.1f}с", 0)

    except KeyboardInterrupt:
        log("⏸️ Прервано пользователем", 0)
    except Exception as e:
        log(f"❌ Критическая ошибка: {str(e)}", 0)


if __name__ == "__main__":
    asyncio.run(main())
