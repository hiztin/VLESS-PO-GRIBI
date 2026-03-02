#!/usr/bin/env python3
"""
Упрощенный парсер для GitHub Actions
"""

import asyncio
import aiohttp
import re
import os
import time
import socket
from datetime import datetime
from typing import List, Tuple, Set, Optional
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('parser')

# Твои 25 источников
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

# Конфигурация
CONFIG = {
    'MAX_PER_SOURCE': 500,      # Максимум конфигов для проверки из источника
    'BEST_PER_SOURCE': 100,      # Сколько лучших сохранять из источника
    'PING_TIMEOUT': 3,           # Таймаут пинга в секундах
    'FETCH_TIMEOUT': 15,         # Таймаут загрузки
}

def extract_host(config: str) -> Optional[str]:
    """Извлекает хост из конфига"""
    try:
        if '@' in config and 'ss://' not in config:
            # Для vless, trojan
            return config.split('@')[1].split(':')[0]
        elif 'vmess://' in config:
            # Для vmess ищем add поле
            match = re.search(r'add["\s]*:["\s]*([^",]+)', config)
            return match.group(1) if match else None
    except:
        pass
    return None

async def check_server(config: str) -> Tuple[Optional[str], Optional[float]]:
    """Проверяет доступность сервера"""
    host = extract_host(config)
    if not host:
        return None, None
    
    try:
        # Пробуем разные порты
        for port in [443, 80, 8080]:
            try:
                start = time.time()
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                
                try:
                    await asyncio.wait_for(
                        loop.sock_connect(sock, (host, port)),
                        timeout=CONFIG['PING_TIMEOUT']
                    )
                    ping = (time.time() - start) * 1000
                    return config, ping
                except:
                    pass
                finally:
                    sock.close()
            except:
                continue
    except:
        pass
    
    return None, None

async def fetch_source(session: aiohttp.ClientSession, url: str) -> str:
    """Загружает данные из источника"""
    try:
        async with session.get(url, timeout=CONFIG['FETCH_TIMEOUT']) as resp:
            return await resp.text() if resp.status == 200 else ''
    except:
        return ''

async def process_source(session: aiohttp.ClientSession, index: int, url: str) -> List[str]:
    """Обрабатывает один источник"""
    logger.info(f"📡 Source {index}")
    
    # Загружаем
    text = await fetch_source(session, url)
    if not text:
        logger.error(f"❌ Source {index}: failed")
        return []
    
    # Находим конфиги
    configs = re.findall(r'(vmess://[^\s]+|vless://[^\s]+|ss://[^\s]+|trojan://[^\s]+)', text)
    logger.info(f"📊 Source {index}: {len(configs)} configs")
    
    if not configs:
        return []
    
    # Проверяем первые N
    to_check = configs[:CONFIG['MAX_PER_SOURCE']]
    
    # Проверяем параллельно
    tasks = [check_server(config) for config in to_check]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем работающие
    working = [r for r in results if r[0] is not None]
    logger.info(f"⚡ Source {index}: {len(working)} working")
    
    if working:
        # Сортируем по пингу
        working.sort(key=lambda x: x[1])
        
        # Берём лучшие
        best = [w[0] for w in working[:CONFIG['BEST_PER_SOURCE']]]
        
        # Сохраняем
        os.makedirs('deploy/subscriptions', exist_ok=True)
        with open(f'deploy/subscriptions/{index}.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(best))
        
        logger.info(f"✅ Source {index}: saved {len(best)}")
        return best
    
    return []

async def main():
    """Основная функция"""
    logger.info("🚀 Starting parser")
    start_time = time.time()
    
    # Создаём папки
    os.makedirs('deploy/subscriptions', exist_ok=True)
    
    # Настраиваем сессию
    connector = aiohttp.TCPConnector(limit=10, limit_per_host=3)
    timeout = aiohttp.ClientTimeout(total=30)
    
    all_configs = []
    
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={'User-Agent': 'Mozilla/5.0'}
    ) as session:
        # Обрабатываем все источники
        tasks = []
        for i, url in enumerate(URLS, 1):
            task = process_source(session, i, url)
            tasks.append(task)
        
        # Собираем результаты
        results = await asyncio.gather(*tasks)
        
        # Объединяем
        for result in results:
            all_configs.extend(result)
    
    # Удаляем дубликаты
    unique_configs = list(set(all_configs))
    
    # Сохраняем общий файл
    if unique_configs:
        # Сортируем (вперемешку для балансировки)
        import random
        random.shuffle(unique_configs)
        
        with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_configs))
        
        logger.info(f"✅ Total: {len(unique_configs)} unique proxies")
    
    # Время выполнения
    elapsed = time.time() - start_time
    logger.info(f"⏱️ Done in {elapsed:.1f}s")

if __name__ == '__main__':
    asyncio.run(main())
