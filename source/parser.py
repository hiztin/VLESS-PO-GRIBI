import asyncio
import aiohttp
import re
import json
import os
from typing import List, Tuple, Optional
from urllib.parse import urlparse
from datetime import datetime

# -------------------- НАСТРОЙКИ --------------------
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

# -------------------- ПАРСЕР --------------------
async def fetch(session: aiohttp.ClientSession, url: str) -> str:
    """Асинхронная загрузка URL"""
    try:
        async with session.get(url, timeout=15) as resp:
            return await resp.text() if resp.status == 200 else ''
    except Exception:
        return ''

def extract_configs(text: str) -> List[str]:
    """Извлекает конфиги из текста"""
    if not text:
        return []
    # Ищем все vmess, vless, ss конфиги
    pattern = r'(vmess://[^\s]+|vless://[^\s]+|ss://[^\s]+)'
    return re.findall(pattern, text)

async def process_source(session: aiohttp.ClientSession, idx: int, url: str) -> Tuple[int, List[str]]:
    """Обрабатывает один источник"""
    print(f"🔍 Источник {idx + 1}")
    
    text = await fetch(session, url)
    if not text:
        print(f"  ❌ Пусто")
        return idx, []
    
    configs = extract_configs(text)
    print(f"  ✅ Найдено: {len(configs)}")
    
    # Берём первые 200
    return idx, configs[:200]

def save_results(results: List[Tuple[int, List[str]]]) -> Tuple[int, int]:
    """Сохраняет результаты в файлы"""
    os.makedirs(SUBSCRIPTIONS_PATH, exist_ok=True)
    
    total = 0
    sources = 0
    all_servers = []
    sources_data = {}
    
    for idx, servers in results:
        if servers:
            # Сохраняем в отдельный файл
            path = os.path.join(SUBSCRIPTIONS_PATH, f"{idx + 1}.txt")
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(servers))
            
            print(f"  ✅ {idx + 1}.txt: {len(servers)} серверов")
            total += len(servers)
            sources += 1
            all_servers.extend(servers)
            sources_data[idx + 1] = len(servers)
    
    # Сохраняем общий файл
    if all_servers:
        with open(os.path.join(DEPLOY_PATH, "sub.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_servers))
        print(f"✅ sub.txt: {len(all_servers)} всего серверов")
    
    # Сохраняем debug.json
    now = datetime.now()
    debug_info = {
        "total": total,
        "alive": total,
        "sources": sources,
        "last_update": now.strftime("%d.%m.%Y %H:%M"),
        "servers_by_source": sources_data
    }
    
    with open(os.path.join(DEPLOY_PATH, "debug.json"), "w", encoding="utf-8") as f:
        json.dump(debug_info, f, indent=2, ensure_ascii=False)
    
    # Создаём файл с временной меткой для коммита
    with open(os.path.join(DEPLOY_PATH, "last_update.txt"), "w", encoding="utf-8") as f:
        f.write(f"Last update: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return sources, total

def update_readme(total_servers: int, sources_count: int):
    """Обновляет README.md с актуальной статистикой"""
    readme_path = "README.md"
    
    # Получаем текущее время
    now = datetime.now()
    date_str = now.strftime("%d.%m.%Y")
    time_str = now.strftime("%H:%M")
    
    if not os.path.exists(readme_path):
        print("❌ README.md не найден")
        return
    
    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    import re
    
    # Обновляем общее количество серверов
    content = re.sub(
        r'(!\[Серверов\].*?alive=)(\d+)',
        f'\\g<1>{total_servers}',
        content
    )
    
    # Обновляем дату последнего обновления
    content = re.sub(
        r'(Последнее обновление:).*',
        f'\\1 {date_str} {time_str}',
        content
    )
    
    # Обновляем количество активных источников
    content = re.sub(
        r'(\*\*Активных источников\*\*:).*',
        f'\\1 {sources_count}',
        content
    )
    
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"✅ README.md обновлён: {total_servers} серверов, {sources_count} источников")

async def main():
    """Основная функция"""
    print("\n" + "="*60)
    print("🚀 ПАРСЕР ЗАПУЩЕН")
    print("="*60)
    
    # Создаём папки
    os.makedirs(DEPLOY_PATH, exist_ok=True)
    os.makedirs(SUBSCRIPTIONS_PATH, exist_ok=True)
    
    async with aiohttp.ClientSession() as session:
        # Создаём задачи для всех источников
        tasks = [process_source(session, i, url) for i, url in enumerate(URLS)]
        results = await asyncio.gather(*tasks)
    
    # Сортируем по номеру источника
    results.sort(key=lambda x: x[0])
    
    # Сохраняем результаты
    sources, total = save_results(results)
    
    # Обновляем README
    update_readme(total, sources)
    
    print("\n" + "="*60)
    print("✅ РАБОТА ЗАВЕРШЕНА")
    print("="*60)
    print(f"📊 Источников с данными: {sources}/{len(URLS)}")
    print(f"📊 Всего серверов: {total}")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
