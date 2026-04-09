import asyncio
import aiohttp
import re
import json
import os
from typing import List, Tuple, Optional
from urllib.parse import urlparse
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY_PATH = os.path.join(BASE_DIR, "deploy")
SUBSCRIPTIONS_PATH = os.path.join(DEPLOY_PATH, "subscriptions")
README_PATH = os.path.join(BASE_DIR, "README.md")

print(f" Корень репозитория: {BASE_DIR}")
print(f" Deploy путь: {DEPLOY_PATH}")

#  ИСТОЧНИКИ есть в README
URLS = [
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",  # 1
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",  # 2
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",  # 3
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.2.txt",  # 4
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",  # 5
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",  # 6
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.txt",  # 7
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",  # 8
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    # 9
    "https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",  # 10
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",  # 11
    "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt",  # 12
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/refs/heads/main/conf-week.txt",  # 13
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",  # 14
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/subscriptions/all.part1.txt",
    # 15
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/subscriptions/all.txt",  # 16
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",  # 17
    "https://raw.githubusercontent.com/FSystem88/vless-keys/refs/heads/main/keys.txt",  # 18
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",  # 19
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/26.txt",  # 20
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",  # 21
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",  # 22
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/23.txt",  # 23
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",  # 24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt"  # 25
]

# Мейн парсер 
async def fetch(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=15) as resp:
            return await resp.text() if resp.status == 200 else ''
    except Exception as e:
        print(f" Ошибка загрузки: {str(e)[:50]}")
        return ''


def extract_configs(text: str) -> List[str]:
    if not text:
        return []
    pattern = r'(vmess://[^\s]+|vless://[^\s]+|ss://[^\s]+)'
    return re.findall(pattern, text)


async def process_source(session: aiohttp.ClientSession, idx: int, url: str) -> Tuple[int, List[str]]:
    """Обрабатывает один источник"""
    print(f" Источник {idx + 1}")

    text = await fetch(session, url)
    if not text:
        print(f"  Пусто")
        return idx, []

    configs = extract_configs(text)
    print(f"  Найдено: {len(configs)}")

    return idx, configs[:200]


def save_results(results: List[Tuple[int, List[str]]]) -> Tuple[int, int]:
    """Сохраняет результаты в файлы"""
    os.makedirs(SUBSCRIPTIONS_PATH, exist_ok=True)
    print(f" Создана папка: {SUBSCRIPTIONS_PATH}")

    total = 0
    sources = 0
    all_servers = []
    sources_data = {}

    for idx, servers in results:
        if servers:
            # Сохраняем в отдельный файл
            file_path = os.path.join(SUBSCRIPTIONS_PATH, f"{idx + 1}.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(servers))

            print(f"   {idx + 1}.txt: {len(servers)} серверов -> {file_path}")
            total += len(servers)
            sources += 1
            all_servers.extend(servers)
            sources_data[idx + 1] = len(servers)

    if all_servers:
        sub_path = os.path.join(DEPLOY_PATH, "sub.txt")
        with open(sub_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_servers))
        print(f" sub.txt: {len(all_servers)} серверов -> {sub_path}")

    now = datetime.now()
    debug_info = {
        "total": total,
        "alive": total,
        "sources": sources,
        "last_update": now.strftime("%d.%m.%Y %H:%M"),
        "servers_by_source": sources_data
    }

    debug_path = os.path.join(DEPLOY_PATH, "debug.json")
    with open(debug_path, "w", encoding="utf-8") as f:
        json.dump(debug_info, f, indent=2, ensure_ascii=False)
    print(f" debug.json создан")

    # Создаём файл с временной меткой
    timestamp_path = os.path.join(DEPLOY_PATH, "last_update.txt")
    with open(timestamp_path, "w", encoding="utf-8") as f:
        f.write(f"Last update: {now.strftime('%Y-%m-%d %H:%M:%S')}")

    return sources, total


def update_readme(total_servers: int, sources_count: int):
    if not os.path.exists(README_PATH):
        print(f" README.md не найден по пути: {README_PATH}")
        return

    now = datetime.now()
    date_str = now.strftime("%d.%m.%Y")
    time_str = now.strftime("%H:%M")

    with open(README_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    import re

    content = re.sub(
        r'(!\[Серверов\].*?alive=)(\d+)',
        f'\\g<1>{total_servers}',
        content
    )

    content = re.sub(
        r'(Последнее обновление:).*',
        f'\\1 {date_str} {time_str}',
        content
    )

    content = re.sub(
        r'(\*\*Активных источников\*\*:).*',
        f'\\1 {sources_count}',
        content
    )

    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f" README.md обновлён: {README_PATH}")


async def main():
    print("\n" + "=" * 60)
    print(" ПАРСЕР ЗАПУЩЕН")
    print("=" * 60)
    print(f" Корень: {BASE_DIR}")
    print(f" Deploy: {DEPLOY_PATH}")

    # Создаём папки
    os.makedirs(DEPLOY_PATH, exist_ok=True)
    os.makedirs(SUBSCRIPTIONS_PATH, exist_ok=True)
    print(f" Папки созданы")

    async with aiohttp.ClientSession() as session:
        tasks = [process_source(session, i, url) for i, url in enumerate(URLS)]
        results = await asyncio.gather(*tasks)

    results.sort(key=lambda x: x[0])
    sources, total = save_results(results)

    print(f"\n Содержимое {DEPLOY_PATH}:")
    if os.path.exists(DEPLOY_PATH):
        for f in os.listdir(DEPLOY_PATH):
            print(f"  - {f}")

    update_readme(total, sources)

    print("\n" + "=" * 60)
    print(" РАБОТА ЗАВЕРШЕНА")
    print("=" * 60)
    print(f"Источников с данными: {sources}/{len(URLS)}")
    print(f"Всего серверов: {total}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

