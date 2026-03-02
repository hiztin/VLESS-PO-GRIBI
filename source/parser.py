import asyncio
import aiohttp
import re
import os
from datetime import datetime

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
import os
# Определяем корень репозитория (поднимаемся на один уровень из папки source)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY_PATH = os.path.join(REPO_ROOT, 'deploy')
SUBSCRIPTIONS_PATH = os.path.join(DEPLOY_PATH, 'subscriptions')
# Разрешённые протоколы
ALLOWED = ['vmess', 'vless', 'ss']

async def fetch(session, url):
    """Скачивание одного источника"""
    try:
        async with session.get(url, timeout=15) as resp:
            return await resp.text() if resp.status == 200 else ''
    except:
        return ''

def parse_configs(text):
    """Извлечение конфигов из текста"""
    if not text:
        return []
    
    # Все возможные протоколы
    found = []
    
    # vmess (base64)
    found.extend(re.findall(r'vmess://[a-zA-Z0-9+/=]+', text))
    
    # vless
    found.extend(re.findall(r'vless://[a-f0-9-]+@[a-zA-Z0-9.-]+:\d+', text))
    
    # ss
    found.extend(re.findall(r'ss://[a-zA-Z0-9+/=]+', text))
    
    # trojan (потом отфильтруем)
    found.extend(re.findall(r'trojan://[a-zA-Z0-9-]+@[a-zA-Z0-9.-]+:\d+', text))
    
    # Убираем дубликаты
    unique = list(set(found))
    
    # Фильтруем по разрешённым протоколам
    filtered = []
    for cfg in unique:
        proto = cfg.split('://')[0].lower()
        if proto in ALLOWED:
            filtered.append(cfg)
    
    return filtered

async def main():
    print("\n" + "="*50)
    print("🚀 ПАРСЕР ЗАПУЩЕН")
    print("="*50)
    
    # Создаём папки
    os.makedirs('deploy/subscriptions', exist_ok=True)
    
    async with aiohttp.ClientSession() as session:
        # Скачиваем все источники
        tasks = [fetch(session, url) for url in URLS]
        results = await asyncio.gather(*tasks)
        
        all_configs = []
        sources_with_data = 0
        
        # Обрабатываем каждый источник
        for i, text in enumerate(results, 1):
            print(f"\n🔍 Источник {i}")
            
            if not text:
                print(f"  ❌ Пусто")
                continue
            
            # Парсим конфиги
            configs = parse_configs(text)
            print(f"  📊 Найдено: {len(configs)}")
            
            if configs:
                # Берём первые 200
                selected = configs[:200]
                
                # Сохраняем в отдельный файл
                path = f'deploy/subscriptions/{i}.txt'
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(selected))
                
                print(f"  ✅ Сохранено: {len(selected)} в {i}.txt")
                
                all_configs.extend(selected)
                sources_with_data += 1
        
        # Сохраняем общий файл
        if all_configs:
            with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_configs))
            
            print(f"\n📦 Всего серверов: {len(all_configs)}")
            print(f"📊 Источников с данными: {sources_with_data}/{len(URLS)}")
        
        # Файл с датой для гарантии коммита
        with open('deploy/updated.txt', 'w', encoding='utf-8') as f:
            f.write(f"Last update: {datetime.now()}")
        
        print("\n✅ РАБОТА ЗАВЕРШЕНА")
        print("="*50)

if __name__ == '__main__':
    asyncio.run(main())

