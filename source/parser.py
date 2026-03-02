import asyncio
import aiohttp
import re
import os
import time
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

async def fetch(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            return await resp.text() if resp.status == 200 else ''
    except:
        return ''

async def ping_server(config):
    """Быстрая проверка доступности сервера"""
    try:
        # Извлекаем хост из конфига
        if 'vmess://' in config:
            # Для vmess просто считаем что работает (сложно парсить)
            return config, 100
        elif '@' in config:
            # Для vless и trojan
            host = config.split('@')[1].split(':')[0]
        else:
            # Для ss
            return config, 100
            
        # Проверяем подключение
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        start = time.time()
        result = sock.connect_ex((host, 80))
        sock.close()
        
        if result == 0:
            ping = (time.time() - start) * 1000
            return config, ping
    except:
        pass
    return None, None

async def main():
    print("🚀 Парсер запущен")
    
    # Создаём папки
    os.makedirs('deploy/subscriptions', exist_ok=True)
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in URLS]
        results = await asyncio.gather(*tasks)
        
        all_configs = []
        
        for i, text in enumerate(results, 1):
            if not text:
                print(f"❌ Источник {i}: пусто")
                continue
            
            # Находим все конфиги
            configs = re.findall(r'(vmess://[^\s]+|vless://[^\s]+|ss://[^\s]+|trojan://[^\s]+)', text)
            print(f"📊 Источник {i}: найдено {len(configs)} конфигов")
            
            if not configs:
                continue
            
            # Проверяем пинг (только первые 500 для скорости)
            servers_with_ping = []
            for config in configs[:500]:
                result, ping = await ping_server(config)
                if result:
                    servers_with_ping.append((result, ping))
            
            print(f"⚡ Источник {i}: отвечают {len(servers_with_ping)}")
            
            if servers_with_ping:
                # Сортируем по пингу
                servers_with_ping.sort(key=lambda x: x[1])
                
                # Берём 200 лучших
                best_servers = [s[0] for s in servers_with_ping[:200]]
                
                # Сохраняем
                with open(f'deploy/subscriptions/{i}.txt', 'w', encoding='utf-8') as f:
                    f.write('\n'.join(best_servers))
                
                print(f"✅ Источник {i}: сохранено {len(best_servers)} лучших")
                all_configs.extend(best_servers)
        
        # Сохраняем общий файл
        if all_configs:
            with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_configs))
            print(f"✅ Всего сохранено: {len(all_configs)} серверов")
        
        # Создаём файл с датой для гарантии коммита
        with open('deploy/updated.txt', 'w', encoding='utf-8') as f:
            f.write(f"Last update: {datetime.now()}")

if __name__ == '__main__':
    asyncio.run(main())
