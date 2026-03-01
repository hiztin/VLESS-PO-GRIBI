import asyncio
import aiohttp
import re
import os
from urllib.parse import urlparse

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
async def fetch(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            return await resp.text() if resp.status == 200 else ''
    except:
        return ''

async def main():
    # Создаём папки
    os.makedirs('deploy/subscriptions', exist_ok=True)
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in URLS]
        results = await asyncio.gather(*tasks)
        
        all_configs = []
        
        # Обрабатываем каждый источник
        for i, text in enumerate(results, 1):
            if not text:
                continue
                
            # Ищем все конфиги
            configs = re.findall(r'(vmess://[^\s]+|vless://[^\s]+|ss://[^\s]+)', text)
            
            # Берём первые 200
            configs = configs[:200]
            
            if configs:
                # Сохраняем в отдельный файл
                with open(f'deploy/subscriptions/{i}.txt', 'w', encoding='utf-8') as f:
                    f.write('\n'.join(configs))
                
                all_configs.extend(configs)
                print(f'✅ {i}.txt: {len(configs)} серверов')
        
        # Сохраняем общий файл
        if all_configs:
            with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_configs))
            print(f'✅ sub.txt: {len(all_configs)} всего серверов')
        
        print('✅ Парсинг завершён!')

if __name__ == '__main__':
    asyncio.run(main())
