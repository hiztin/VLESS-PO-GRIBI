import asyncio
import httpx
import re
import base64
import json
import os
import ipaddress
import subprocess
import platform
from urllib.parse import urlparse

SOURCES = [
    #"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    #"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt"
]

TIMEOUT = 0.5
CONCURRENT_LIMIT = 50


class TurboParser:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def decode_base64(self, text):
        try:
            text = re.sub(r'\s+', '', text)
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            return decoded
        except Exception as e:
            return ""

    def extract_keys(self, text):
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
        for pattern in patterns:
            found.extend(re.findall(pattern, text, re.IGNORECASE))

        return list(set(found))

    def extract_host_port(self, config):
        try:
            if config.startswith('vmess://'):
                try:
                    vmess_data = config[8:]
                    decoded = self.decode_base64(vmess_data)
                    if decoded:
                        data = json.loads(decoded)
                        return data.get('add'), int(data.get('port', 0))
                except:
                    pass

            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port

            parts = config.split('://')[1].split('@')
            if len(parts) > 1:
                addr_part = parts[-1]
            else:
                addr_part = parts[0]

            addr_part = addr_part.split('/')[0].split('?')[0]
            if ':' in addr_part:
                host, port_str = addr_part.split(':')
                return host, int(port_str)

        except Exception as e:
            pass
        return None, None

    async def fetch_source(self, client, url):
        try:
            print(f"[*] Запрос к: {url}")
            r = await client.get(url, timeout=20.0, follow_redirects=True)
            print(f"    [!] Статус: {r.status_code}, Размер: {len(r.text)} байт")

            if r.status_code != 200:
                return []

            raw_data = r.text
            found = []

            found.extend(self.extract_keys(raw_data))

            for line in raw_data.split('\n'):
                line = line.strip()
                if line and len(line) > 20:
                    decoded = self.decode_base64(line)
                    if decoded and '://' in decoded:
                        found.extend(self.extract_keys(decoded))

            if found:
                print(f"    [+] Найдено ссылок: {len(set(found))}")
            return list(set(found))
        except Exception as e:
            print(f"    [X] Ошибка при запросе {url}: {e}")
            return []

    async def check_server(self, config, semaphore):
        host, port = self.extract_host_port(config)

        if not host or not port:
            return None

        async with semaphore:
            try:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    try:
                        await asyncio.get_event_loop().getaddrinfo(host, port)
                    except:
                        return None

                conn = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                writer.close()
                await writer.wait_closed()
                print(f"    [LIVE] {host}:{port}")
                return config
            except:
                return None

    def subscribe_to_servers(self, configs, app_type="v2ray"):

        system = platform.system()

        if app_type == "v2ray" and system == "Windows":
            return self._subscribe_v2ray_windows(configs)
        elif app_type == "clash" and system == "Windows":
            return self._subscribe_clash_windows(configs)

    def _subscribe_v2ray_windows(self, configs):
        v2ray_path = "C:\\Users\\h1zz\\Desktop\\v2rayN\\v2rayN.exe"  # Укажи свой путь!

        if not os.path.exists(v2ray_path):
            print(f"❌ v2rayN не найден по пути: {v2ray_path}")


        sub_file = os.path.join(os.path.expanduser("~"), "v2ray_sub.txt")
        with open(sub_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(configs[:50]))


        try:
            subprocess.run([v2ray_path, "-import", sub_file], check=True)
            print(f"✅ Импортировано {len(configs[:50])} серверов в v2rayN")
        except Exception as e:
            print(f"❌ Ошибка импорта в v2rayN: {e}")

        return sub_file

    def _subscribe_clash_windows(self, configs):

        clash_config = self._convert_to_clash(configs[:100])

        clash_file = os.path.join(os.path.expanduser("~"), "clash_config.yaml")
        with open(clash_file, 'w', encoding='utf-8') as f:
            f.write(clash_config)

        print(f"✅ Создан файл для Clash: {clash_file}")
        return clash_file

    def _convert_to_clash(self, configs):
        proxies = []
        for config in configs[:50]:  # Ограничим для простоты
            proxy = self._parse_to_clash_proxy(config)
            if proxy:
                proxies.append(proxy)

        clash_template = f"""
port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
{''.join([f'  {p}\n' for p in proxies])}

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
{''.join([f'      - {p["name"]}\n' for p in proxies if "name" in p])}

rules:
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"""
        return clash_template

    def _parse_to_clash_proxy(self, config):

        try:
            if config.startswith('vmess://'):
                return {"name": f"VMess-{hash(config) % 10000}", "type": "vmess", "server": "example.com", "port": 443}
            elif config.startswith('vless://'):
                return {"name": f"VLESS-{hash(config) % 10000}", "type": "vless", "server": "example.com", "port": 443}
            elif config.startswith('trojan://'):
                return {"name": f"Trojan-{hash(config) % 10000}", "type": "trojan", "server": "example.com",
                        "port": 443}
        except:
            pass
        return None



    def auto_subscribe(self, configs):
        system = platform.system()
        print(f"\n--- АВТОМАТИЧЕСКАЯ ПОДПИСКА ({system}) ---")

        results = {}


        if system == "Windows":
            results['v2ray'] = self.subscribe_to_servers(configs, "v2ray")
            results['clash'] = self.subscribe_to_servers(configs, "clash")


        return results


def split_into_files(data, base_filename, items_per_file=200):
    if not data:
        return

    subs_dir = os.path.join('deploy', 'subscribes') 
    os.makedirs(subs_dir, exist_ok=True)
    
    total_items = len(data)
    num_files = (total_items + items_per_file - 1) // items_per_file

    print(f"\nРАЗБИВКА НА {num_files} ФАЙЛОВ по {items_per_file} серверов ")

    for i in range(num_files):
        start_idx = i * items_per_file
        end_idx = min((i + 1) * items_per_file, total_items)

        chunk = data[start_idx:end_idx]
        chunk_text = "\n".join(chunk)

        txt_filename = f"sub_{i + 1:03d}.txt"
        txt_path = os.path.join(subs_dir, txt_filename)
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(chunk_text)

        b64_filename = f"sub_{i + 1:03d}_b64.txt"
        b64_path = os.path.join(subs_dir, b64_filename)
        chunk_b64 = base64.b64encode(chunk_text.encode()).decode()
        with open(b64_path, 'w', encoding='utf-8') as f:
            f.write(chunk_b64)

        print(f"  [{i + 1:03d}/{num_files}] {txt_filename}: {len(chunk)} серверов")

    return subs_dir


async def main():
    parser = TurboParser()

    transport = httpx.AsyncHTTPTransport(retries=2)

    async with httpx.AsyncClient(
            transport=transport,
            verify=False,
            follow_redirects=True,
            headers=parser.headers,
            timeout=30.0
    ) as client:

        print(" 1: СБОР")
        tasks = [parser.fetch_source(client, url) for url in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_links = []
        for result in results:
            if isinstance(result, list):
                raw_links.extend(result)

        unique_links = list(set(raw_links))

        print(f"\nИТОГО УНИКАЛЬНЫХ: {len(unique_links)}")

        if not unique_links:
            print("Ссылок не найдено.")
            return

        print("\n 2: ВАЛИДАЦИЯ")
        sem = asyncio.Semaphore(CONCURRENT_LIMIT)
        check_tasks = [parser.check_server(link, sem) for link in unique_links]
        valid_results = await asyncio.gather(*check_tasks)

        alive = [r for r in valid_results if r]

        print(f"\n 3: СОХРАНЕНИЕ ({len(alive)} живых из {len(unique_links)})")

        if alive:
            # Обычное сохранение
            if not os.path.exists('deploy'):
                os.makedirs('deploy')

            final_text = "\n".join(alive)

            with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
                f.write(final_text)

            final_b64 = base64.b64encode(final_text.encode()).decode()
            with open('deploy/sub_base64.txt', 'w', encoding='utf-8') as f:
                f.write(final_b64)

            with open('deploy/debug.json', 'w', encoding='utf-8') as f:
                json.dump({
                    'total': len(unique_links),
                    'alive': len(alive),
                    'servers': alive[:100]  # Только первые 100 для экономии места
                }, f, indent=2, ensure_ascii=False)

            # Разбивка на маленькие файлы
            split_into_files(alive, 'sub', items_per_file=150)


            print("\n 4: АВТОМАТИЧЕСКАЯ ПОДПИСКА")
            subscription_results = parser.auto_subscribe(alive)


            print(f" Готов Файлы сохранены ")
            print(f"   - deploy/sub.txt: {len(alive)} серверов в текстовом формате")
            print(f"   - deploy/sub_base64.txt: для V2Ray")
            print(f"   - deploy/subscriptions/: разбивка по файлам")
        else:
            print("❌ Не найдено рабочих серверов")


if __name__ == "__main__":
    asyncio.run(main())
