import asyncio
import httpx
import re
import base64
import json
import os
import ipaddress
import math
from urllib.parse import urlparse

SOURCES = [
    #"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    #"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt"
]

TIMEOUT = 7.0
CONCURRENT_LIMIT = 50
SERVERS_PER_FILE = 200  # Количество серверов в одном файле

ALLOWED_PROTOCOLS = ['vless', 'vmess', 'ss']  # Только эти протоколы


class TurboParser:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def decode_base64(self, text):
        """Безопасное декодирование Base64"""
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
        """Извлечение ключей из текста"""
        if not text:
            return []

        # Паттерны для всех протоколов (включая trojan, но мы его отфильтруем позже)
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

    def filter_by_protocol(self, configs):
        """
        Оставляет только серверы с разрешёнными протоколами
        """
        filtered = []
        removed = []

        for config in configs:
            # Определяем протокол
            protocol = config.split('://')[0].lower()

            if protocol in ALLOWED_PROTOCOLS:
                filtered.append(config)
            else:
                removed.append(config)

        print(f" Фильтрация протоколов:")
        print(f"    Оставлено ({len(filtered)}): {', '.join(ALLOWED_PROTOCOLS)}")
        print(f"    Удалено ({len(removed)}): trojan и другие")

        return filtered

    def extract_host_port(self, config):
        """Извлечение хоста и порта из конфига"""
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
        """Получение данных из источника"""
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
        """Проверка доступности сервера"""
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


def split_into_files(data, base_filename="sub", items_per_file=SERVERS_PER_FILE):

    if not data:
        print("⚠️ Нет данных для разбивки")
        return []

    # Создаём папку для маленьких файлов
    subs_dir = os.path.join('deploy', 'subscriptions')
    os.makedirs(subs_dir, exist_ok=True)

    total_items = len(data)
    num_files = math.ceil(total_items / items_per_file)

    print(f"\n--- РАЗБИВКА НА {num_files} МАЛЕНЬКИХ ФАЙЛОВ (по ~{items_per_file} серверов) ---")

    created_files = []

    for i in range(num_files):
        start_idx = i * items_per_file
        end_idx = min((i + 1) * items_per_file, total_items)

        # Текущий кусок серверов
        chunk = data[start_idx:end_idx]
        chunk_text = "\n".join(chunk)

        # Формируем имена файлов с ведущими нулями (001, 002, ...)
        file_number = i + 1
        file_prefix = f"{base_filename}_{file_number:03d}"

        # 1. Текстовый файл с сырыми ссылками
        txt_filename = f"{file_prefix}.txt"
        txt_path = os.path.join(subs_dir, txt_filename)
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(chunk_text)
        created_files.append(txt_path)

        # 2. Base64 файл для V2Ray/V2Box
        b64_filename = f"{file_prefix}_b64.txt"
        b64_path = os.path.join(subs_dir, b64_filename)
        chunk_b64 = base64.b64encode(chunk_text.encode()).decode()
        with open(b64_path, 'w', encoding='utf-8') as f:
            f.write(chunk_b64)
        created_files.append(b64_path)

        print(f"  [{file_number:03d}/{num_files:03d}] {txt_filename}: {len(chunk)} серверов")


    # Создаём файл со всеми ссылками
    create_links_file(subs_dir, num_files, base_filename)

    print(f"✅ Всего создано файлов: {len(created_files)}")
    return created_files
    create_readme(subs_dir, num_files, items_per_file, total_items)
    
def create_readme(subs_dir, num_files, items_per_file, total_items):
    """Создаёт README в папке с маленькими файлами"""
    readme_path = os.path.join(subs_dir, 'README.md')
    
    content = f"""#  Маленькие подписки по {items_per_file} серверов

## Статистика
- **Всего серверов:** {total_items}
- **Количество файлов:** {num_files}
- **Серверов в файле:** ~{items_per_file}
- **Протоколы:** VLESS, VMess, SS
- **Форматы:** Текст (.txt) и Base64 (_b64.txt)

##  Прямые ссылки

"""
    
    base_url = "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions"
    
    for i in range(num_files):
        file_number = i + 1
        content += f"- **Часть {file_number:02d}**: [`sub_{file_number:03d}.txt`]({base_url}/sub_{file_number:03d}.txt) | [`sub_{file_number:03d}_b64.txt`]({base_url}/sub_{file_number:03d}_b64.txt)\n"
    
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"📖 Создан README: {readme_path}")


def create_links_file(subs_dir, num_files, base_filename):
    """Создаёт файл со всеми ссылками для быстрого копирования"""
    links_path = os.path.join(subs_dir, 'all_links.txt')

    base_url = "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions"

    with open(links_path, 'w', encoding='utf-8') as f:
        f.write("# Все ссылки на маленькие подписки (VLESS/VMess/SS)\n\n")
        f.write("## Base64 ссылки (для V2Ray/V2Box)\n")
        for i in range(num_files):
            file_num = i + 1
            f.write(f"{base_url}/sub_{file_num:03d}_b64.txt\n")

        f.write("\n## Текстовые ссылки (для ручного импорта)\n")
        for i in range(num_files):
            file_num = i + 1
            f.write(f"{base_url}/sub_{file_num:03d}.txt\n")

    print(f"🔗 Создан файл со ссылками: {links_path}")


def save_main_files(alive_servers, total_found):
    """Сохраняет основные файлы (полные подписки)"""
    os.makedirs('deploy', exist_ok=True)

    # Текстовый файл со всеми серверами
    with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(alive_servers))

    # Base64 файл со всеми серверами
    with open('deploy/sub_base64.txt', 'w', encoding='utf-8') as f:
        all_b64 = base64.b64encode("\n".join(alive_servers).encode()).decode()
        f.write(all_b64)
        
    with open('deploy/debug.json', 'w', encoding='utf-8') as f:
        protocols = {}
        for server in alive_servers[:100]:  
            proto = server.split('://')[0]
            protocols[proto] = protocols.get(proto, 0) + 1

        json.dump({
            'total': total_found,
            'alive': len(alive_servers),
            'allowed_protocols': ALLOWED_PROTOCOLS,
            'date': str(__import__('datetime').datetime.now()),
            'protocol_stats': protocols,
            'servers_preview': alive_servers[:10]
        }, f, indent=2, ensure_ascii=False)

    print(f" Основные файлы сохранены в deploy/")
    print(f"   - sub.txt: {len(alive_servers)} серверов (VLESS/VMess/SS)")
    print(f"   - sub_base64.txt: для V2Ray")
    print(f"   - debug.json: статистика")


def save_protocol_stats(servers):
    """Сохраняет статистику по протоколам в отдельный файл"""
    stats = {}
    for server in servers:
        protocol = server.split('://')[0]
        stats[protocol] = stats.get(protocol, 0) + 1

    stats_path = os.path.join('deploy', 'protocol_stats.json')
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total': len(servers),
            'by_protocol': stats,
            'filtered_out': ['trojan']  
        }, f, indent=2)

    print(f"📊 Статистика по протоколам: {stats}")


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

        print("СБОР")
        tasks = [parser.fetch_source(client, url) for url in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_links = []
        for result in results:
            if isinstance(result, list):
                raw_links.extend(result)

        unique_links = list(set(raw_links))

        print(f"\nИТОГО УНИКАЛЬНЫХ: {len(unique_links)}")

        if not unique_links:
            print(" Ссылок не найдено. Создаю тестовые файлы")
            test_servers = [
                "vmess://eyJhZGQiOiJ0ZXN0LmNvbSIsInBvcnQiOiI4MCIsImlkIjoiMTIzNDU2Nzg5MCJ9",
                "vless://test-uuid@test.com:443?security=tls",
                "ss://YWVzLTI1Ni1nY206dGVzdEB0ZXN0LmNvbTo4MA=="
            ]
            save_main_files(test_servers, 3)
            split_into_files(test_servers, items_per_file=2)
            return

        print("\n2: ВАЛИДАЦИЯ")
        sem = asyncio.Semaphore(CONCURRENT_LIMIT)
        check_tasks = [parser.check_server(link, sem) for link in unique_links]
        valid_results = await asyncio.gather(*check_tasks)

        alive = [r for r in valid_results if r]

        print(f"\n 3: ФИЛЬТРАЦИЯ ПО ПРОТОКОЛАМ")
        filtered_servers = parser.filter_by_protocol(alive)

        print(f"\n--- ШАГ 4: СОХРАНЕНИЕ ({len(filtered_servers)} живых из {len(alive)} после фильтрации) ---")

        if filtered_servers:
            save_main_files(filtered_servers, len(unique_links))


            save_protocol_stats(filtered_servers)
            split_into_files(filtered_servers, items_per_file=SERVERS_PER_FILE)

            print("\n" + "=" * 50)
            print(" ВСЁ ГОТОВО!")
            print("=" * 50)
            print(f" Всего рабочих серверов: {len(filtered_servers)}")
            print(f" Разрешённые протоколы: {', '.join(ALLOWED_PROTOCOLS)}")
            print(f" Отфильтровано: trojan и другие")
            print(f" Основные файлы: deploy/sub.txt, deploy/sub_base64.txt")
            print(f" Маленькие файлы: deploy/subscriptions/ (папка)")
            print("\n Ссылки для V2Ray/V2Box:")
            print(f"   • Полная: https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/sub_base64.txt")
            print(f"   • По частям: в папке deploy/subscriptions/")
        else:
            print(" Не найдено рабочих серверов с разрешёнными протоколами")
            # Всё равно создаём тестовые файлы
            test_servers = [
                "vmess://test-vmess",
                "vless://test-vless",
                "ss://test-ss"
            ]
            save_main_files(test_servers, 3)
            split_into_files(test_servers, items_per_file=2)
def generate_readme_table(num_files, base_url="https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions"):
    """Генерирует таблицу для README на основе количества файлов"""
    
    table = "### 📁 Разбивка по файлам (по ~150 серверов в каждом)\n\n"
    table += "| Часть | Диапазон | Серверов | Ссылка для V2Ray (Base64) |\n"
    table += "|-------|----------|----------|---------------------------|\n"
    
    for i in range(1, num_files + 1):
        start = (i-1)*150 + 1
        end = i*150
        table += f"| **{i:02d}** | {start}-{end} | ~150 | [`sub_{i:03d}_b64.txt`]({base_url}/sub_{i:03d}_b64.txt) |\n"
    
    table += f"\n**[📂 Смотреть все {num_files} файлов в папке subscriptions](https://github.com/hiztin/VLESS-PO-GRIBI/tree/main/deploy/subscriptions)**"
    
    return table

if __name__ == "__main__":
    asyncio.run(main())
