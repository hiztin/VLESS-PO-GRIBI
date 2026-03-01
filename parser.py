import asyncio
import httpx
import re
import base64
import json
import os
import ipaddress
import math
import time
import statistics
from urllib.parse import urlparse
from typing import List, Tuple, Optional

SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    # "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    #"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt"
]
TIMEOUT = 7.0
CONCURRENT_LIMIT = 50
SERVERS_PER_FILE = 200

MAX_PING_MS = 800
MIN_PING_MS = 10
PING_SAMPLES = 2

# Протоколы, которые нужно сохранять
ALLOWED_PROTOCOLS = ['vless', 'vmess', 'ss']


class TurboParser:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.servers_with_ping: List[Tuple[str, float]] = []

    def decode_base64(self, text):
        """Безопасное декодирование Base64"""
        try:
            text = re.sub(r'\s+', '', text)
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            return decoded
        except Exception:
            return ""

    def extract_keys(self, text):
        """Извлечение ключей из текста"""
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

    def filter_by_protocol(self, configs):
        """Оставляет только серверы с разрешёнными протоколами"""
        filtered = []
        removed = []

        for config in configs:
            protocol = config.split('://')[0].lower()
            if protocol in ALLOWED_PROTOCOLS:
                filtered.append(config)
            else:
                removed.append(config)

        print(f"🔍 Фильтрация протоколов:")
        print(f"   ✅ Оставлено ({len(filtered)}): {', '.join(ALLOWED_PROTOCOLS)}")
        print(f"   ❌ Удалено ({len(removed)}): trojan и другие")
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

        except Exception:
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

    async def check_server_with_ping(self, config, semaphore):
        """Умная проверка сервера с несколькими замерами"""
        host, port = self.extract_host_port(config)

        if not host or not port:
            return None, None

        async with semaphore:
            try:
                # Делаем несколько замеров
                pings = []

                for sample in range(PING_SAMPLES):
                    try:
                        start = time.time()

                        # Проверяем DNS если нужно
                        try:
                            ipaddress.ip_address(host)
                        except ValueError:
                            await asyncio.get_event_loop().getaddrinfo(host, port)

                        # Подключаемся
                        conn = asyncio.open_connection(host, port)
                        _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)

                        elapsed = (time.time() - start) * 1000
                        pings.append(elapsed)

                        writer.close()
                        await writer.wait_closed()

                        # Небольшая пауза между замерами
                        if sample < PING_SAMPLES - 1:
                            await asyncio.sleep(0.1)

                    except Exception:
                        return None, None

                # Берём медиану (устойчива к выбросам)
                final_ping = statistics.median(pings)

                # Проверяем на реалистичность
                if final_ping < MIN_PING_MS or final_ping > 2000:
                    return None, None

                print(f"    [LIVE] {host}:{port} - {final_ping:.1f}ms (медиана из {PING_SAMPLES})")
                return config, final_ping

            except asyncio.TimeoutError:
                return None, None
            except Exception:
                return None, None


def split_into_files(data, base_filename="sub", items_per_file=SERVERS_PER_FILE):
    """Разбивает список серверов на маленькие файлы"""
    if not data:
        print("⚠️ Нет данных для разбивки")
        return []

    subs_dir = os.path.join('deploy', 'subscriptions')
    os.makedirs(subs_dir, exist_ok=True)

    total_items = len(data)
    num_files = math.ceil(total_items / items_per_file)

    print(f"\n--- РАЗБИВКА НА {num_files} МАЛЕНЬКИХ ФАЙЛОВ ---")

    created_files = []

    for i in range(num_files):
        start_idx = i * items_per_file
        end_idx = min((i + 1) * items_per_file, total_items)

        chunk = data[start_idx:end_idx]
        chunk_text = "\n".join(chunk)

        file_number = i + 1
        file_prefix = f"{base_filename}_{file_number:03d}"

        txt_filename = f"{file_prefix}.txt"
        txt_path = os.path.join(subs_dir, txt_filename)
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(chunk_text)
        created_files.append(txt_path)

        b64_filename = f"{file_prefix}_b64.txt"
        b64_path = os.path.join(subs_dir, b64_filename)
        chunk_b64 = base64.b64encode(chunk_text.encode()).decode()
        with open(b64_path, 'w', encoding='utf-8') as f:
            f.write(chunk_b64)
        created_files.append(b64_path)

        print(f"  [{file_number:03d}/{num_files:03d}] {txt_filename}: {len(chunk)} серверов")

    create_links_file(subs_dir, num_files, base_filename)
    print(f"✅ Всего создано файлов: {len(created_files)}")
    return created_files


def create_links_file(subs_dir, num_files, base_filename):
    """Создаёт файл со всеми ссылками"""
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


def save_sorted_by_ping(servers_with_ping: List[Tuple[str, float]]):
    """Сохраняет серверы, отсортированные по пингу"""
    if not servers_with_ping:
        return

    # Сортируем по пингу
    sorted_servers = sorted(servers_with_ping, key=lambda x: x[1])
    sorted_configs = [s[0] for s in sorted_servers]

    os.makedirs('deploy', exist_ok=True)

    # Текстовый файл
    with open('deploy/sub_sorted.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted_configs))

    # Base64 файл
    with open('deploy/sub_sorted_b64.txt', 'w', encoding='utf-8') as f:
        all_b64 = base64.b64encode("\n".join(sorted_configs).encode()).decode()
        f.write(all_b64)

    # Статистика по пингу
    ping_values = [p for _, p in sorted_servers]

    # Квартили для анализа
    q1 = statistics.quantiles(ping_values, n=4)[0] if len(ping_values) >= 4 else 0
    q3 = statistics.quantiles(ping_values, n=4)[2] if len(ping_values) >= 4 else 0

    ping_details = []
    for config, ping_ms in sorted_servers[:50]:  # Только первые 50 для читаемости
        host, _ = extract_host_port_simple(config)
        ping_details.append({
            'host': host,
            'ping_ms': round(ping_ms, 1),
            'quality': 'быстрый' if ping_ms < 200 else 'средний' if ping_ms < 400 else 'медленный'
        })

    with open('deploy/ping_stats.json', 'w', encoding='utf-8') as f:
        json.dump({
            'total': len(sorted_servers),
            'min_ping': round(min(ping_values), 1),
            'max_ping': round(max(ping_values), 1),
            'avg_ping': round(statistics.mean(ping_values), 1),
            'median_ping': round(statistics.median(ping_values), 1),
            'q1_ping': round(q1, 1),
            'q3_ping': round(q3, 1),
            'fast_servers': len([p for p in ping_values if p < 200]),
            'medium_servers': len([p for p in ping_values if 200 <= p < 400]),
            'slow_servers': len([p for p in ping_values if p >= 400]),
            'samples_per_server': PING_SAMPLES,
            'servers_by_ping': ping_details
        }, f, indent=2, ensure_ascii=False)

    print(f"📊 Статистика по пингу:")
    print(f"   • Мин: {min(ping_values):.1f}ms, Макс: {max(ping_values):.1f}ms")
    print(f"   • Средний: {statistics.mean(ping_values):.1f}ms")
    print(f"   • Медиана: {statistics.median(ping_values):.1f}ms")
    print(f"   • Быстрых (<200ms): {len([p for p in ping_values if p < 200])}")
    print(f"   • Медленных (>400ms): {len([p for p in ping_values if p >= 400])}")

    return sorted_configs


def extract_host_port_simple(config):
    """Упрощённое извлечение хоста для статистики"""
    try:
        if config.startswith('vmess://'):
            return "vmess-server", 0
        parsed = urlparse(config)
        if parsed.hostname:
            return parsed.hostname, parsed.port or 0
        return "unknown", 0
    except:
        return "unknown", 0


def filter_by_ping_intelligently(servers_with_ping: List[Tuple[str, float]]):
    """
    Умная фильтрация по пингу:
    - Не отсекаем всех подряд, а анализируем распределение
    """
    if not servers_with_ping:
        return []

    ping_values = [p for _, p in servers_with_ping]

    # Если серверов мало - оставляем все
    if len(ping_values) < 10:
        print(f"⚠️ Мало серверов ({len(ping_values)}), оставляем все")
        return servers_with_ping

    median_ping = statistics.median(ping_values)
    q3 = statistics.quantiles(ping_values, n=4)[2] if len(ping_values) >= 4 else median_ping * 1.5

    threshold = min(median_ping * 2, q3 * 1.2, 800)  

    filtered = [(c, p) for c, p in servers_with_ping if p <= threshold]
    removed = len(servers_with_ping) - len(filtered)

    print(f"📊 Анализ пинга:")
    print(f"   • Медиана: {median_ping:.1f}ms")
    print(f"   • Порог отсечения: {threshold:.1f}ms")
    print(f"   • Оставлено: {len(filtered)}, отсеяно: {removed}")

    return filtered


def save_main_files(alive_servers, total_found):
    """Сохраняет основные файлы"""
    os.makedirs('deploy', exist_ok=True)

    with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(alive_servers))

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

    print(f"📦 Основные файлы сохранены в deploy/")


def save_protocol_stats(servers):
    """Сохраняет статистику по протоколам"""
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
    start_time = time.time()
    parser = TurboParser()

    transport = httpx.AsyncHTTPTransport(retries=2)

    async with httpx.AsyncClient(
            transport=transport,
            verify=False,
            follow_redirects=True,
            headers=parser.headers,
            timeout=30.0
    ) as client:

        print("🔍 СБОР КОНФИГУРАЦИЙ")
        tasks = [parser.fetch_source(client, url) for url in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_links = []
        for result in results:
            if isinstance(result, list):
                raw_links.extend(result)

        unique_links = list(set(raw_links))
        print(f"\n📊 ВСЕГО УНИКАЛЬНЫХ: {len(unique_links)}")

        if not unique_links:
            print("❌ Ссылок не найдено. Создаю тестовые файлы")
            test_servers = [
                "vmess://eyJhZGQiOiJ0ZXN0LmNvbSIsInBvcnQiOiI4MCIsImlkIjoiMTIzNDU2Nzg5MCJ9",
                "vless://test-uuid@test.com:443?security=tls",
                "ss://YWVzLTI1Ni1nY206dGVzdEB0ZXN0LmNvbTo4MA=="
            ]
            save_main_files(test_servers, 3)
            split_into_files(test_servers, items_per_file=2)
            return

        print("\n⚡ ПРОВЕРКА ДОСТУПНОСТИ И ЗАМЕР ПИНГА")
        sem = asyncio.Semaphore(CONCURRENT_LIMIT)

        check_tasks = [parser.check_server_with_ping(link, sem) for link in unique_links]
        results_with_ping = await asyncio.gather(*check_tasks)

        servers_with_ping = [(c, p) for c, p in results_with_ping if c is not None]

        print(f"\n📊 ДОСТУПНО СЕРВЕРОВ: {len(servers_with_ping)}")

        if not servers_with_ping:
            print("❌ Нет доступных серверов")
            return
        servers_with_ping = filter_by_ping_intelligently(servers_with_ping)

        alive_configs = [c for c, _ in servers_with_ping]

        print(f"\n🔬 ФИЛЬТРАЦИЯ ПО ПРОТОКОЛАМ")
        filtered_servers = parser.filter_by_protocol(alive_configs)

        filtered_with_ping = [(c, p) for c, p in servers_with_ping if c in filtered_servers]

        print(f"\n💾 СОХРАНЕНИЕ РЕЗУЛЬТАТОВ ({len(filtered_with_ping)} серверов)")

        if filtered_with_ping:
            save_main_files([c for c, _ in filtered_with_ping], len(unique_links))
            save_protocol_stats([c for c, _ in filtered_with_ping])
            sorted_configs = save_sorted_by_ping(filtered_with_ping)

            # Разбиваем на файлы
            split_into_files(sorted_configs, items_per_file=SERVERS_PER_FILE)

            elapsed = time.time() - start_time
            print("\n" + "=" * 60)
            print("✅ ВСЁ УСПЕШНО ЗАВЕРШЕНО!")
            print("=" * 60)
            print(f"📊 Всего серверов: {len(filtered_with_ping)}")
            print(f"⚡ Медианный пинг: {statistics.median([p for _, p in filtered_with_ping]):.1f}ms")
            print(f"⏱ Время выполнения: {elapsed:.1f}с")
        else:
            print("❌ Нет серверов после фильтрации")


if __name__ == "__main__":
    asyncio.run(main())
