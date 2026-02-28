import asyncio
import httpx
import re
import base64
import json
import os
import ipaddress
from urllib.parse import urlparse

# --- ИСТОЧНИКИ ---
SOURCES = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    #"https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    #"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt"
]

TIMEOUT = 0.5
CONCURRENT_LIMIT = 200


class TurboParser:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def decode_base64(self, text):
        """Безопасное декодирование Base64"""
        try:
            # Убираем пробелы и лишние символы
            text = re.sub(r'\s+', '', text)

            # Добавляем padding если нужно
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)

            # Пробуем декодировать
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            return decoded
        except Exception as e:
            return ""

    def extract_keys(self, text):
        """Извлечение ключей из текста"""
        if not text:
            return []

        # Паттерн для разных протоколов
        patterns = [
            r'(vmess://[a-zA-Z0-9+/=]+)',  # vmess обычно в base64
            r'(vless://[a-f0-9-]+@[a-zA-Z0-9.-]+:\d+)',
            r'(ss://[a-zA-Z0-9+/=]+[@#])',
            r'(trojan://[a-zA-Z0-9-]+@[a-zA-Z0-9.-]+:\d+)',
            r'(ss://[a-zA-Z0-9+/=]+)',  # упрощенный вариант
        ]

        found = []
        for pattern in patterns:
            found.extend(re.findall(pattern, text, re.IGNORECASE))

        return list(set(found))

    def extract_host_port(self, config):
        """Извлечение хоста и порта из конфига"""
        try:
            # Для vmess (JSON в base64)
            if config.startswith('vmess://'):
                try:
                    vmess_data = config[8:]  # убираем 'vmess://'
                    decoded = self.decode_base64(vmess_data)
                    if decoded:
                        data = json.loads(decoded)
                        return data.get('add'), int(data.get('port', 0))
                except:
                    pass

            # Для остальных протоколов
            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port

            # Парсим вручную для простых форматов
            parts = config.split('://')[1].split('@')
            if len(parts) > 1:
                addr_part = parts[-1]  # часть после @
            else:
                addr_part = parts[0]

            # Извлекаем хост и порт
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

            # Прямое извлечение
            found.extend(self.extract_keys(raw_data))

            # Построчная проверка на base64
            for line in raw_data.split('\n'):
                line = line.strip()
                if line and len(line) > 20:
                    # Проверяем не является ли строка base64
                    decoded = self.decode_base64(line)
                    if decoded and '://' in decoded:
                        found.extend(self.extract_keys(decoded))

            if found:
                print(f"    [+] Найдено ссылок: {len(set(found))}")
                # Покажем первые 3 для примера
                for i, f in enumerate(list(set(found))[:3]):
                    print(f"        {i + 1}. {f[:50]}...")
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
                # Проверяем валидность хоста
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    # Это домен, проверяем разрешается ли он
                    try:
                        await asyncio.get_event_loop().getaddrinfo(host, port)
                    except:
                        return None

                # Пробуем подключиться
                conn = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                writer.close()
                await writer.wait_closed()
                print(f"    [LIVE] {host}:{port}")
                return config
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                pass
            return None


async def main():
    parser = TurboParser()

    # Настройки для httpx с поддержкой прокси если нужно
    transport = httpx.AsyncHTTPTransport(retries=2)

    async with httpx.AsyncClient(
            transport=transport,
            verify=False,
            follow_redirects=True,
            headers=parser.headers,
            timeout=30.0
    ) as client:

        print("--- ШАГ 1: СБОР ---")
        tasks = [parser.fetch_source(client, url) for url in SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_links = []
        for result in results:
            if isinstance(result, list):
                raw_links.extend(result)

        unique_links = list(set(raw_links))

        print(f"\nИТОГО УНИКАЛЬНЫХ: {len(unique_links)}")

        if not unique_links:
            print("Ссылок не найдено. Возможные причины:")
            print("1. Нет доступа к источникам (нужен VPN)")
            print("2. Источники изменили формат")
            print("3. Проблемы с сетью")
            return

        print("\n--- ШАГ 2: ВАЛИДАЦИЯ ---")
        sem = asyncio.Semaphore(CONCURRENT_LIMIT)
        check_tasks = [parser.check_server(link, sem) for link in unique_links]
        valid_results = await asyncio.gather(*check_tasks)

        alive = [r for r in valid_results if r]

        print(f"\n--- ШАГ 3: СОХРАНЕНИЕ ({len(alive)} живых из {len(unique_links)}) ---")

        if alive:
            if not os.path.exists('deploy'):
                os.makedirs('deploy')

            # Сохраняем в разных форматах
            final_text = "\n".join(alive)

            # Обычный текст
            with open('deploy/sub.txt', 'w', encoding='utf-8') as f:
                f.write(final_text)

            # Base64 для V2Ray
            final_b64 = base64.b64encode(final_text.encode()).decode()
            with open('deploy/sub_base64.txt', 'w', encoding='utf-8') as f:
                f.write(final_b64)

            # Также сохраняем JSON для отладки
            with open('deploy/debug.json', 'w', encoding='utf-8') as f:
                json.dump({
                    'total': len(unique_links),
                    'alive': len(alive),
                    'servers': alive
                }, f, indent=2, ensure_ascii=False)

            print(f"✅ Готово! Файлы сохранены в папке 'deploy'")
            print(f"   - deploy/sub.txt: {len(alive)} серверов в текстовом формате")
            print(f"   - deploy/sub_base64.txt: для V2Ray")
            print(f"   - deploy/debug.json: для отладки")
        else:
            print("❌ Не найдено рабочих серверов")


if __name__ == "__main__":
    asyncio.run(main())