#!/usr/bin/env python3
"""
Proxy Parser - собирает и проверяет прокси из различных источников
Проверяет все конфиги и выбирает лучшие по скорости и стабильности
"""

import asyncio
import aiohttp
import aiohttp_socks  # Добавляем поддержку прокси для проверки
import re
import os
import time
import socket
import json
import base64
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Set, Dict, Any
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse
import random

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('proxy_parser')

# Конфигурация
CONFIG = {
    'MAX_CONFIGS_PER_SOURCE': 1000,     # Максимум конфигов для проверки
    'BEST_CONFIGS_PER_SOURCE': 100,      # Сколько лучших сохранять
    'TOTAL_BEST_CONFIGS': 500,           # Всего лучших конфигов
    'PING_TIMEOUT': 5,                    # Таймаут пинга (сек)
    'PING_PORTS': [443, 80, 8080, 8443],  # Порты для проверки
    'FETCH_TIMEOUT': 30,                   # Таймаут загрузки
    'MAX_RETRIES': 3,                       # Количество попыток
    'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'CONCURRENT_CHECKS': 100,               # Одновременных проверок
    'SPEED_TEST_SIZE': 1024 * 1024,         # 1MB для теста скорости
    'SPEED_TEST_URL': 'http://speedtest.tele2.net/1MB.zip',
    'MIN_SPEED': 100 * 1024,                 # Минимальная скорость 100 KB/s
    'MAX_LATENCY': 1000,                     # Максимальная задержка 1000ms
    'REQUIRE_HTTPS': False,                   # Требовать HTTPS
    'DEDUPLICATION': True,                    # Удалять дубликаты
    'CHECK_STABILITY': True,                  # Проверять стабильность
    'STABILITY_CHECKS': 3,                     # Количество проверок стабильности
}

@dataclass
class ProxyResult:
    """Результат проверки прокси"""
    config: str
    latency: float = float('inf')
    speed: float = 0
    stability: float = 0
    port: int = 443
    protocol: str = 'unknown'
    host: str = ''
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def score(self) -> float:
        """Вычисляет общий балл прокси"""
        if self.latency == float('inf') or self.speed == 0:
            return 0
        
        # Нормализуем метрики
        latency_score = max(0, 1 - (self.latency / CONFIG['MAX_LATENCY']))
        speed_score = min(1, self.speed / (CONFIG['MIN_SPEED'] * 10))
        stability_score = self.stability
        
        # Веса метрик
        weights = {
            'latency': 0.4,
            'speed': 0.4,
            'stability': 0.2
        }
        
        return (latency_score * weights['latency'] + 
                speed_score * weights['speed'] + 
                stability_score * weights['stability'])

class ConfigParser:
    """Парсер для разных типов конфигураций"""
    
    PROTOCOLS = ['vmess', 'vless', 'trojan', 'ss', 'ssr']
    
    @classmethod
    def extract_configs(cls, text: str) -> Set[str]:
        """Извлекает все конфиги из текста"""
        configs = set()
        
        # Базовые паттерны
        patterns = [
            r'(?:vmess|vless|trojan)://[^\s<>"\']+',
            r'ss://[A-Za-z0-9+/=]+@[^\s<>"\']+',
            r'ss://[A-Za-z0-9+/=]+(?:\?[^\s<>"\']+)?',
            r'ssr://[A-Za-z0-9+/=]+',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            configs.update(matches)
        
        # Ищем в base64
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', text)
        for b64 in base64_patterns:
            try:
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                # Ищем конфиги в декодированном
                for pattern in patterns:
                    matches = re.findall(pattern, decoded)
                    configs.update(matches)
            except:
                pass
        
        return configs
    
    @classmethod
    def parse_config(cls, config: str) -> Optional[Dict[str, Any]]:
        """Парсит конфиг и возвращает информацию о нем"""
        result = {
            'config': config,
            'protocol': 'unknown',
            'host': None,
            'port': None,
            'uuid': None,
            'path': None,
            'tls': False
        }
        
        try:
            if config.startswith('vmess://'):
                result['protocol'] = 'vmess'
                cls._parse_vmess(config, result)
            elif config.startswith('vless://'):
                result['protocol'] = 'vless'
                cls._parse_vless_trojan(config, result)
            elif config.startswith('trojan://'):
                result['protocol'] = 'trojan'
                cls._parse_vless_trojan(config, result)
            elif config.startswith('ss://'):
                result['protocol'] = 'ss'
                cls._parse_ss(config, result)
            elif config.startswith('ssr://'):
                result['protocol'] = 'ssr'
                cls._parse_ssr(config, result)
        except Exception as e:
            logger.debug(f"Error parsing {config[:50]}: {e}")
            return None
        
        return result if result['host'] else None
    
    @classmethod
    def _parse_vmess(cls, config: str, result: Dict[str, Any]):
        """Парсит vmess конфиг"""
        base64_part = config[8:]  # убираем 'vmess://'
        
        # Добавляем padding
        missing_padding = len(base64_part) % 4
        if missing_padding:
            base64_part += '=' * (4 - missing_padding)
        
        try:
            decoded = base64.b64decode(base64_part).decode('utf-8')
            data = json.loads(decoded)
            
            result['host'] = data.get('add')
            result['port'] = int(data.get('port', 0))
            result['uuid'] = data.get('id')
            result['path'] = data.get('path')
            result['tls'] = data.get('tls', '') == 'tls'
            
        except json.JSONDecodeError:
            # Пробуем через regex
            host_match = re.search(r'add["\s]*:["\s]*([^",]+)', config)
            port_match = re.search(r'port["\s]*:["\s]*(\d+)', config)
            
            result['host'] = host_match.group(1) if host_match else None
            result['port'] = int(port_match.group(1)) if port_match else None
    
    @classmethod
    def _parse_vless_trojan(cls, config: str, result: Dict[str, Any]):
        """Парсит vless/trojan конфиг"""
        # Формат: protocol://uuid@host:port?params#remark
        parts = config.split('@')
        if len(parts) < 2:
            return
        
        # UUID
        uuid_part = parts[0].split('://')[-1]
        result['uuid'] = uuid_part
        
        # Host и port
        host_part = parts[1].split('?')[0].split('#')[0]
        if ':' in host_part:
            result['host'], port_str = host_part.split(':')
            result['port'] = int(port_str)
        else:
            result['host'] = host_part
            result['port'] = 443
        
        # Параметры
        if '?' in parts[1]:
            params = parts[1].split('?')[1].split('#')[0]
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=')
                    if key == 'security' and value == 'tls':
                        result['tls'] = True
                    elif key == 'path':
                        result['path'] = value
    
    @classmethod
    def _parse_ss(cls, config: str, result: Dict[str, Any]):
        """Парсит shadowsocks конфиг"""
        # Формат: ss://method:password@host:port#remark
        if '@' in config:
            # SIP002 формат
            parts = config.split('@')
            if len(parts) < 2:
                return
            
            # Декодируем метод и пароль
            userinfo = parts[0][5:]  # убираем 'ss://'
            try:
                decoded = base64.b64decode(userinfo).decode('utf-8')
                method, password = decoded.split(':', 1)
                result['method'] = method
                result['password'] = password
            except:
                pass
            
            # Хост и порт
            host_part = parts[1].split('#')[0]
            if ':' in host_part:
                result['host'], port_str = host_part.split(':')
                result['port'] = int(port_str)
    
    @classmethod
    def _parse_ssr(cls, config: str, result: Dict[str, Any]):
        """Парсит shadowsocksR конфиг"""
        base64_part = config[6:]  # убираем 'ssr://'
        
        # Добавляем padding
        missing_padding = len(base64_part) % 4
        if missing_padding:
            base64_part += '=' * (4 - missing_padding)
        
        try:
            decoded = base64.b64decode(base64_part).decode('utf-8')
            # SSR формат: server:port:protocol:method:obfs:password_base64/?params
            parts = decoded.split('/?')[0].split(':')
            if len(parts) >= 6:
                result['host'] = parts[0]
                result['port'] = int(parts[1])
                result['protocol'] = parts[2]
                result['method'] = parts[3]
                result['obfs'] = parts[4]
        except:
            pass

class ProxyTester:
    """Тестирование прокси"""
    
    def __init__(self):
        self.parser = ConfigParser()
        self.results: Dict[str, ProxyResult] = {}
    
    async def test_proxy(self, config: str, session: aiohttp.ClientSession) -> Optional[ProxyResult]:
        """Тестирует прокси полностью"""
        parsed = self.parser.parse_config(config)
        if not parsed or not parsed['host']:
            return None
        
        result = ProxyResult(
            config=config,
            host=parsed['host'],
            protocol=parsed['protocol'],
            port=parsed['port'] or 443
        )
        
        try:
            # Тест 1: TCP соединение (латентность)
            latency = await self._test_tcp_latency(parsed['host'], result.port)
            if latency is None or latency > CONFIG['MAX_LATENCY']:
                return None
            result.latency = latency
            
            # Тест 2: Скорость (если нужно)
            if CONFIG['SPEED_TEST_SIZE'] > 0:
                speed = await self._test_speed(parsed['host'], result.port, session)
                if speed and speed >= CONFIG['MIN_SPEED']:
                    result.speed = speed
            
            # Тест 3: Стабильность
            if CONFIG['CHECK_STABILITY']:
                stability = await self._test_stability(parsed['host'], result.port)
                result.stability = stability
            
            # Дополнительные проверки для конкретных протоколов
            if parsed['protocol'] == 'vmess' and parsed.get('tls'):
                # Проверяем TLS соединение
                if not await self._test_tls(parsed['host'], result.port):
                    return None
            
            logger.debug(f"Proxy OK: {parsed['host']} - {result.latency:.0f}ms - {result.speed/1024:.1f}KB/s")
            return result
            
        except Exception as e:
            logger.debug(f"Proxy test failed for {parsed['host']}: {e}")
            return None
    
    async def _test_tcp_latency(self, host: str, port: int) -> Optional[float]:
        """Тестирует TCP латентность"""
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            
            start = time.time()
            try:
                await asyncio.wait_for(
                    loop.sock_connect(sock, (host, port)),
                    timeout=CONFIG['PING_TIMEOUT']
                )
                latency = (time.time() - start) * 1000  # в миллисекундах
                return latency
            except:
                return None
            finally:
                sock.close()
        except:
            return None
    
    async def _test_speed(self, host: str, port: int, session: aiohttp.ClientSession) -> Optional[float]:
        """Тестирует скорость через HTTP"""
        try:
            # Пробуем разные порты
            test_ports = [port, 80, 8080] if port != 80 else [80, 8080, 443]
            
            for test_port in test_ports:
                try:
                    protocol = 'https' if test_port == 443 else 'http'
                    url = f"{protocol}://{host}:{test_port}/speedtest"
                    
                    start = time.time()
                    downloaded = 0
                    
                    async with session.get(url, timeout=CONFIG['PING_TIMEOUT']) as resp:
                        async for chunk in resp.content.iter_chunked(8192):
                            downloaded += len(chunk)
                            if downloaded >= CONFIG['SPEED_TEST_SIZE']:
                                break
                    
                    if downloaded > 0:
                        duration = time.time() - start
                        speed = downloaded / duration  # bytes per second
                        return speed
                        
                except:
                    continue
            
            return None
        except:
            return None
    
    async def _test_stability(self, host: str, port: int) -> float:
        """Тестирует стабильность соединения"""
        latencies = []
        
        for _ in range(CONFIG['STABILITY_CHECKS']):
            latency = await self._test_tcp_latency(host, port)
            if latency:
                latencies.append(latency)
            await asyncio.sleep(0.5)  # Пауза между проверками
        
        if not latencies:
            return 0
        
        # Стабильность = 1 - (стандартное отклонение / среднее)
        avg_latency = sum(latencies) / len(latencies)
        variance = sum((l - avg_latency) ** 2 for l in latencies) / len(latencies)
        std_dev = variance ** 0.5
        
        if avg_latency == 0:
            return 0
        
        stability = max(0, 1 - (std_dev / avg_latency))
        return stability
    
    async def _test_tls(self, host: str, port: int) -> bool:
        """Проверяет TLS соединение"""
        try:
            import ssl
            context = ssl.create_default_context()
            loop = asyncio.get_event_loop()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            
            try:
                await asyncio.wait_for(
                    loop.sock_connect(sock, (host, port)),
                    timeout=CONFIG['PING_TIMEOUT']
                )
                
                # Пробуем установить TLS
                ssl_sock = context.wrap_socket(sock, server_hostname=host)
                ssl_sock.do_handshake()
                ssl_sock.close()
                
                return True
            except:
                return False
            finally:
                sock.close()
        except:
            return False

class ProxyCollector:
    """Сборщик и обработчик прокси"""
    
    def __init__(self):
        self.tester = ProxyTester()
        self.results: List[ProxyResult] = []
        self.processed_configs: Set[str] = set()
    
    async def fetch_source(self, session: aiohttp.ClientSession, url: str) -> str:
        """Загружает данные из источника"""
        for attempt in range(CONFIG['MAX_RETRIES']):
            try:
                async with session.get(url, timeout=CONFIG['FETCH_TIMEOUT']) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    elif resp.status == 429:  # Rate limit
                        wait = 2 ** attempt
                        logger.warning(f"Rate limited for {url}, waiting {wait}s")
                        await asyncio.sleep(wait)
                    else:
                        logger.warning(f"HTTP {resp.status} for {url}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout for {url}, attempt {attempt + 1}")
            except Exception as e:
                logger.warning(f"Error fetching {url}: {e}")
            
            if attempt < CONFIG['MAX_RETRIES'] - 1:
                await asyncio.sleep(2 ** attempt)
        
        return ''
    
    async def process_source(self, session: aiohttp.ClientSession, index: int, url: str) -> List[ProxyResult]:
        """Обрабатывает один источник"""
        logger.info(f"📡 Source {index}: {url}")
        
        # Загружаем данные
        text = await self.fetch_source(session, url)
        if not text:
            logger.error(f"❌ Source {index}: failed to fetch")
            return []
        
        # Извлекаем конфиги
        configs = ConfigParser.extract_configs(text)
        logger.info(f"📊 Source {index}: found {len(configs)} configs")
        
        if not configs:
            return []
        
        # Удаляем дубликаты (глобально)
        new_configs = [c for c in configs if c not in self.processed_configs]
        logger.info(f"🆕 Source {index}: {len(new_configs)} new configs")
        
        if not new_configs:
            return []
        
        # Добавляем в обработанные
        self.processed_configs.update(new_configs)
        
        # Ограничиваем количество для проверки
        configs_to_test = list(new_configs)[:CONFIG['MAX_CONFIGS_PER_SOURCE']]
        
        # Тестируем все конфиги параллельно
        tasks = []
        for config in configs_to_test:
            task = self.tester.test_proxy(config, session)
            tasks.append(task)
        
        # Запускаем батчами
        batch_size = CONFIG['CONCURRENT_CHECKS']
        source_results = []
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch)
            source_results.extend([r for r in batch_results if r])
            
            logger.info(f"⚡ Source {index}: {len(source_results)}/{len(configs_to_test)} tested")
        
        # Сортируем по качеству
        source_results.sort(key=lambda x: x.score, reverse=True)
        
        # Сохраняем лучшие из этого источника
        best_from_source = source_results[:CONFIG['BEST_CONFIGS_PER_SOURCE']]
        
        # Сохраняем в файл источника
        if best_from_source:
            output_path = f'deploy/subscriptions/{index}.txt'
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                for result in best_from_source:
                    f.write(f"{result.config}\n")
            
            logger.info(f"✅ Source {index}: saved {len(best_from_source)} best servers")
        
        return source_results
    
    def deduplicate_results(self, results: List[ProxyResult]) -> List[ProxyResult]:
        """Удаляет дубликаты по хосту"""
        seen_hosts = set()
        unique_results = []
        
        for result in sorted(results, key=lambda x: x.score, reverse=True):
            if result.host not in seen_hosts:
                seen_hosts.add(result.host)
                unique_results.append(result)
        
        return unique_results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Возвращает статистику"""
        stats = {
            'total_tested': len(self.results),
            'by_protocol': defaultdict(int),
            'avg_latency': 0,
            'avg_speed': 0,
            'best_score': 0
        }
        
        if self.results:
            latencies = [r.latency for r in self.results if r.latency != float('inf')]
            speeds = [r.speed for r in self.results if r.speed > 0]
            
            stats['avg_latency'] = sum(latencies) / len(latencies) if latencies else 0
            stats['avg_speed'] = sum(speeds) / len(speeds) if speeds else 0
            stats['best_score'] = max(r.score for r in self.results)
            
            for r in self.results:
                stats['by_protocol'][r.protocol] += 1
        
        return stats

async def main():
    """Основная функция"""
    logger.info("🚀 Starting proxy collector")
    logger.info(f"📋 Configuration: {json.dumps(CONFIG, indent=2)}")
    
    start_time = time.time()
    collector = ProxyCollector()
    
    try:
        # Создаём структуру папок
        os.makedirs('deploy/subscriptions', exist_ok=True)
        
        # Настраиваем HTTP сессию
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300,
            ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(
            total=CONFIG['FETCH_TIMEOUT'],
            connect=10,
            sock_read=CONFIG['FETCH_TIMEOUT']
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': CONFIG['USER_AGENT']}
        ) as session:
            
            # Обрабатываем все источники
            tasks = []
            for i, url in enumerate(URLS, 1):
                task = collector.process_source(session, i, url)
                tasks.append(task)
            
            # Собираем результаты
            source_results = await asyncio.gather(*tasks)
            
            # Объединяем все результаты
            all_results = []
            for results in source_results:
                if results:
                    all_results.extend(results)
            
            collector.results = all_results
            
            # Удаляем дубликаты
            if CONFIG['DEDUPLICATION']:
                unique_results = collector.deduplicate_results(all_results)
            else:
                unique_results = all_results
            
            # Сортируем по качеству
            unique_results.sort(key=lambda x: x.score, reverse=True)
            
            # Берём общее количество лучших
            best_results = unique_results[:CONFIG['TOTAL_BEST_CONFIGS']]
            
            # Сохраняем общий файл
            if best_results:
                output_path = 'deploy/sub.txt'
                with open(output_path, 'w', encoding='utf-8') as f:
                    for result in best_results:
                        f.write(f"{result.config}\n")
                
                logger.info(f"✅ Total saved: {len(best_results)} best servers")
                
                # Сохраняем детальную информацию
                details_path = 'deploy/proxies.json'
                with open(details_path, 'w', encoding='utf-8') as f:
                    json.dump([
                        {
                            'host': r.host,
                            'protocol': r.protocol,
                            'latency': round(r.latency, 2),
                            'speed': round(r.speed, 2),
                            'stability': round(r.stability, 2),
                            'score': round(r.score, 3),
                            'port': r.port,
                            'timestamp': r.timestamp.isoformat()
                        }
                        for r in best_results
                    ], f, indent=2)
            else:
                logger.warning("⚠️ No servers found")
            
            # Статистика
            stats = collector.get_statistics()
            logger.info(f"📊 Statistics: {json.dumps(stats, indent=2)}")
        
        # Сохраняем информацию об обновлении
        elapsed = time.time() - start_time
        with open('deploy/last_update.txt', 'w', encoding='utf-8') as f:
            f.write(f"Last update: {datetime.now().isoformat()}\n")
            f.write(f"Duration: {elapsed:.2f} seconds\n")
            f.write(f"Sources processed: {len(URLS)}\n")
            f.write(f"Total configs found: {len(collector.processed_configs)}\n")
            f.write(f"Working proxies: {len(collector.results)}\n")
            f.write(f"Best proxies saved: {len(best_results) if best_results else 0}\n")
            
            if stats:
                f.write(f"\nStatistics:\n")
                f.write(f"  Average latency: {stats['avg_latency']:.0f}ms\n")
                f.write(f"  Average speed: {stats['avg_speed']/1024:.1f}KB/s\n")
                f.write(f"  By protocol:\n")
                for proto, count in stats['by_protocol'].items():
                    f.write(f"    {proto}: {count}\n")
        
        logger.info(f"✅ Parser finished in {elapsed:.2f} seconds")
        
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}", exc_info=True)
        raise

def run():
    """Точка входа"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Parser stopped by user")
    except Exception as e:
        logger.error(f"💥 Parser crashed: {e}")
        raise

if __name__ == '__main__':
    run()
