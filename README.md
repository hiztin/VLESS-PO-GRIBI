# 🌐 VLESS PO GRIBI - Бесплатные VPN подписки 

<div align="center">
  
### 🚀 Ежедневно обновляемая коллекция рабочих VPN-серверов

[![GitHub last commit](https://img.shields.io/github/last-commit/hiztin/VLESS-PO-GRIBI)](https://github.com/hiztin/VLESS-PO-GRIBI/commits/main)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/hiztin/VLESS-PO-GRIBI/update-subscriptions.yml)](https://github.com/hiztin/VLESS-PO-GRIBI/actions)
[![License](https://img.shields.io/github/license/hiztin/VLESS-PO-GRIBI)](LICENSE)
![Серверов](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/debug.json&query=alive&label=рабочих&color=green)

</div>

## 📋 О проекте

Этот проект автоматически собирает и проверяет **бесплатные VPN-серверы** из открытых источников. Обновление происходит **каждый день** через GitHub Actions, поэтому подписки всегда актуальны. Проект ещё в разработке,
поэтому подписки не подписаны и\или что-то может не работать


### 📦 Основные подписки

| Формат | Описание | Прямая ссылка для копирования |
|--------|----------|-------------------------------|
| **Base64 (для V2Ray/V2Box)** | Полная подписка, все серверы | `https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/sub_base64.txt` |
| **Текстовый формат** | Обычный текст, по одному ключу в строке | `https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/sub.txt` |
| **Статистика** | Данные о количестве серверов | `https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/debug.json` |

### 📁 Разбивка по файлам (по ~150 серверов в каждом)

### 📁 Разбивка по файлам (по ~150 серверов в каждом)

| Часть | Диапазон | Серверов | Ссылка для V2Ray (Base64) |
|-------|----------|----------|---------------------------|
| **01** | 1-150 | ~150 | [`sub_001_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_001_b64.txt) |
| **02** | 151-300 | ~150 | [`sub_002_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_002_b64.txt) |
| **03** | 301-450 | ~150 | [`sub_003_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_003_b64.txt) |
| **04** | 451-600 | ~150 | [`sub_004_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_004_b64.txt) |
| **05** | 601-750 | ~150 | [`sub_005_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_005_b64.txt) |
| **06** | 751-900 | ~150 | [`sub_006_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_006_b64.txt) |
| **07** | 901-1050 | ~150 | [`sub_007_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_007_b64.txt) |
| **08** | 1051-1200 | ~150 | [`sub_008_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_008_b64.txt) |
| **09** | 1201-1350 | ~150 | [`sub_009_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_009_b64.txt) |
| **10** | 1351-1500 | ~150 | [`sub_010_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_010_b64.txt) |
| **11** | 1501-1650 | ~150 | [`sub_011_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_011_b64.txt) |
| **12** | 1651-1800 | ~150 | [`sub_012_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_012_b64.txt) |
| **13** | 1801-1950 | ~150 | [`sub_013_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_013_b64.txt) |
| **14** | 1951-2100 | ~150 | [`sub_014_b64.txt`](https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/sub_014_b64.txt) |

**[📂 Открыть папку со всеми файлами](https://github.com/hiztin/VLESS-PO-GRIBI/tree/main/deploy/subscriptions)**

## 📱 Как использовать (скопируй ссылку и вставь в приложение)

<details>
<summary><b>📱 Android (нажми для раскрытия)</b></summary>
<br>

| Приложение | Ссылка | Инструкция |
|------------|--------|------------|
| **v2rayNG** | ![Google Play](https://github.com/2dust/v2rayNG) | 1. Открой приложение<br>2. Нажми на "+" в правом верхнем углу<br>3. Выбери "Импорт подписки из буфера"<br>4. Вставь ссылку на `sub_base64.txt` |
| **V2Box** | [![Google Play](https://img.shields.io/badge/Google_Play-Скачать-414141?logo=google-play)](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box&hl=ru) | 1. Открой приложение<br>2. Перейди в "Подписки" (нижнее меню)<br>3. Нажми "+" в правом верхнем углу<br>4. Вставь ссылку на любой файл из разбивки |
| **NekoBox** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases) | 1. Открой приложение<br>2. Нажми на меню (три полоски)<br>3. Выбери "Профили" → "Импорт"<br>4. Вставь ссылку на `sub_base64.txt` |
| **Clash Meta** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/MetaCubeX/ClashMetaForAndroid/releases) | 1. Открой приложение<br>2. Перейди в "Профили"<br>3. Нажми "+" и выбери "Импорт из буфера"<br>4. Вставь ссылку на `sub_base64.txt` |

</details>

<details>
<summary><b>📱 iOS (нажми для раскрытия)</b></summary>
<br>

| Приложение | Ссылка | Инструкция |
|------------|--------|------------|
| **V2Box** | [![App Store](https://img.shields.io/badge/App_Store-Скачать-0D96F6?logo=apple)](https://apps.apple.com/app/v2box-v2ray-client/id6446018965) | 1. Открой приложение<br>2. Нажми на "Конфигурации" в нижнем меню<br>3. Нажми на плюсик в правом верхнем углу<br>4. Выбери "Импортировать v2ray URL из буфера"<br>5. Вставь ссылку на `sub_base64.txt` |
| **Shadowrocket** | [![App Store](https://img.shields.io/badge/App_Store-Скачать-0D96F6?logo=apple)](https://apps.apple.com/app/shadowrocket/id932747118) | 1. Открой приложение<br>2. Нажми на "+" в правом верхнем углу<br>3. Выбери "Тип: Подписка"<br>4. Вставь ссылку на `sub_base64.txt`<br>5. Нажми "Готово" |
| **Quantumult X** | [![App Store](https://img.shields.io/badge/App_Store-Скачать-0D96F6?logo=apple)](https://apps.apple.com/app/quantumult-x/id1443988620) | 1. Открой приложение<br>2. Нажми на вкладку "Ссылки" внизу<br>3. Нажми "+" в правом верхнем углу<br>4. Вставь ссылку на `sub_base64.txt`<br>5. Нажми "Сохранить" |
| **Stash** | [![App Store](https://img.shields.io/badge/App_Store-Скачать-0D96F6?logo=apple)](https://apps.apple.com/app/stash/id1596063349) | 1. Открой приложение<br>2. Перейди в "Профили"<br>3. Нажми "Импортировать"<br>4. Выбери "Из буфера обмена"<br>5. Вставь ссылку на `sub_base64.txt` |

</details>

<details>
<summary><b>💻 Windows (нажми для раскрытия)</b></summary>
<br>

| Приложение | Ссылка | Инструкция |
|------------|--------|------------|
| **v2rayN** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/2dust/v2rayN/releases) | 1. Открой приложение<br>2. Нажми "Подписки" в верхнем меню<br>3. Выбери "Управление подписками"<br>4. Нажми "Добавить"<br>5. Вставь ссылку на `sub_base64.txt`<br>6. Нажми "Обновить" |
| **Throne** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/Throne-Moe/Throne/releases) | 1. Открой приложение<br>2. Нажми на "Профили" слева<br>3. Нажми "Добавить профиль из буфера"<br>4. Вставь ссылку на `sub_base64.txt` |
| **Clash Verge** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/zzzgydi/clash-verge/releases) | 1. Открой приложение<br>2. Перейди в "Подписки"<br>3. Вставь ссылку на `sub_base64.txt`<br>4. Нажми "Импортировать" |
| **Netch** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/netchx/netch/releases) | 1. Открой приложение<br>2. Нажми "Подписки" → "Управление подписками"<br>3. Нажми "Добавить"<br>4. Вставь ссылку на `sub_base64.txt`<br>5. Нажми "Обновить" |

</details>

<details>
<summary><b>🐧 Linux (нажми для раскрытия)</b></summary>
<br>

| Приложение | Ссылка | Инструкция |
|------------|--------|------------|
| **Clash Verge** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/zzzgydi/clash-verge/releases) | 1. Открой приложение<br>2. Перейди в "Подписки"<br>3. Вставь ссылку на `sub_base64.txt`<br>4. Нажми "Импортировать" |
| **Qv2ray** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/Qv2ray/Qv2ray/releases) | 1. Открой приложение<br>2. Перейди в "Настройки" → "Подписки"<br>3. Нажми "Добавить"<br>4. Вставь ссылку на `sub_base64.txt`<br>5. Нажми "Обновить" |
| **NekoRay** | [![GitHub](https://img.shields.io/badge/GitHub-Скачать-181717?logo=github)](https://github.com/MatsuriDayo/nekoray/releases) | 1. Открой приложение<br>2. Нажми "Программа" → "Добавить подписку"<br>3. Вставь ссылку на `sub_base64.txt`<br>4. Нажми "Обновить" |

</details>

## 📊 Статистика

- **Всего серверов**: ~13,000+
- **Протоколы**: VMess, VLESS, Shadowsocks (Trojan отфильтрован)
- **Обновление**: каждые 3 часа UTC

## 🔄 Автоматическое обновление

Подписки обновляются автоматически каждые 3 часа. Просто добавь одну из ссылок выше в своё приложение один раз, и оно будет получать свежие серверы автоматически.

## 📞 Контакты и поддержка

- **Discord**: `h1zz`
- **GitHub Issues**: [Создать issue](https://github.com/hiztin/VLESS-PO-GRIBI/issues)

## ⚠️ Дисклеймер

Данный проект носит исключительно образовательный и технический характер. Материалы предоставлены для изучения принципов работы сетевых протоколов и автоматизации сбора данных.

Автор не несет ответственности за использование предоставленной информации. Проект не ставит целью рекламу или побуждение к обходу законодательства РФ. Использование любых технологий должно соответствовать законам вашей страны.

<div align="center">

### ⭐ Если проект полезен, поставь звезду! ⭐

[![GitHub stars](https://img.shields.io/github/stars/hiztin/VLESS-PO-GRIBI?style=social)](https://github.com/hiztin/VLESS-PO-GRIBI/stargazers)

</div>
