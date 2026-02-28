import os
import base64
import math


def split_subscription_file(input_file, output_dir='deploy/split', items_per_file=150):
    """Разбивает существующий файл подписки на несколько маленьких"""

    # Создаем папку
    os.makedirs(output_dir, exist_ok=True)

    # Читаем исходный файл
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]

    total = len(lines)
    num_files = math.ceil(total / items_per_file)

    print(f"📊 Всего серверов: {total}")
    print(f"📦 Будет создано файлов: {num_files} (по ~{items_per_file} шт.)")
    print("-" * 40)

    for i in range(num_files):
        start = i * items_per_file
        end = min((i + 1) * items_per_file, total)

        chunk = lines[start:end]
        chunk_text = "\n".join(chunk)

        # Текстовый формат
        txt_file = os.path.join(output_dir, f'sub_{i + 1:03d}.txt')
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(chunk_text)

        # Base64 формат для V2Ray
        b64_file = os.path.join(output_dir, f'sub_{i + 1:03d}_b64.txt')
        chunk_b64 = base64.b64encode(chunk_text.encode()).decode()
        with open(b64_file, 'w', encoding='utf-8') as f:
            f.write(chunk_b64)

        print(f"✅ [{i + 1:03d}] {txt_file}: {len(chunk)} серверов")

    # Создаем README с инструкциями
    create_readme(output_dir, num_files)

    print(f"\n✨ Готово! Файлы сохранены в папке: {output_dir}")


def create_readme(output_dir, num_files):
    """Создает README с инструкциями по использованию"""
    readme_path = os.path.join(output_dir, 'README.txt')

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("🌐 ПОДПИСКИ ДЛЯ V2Ray / V2Box\n")
        f.write("=" * 40 + "\n\n")
        f.write("📱 КАК ИСПОЛЬЗОВАТЬ:\n")
        f.write("1. Открой V2Box или другой клиент\n")
        f.write("2. Выбери 'Добавить подписку'\n")
        f.write("3. Скопируй содержимое нужного файла *_b64.txt\n")
        f.write("4. Или загрузи файл целиком\n\n")
        f.write("📋 СПИСОК ФАЙЛОВ:\n")

        for i in range(num_files):
            f.write(f"   sub_{i + 1:03d}.txt - обычный текст\n")
            f.write(f"   sub_{i + 1:03d}_b64.txt - для V2Ray (base64)\n")

        f.write(f"\n📊 Всего файлов: {num_files}\n")
        f.write(f"🔢 Примерно по 150-200 серверов в каждом\n")


if __name__ == "__main__":
    # Использование
    input_file = "deploy/sub.txt"  # твой исходный файл

    if os.path.exists(input_file):
        split_subscription_file(
            input_file,
            output_dir="deploy/subscriptions",
            items_per_file=150  # меняй это число (100, 150, 200 и т.д.)
        )
    else:
        print(f"❌ Файл {input_file} не найден!")
        print("Сначала запусти парсер для сбора серверов")