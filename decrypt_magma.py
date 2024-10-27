import os
from gostcrypto.gostcipher import GOST34122015Magma
from binascii import unhexlify

# Входные данные
file_name = "28-Magma.png.enc"
key_hex = "d4a1ffc7798a491a72ec35aa5c77cf08cbfa7d6e162fdb5a8e5fdd4310be4c40"

# Пути к директориям
encrypted_dir = "encrypted"
decrypted_dir = "decrypted"

# Конвертация ключа в байты
key = unhexlify(key_hex)

# Путь к зашифрованному файлу
encrypted_file_path = os.path.join(encrypted_dir, file_name)

# Открытие зашифрованного файла
try:
    with open(encrypted_file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
except FileNotFoundError:
    print(f"Ошибка: Файл {encrypted_file_path} не найден.")
    exit(1)

# Инициализация Магмы
cipher = GOST34122015Magma(key)

# Размер блока для Магмы
block_size = cipher.block_size

# Расшифровка данных
decrypted_data = bytearray()
try:
    for i in range(0, len(encrypted_data), block_size):
        block = encrypted_data[i:i+block_size]
        decrypted_block = cipher.decrypt(block)
        decrypted_data.extend(decrypted_block)
except Exception as e:
    print(f"Ошибка при расшифровке данных: {e}")
    exit(1)

# Удаление паддинга (если используется PKCS7 padding)
def remove_padding(data):
    pad_len = data[-1]
    if pad_len > 0 and pad_len <= len(data):
        return data[:-pad_len]
    return data

# Удаление паддинга, если он есть
try:
    decrypted_data = remove_padding(decrypted_data)
except IndexError:
    print("Ошибка при удалении паддинга. Проверьте, соответствует ли паддинг ГОСТ 34.13-2018.")
    exit(1)

# Проверка расшифрованных данных
if not decrypted_data:
    print("Ошибка: Расшифрованные данные пусты.")
    exit(1)

# Создаем директорию decrypted, если она не существует
os.makedirs(decrypted_dir, exist_ok=True)

# Путь к расшифрованному файлу
decrypted_file_name = file_name.replace(".enc", ".png")
decrypted_file_path = os.path.join(decrypted_dir, decrypted_file_name)

# Сохранение расшифрованного файла
try:
    with open(decrypted_file_path, "wb") as dec_file:
        dec_file.write(decrypted_data)
    print(f"Файл успешно расшифрован и сохранен как {decrypted_file_path}")
except IOError as e:
    print(f"Ошибка при сохранении файла: {e}")
    exit(1)
