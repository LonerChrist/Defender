# -*- coding: utf-8 -*-
"""
Модуль лицензирования системы CyberShield для ИП
Использует HMAC-SHA256 для генерации и проверки лицензионных ключей
"""

import hmac
import hashlib
import json
import os
import uuid
import platform
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Загрузка переменных окружения из .env файла
load_dotenv()

# Секретный ключ берётся из переменных окружения, а не из кода
SECRET_KEY = os.getenv('LICENSE_SECRET_KEY')
ISSUER = os.getenv('LICENSE_ISSUER', 'cybershield_official')

LICENSE_FILE = 'license.dat'


def get_machine_fingerprint():
    """
    Генерация уникального отпечатка устройства на основе характеристик железа.
    Используется для привязки лицензии к конкретному компьютеру.
    """
    # Собираем информацию о системе
    system_info = {
        'platform': platform.platform(),
        'processor': platform.processor(),
        'hostname': platform.node(),
        'mac_address': get_mac_address(),
        'cpu_count': os.cpu_count(),
    }

    # Создаём хеш из собранной информации
    fingerprint_data = json.dumps(system_info, sort_keys=True).encode('utf-8')
    return hashlib.sha256(fingerprint_data).hexdigest()[:32]


def get_mac_address():
    """Получение MAC-адреса сетевого адаптера"""
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                    for elements in range(0, 2 * 6, 2)][::-1])
    return mac


def generate_license_key(user_id: str, expiry_days: int = 365, device_fingerprint: str = None) -> str:
    """
    Генерация лицензионного ключа с HMAC-подписью

    :param user_id: Идентификатор пользователя (email или ID)
    :param expiry_days: Срок действия лицензии в днях
    :param device_fingerprint: Отпечаток устройства (опционально)
    :return: Лицензионный ключ формата: signature.payload.fingerprint
    """
    if not SECRET_KEY:
        raise ValueError("LICENSE_SECRET_KEY не настроен в переменных окружения!")

    # Формирование полезной нагрузки
    payload = {
        'user_id': user_id,
        'issuer': ISSUER,
        'issued': datetime.now().isoformat(),
        'expires': (datetime.now() + timedelta(days=expiry_days)).isoformat(),
        'device_fingerprint': device_fingerprint or get_machine_fingerprint(),
        'license_type': 'standard'
    }

    # Создание HMAC-подписи
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

    # Кодирование полезной нагрузки в base64
    import base64
    payload_encoded = base64.b64encode(payload_bytes).decode('utf-8')

    # Формирование ключа: подпись.полезная_нагрузка.отпечаток
    license_key = f"{signature}.{payload_encoded}.{payload['device_fingerprint']}"

    return license_key


def validate_license(key: str) -> dict:
    """
    Проверка лицензионного ключа

    :param key: Лицензионный ключ для проверки
    :return: Словарь с результатом проверки
    """
    if not SECRET_KEY:
        return {'valid': False, 'error': 'LICENSE_SECRET_KEY не настроен'}

    try:
        # Разбор ключа на компоненты
        parts = key.split('.')
        if len(parts) != 3:
            return {'valid': False, 'error': 'Неверный формат ключа'}

        signature, payload_encoded, device_fingerprint = parts

        # Декодирование полезной нагрузки
        import base64
        payload_bytes = base64.b64decode(payload_encoded)
        payload = json.loads(payload_bytes)

        # Проверка HMAC-подписи
        expected_signature = hmac.new(
            SECRET_KEY.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return {'valid': False, 'error': 'Неверная подпись ключа'}

        # Проверка издателя
        if payload.get('issuer') != ISSUER:
            return {'valid': False, 'error': 'Ключ выпущен неизвестным издателем'}

        # Проверка срока действия
        expires = datetime.fromisoformat(payload['expires'])
        if datetime.now() > expires:
            return {'valid': False, 'error': 'Срок действия лицензии истёк'}

        # Проверка привязки к устройству (machine binding)
        current_fingerprint = get_machine_fingerprint()
        if payload.get('device_fingerprint') != current_fingerprint:
            return {
                'valid': False,
                'error': 'Лицензия привязана к другому устройству',
                'requires_reactivation': True
            }

        return {
            'valid': True,
            'user_id': payload.get('user_id'),
            'expires': payload['expires'],
            'license_type': payload.get('license_type', 'standard'),
            'issued': payload.get('issued')
        }

    except Exception as e:
        return {'valid': False, 'error': f'Ошибка проверки лицензии: {str(e)}'}


def save_license(key: str) -> bool:
    """Сохранение активированной лицензии в локальный файл"""
    try:
        with open(LICENSE_FILE, 'w', encoding='utf-8') as f:
            f.write(key)
        return True
    except Exception:
        return False


def load_license() -> dict:
    """Загрузка и проверка сохранённой лицензии"""
    if not os.path.exists(LICENSE_FILE):
        return {'valid': False, 'error': 'Лицензия не активирована'}

    try:
        with open(LICENSE_FILE, 'r', encoding='utf-8') as f:
            key = f.read().strip()
        return validate_license(key)
    except Exception as e:
        return {'valid': False, 'error': f'Ошибка загрузки лицензии: {str(e)}'}


def generate_activation_code(user_id: str, days: int = 30) -> str:
    """
    Генерация кода активации для администратора
    Используется для выдачи ключей клиентам
    """
    return generate_license_key(user_id, expiry_days=days)