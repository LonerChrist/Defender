import hashlib
import json
import os
from datetime import datetime, timedelta

LICENSE_FILE = 'license.dat'
SECRET_KEY = os.getenv('LICENSE_SECRET', 'default_secret_change_in_prod')


def generate_license_key(user_id: str, expiry_days: int = 365) -> str:
    """Генерация лицензионного ключа (для администратора)"""
    payload = {
        'user_id': user_id,
        'issued': datetime.now().isoformat(),
        'expires': (datetime.now() + timedelta(days=expiry_days)).isoformat()
    }
    signature = hashlib.sha256(
        f"{json.dumps(payload)}{SECRET_KEY}".encode()
    ).hexdigest()
    return f"{signature}.{json.dumps(payload).encode().hex()}"


def validate_license(key: str) -> dict:
    """Проверка лицензионного ключа"""
    try:
        signature, payload_hex = key.split('.')
        payload = json.loads(bytes.fromhex(payload_hex).decode())

        expected_sig = hashlib.sha256(
            f"{json.dumps(payload)}{SECRET_KEY}".encode()
        ).hexdigest()
        if signature != expected_sig:
            return {'valid': False, 'error': 'Invalid signature'}

        # Проверка срока действия
        expires = datetime.fromisoformat(payload['expires'])
        if datetime.now() > expires:
            return {'valid': False, 'error': 'License expired'}

        return {'valid': True, 'user_id': payload['user_id'], 'expires': payload['expires']}
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def save_license(key: str) -> bool:
    """Сохранение активированной лицензии"""
    try:
        with open(LICENSE_FILE, 'w') as f:
            f.write(key)
        return True
    except:
        return False


def load_license() -> dict:
    """Загрузка и проверка сохранённой лицензии"""
    if not os.path.exists(LICENSE_FILE):
        return {'valid': False, 'error': 'No license file'}

    try:
        with open(LICENSE_FILE, 'r', encoding='utf-8') as f:
            key = f.read().strip()
        return validate_license(key)
    except Exception as e:
        return {'valid': False, 'error': str(e)}