from functools import wraps
from flask import request, jsonify
import os


def require_api_key(f):
    """Декоратор для проверки API-ключа"""

    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        valid_key = os.getenv('API_KEY', 'default_key_for_dev')

        if not api_key or api_key != valid_key:
            return jsonify({'error': 'Invalid or missing API key'}), 401

        return f(*args, **kwargs)

    return decorated