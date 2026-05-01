# -*- coding: utf-8 -*-
"""
Модуль безопасности: проверка API-ключей и сессий пользователей
"""

from functools import wraps
from flask import request, jsonify, session, redirect, url_for
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

def login_required(f):
    """Декоратор для защиты маршрутов - требует авторизации"""

    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)

    return decorated


def api_login_required(f):
    """Декоратор для защиты API - требует авторизации"""

    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)

    return decorated