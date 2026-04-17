from flask import Blueprint, request, jsonify
from functools import wraps
import os

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')


def require_api_key(f):
    """Декоратор для проверки API-ключа"""

    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        valid_key = os.getenv('API_KEY')
        if not api_key or api_key != valid_key:
            return jsonify({'error': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)

    return decorated


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Проверка доступности API"""
    return jsonify({'status': 'ok', 'version': '1.0.0'})


@api_bp.route('/check/email', methods=['POST'])
@require_api_key
def check_email(core=None):
    """Проверка email на участие в утечках"""
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Вызов бизнес-логики
        from core import check_email_breach
        breaches = check_email_breach(email)

        return jsonify({
            'email': email,
            'breaches_found': len(breaches),
            'breaches': breaches[:10]  # Ограничиваем вывод
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/check/password', methods=['POST'])
@require_api_key
def check_password():
    """Анализ надёжности пароля"""
    try:
        data = request.get_json()
        password = data.get('password')
        if not password:
            return jsonify({'error': 'Password is required'}), 400

        from core.password_analyzer import analyze_password
        result = analyze_password(password)

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500