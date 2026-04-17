from functools import wraps
from flask import request, jsonify
from utils.license import load_license
import os
from core.password_analyzer import analyze_password
from utils.security import require_api_key

def require_active_license(f):
    """Декоратор: требует активную лицензию для доступа к функционалу"""
    @wraps(f)
    def decorated(*args, **kwargs):
        license_status = load_license()
        if not license_status.get('valid'):
            return jsonify({
                'error': 'License required',
                'message': 'Please activate your license to use this feature'
            }), 403
        return f(*args, **kwargs)
    return decorated

@api_bp.route('/check/password', methods=['POST'])
@require_api_key
@require_active_license
def check_password():
    """API-эндпоинт для анализа надёжности пароля"""
    try:
        # Получение данных из запроса
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body must be JSON'}), 400

        password = data.get('password')
        if not password:
            return jsonify({'error': 'Password is required'}), 400

        # Вызов бизнес-логики
        result = analyze_password(password)

        # Формирование ответа
        return jsonify({
            'success': True,
            'data': result
        }), 200

    except Exception as e:
        # Логирование ошибки (в продакшене использовать logger)
        print(f"Error in check_password: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@api_bp.route('/check/email', methods=['POST'])
@require_api_key
@require_active_license
def check_email():
    """API-эндпоинт для проверки email на участие в утечках"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body must be JSON'}), 400

        email = data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        from core.email_checker import check_email_breach
        breaches = check_email_breach(email)

        return jsonify({
            'success': True,
            'data': {
                'email': email,
                'breaches_found': len(breaches),
                'breaches': breaches
            }
        }), 200

    except Exception as e:
        print(f"Error in check_email: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@api_bp.route('/license/activate', methods=['POST'])
def activate_license():
    """Эндпоинт для активации лицензии (без проверки лицензии)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body must be JSON'}), 400

        key = data.get('key')
        if not key:
            return jsonify({'error': 'License key is required'}), 400

        from utils.license import validate_license, save_license

        # Проверка ключа
        validation = validate_license(key)
        if not validation.get('valid'):
            return jsonify({
                'success': False,
                'error': validation.get('error', 'Invalid license')
            }), 400

        # Сохранение лицензии
        if save_license(key):
            return jsonify({
                'success': True,
                'message': 'License activated successfully',
                'expires': validation.get('expires')
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to save license'
            }), 500

    except Exception as e:
        print(f"Error in activate_license: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500