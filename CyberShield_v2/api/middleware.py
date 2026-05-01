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


@app.route('/api/license/activate', methods=['POST'])
@require_api_key
def api_activate_license():
    """Активация лицензии с проверкой устройства"""
    try:
        from utils.license import validate_license, save_license, get_machine_fingerprint

        data = request.get_json()
        key = data.get('key')

        if not key:
            return jsonify({'error': 'Лицензионный ключ не предоставлен'}), 400


        validation = validate_license(key)

        if not validation.get('valid'):
            return jsonify({
                'success': False,
                'error': validation.get('error')
            }), 400

        if save_license(key):
            return jsonify({
                'success': True,
                'message': 'Лицензия активирована успешно',
                'expires': validation.get('expires'),
                'device_fingerprint': get_machine_fingerprint()[:16] + '...'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Не удалось сохранить лицензию'
            }), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/license/generate', methods=['POST'])
@require_api_key
def api_generate_license():
    """
    Генерация нового ключа (только для администратора!)
    В продакшене требует дополнительной авторизации
    """
    try:
        from utils.license import generate_license_key, get_machine_fingerprint

        data = request.get_json()
        user_id = data.get('user_id', 'demo_user')
        expiry_days = data.get('expiry_days', 365)

        # Генерация ключа с привязкой к текущему устройству
        key = generate_license_key(
            user_id=user_id,
            expiry_days=expiry_days,
            device_fingerprint=get_machine_fingerprint()
        )

        return jsonify({
            'success': True,
            'license_key': key,
            'expires_in_days': expiry_days
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500