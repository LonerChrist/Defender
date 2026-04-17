from flask import Flask, render_template, request, jsonify, send_file
from core.password_analyzer import analyze_password
from core.email_checker import check_email_breach
from utils.security import require_api_key
from core.port_scanner import PortScanner
from core.offline_password_checker import OfflinePasswordChecker
from utils.report_generator import PDFReportGenerator
import os
import webbrowser
import threading
from datetime import datetime

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(basedir, 'frontend', 'templates'),
    static_folder=os.path.join(basedir, 'frontend', 'static'),
    static_url_path='/static'
)

session_data = {}

@app.route('/')
def index():
    """Главная страница веб-приложения"""
    return render_template('index.html')


@app.route('/report/<session_id>')
def generate_report(session_id):
    """Генерация и отображение отчёта"""
    data = session_data.get(session_id, {})
    return render_template('report.html', session_id=session_id, data=data)

@app.route('/api/check/email', methods=['POST'])
@require_api_key
def api_check_email():
    """API-эндпоинт для проверки email на участие в утечках"""
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        result = check_email_breach(email)

        return jsonify({
            'email': email,
            'breaches': result,
            'breaches_count': len(result) if result else 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check/password', methods=['POST'])
@require_api_key
def api_check_password():
    """API-эндпоинт для анализа пароля с проверкой в базах утечек"""
    try:
        data = request.get_json()
        password = data.get('password')

        if not password:
            return jsonify({'error': 'Password is required'}), 400

        result = analyze_password(password)

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check/password/offline', methods=['POST'])
@require_api_key
def api_check_password_offline():
    """API-эндпоинт для офлайн анализа пароля (без внешних API)"""
    try:
        data = request.get_json()
        password = data.get('password')

        if not password:
            return jsonify({'error': 'Password is required'}), 400

        checker = OfflinePasswordChecker()
        result = checker.check_strength(password)

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/ports', methods=['POST'])
@require_api_key
def api_scan_ports():
    """API-эндпоинт для сканирования сетевых портов"""
    try:
        data = request.get_json()
        host = data.get('host', 'localhost')

        scanner = PortScanner(host=host)
        open_ports = scanner.scan()
        vulnerabilities = scanner.get_vulnerabilities()

        return jsonify({
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities,
            'total_ports': len(open_ports),
            'total_vulnerabilities': len(vulnerabilities)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate/pdf-report', methods=['POST'])
@require_api_key
def api_generate_pdf_report():
    """API-эндпоинт для генерации PDF отчёта"""
    try:
        data = request.get_json()

        audit_data = {
            'target': data.get('target', 'Информационная система ИП'),
            'overall_score': data.get('overall_score', 0),
            'critical_count': data.get('critical_count', 0),
            'warning_count': data.get('warning_count', 0),
            'email_check': data.get('email_check', {}),
            'password_analysis': data.get('password_analysis', {}),
            'port_scan': data.get('port_scan', {}),
            'recommendations': data.get('recommendations', []),
            'generated_at': datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        }

        session_id = f"session_{datetime.now().timestamp()}"
        session_data[session_id] = audit_data

        generator = PDFReportGenerator(output_path='security_report.pdf')
        report_path = generator.generate_report(audit_data)

        return jsonify({
            'report_path': report_path,
            'message': 'Отчёт успешно сгенерирован',
            'session_id': session_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/license/activate', methods=['POST'])
@require_api_key
def api_activate_license():
    """API-эндпоинт для активации лицензии"""
    try:
        from utils.license import validate_license, save_license

        data = request.get_json()
        key = data.get('key')

        if not key:
            return jsonify({'error': 'License key is required'}), 400

        validation = validate_license(key)

        if not validation.get('valid'):
            return jsonify({
                'success': False,
                'error': validation.get('error', 'Invalid license key')
            }), 400

        if save_license(key):
            return jsonify({
                'success': True,
                'message': 'License activated successfully',
                'expires': validation.get('expires')
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to save license'
            }), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/license/status', methods=['GET'])
@require_api_key
def api_license_status():
    """API-эндпоинт для проверки статуса лицензии"""
    try:
        from utils.license import load_license

        status = load_license()
        return jsonify(status)
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})

@app.route('/download/<filename>')
def download_file(filename):
    """Скачивание сгенерированного отчёта"""
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def open_browser():
    """Автоматическое открытие браузера при запуске"""
    webbrowser.open('http://127.0.0.1:5000')


if __name__ == '__main__':
    # Открываем браузер через 1 секунду после старта
    threading.Timer(1, open_browser).start()

    # Запускаем Flask сервер
    app.run(debug=False, host='0.0.0.0', port=5000)