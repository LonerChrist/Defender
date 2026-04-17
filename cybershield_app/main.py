from flask import Flask, render_template, request, jsonify
from core.password_analyzer import analyze_password
from core.email_checker import check_email_breach
from utils.security import require_api_key

app = Flask(__name__)

@app.route('/')
def index():
    """Главная страница веб-приложения"""
    return render_template('index.html')

@app.route('/api/check/email', methods=['POST'])
@require_api_key
def api_check_email():
    """API-эндпоинт для проверки email"""
    data = request.get_json()
    email = data.get('email')
    result = check_email_breach(email)
    return jsonify({'email': email, 'breaches': result})

@app.route('/api/check/password', methods=['POST'])
@require_api_key
def api_check_password():
    """API-эндпоинт для анализа пароля"""
    data = request.get_json()
    password = data.get('password')
    result = analyze_password(password)
    return jsonify(result)

@app.route('/report/<session_id>')
def generate_report(session_id):
    """Генерация и отображение отчёта"""
    return render_template('report.html', session_id=session_id)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)