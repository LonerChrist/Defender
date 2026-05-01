# -*- coding: utf-8 -*-
"""
CyberShield для ИП - Система аудита кибербезопасности
"""

from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, send_file, flash
)
from core.password_analyzer import analyze_password
from core.email_checker import check_email_breach
from core.port_scanner import PortScanner
from core.offline_password_checker import OfflinePasswordChecker
from utils.security import require_api_key, login_required, api_login_required
from utils.report_generator import PDFReportGenerator
from database import (
    init_database, create_user, get_user_by_email, get_user_by_id,
    update_last_login, create_session, get_session_by_token, invalidate_session,
    create_scan, get_user_scans, create_license, get_user_license,
    verify_password, create_reset_token, get_reset_token, invalidate_reset_token,
    reset_user_password, get_statistics, get_user_statistics

)
import os
import webbrowser
import threading
import hashlib
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(basedir, 'frontend', 'templates'),
    static_folder=os.path.join(basedir, 'frontend', 'static'),
    static_url_path='/static'
)

app.secret_key = os.getenv('SECRET_KEY', 'dev_secret_key_change_in_production')
init_database()
session_data = {}

SEVERITY_LABELS = {
    'critical': 'Критический',
    'high': 'Высокий',
    'medium': 'Средний',
    'low': 'Низкий'
}

PORT_EXPLANATIONS = {
    21: {
        'attack_vector': 'Злоумышленник может перехватить учётные данные.',
        'business_impact': 'Компрометация файлового обмена.',
        'user_guidance': 'Используйте SFTP вместо FTP.',
        'insurance_note': 'Фактор повышенного риска.'
    },
    23: {
        'attack_vector': 'Telnet не шифрует трафик.',
        'business_impact': 'Удалённый несанкционированный доступ.',
        'user_guidance': 'Используйте SSH.',
        'insurance_note': 'Неблагоприятный фактор.'
    },
    445: {
        'attack_vector': 'Порт SMB часто используется для атак.',
        'business_impact': 'Шифрование файлов, остановка работы.',
        'user_guidance': 'Оставляйте SMB только внутри доверенной сети.',
        'insurance_note': 'Повышает вероятность инцидента.'
    },
    3389: {
        'attack_vector': 'RDP часто атакуют через перебор паролей.',
        'business_impact': 'Доступ к рабочему столу, вымогательское ПО.',
        'user_guidance': 'Включите MFA и ограничение по IP.',
        'insurance_note': 'Существенный фактор риска.'
    },
    3306: {
        'attack_vector': 'Открытая БД может стать целью перебора.',
        'business_impact': 'Утечка клиентских данных.',
        'user_guidance': 'База не должна быть доступна из интернета.',
        'insurance_note': 'Ухудшает профиль защищённости.'
    },
    5432: {
        'attack_vector': 'При доступности PostgreSQL возможен подбор пароля.',
        'business_impact': 'Риск изменения или выгрузки данных.',
        'user_guidance': 'Ограничьте доступ доверенными адресами.',
        'insurance_note': 'Требует контроля доступа.'
    }
}


def _safe_dict(value):
    return value if isinstance(value, dict) else {}


def _safe_list(value):
    return value if isinstance(value, list) else []


def _risk_label(score):
    try:
        score = int(score)
    except Exception:
        score = 0
    if score >= 80:
        return 'Низкий'
    if score >= 60:
        return 'Средний'
    return 'Высокий'


def _underwriting_posture(score, critical_count):
    try:
        score = int(score)
        critical_count = int(critical_count)
    except Exception:
        return 'Требует дополнительного рассмотрения'
    if critical_count == 0 and score >= 80:
        return 'Базово приемлемый профиль риска'
    if critical_count <= 1 and score >= 60:
        return 'Приемлемый при условии выполнения корректирующих мер'
    return 'Требует корректирующих мер до страхового согласования'


def _build_findings(audit_data):
    findings = []
    critical_count = len([f for f in findings if f.get('severity') == 'critical'])
    high_count = len([f for f in findings if f.get('severity') == 'high'])
    medium_count = len([f for f in findings if f.get('severity') == 'medium'])

    warning_count = high_count + medium_count

    overall_score = 100

    overall_score -= critical_count * 30
    overall_score -= high_count * 20
    overall_score -= medium_count * 10

    if overall_score < 0:
        overall_score = 0

    audit_data['critical_count'] = critical_count
    audit_data['warning_count'] = warning_count
    audit_data['overall_score'] = overall_score
    email_data = _safe_dict(audit_data.get('email_check'))
    breaches = _safe_list(email_data.get('breaches'))
    breaches_count = email_data.get('breaches_count', len(breaches) if breaches else 0)

    if breaches_count:
        breach_names = []
        for breach in breaches[:5]:
            breach = _safe_dict(breach)
            name = breach.get('name')
            if name:
                breach_names.append(str(name))
        examples = ', '.join(breach_names) if breach_names else 'известных базах утечек'
        findings.append({
            'category': 'Email и учётные записи',
            'severity': 'high',
            'severity_label': SEVERITY_LABELS['high'],
            'title': 'Email обнаружен в известных утечках данных',
            'asset': email_data.get('email', 'Указанный email'),
            'description': f'Проверяемый адрес ранее встречался в {breaches_count} случае(ях) компрометации.',
            'attack_vector': 'При повторном использовании пароля возможен вход в сервисы.',
            'business_impact': 'Риск захвата почтового ящика и сброса паролей.',
            'user_guidance': 'Смените пароль, включите двухфакторную аутентификацию.',
            'insurer_relevance': 'Наличие скомпрометированных учётных данных увеличивает риск.',
            'recommendation_title': 'Защитить скомпрометированный email',
            'recommendation': 'Сменить пароль, включить 2FA, проверить активные сессии.'
        })

    password_data = _safe_dict(audit_data.get('password_analysis'))
    password_strength = str(password_data.get('strength', 'unknown'))
    password_score = int(password_data.get('score', 0) or 0)

    if password_data and password_strength not in ('strong', 'very_strong'):
        suggestions = _safe_list(password_data.get('suggestions'))
        findings.append({
            'category': 'Парольная политика',
            'severity': 'medium' if password_strength == 'medium' else 'high',
            'severity_label': SEVERITY_LABELS['medium' if password_strength == 'medium' else 'high'],
            'title': 'Пароль требует усиления',
            'asset': 'Проверяемая учётная запись',
            'description': f'Оценка надёжности пароля составила {password_score}/100.',
            'attack_vector': 'Слабые пароли атакуются перебором и словарными атаками.',
            'business_impact': 'Получение доступа к рабочим сервисам и почте.',
            'user_guidance': 'Используйте пароль-фразу не короче 12-14 символов.',
            'insurer_relevance': 'Зрелость парольной политики - базовый критерий оценки.',
            'recommendation_title': 'Усилить парольную защиту',
            'recommendation': suggestions[0] if suggestions else 'Увеличить длину пароля.'
        })

    port_scan = _safe_dict(audit_data.get('port_scan'))
    vulnerabilities = _safe_list(port_scan.get('vulnerabilities'))

    for vuln in vulnerabilities:
        vuln = _safe_dict(vuln)
        severity = str(vuln.get('severity', 'medium')).lower()
        port = vuln.get('port')
        service = vuln.get('service', 'Unknown')
        extra = PORT_EXPLANATIONS.get(port, {})

        findings.append({
            'category': 'Сетевая поверхность атаки',
            'severity': severity,
            'severity_label': SEVERITY_LABELS.get(severity, 'Средний'),
            'title': f'Открыт сетевой сервис {service} на порту {port}',
            'asset': f'{port_scan.get("host", "Хост")}:{port}',
            'description': vuln.get('description', 'Обнаружен сетевой сервис.'),
            'attack_vector': extra.get('attack_vector', 'Открытый сервис увеличивает поверхность атаки.'),
            'business_impact': extra.get('business_impact', 'Риск несанкционированного доступа.'),
            'user_guidance': extra.get('user_guidance', vuln.get('recommendation', 'Ограничьте доступ.')),
            'insurer_relevance': extra.get('insurance_note', 'Требует оценки компенсирующих мер.'),
            'recommendation_title': f'Снизить риск по сервису {service} ({port})',
            'recommendation': vuln.get('recommendation', 'Закрыть сервис или ограничить доступ.')
        })

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda item: severity_order.get(item.get('severity'), 9))
    return findings


def _build_recommendations(findings):
    recommendations = []
    seen = set()

    for index, finding in enumerate(findings, 1):
        title = finding.get('recommendation_title') or f'Корректирующая мера {index}'
        description = finding.get('recommendation') or finding.get('user_guidance') or 'Требуется действие.'
        key = (title.strip().lower(), description.strip().lower())
        if key in seen:
            continue
        seen.add(key)

        severity = finding.get('severity', 'medium')
        priority = 'Высокий приоритет' if severity in ('critical', 'high') else 'Плановый приоритет'

        recommendations.append({
            'title': title,
            'description': description,
            'priority': priority,
            'rationale': finding.get('attack_vector', ''),
            'business_effect': finding.get('business_impact', ''),
            'for_non_technical_user': finding.get('user_guidance', ''),
            'category': finding.get('category', ''),
            'severity': severity,
            'severity_label': finding.get('severity_label', SEVERITY_LABELS.get(severity, 'Средний'))
        })

    if not recommendations:
        recommendations.append({
            'title': 'Поддерживать текущий уровень защиты',
            'description': 'Критичных замечаний не обнаружено. Рекомендуется повторять аудит ежеквартально.',
            'priority': 'Плановый приоритет',
            'rationale': 'Риск изменяется после обновлений и смены сотрудников.',
            'business_effect': 'Регулярный контроль снижает вероятность инцидента.',
            'for_non_technical_user': 'Запланируйте повторную проверку.',
            'category': 'Общий контроль',
            'severity': 'low',
            'severity_label': 'Низкий'
        })

    return recommendations


def _build_insurance_profile(audit_data, findings):
    score = audit_data.get('overall_score', 0)
    critical_count = audit_data.get('critical_count', 0)
    warning_count = audit_data.get('warning_count', 0)

    negative_factors = []
    positive_factors = []

    if findings:
        for finding in findings[:5]:
            negative_factors.append(f"{finding.get('severity_label', 'Средний')} риск: {finding.get('title', 'Выявлено замечание')}")
    else:
        positive_factors.append('По выполненным проверкам выраженных уязвимостей не обнаружено.')

    password_data = _safe_dict(audit_data.get('password_analysis'))
    if password_data and str(password_data.get('strength', 'unknown')) in ('strong', 'very_strong'):
        positive_factors.append('Проверенный пароль имеет приемлемый или высокий уровень стойкости.')

    email_data = _safe_dict(audit_data.get('email_check'))
    if email_data and not email_data.get('breaches_count'):
        positive_factors.append('Проверенный email не найден в известных публичных утечках.')

    port_data = _safe_dict(audit_data.get('port_scan'))
    if port_data and not _safe_list(port_data.get('vulnerabilities')):
        positive_factors.append('По стандартному набору проверенных портов опасные сетевые сервисы не выявлены.')

    return {
        'assessment_basis': 'Экспресс-аудит технической защищённости по внешним и пользовательским признакам риска.',
        'target': audit_data.get('target', 'Информационная система ИП'),
        'overall_risk': _risk_label(score),
        'underwriting_posture': _underwriting_posture(score, critical_count),
        'critical_count': critical_count,
        'warning_count': warning_count,
        'negative_factors': negative_factors,
        'positive_factors': positive_factors,
        'residual_risk_note': 'Отчёт предназначен для первичной андеррайтинговой оценки и не заменяет полный технический аудит, тест на проникновение или проверку конфигурации всех узлов.',
        'insurer_summary': 'Отчёт содержит краткий вывод, перечень факторов риска, корректирующие меры и комментарий по остаточному риску.'
    }

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    """Страница регистрации нового пользователя"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not email or not password:
            return render_template('register.html', error='Email и пароль обязательны')

        if password != confirm_password:
            return render_template('register.html', error='Пароли не совпадают')

        if len(password) < 6:
            return render_template('register.html', error='Пароль должен быть минимум 6 символов')

        result = create_user(email, password)

        if result['success']:
            return redirect(url_for('login_page'))
        else:
            return render_template('register.html', error=result['error'])

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Страница входа пользователя"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = get_user_by_email(email)

        if not user:
            return render_template('login.html', error='Пользователь не найден')

        if not verify_password(password, user['password_hash']):
            return render_template('login.html', error='Неверный пароль')

        session_token = create_session(user['id'])
        session['user_id'] = user['id']
        session['session_token'] = session_token
        session['email'] = user['email']

        update_last_login(user['id'])

        return redirect(url_for('dashboard_page'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Выход из системы и завершение сессии"""
    if 'session_token' in session:
        invalidate_session(session['session_token'])
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    """Страница запроса сброса пароля"""
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            return render_template('forgot_password.html', error='Введите email')

        user = get_user_by_email(email)

        if not user:
            return render_template('forgot_password.html',
                                   success='Если email зарегистрирован, инструкция отправлена')

        reset_token = create_reset_token(user['id'])
        reset_link = f"http://127.0.0.1:5000/reset-password?token={reset_token}"

        return render_template('forgot_password.html',
                               success='Инструкция отправлена',
                               demo_token=reset_token,
                               demo_link=reset_link)

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_page():
    """Страница установки нового пароля"""
    token = request.args.get('token')

    if not token:
        return render_template('reset_password.html', error='Токен не указан')

    token_data = get_reset_token(token)

    if not token_data:
        return render_template('reset_password.html', error='Токен недействителен или истёк')

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or len(new_password) < 6:
            return render_template('reset_password.html',
                                   error='Пароль должен быть минимум 6 символов',
                                   token=token)

        if new_password != confirm_password:
            return render_template('reset_password.html',
                                   error='Пароли не совпадают',
                                   token=token)

        reset_user_password(token_data['user_id'], new_password)
        invalidate_reset_token(token)

        return render_template('reset_password.html', success='Пароль успешно изменён')

    return render_template('reset_password.html', token=token)

@app.route('/')
def index():
    """Главная страница - редирект на вход или кабинет"""
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return redirect(url_for('login_page'))


@app.route('/dashboard')
@login_required
def dashboard_page():
    """Личный кабинет пользователя"""
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    scans = get_user_scans(user_id, limit=10)
    license_info = get_user_license(user_id)

    user_stats = get_user_statistics(user_id)

    return render_template('dashboard.html',
                           user=user,
                           scans=scans,
                           license=license_info,
                           stats=user_stats)


@app.route('/profile')
@login_required
def profile_page():
    """Страница профиля пользователя"""
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    license_info = get_user_license(user_id)

    return render_template('profile.html', user=user, license=license_info)


@app.route('/report/<session_id>')
def generate_report(session_id):
    """Генерация и отображение отчёта"""
    data = session_data.get(session_id, {})
    return render_template('report.html', session_id=session_id, data=data)

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """API регистрации нового пользователя"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email и пароль обязательны'}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    result = create_user(email, password_hash)

    if result['success']:
        return jsonify({
            'message': 'Пользователь зарегистрирован',
            'user_id': result['user_id']
        }), 201
    else:
        return jsonify({'error': result['error']}), 400


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API входа пользователя"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = get_user_by_email(email)

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user['password_hash'] != password_hash:
        return jsonify({'error': 'Неверный пароль'}), 401

    update_last_login(user['id'])
    session_token = hashlib.sha256(f"{user['id']}{datetime.now().isoformat()}".encode()).hexdigest()

    return jsonify({
        'message': 'Вход выполнен успешно',
        'user_id': user['id'],
        'email': user['email'],
        'session_token': session_token
    })


@app.route('/api/check/email', methods=['POST'])
@api_login_required
@require_api_key
def api_check_email():
    """API проверки email на участие в утечках"""
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    result = check_email_breach(email)

    create_scan(
        user_id=session['user_id'],
        scan_type='email',
        target=email,
        risk_score=len(result) * 20,
        risk_level='high' if len(result) > 0 else 'low'
    )

    return jsonify({
        'email': email,
        'breaches': result,
        'breaches_count': len(result)
    })


@app.route('/api/check/password', methods=['POST'])
@api_login_required
@require_api_key
def api_check_password():
    """API анализа надёжности пароля"""
    data = request.get_json()
    password = data.get('password')

    if not password:
        return jsonify({'error': 'Password is required'}), 400

    result = analyze_password(password)

    create_scan(
        user_id=session['user_id'],
        scan_type='password',
        target='Password Analysis',
        risk_score=result.get('score', 0),
        risk_level=result.get('strength', 'unknown')
    )

    return jsonify(result)


@app.route('/api/check/password/offline', methods=['POST'])
@require_api_key
def api_check_password_offline():
    """API оффлайн анализа пароля"""
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
@api_login_required
@require_api_key
def api_scan_ports():
    """API сканирования сетевых портов"""
    try:
        data = request.get_json()
        host = data.get('host', 'localhost')

        scanner = PortScanner(host=host)
        open_ports = scanner.scan()
        vulnerabilities = scanner.get_vulnerabilities()

        create_scan(
            user_id=session['user_id'],
            scan_type='port_scan',
            target=host,
            risk_score=len(vulnerabilities) * 30,
            risk_level='high' if len(vulnerabilities) > 0 else 'low'
        )

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
    """API генерации PDF отчёта"""
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

        findings = _build_findings(audit_data)
        detailed_recommendations = _build_recommendations(findings)
        insurance_profile = _build_insurance_profile(audit_data, findings)

        audit_data['findings'] = findings
        audit_data['recommendations'] = detailed_recommendations
        audit_data['insurance_profile'] = insurance_profile
        audit_data['executive_summary'] = (
            'Отчёт содержит описание выявленных рисков, возможных сценариев атаки, '
            'последствий для бизнеса и рекомендуемых корректирующих мер.'
        )

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
        print(f"Ошибка генерации отчёта: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/license/activate', methods=['POST'])
@require_api_key
def api_activate_license():
    """API активации лицензии"""
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
    """API проверки статуса лицензии"""
    try:
        from utils.license import load_license
        status = load_license()
        return jsonify(status)
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})


@app.route('/api/user/scans', methods=['GET'])
@require_api_key
def api_get_user_scans():
    """API получения истории сканирований пользователя"""
    user_id = request.headers.get('X-User-ID')

    if not user_id:
        return jsonify({'error': 'User-ID не указан'}), 400

    scans = get_user_scans(int(user_id))

    return jsonify({
        'scans': scans,
        'total': len(scans)
    })


@app.route('/api/user/license', methods=['GET'])
@require_api_key
def api_get_user_license():
    """API получения информации о лицензии"""
    user_id = request.headers.get('X-User-ID')

    if not user_id:
        return jsonify({'error': 'User-ID не указан'}), 400

    license_info = get_user_license(int(user_id))

    if license_info:
        return jsonify({
            'has_license': True,
            'license_type': license_info['license_type'],
            'expires_at': license_info['expires_at']
        })
    else:
        return jsonify({'has_license': False})


@app.route('/api/admin/statistics', methods=['GET'])
@require_api_key
def api_get_statistics():
    """API получения общей статистики системы"""
    stats = get_statistics()
    return jsonify(stats)


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
    threading.Timer(1, open_browser).start()
    app.run(debug=False, host='0.0.0.0', port=5000)