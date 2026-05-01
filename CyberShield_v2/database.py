# -*- coding: utf-8 -*-
"""
Модуль работы с базой данных SQLite
"""

import sqlite3
import os
from datetime import datetime, timedelta
import hashlib
import secrets

DATABASE_PATH = 'cybershield.db'


def get_db_connection():
    """Получение подключения к базе данных"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Инициализация таблиц"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_valid BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT,
            risk_score REAL,
            risk_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            report_path TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            license_key TEXT UNIQUE NOT NULL,
            license_type TEXT DEFAULT 'standard',
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reset_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_valid BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()
    print("✓ База данных инициализирована")

def hash_password(password, salt=None):
    """Хеширование пароля с солью"""
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{password_hash}"


def verify_password(password, stored_hash):
    """Проверка пароля"""
    try:
        salt, hash_value = stored_hash.split(':')
        new_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return new_hash == hash_value
    except:
        return False

def create_user(email, password):
    """Создание нового пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        password_hash = hash_password(password)
        cursor.execute(
            'INSERT INTO users (email, password_hash) VALUES (?, ?)',
            (email, password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return {'success': True, 'user_id': user_id}
    except sqlite3.IntegrityError:
        return {'success': False, 'error': 'Email уже зарегистрирован'}
    finally:
        conn.close()


def get_user_by_email(email):
    """Получение пользователя по email"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    """Получение пользователя по ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None


def update_last_login(user_id):
    """Обновление времени последнего входа"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
        (user_id,)
    )
    conn.commit()
    conn.close()

def create_session(user_id):
    """Создание новой сессии"""
    conn = get_db_connection()
    cursor = conn.cursor()
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=24)

    cursor.execute('''
        INSERT INTO sessions (user_id, session_token, expires_at)
        VALUES (?, ?, ?)
    ''', (user_id, session_token, expires_at))

    conn.commit()
    conn.close()
    return session_token


def get_session_by_token(token):
    """Проверка сессии"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, u.email 
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND s.is_valid = 1 AND s.expires_at > CURRENT_TIMESTAMP
    ''', (token,))
    session = cursor.fetchone()
    conn.close()
    return dict(session) if session else None


def invalidate_session(token):
    """Завершение сессии"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE sessions SET is_valid = 0 WHERE session_token = ?',
        (token,)
    )
    conn.commit()
    conn.close()

def create_scan(user_id, scan_type, target, risk_score, risk_level, report_path=None):
    """Создание записи о сканировании"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (user_id, scan_type, target, risk_score, risk_level, report_path)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, scan_type, target, risk_score, risk_level, report_path))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_user_scans(user_id, limit=50):
    """Получение истории сканирований"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    ''', (user_id, limit))
    scans = cursor.fetchall()
    conn.close()
    return [dict(scan) for scan in scans]


def create_license(user_id, license_key, license_type, expires_at):
    """Создание лицензии"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO licenses (user_id, license_key, license_type, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (user_id, license_key, license_type, expires_at))
    conn.commit()
    conn.close()
    return True


def get_user_license(user_id):
    """Получение активной лицензии"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM licenses 
        WHERE user_id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP
        ORDER BY expires_at DESC LIMIT 1
    ''', (user_id,))
    license = cursor.fetchone()
    conn.close()
    return dict(license) if license else None


def get_statistics():
    """Получение общей статистики системы"""
    conn = get_db_connection()
    cursor = conn.cursor()

    stats = {}
    cursor.execute('SELECT COUNT(*) FROM users')
    stats['total_users'] = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM scans')
    stats['total_scans'] = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE is_active = 1 AND expires_at > CURRENT_TIMESTAMP')
    stats['active_licenses'] = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE DATE(created_at) = DATE('now')")
    stats['scans_today'] = cursor.fetchone()[0]

    conn.close()
    return stats

def create_reset_token(user_id):
    """Создание токена для сброса пароля"""
    conn = get_db_connection()
    cursor = conn.cursor()

    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=1)  # Токен действителен 1 час

    # Удаляем старые активные токены пользователя
    cursor.execute(
        'DELETE FROM password_reset_tokens WHERE user_id = ? AND is_valid = 1',
        (user_id,)
    )

    cursor.execute('''
        INSERT INTO password_reset_tokens (user_id, reset_token, expires_at)
        VALUES (?, ?, ?)
    ''', (user_id, reset_token, expires_at))

    conn.commit()
    conn.close()
    return reset_token


def get_reset_token(token):
    """Проверка токена сброса пароля"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT prt.*, u.email 
        FROM password_reset_tokens prt
        JOIN users u ON prt.user_id = u.id
        WHERE prt.reset_token = ? AND prt.is_valid = 1 AND prt.expires_at > CURRENT_TIMESTAMP
    ''', (token,))
    result = cursor.fetchone()
    conn.close()
    return dict(result) if result else None


def invalidate_reset_token(token):
    """Деактивация токена после использования"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE password_reset_tokens SET is_valid = 0 WHERE reset_token = ?',
        (token,)
    )
    conn.commit()
    conn.close()


def reset_user_password(user_id, new_password):
    """Сброс пароля пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = hash_password(new_password)
    cursor.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (password_hash, user_id)
    )
    conn.commit()
    conn.close()
    return True


def get_user_statistics(user_id):
    """Получение статистики конкретного пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()

    stats = {}

    cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,))
    stats['total_scans'] = cursor.fetchone()[0]

    cursor.execute('''
        SELECT risk_score, risk_level 
        FROM scans 
        WHERE user_id = ? AND scan_type = 'port_scan' 
        ORDER BY created_at DESC LIMIT 1
    ''', (user_id,))
    last_port_scan = cursor.fetchone()
    stats['open_ports'] = last_port_scan[0] if last_port_scan else 0

    cursor.execute('''
        SELECT COUNT(*) FROM scans 
        WHERE user_id = ? AND (
            scan_type = 'email' AND risk_score > 0 OR
            scan_type = 'password' AND risk_level IN ('weak', 'medium') OR
            scan_type = 'port_scan' AND risk_score > 0
        )
    ''', (user_id,))
    stats['problems_count'] = cursor.fetchone()[0]


    cursor.execute('''
        SELECT AVG(risk_score) FROM (
            SELECT risk_score FROM scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC LIMIT 10
        )
    ''', (user_id,))
    avg_risk = cursor.fetchone()[0]

    if avg_risk is None:
        stats['overall_risk'] = 'Не оценён'
    elif avg_risk >= 80:
        stats['overall_risk'] = 'Низкий'
    elif avg_risk >= 60:
        stats['overall_risk'] = 'Средний'
    else:
        stats['overall_risk'] = 'Высокий'

    conn.close()
    return stats

if __name__ == '__main__':
    init_database()
    print("✓ База данных готова к работе")