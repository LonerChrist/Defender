# -*- coding: utf-8 -*-

import hashlib
import requests
import re
import os
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'password_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'scaler.pkl')

from core.offline_password_checker import OfflinePasswordChecker

def extract_password_features(password):

    features = []
    features.append(min(len(password), 32) / 32.0)
    features.append(1 if re.search(r"[a-z]", password) else 0)
    features.append(1 if re.search(r"[A-Z]", password) else 0)
    features.append(1 if re.search(r"\d", password) else 0)
    features.append(1 if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) else 0)
    features.append(len(set(password)) / len(password) if len(password) > 0 else 0)
    features.append(1 if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def)", password.lower()) else 0)
    features.append(1 if re.search(r"(.)\1{2,}", password) else 0)
    return features


def analyze_password(password):
    if not password:
        return {'error': 'Password is required'}

    score = sum([
        len(password) >= 8,
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    ])

    breach_count = check_password_breach(password)

    ml_risk = predict_password_risk(password)

    return {
        'password_length': len(password),
        'strength_score': score,
        'breach_count': breach_count,
        'ml_risk': ml_risk
    }


def analyze_password(password):
    if not password:
        return {'error': 'Password is required'}

    ml_result = predict_password_risk(password)

    checker = OfflinePasswordChecker()
    offline_result = checker.check_strength(password)

    breach_count = check_password_breach(password)

    return {
        'length': len(password),
        'entropy': offline_result.get('entropy', 0),
        'crack_time': offline_result.get('crack_time', 'N/A'),
        'breach_count': breach_count if breach_count is not None else 0,
        'score': offline_result.get('score', 0),
        'strength': offline_result.get('strength', 'unknown'),
        'ml_risk': ml_result,
        'issues': offline_result.get('issues', []),
        'suggestions': offline_result.get('suggestions', [])
    }


def predict_password_risk(password, model=None, scaler=None, model_path=None, scaler_path=None):


    if model_path is None:
        model_path = "models/password_model.pkl"
    if scaler_path is None:
        scaler_path = "models/scaler.pkl"

    try:

        if model is None or scaler is None:
            import joblib
            import os
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                model = joblib.load(model_path)
                scaler = joblib.load(scaler_path)
            else:
                return {'probability': 0.5, 'level': 'unknown'}

        # Извлечение признаков
        features = extract_password_features(password)
        features_scaled = scaler.transform([features])

        # Прогноз вероятности
        prob = model.predict_proba(features_scaled)[0][1]

        # Классификация уровня риска
        if prob > 0.7:
            level = 'high'
        elif prob > 0.4:
            level = 'medium'
        else:
            level = 'low'

        return {'probability': round(prob, 3), 'level': level}

    except Exception:
        return {'probability': 0.5, 'level': 'unknown'}


def extract_password_features(password):
    import re

    features = []

    # Нормализованная длина (0-1)
    features.append(min(len(password), 32) / 32.0)

    # Наличие разных типов символов (бинарные признаки)
    features.append(1 if re.search(r"[a-z]", password) else 0)  # строчные
    features.append(1 if re.search(r"[A-Z]", password) else 0)  # заглавные
    features.append(1 if re.search(r"\d", password) else 0)  # цифры
    features.append(1 if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) else 0)  # спецсимволы

    # Разнообразие символов
    features.append(len(set(password)) / len(password) if len(password) > 0 else 0)

    # Наличие последовательностей (123, abc)
    features.append(1 if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def)", password.lower()) else 0)

    # Наличие повторений (aaa, 111)
    features.append(1 if re.search(r"(.)\1{2,}", password) else 0)

    return features


def check_password_breach(password, timeout=10):
    """
    Проверка пароля через Pwned Passwords API (k-anonymity)

    :param password: Пароль для проверки
    :param timeout: Таймаут запроса в секундах
    :return: Количество вхождений пароля в утечки или None при ошибке
    """
    try:
        # SHA1-хеш пароля
        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1password[:5], sha1password[5:]

        # Запрос к API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=timeout)

        if response.status_code != 200:
            return None

        # Поиск суффикса в ответе
        for line in response.text.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':', 1)
                if hash_suffix == suffix:
                    return int(count)

        return 0  # Не найдено в утечках

    except Exception:
        return None