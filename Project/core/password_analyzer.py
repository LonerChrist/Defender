import hashlib
import requests
import re
import os
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'password_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'scaler.pkl')


def extract_password_features(password):
    """Извлечение признаков из пароля для модели МО"""
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
    """Анализ надёжности пароля"""
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


def check_password_breach(password, timeout=10):
    """Проверка пароля через Pwned Passwords API"""
    try:
        sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1password[:5], sha1password[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=timeout)

        if response.status_code != 200:
            return None

        for line in response.text.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':', 1)
                if hash_suffix == suffix:
                    return int(count)
        return 0
    except Exception:
        return None


def predict_password_risk(password):
    """Прогноз риска компрометации пароля"""
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            model = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            features = extract_password_features(password)
            features_scaled = scaler.transform([features])
            prob = model.predict_proba(features_scaled)[0][1]
            return {'probability': round(prob, 3), 'level': 'high' if prob > 0.7 else 'medium' if prob > 0.4 else 'low'}
    except Exception:
        pass
    return {'probability': 0.5, 'level': 'unknown'}