import re
import hashlib
import os
import json


class OfflinePasswordChecker:

    COMMON_PASSWORDS = {
        '123456', 'password', '12345678', 'qwerty', '123456789',
        '12345', '1234', '111111', '1234567', 'dragon',
        '123123', 'baseball', 'abc123', 'football', 'monkey',
        'letmein', '696969', 'shadow', 'master', '666666',
        'qwertyuiop', '123321', 'mustang', '1234567890',
        'admin', 'admin123', 'root', 'toor', 'passw0rd'
    }


    WEAK_PATTERNS = [
        r'^[0-9]+$',
        r'^[a-z]+$',
        r'^[A-Z]+$',
        r'(.)\1{2,}',
        r'(012|123|234|345|456|567|678|789)',
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',

    ]

    def __init__(self, custom_dictionary_path=None):
        self.custom_passwords = set()
        if custom_dictionary_path and os.path.exists(custom_dictionary_path):
            self.load_custom_dictionary(custom_dictionary_path)

    def load_custom_dictionary(self, path):
        """Загрузка пользовательского словаря паролей"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    self.custom_passwords.add(line.strip().lower())
        except Exception:
            pass

    def check_strength(self, password):
        """
        Комплексная проверка надежности пароля
        :return: dict с результатами анализа
        """
        result = {
            'length': len(password),
            'score': 0,
            'max_score': 100,
            'strength': 'very_weak',
            'issues': [],
            'suggestions': [],
            'entropy': 0,
            'crack_time': 'instant'
        }

        if not password:
            result['issues'].append('Пароль пустой')
            return result

        if len(password) < 8:
            result['issues'].append('Пароль слишком короткий (минимум 8 символов)')
            result['suggestions'].append('Увеличьте длину пароля до 12+ символов')
        elif len(password) >= 12:
            result['score'] += 20
        elif len(password) >= 8:
            result['score'] += 10

        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        char_types = sum([has_lower, has_upper, has_digit, has_special])

        if char_types == 1:
            result['issues'].append('Используйте только один тип символов')
            result['suggestions'].append('Добавьте заглавные буквы, цифры и спецсимволы')
        elif char_types == 2:
            result['score'] += 10
        elif char_types == 3:
            result['score'] += 20
            result['score'] += 30

        if password.lower() in self.COMMON_PASSWORDS or password.lower() in self.custom_passwords:
            result['issues'].append('Пароль находится в списке популярных')
            result['suggestions'].append('Используйте уникальный пароль')
            result['strength'] = 'very_weak'
            return result

        for pattern in self.WEAK_PATTERNS:
            if re.search(pattern, password.lower()):
                result['issues'].append('Обнаружен слабый шаблон в пароле')
                result['suggestions'].append('Избегайте последовательностей и повторений')
                break

        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_special:
            pool_size += 32

        if pool_size > 0:
            result['entropy'] = len(password) * (pool_size).bit_length()

        result['crack_time'] = self.estimate_crack_time(result['entropy'])

        if result['score'] >= 80:
            result['strength'] = 'very_strong'
        elif result['score'] >= 60:
            result['strength'] = 'strong'
        elif result['score'] >= 40:
            result['strength'] = 'medium'
        elif result['score'] >= 20:
            result['strength'] = 'weak'
        else:
            result['strength'] = 'very_weak'

        return result

    def estimate_crack_time(self, entropy):
        """Оценка времени взлома пароля"""
        if entropy < 28:
            return 'мгновенно'
        elif entropy < 36:
            return 'несколько секунд'
        elif entropy < 60:
            return 'несколько минут'
        elif entropy < 80:
            return 'несколько часов'
        elif entropy < 100:
            return 'несколько дней'
        elif entropy < 120:
            return 'несколько лет'
        else:
            return 'века'

    def check_password_hash_in_breach(self, password, breach_database_path=None):
        """
        Проверка хеша пароля в локальной базе утечек
        :param password: пароль для проверки
        :param breach_database_path: путь к базе хешей скомпрометированных паролей
        :return: bool (True если найден в утечке)
        """
        if not breach_database_path or not os.path.exists(breach_database_path):
            return False

        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        try:
            with open(breach_database_path, 'r') as f:
                for line in f:
                    if password_hash in line:
                        return True
        except Exception:
            pass

        return False