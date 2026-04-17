import requests
import base64
import os

DEHASHED_API_KEY = os.getenv('DEHASHED_API_KEY', 'd4658bf200c8fbcaef9cdfe3e713e1122e17500aa601085fb6ff2144a3027bf4')


def check_email_breach(email):
    """Проверка email на участие в утечках через Dehashed API"""
    if not email:
        return []

    try:
        url = "https://api.dehashed.com/search"
        headers = {
            "Accept": "application/json",
            "Authorization": "Basic " + base64.b64encode((DEHASHED_API_KEY + ":").encode()).decode()
        }
        params = {"query": f'email:"{email}"'}

        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()
            entries = data.get("entries", [])
            return [{'name': e.get('Name', 'Unknown'), 'date': e.get('BreachDate', 'N/A')} for e in entries[:10]]
        elif response.status_code == 404:
            return []
        else:
            return []
    except Exception:
        return []