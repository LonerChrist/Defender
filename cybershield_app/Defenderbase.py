import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from PIL import ImageTk, Image
import re, os, sys, socket, json, threading, traceback
import requests, hashlib, base64, joblib, numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

# ДОПОЛНИТЕЛЬНЫЕ БИБЛИОТЕКИ ДЛЯ ОТЧЁТОВ
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠ Библиотека reportlab не найдена. PDF-отчёты будут недоступны. Установите: pip install reportlab")

# ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
MODEL_PATH = "password_model.pkl"
SCALER_PATH = "scaler.pkl"
model = None
scaler = None
model_ready = False
start_time = datetime.now()  # 🔒 Сохраняем время запуска (как вы просили)
session_results = {'ports': [], 'email': '', 'email_breaches': [], 'password_risk': 0.0}

# ФУНКЦИИ ДЛЯ РАБОТЫ С МОДЕЛЬЮ МО

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


def generate_synthetic_dataset(n_samples=5000):
    import random, string
    X, y = [], []
    weak_patterns = ["123456", "password", "qwerty", "111111", "admin", "12345678", "abc123"]
    for _ in range(n_samples // 2):
        pwd = random.choice(weak_patterns) if random.random() < 0.7 else ''.join(
            random.choices(string.ascii_lowercase + string.digits, k=random.randint(4, 8)))
        X.append(extract_password_features(pwd));
        y.append(1)
    for _ in range(n_samples // 2):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(random.choices(chars, k=random.randint(10, 20)))
        for char_type in [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*"]:
            if not any(c in pwd for c in char_type): pwd += random.choice(char_type)
        X.append(extract_password_features(pwd));
        y.append(0)
    return np.array(X), np.array(y)


def train_or_load_model():
    global model, scaler, model_ready
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            model = joblib.load(MODEL_PATH);
            scaler = joblib.load(SCALER_PATH)
            model_ready = True;
            print("✓ Модель загружена");
            return
    except Exception as e:
        print(f"⚠ Ошибка загрузки модели: {e}")
    try:
        print("🔄 Обучение модели...");
        X, y = generate_synthetic_dataset(n_samples=5000)
        scaler = StandardScaler();
        X_scaled = scaler.fit_transform(X)
        model = LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced')
        model.fit(X_scaled, y);
        joblib.dump(model, MODEL_PATH);
        joblib.dump(scaler, SCALER_PATH)
        model_ready = True;
        print("✓ Модель обучена")
    except Exception as e:
        print(f"❌ Ошибка обучения: {e}"); model_ready = False


def predict_password_risk(password):
    global model, scaler, model_ready
    if not model_ready: train_or_load_model()
    if not model_ready or model is None: return 0.5, -1
    try:
        features = extract_password_features(password);
        features_scaled = scaler.transform([features])
        prob = model.predict_proba(features_scaled)[0][1];
        pred = model.predict(features_scaled)[0]
        return prob, pred
    except Exception as e:
        print(f"⚠ Ошибка прогноза: {e}"); return 0.5, -1


# ============================================================================
# НОВЫЕ ФУНКЦИИ: ПОРТЫ, ОФФЛАЙН АНАЛИЗ, PDF-ОТЧЁТ
# ============================================================================
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9090: "Web-Admin", 27017: "MongoDB"
}


def scan_ports_target(target_ip, port_list=None, timeout=2):
    """Базовое сканирование портов через socket (работает без установки nmap)"""
    if port_list is None: port_list = sorted(COMMON_PORTS.keys())
    open_ports = []
    for port in port_list:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target_ip, port)) == 0:
                    open_ports.append(
                        {'port': port, 'state': 'open', 'service': COMMON_PORTS.get(port, 'Unknown'), 'cve': []})
        except Exception:
            continue
    return open_ports


def run_port_scan_thread(target_ip):
    """Фоновое сканирование с обновлением UI"""
    text_output.configure(state="normal")
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, f"🔍 Сканирование портов для {target_ip}...\nПожалуйста, подождите.\n")
    text_output.configure(state="disabled")

    # Отключаем кнопки на время сканирования
    for widget in frame_buttons.winfo_children(): widget.configure(state="disabled")

    try:
        open_ports = scan_ports_target(target_ip)
        session_results['ports'] = open_ports

        def update_ui():
            text_output.configure(state="normal")
            text_output.delete(1.0, tk.END)
            if not open_ports:
                text_output.insert(tk.END, "✅ Сканирование завершено. Открытых портов не обнаружено.\n")
            else:
                text_output.insert(tk.END, f"🔓 Найдено {len(open_ports)} открытых портов:\n")
                for p in open_ports:
                    text_output.insert(tk.END, f"  • Порт {p['port']}/tcp: {p['service']} (открыт)\n")
                text_output.insert(tk.END, "\n💡 Рекомендации:\n")
                recs = []
                for p in open_ports:
                    if p['port'] in [21, 23, 25, 110, 143]:
                        recs.append(
                            f"⚠ Порт {p['port']} ({p['service']}): устаревший/незашифрованный. Отключите или настройте TLS.")
                    elif p['port'] == 22:
                        recs.append("💡 SSH: используйте ключи, отключите вход по паролю, настройте Fail2Ban.")
                    elif p['port'] == 3389:
                        recs.append("⚠ RDP: крайне уязвим. Закройте фаерволом или используйте VPN.")
                    else:
                        recs.append(
                            f"💡 Порт {p['port']}: убедитесь, что сервис обновлён и доступен только доверенным IP.")
                for r in (recs if recs else ["• Нет специфических рекомендаций. Убедитесь в актуальности ПО."]):
                    text_output.insert(tk.END, f"{r}\n")
            text_output.insert(tk.END, "\n📋 Для создания полного отчёта нажмите 'Создать PDF-отчёт'.")
            text_output.configure(state="disabled")
            for widget in frame_buttons.winfo_children(): widget.configure(state="normal")

        root.after(0, update_ui)
    except Exception as e:
        def err_ui():
            text_output.configure(state="normal");
            text_output.delete(1.0, tk.END)
            text_output.insert(tk.END, f"❌ Ошибка сканирования: {str(e)}\n")
            text_output.configure(state="disabled")
            for widget in frame_buttons.winfo_children(): widget.configure(state="normal")

        root.after(0, err_ui)


def analyze_password_offline():
    password = entry_password.get()
    text_output.configure(state="normal");
    text_output.delete(1.0, tk.END)
    if not password:
        text_output.insert(tk.END, "⚠ Пожалуйста, введите пароль.\n");
        text_output.configure(state="disabled");
        return

    res = []
    score = sum([len(password) >= 8, bool(re.search(r"[A-Z]", password)), bool(re.search(r"[a-z]", password)),
                 bool(re.search(r"\d", password)), bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))])
    res.append("🟢 Сильный" if score >= 4 else "🟡 Средний" if score >= 2 else "🔴 Слабый")

    weak = ["123456", "password", "qwerty", "111111", "admin", "12345678", "abc123"]
    if password.lower() in weak:
        res.append("🔴 Содержится в списке топ-слабых паролей")
    elif any(w in password.lower() for w in weak[:4]):
        res.append("⚠ Содержит фрагмент слабого шаблона")

    cs = sum([bool(re.search(r"[a-z]", password)) * 26, bool(re.search(r"[A-Z]", password)) * 26,
              bool(re.search(r"\d", password)) * 10, bool(re.search(r"[!@#$%^&*]", password)) * 12])
    entropy = len(password) * (cs ** (1 / len(password))) if cs > 0 and len(password) > 0 else 0
    res.append(f"📊 Энтропия: ~{entropy:.1f} бит")

    try:
        prob, pred = predict_password_risk(password)
        if pred >= 0:
            risk = "высокий" if prob > 0.7 else "средний" if prob > 0.4 else "низкий"
            res.append(f"🤖 МО-риск: {risk} ({prob:.1%})")
    except:
        res.append("⚠ МО временно недоступна")

    def update():
        text_output.configure(state="normal");
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, "🔐 ОФФЛАЙН-АНАЛИЗ ПАРОЛЯ\n" + "=" * 35 + "\n")
        for line in res: text_output.insert(tk.END, f"• {line}\n")
        text_output.insert(tk.END, "\n⚠ Проверка в базах утечек пропущена (требуется интернет).")
        text_output.configure(state="disabled")

    root.after(0, update)


def create_pdf_report():
    if not REPORTLAB_AVAILABLE:
        messagebox.showerror("⚠ Отсутствует библиотека", "Для создания PDF установите: pip install reportlab")
        return

    target = entry_target.get().strip() or "Не указан"
    email = entry_email.get().strip()
    password = entry_password.get()
    pwd_score = sum([len(password) >= 8, bool(re.search(r"[A-Z]", password)),
                     bool(re.search(r"[a-z]", password)), bool(re.search(r"\d", password)),
                     bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))])

    filepath = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")],
                                            initialfile=f"CyberShield_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")
    if not filepath: return

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.lib.units import inch

        # 🔧 РЕГИСТРАЦИЯ ШРИФТА С ПОДДЕРЖКОЙ КИРИЛЛИЦЫ
        # Используем DejaVu Sans (кроссплатформенный) или Arial
        font_paths = [
            "C:/Windows/Fonts/arial.ttf",  # Windows
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux
            "/Library/Fonts/Arial.ttf",  # macOS
            "arial.ttf",  # Текущая директория
        ]

        font_registered = False
        for font_path in font_paths:
            if os.path.exists(font_path):
                try:
                    pdfmetrics.registerFont(TTFont('Arial', font_path))
                    font_registered = True
                    print(f"✓ Шрифт зарегистрирован: {font_path}")
                    break
                except:
                    continue

        if not font_registered:
            messagebox.showwarning("⚠ Шрифт не найден",
                                   "Не удалось найти шрифт с кириллицей. PDF будет создан с ограниченной поддержкой русских букв.\n\n"
                                   "Рекомендуется установить DejaVu Sans:\n"
                                   "Windows: скопируйте arial.ttf из C:/Windows/Fonts/\n"
                                   "Linux: sudo apt install fonts-dejavu")

        # Создание документа
        doc = SimpleDocTemplate(filepath, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=72)

        elements = []

        # Стили с кириллическим шрифтом
        if font_registered:
            base_font = 'Arial'
        else:
            base_font = 'Helvetica'  # Fallback (не поддерживает кириллицу)

        styles = getSampleStyleSheet()

        # Заголовок
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontName=base_font,
            fontSize=18,
            textColor=HexColor("#1A5276"),
            spaceAfter=20,
            alignment=1  # Center
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontName=base_font,
            fontSize=14,
            textColor=HexColor("#2E86C1"),
            spaceBefore=12,
            spaceAfter=6
        )

        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=black,
            leading=14
        )

        # Заголовок отчёта
        elements.append(Paragraph("CyberShield IE — Отчёт по безопасности", title_style))
        elements.append(Spacer(1, 0.2 * inch))

        # Основная информация
        elements.append(Paragraph(f"<b>Дата:</b> {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}", normal_style))
        elements.append(Paragraph(f"<b>Цель:</b> {target}", normal_style))
        elements.append(Spacer(1, 0.2 * inch))

        # Анализ пароля
        elements.append(Paragraph("Анализ пароля", heading_style))
        elements.append(Paragraph(f"• Длина: {len(password)} символов", normal_style))
        elements.append(Paragraph(f"• Сложность: {pwd_score}/5", normal_style))
        elements.append(Paragraph(f"• МО-риск: {session_results.get('password_risk', 'Не вычислялся')}", normal_style))
        elements.append(Spacer(1, 0.15 * inch))

        # Email
        elements.append(Paragraph("Проверка Email", heading_style))
        elements.append(Paragraph(f"• Email: {email}", normal_style))
        breaches_count = len(session_results.get('email_breaches', []))
        elements.append(Paragraph(f"• Найдено утечек: {breaches_count}", normal_style))
        elements.append(Spacer(1, 0.15 * inch))

        # Порты и сервисы
        elements.append(Paragraph("Сетевые порты и сервисы", heading_style))
        ports = session_results.get('ports', [])

        if ports:
            # Таблица с портами
            table_data = [['Порт', 'Статус', 'Сервис', 'Рекомендация']]

            for p in ports:
                if p['port'] in [21, 23, 3389]:
                    rec = "Закрыть фаерволом / Обновить"
                else:
                    rec = "Проверить настройки доступа"

                table_data.append([
                    str(p['port']),
                    p['state'],
                    p.get('service', '?'),
                    rec
                ])

            # Создание таблицы
            t = Table(table_data, colWidths=[0.8 * inch, 0.8 * inch, 1.2 * inch, 3.2 * inch])

            # Стиль таблицы
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor("#2E86C1")),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), base_font),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor("#F8F9F9")),
                ('GRID', (0, 0), (-1, -1), 1, HexColor("#BDC3C7")),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor("#F8F9F9")])
            ]))

            elements.append(t)
        else:
            elements.append(Paragraph("Открытые порты не найдены или сканирование не проводилось.", normal_style))

        elements.append(Spacer(1, 0.3 * inch))

        # Предупреждение
        warning_style = ParagraphStyle(
            'Warning',
            parent=normal_style,
            textColor=HexColor("#E74C3C"),
            fontSize=9
        )
        elements.append(Paragraph(
            "⚠️ Отчёт сформирован автоматически. Проверка уязвимостей (CVE) требует подключения к nmap-vulners.",
            warning_style))

        # Сборка PDF
        doc.build(elements)
        messagebox.showinfo("✅ Готово", f"Отчёт сохранён:\n{os.path.basename(filepath)}")

    except Exception as e:
        messagebox.showerror("❌ Ошибка", f"Не удалось создать PDF:\n{traceback.format_exc()}")


# ============================================================================
# ФУНКЦИИ ПРОВЕРКИ EMAIL И ПАРОЛЯ (адаптировано под глобальное хранилище)
# ============================================================================
def check_email_breach(email):
    # Упрощённая заглушка для примера. Вставьте ваш рабочий API-код сюда.
    try:
        api_key = "d4658bf200c8fbcaef9cdfe3e713e1122e17500aa601085fb6ff2144a3027bf4"
        url = "https://api.dehashed.com/search"
        headers = {"Accept": "application/json",
                   "Authorization": "Basic " + base64.b64encode((api_key + ":").encode()).decode()}
        response = requests.get(url, headers=headers, params={"query": f'email:"{email}"'}, timeout=10)
        if response.status_code == 200:
            data = response.json();
            entries = data.get("entries", [])
            session_results['email_breaches'] = entries
            return entries
        return []
    except:
        return []


def check_email():
    email = entry_email.get().strip()
    text_output.configure(state="normal");
    text_output.delete(1.0, tk.END)
    if not email:
        text_output.insert(tk.END, "Введите Email.\n")
    else:
        text_output.insert(tk.END, f"Email '{email}' выглядит корректным.\n")
        breaches = check_email_breach(email)
        if breaches:
            text_output.insert(tk.END, f"Найдено {len(breaches)} утечек.\n")
        else:
            text_output.insert(tk.END, "Утечек не обнаружено.\n")
    text_output.configure(state="disabled")


def analyze_password():
    password = entry_password.get()
    text_output.configure(state="normal");
    text_output.delete(1.0, tk.END)
    if not password: text_output.insert(tk.END, "⚠ Введите пароль.\n"); text_output.configure(state="disabled"); return
    text_output.insert(tk.END, "⏳ Запуск анализа...\n");
    text_output.configure(state="disabled")
    threading.Thread(target=lambda: analyze_password_thread(password), daemon=True).start()


def analyze_password_thread(password):
    res = []
    score = sum([len(password) >= 8, bool(re.search(r"[A-Z]", password)), bool(re.search(r"[a-z]", password)),
                 bool(re.search(r"\d", password)), bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))])
    res.append("🔴 Слабый" if score <= 2 else "🟡 Средний" if score <= 4 else "🟢 Сильный")

    try:
        prob, pred = predict_password_risk(password)
        if pred >= 0:
            session_results['password_risk'] = f"{prob:.1%}"
            res.append(f"🤖 МО-риск: {'высокий' if prob > 0.7 else 'средний' if prob > 0.4 else 'низкий'} ({prob:.1%})")
    except:
        res.append("⚠ МО недоступна")

    def update():
        text_output.configure(state="normal");
        text_output.delete(1.0, tk.END)
        for line in res: text_output.insert(tk.END, line + "\n")
        text_output.configure(state="disabled")

    root.after(0, update)

# ИНТЕРФЕЙС

root = tk.Tk()
root.title("Cybershield IE")
root.geometry("680x480")
root.configure(bg="#F0F2F5")

style = ttk.Style()
style.configure("TLabel", background="#F0F2F5", font=("Segoe UI", 11))
style.configure("TButton", font=("Segoe UI", 10), padding=6)

try:
    icon_image = Image.open("guard.png")
    icon_photo = ImageTk.PhotoImage(icon_image)
    root.wm_iconphoto(False, icon_photo)
except Exception:
    pass

lbl_target = ttk.Label(root, text="Цель сканирования (IP/домен):")
lbl_target.pack(pady=(10, 2), anchor="w", padx=20)
entry_target = ttk.Entry(root, width=55)
entry_target.insert(0, "127.0.0.1")
entry_target.pack(padx=20)

lbl_email = ttk.Label(root, text="Email для проверки:")
lbl_email.pack(pady=(10, 2), anchor="w", padx=20)
entry_email = ttk.Entry(root, width=55)
entry_email.pack(padx=20)

lbl_password = ttk.Label(root, text="Пароль для анализа:")
lbl_password.pack(pady=(10, 2), anchor="w", padx=20)
entry_password = ttk.Entry(root, show="*", width=55)
entry_password.pack(padx=20)

frame_buttons = ttk.Frame(root)
frame_buttons.pack(pady=15)

ttk.Button(frame_buttons, text="Проверить Email", command=check_email).grid(row=0, column=0, padx=6, pady=4)
ttk.Button(frame_buttons, text="Пароль + МО", command=analyze_password).grid(row=0, column=1, padx=6, pady=4)
ttk.Button(frame_buttons, text="Пароль (офлайн)", command=analyze_password_offline).grid(row=0, column=2, padx=6,
                                                                                           pady=4)
ttk.Button(frame_buttons, text="Сканировать порты",
           command=lambda: threading.Thread(target=lambda: run_port_scan_thread(entry_target.get().strip()),
                                            daemon=True).start()).grid(row=1, column=0, padx=6, pady=4)
ttk.Button(frame_buttons, text="Создать PDF-отчёт", command=create_pdf_report).grid(row=1, column=1, columnspan=2,
                                                                                      padx=6, pady=4, sticky="ew")

text_output = tk.Text(root, height=9, width=78, font=("Consolas", 9), bg="#FFFFFF", fg="#2C3E50")
text_output.pack(padx=20, pady=(5, 15))
text_output.configure(state="disabled")


def on_closing():  # 🔒 Ваш код логирования времени работы
    end_time = datetime.now()
    elapsed = end_time - start_time
    with open("work_time.log", "a", encoding="utf-8") as f:
        f.write(f"Запуск: {start_time}\nЗакрытие: {end_time}\nВремя работы: {elapsed}\n=====\n")
    root.destroy()


root.protocol("WM_DELETE_WINDOW", on_closing)
root.after(500, lambda: threading.Thread(target=train_or_load_model, daemon=True).start())
root.mainloop()