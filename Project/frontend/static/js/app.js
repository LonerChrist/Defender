// CyberShield IE — Клиентская логика
// Версия: 1.0

document.addEventListener('DOMContentLoaded', function() {
    console.log('CyberShield IE загружен');
    checkLicenseStatus();
});

const API_KEY = 'default_key_for_dev';
const API_BASE = '';

async function checkLicenseStatus() {
    try {
        const response = await fetch('/api/license/status', {
            headers: { 'X-API-Key': API_KEY }
        });
        const data = await response.json();

        const statusDot = document.querySelector('#licenseStatus .status-dot');
        const statusText = document.getElementById('licenseText');

        if (data.valid) {
            statusDot.classList.add('active');
            statusText.textContent = `Лицензия: активна (до ${data.expires})`;
        } else {
            statusDot.classList.remove('active');
            statusText.textContent = 'Лицензия: не активирована';
        }
    } catch (error) {
        console.log('Не удалось проверить лицензию:', error);
    }
}

async function activateLicense() {
    const key = document.getElementById('licenseKey').value.trim();
    const resultDiv = document.getElementById('licenseResult');

    if (!key) {
        showResult(resultDiv, 'Введите лицензионный ключ', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/license/activate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ key: key })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showResult(resultDiv, 'Лицензия активирована!', 'success');
            checkLicenseStatus();
            document.getElementById('licenseKey').value = '';
        } else {
            showResult(resultDiv, `${data.error || 'Ошибка активации'}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}

async function checkEmail() {
    const email = document.getElementById('emailInput').value.trim();
    const resultDiv = document.getElementById('emailResult');
    const breachesList = document.getElementById('emailBreachesList');

    if (!email) {
        showResult(resultDiv, 'Введите email для проверки', 'warning');
        return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showResult(resultDiv, 'Неверный формат email', 'error');
        return;
    }

    showResult(resultDiv, 'Проверка...', 'info');
    breachesList.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE}/api/check/email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ email: email })
        });

        const data = await response.json();

        if (response.ok) {
            const breaches = data.breaches || [];
            const count = breaches.length;

            if (count === 0) {
                showResult(resultDiv, 'Утечек не обнаружено', 'success');
            } else {
                showResult(resultDiv, `Найдено ${count} утечек`, 'warning');

                let html = '';
                breaches.forEach(breach => {
                    html += `
                        <div class="breach-item">
                            <span class="breach-name">${breach.name || 'Unknown'}</span>
                            <span class="breach-date">${breach.date || 'N/A'}</span>
                        </div>
                    `;
                });
                breachesList.innerHTML = html;
            }
        } else {
            showResult(resultDiv, `Ошибка: ${data.error || 'Неизвестная ошибка'}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}

function togglePasswordMode() {
    const offline = document.getElementById('offlineMode').checked;
    const passwordInput = document.getElementById('passwordInput');

    if (offline) {
        passwordInput.placeholder = 'Введите пароль (оффлайн-анализ)';
        passwordInput.type = 'password';
    } else {
        passwordInput.placeholder = 'Введите пароль (с проверкой в базах утечек)';
    }
}

async function checkPassword() {
    const password = document.getElementById('passwordInput').value;
    const resultDiv = document.getElementById('passwordResult');
    const detailsDiv = document.getElementById('passwordDetails');
    const offline = document.getElementById('offlineMode').checked;

    console.log('Password check started');
    console.log('Password length:', password.length);
    console.log('Offline mode:', offline);

    if (!password) {
        showResult(resultDiv, 'Введите пароль для проверки', 'warning');
        return;
    }

    if (password.length < 6) {
        showResult(resultDiv, 'Пароль слишком короткий (минимум 6 символов)', 'error');
        return;
    }

    showResult(resultDiv, 'Анализ...', 'info');
    detailsDiv.style.display = 'none';

    try {
        const endpoint = offline
            ? `${API_BASE}/api/check/password/offline`
            : `${API_BASE}/api/check/password`;

        console.log('Calling endpoint:', endpoint);

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ password: password })
        });

        console.log('Response status:', response.status);

        const data = await response.json();
        console.log('Response data:', data);

        if (response.ok) {
            const strength = data.strength || data.ml_risk?.level || 'unknown';
            const score = data.score || 0;

            let statusClass = 'info';
            let statusText = '';

            switch(strength) {
                case 'very_strong':
                case 'strong':
                    statusClass = 'success';
                    statusText = '✅ Надёжный пароль';
                    break;
                case 'medium':
                    statusClass = 'warning';
                    statusText = 'Средний уровень надёжности';
                    break;
                default:
                    statusClass = 'error';
                    statusText = 'Слабый пароль';
            }

            showResult(resultDiv, `${statusText} (${score}/100)`, statusClass);

            // Детали
            document.getElementById('pwdLength').textContent = `${data.length || 0} символов`;
            document.getElementById('pwdEntropy').textContent = `${data.entropy?.toFixed(1) || '-'} бит`;
            document.getElementById('pwdCrackTime').textContent = data.crack_time || '-';
            document.getElementById('pwdBreaches').textContent =
                data.breach_count !== undefined
                    ? (data.breach_count > 0 ? `Да (${data.breach_count})` : 'Нет')
                    : '-';

            detailsDiv.style.display = 'block';

            if (data.suggestions?.length > 0) {
                let recs = '<br><small><b>Рекомендации:</b><br>';
                data.suggestions.slice(0, 3).forEach(s => {
                    recs += `• ${s}<br>`;
                });
                recs += '</small>';
                resultDiv.innerHTML += recs;
            }

        } else {
            showResult(resultDiv, `Ошибка: ${data.error || 'Неизвестная ошибка'}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}

async function scanPorts() {
    const host = document.getElementById('hostInput').value.trim() || 'localhost';
    const resultDiv = document.getElementById('portResult');
    const tableContainer = document.getElementById('portsTable');
    const tableBody = document.getElementById('portsTableBody');
    const vulnsList = document.getElementById('vulnerabilitiesList');
    const vulnsContent = document.getElementById('vulnsContent');

    showResult(resultDiv, 'Сканирование портов...', 'info');
    tableContainer.style.display = 'none';
    vulnsList.style.display = 'none';

    try {
        const response = await fetch(`${API_BASE}/api/scan/ports`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ host: host })
        });

        const data = await response.json();

        if (response.ok) {
            const openPorts = data.open_ports || [];
            const vulnerabilities = data.vulnerabilities || [];

            if (openPorts.length === 0) {
                showResult(resultDiv, 'Открытых портов не обнаружено', 'success');
                return;
            }

            showResult(resultDiv, `Найдено ${openPorts.length} открытых портов`, 'info');

            tableBody.innerHTML = '';
            openPorts.forEach(port => {
                let risk = 'low';
                let riskText = 'Низкий';

                for (const vuln of vulnerabilities) {
                    if (vuln.port === port.port) {
                        risk = vuln.severity;
                        riskText = vuln.severity.toUpperCase();
                        break;
                    }
                }

                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${port.port}</td>
                    <td>${port.service || 'Unknown'}</td>
                    <td>${port.state}</td>
                    <td class="risk-${risk}">${riskText}</td>
                    <td>
                        ${vulnerabilities.some(v => v.port === port.port)
                            ? `<a href="#" class="btn btn-secondary" style="padding:4px 8px;font-size:12px;"
                                 onclick="showVulnDetails(${JSON.stringify(vulnerabilities.find(v => v.port === port.port))}); return false;">
                                 Подробнее
                               </a>`
                            : '-'
                        }
                    </td>
                `;
                tableBody.appendChild(row);
            });

            tableContainer.style.display = 'block';

            if (vulnerabilities.length > 0) {
                let html = '';
                vulnerabilities.forEach(vuln => {
                    const cveLink = vuln.cve
                        ? `<a href="https://nvd.nist.gov/vuln/detail/${vuln.cve}" target="_blank" class="vuln-cve">${vuln.cve}</a>`
                        : '';

                    html += `
                        <div class="vuln-item">
                            <div class="vuln-title">Порт ${vuln.port} (${vuln.service})</div>
                            <div class="vuln-desc">${vuln.description}</div>
                            ${cveLink}
                            <div style="margin-top:8px;font-size:13px;color:#7F8C8D;">
                                <b>Рекомендация:</b> ${vuln.recommendation}
                            </div>
                        </div>
                    `;
                });
                vulnsContent.innerHTML = html;
                vulnsList.style.display = 'block';
            }

        } else {
            showResult(resultDiv, `Ошибка: ${data.error || 'Неизвестная ошибка'}`, 'error');
        }
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}


function showVulnDetails(vuln) {
    alert(`Уязвимость порта ${vuln.port}:\n\n${vuln.description}\n\nРекомендация: ${vuln.recommendation}`);
}


async function generateReport(format) {
    const target = document.getElementById('reportTarget').value.trim() || 'Информационная система ИП';
    const resultDiv = document.getElementById('reportResult');

    showResult(resultDiv, 'Формирование отчёта...', 'info');

    const auditData = {
        target: target,
        include_email: document.getElementById('includeEmail').checked,
        include_password: document.getElementById('includePassword').checked,
        include_ports: document.getElementById('includePorts').checked
    };

    try {
        if (format === 'pdf') {
            const response = await fetch(`${API_BASE}/api/generate/pdf-report`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': API_KEY
                },
                body: JSON.stringify(auditData)
            });

            const data = await response.json();

            if (response.ok) {
                showResult(resultDiv, `✅ Отчёт сохранён: ${data.report_path}`, 'success');

                const link = document.createElement('a');
                link.href = `/download/${data.report_path}`;
                link.download = data.report_path;
                link.click();
            } else {
                showResult(resultDiv, `Ошибка: ${data.error || 'Не удалось сгенерировать отчёт'}`, 'error');
            }
        } else {
            const sessionId = 'session_' + Date.now();
            window.open(`${API_BASE}/report/${sessionId}`, '_blank');
            showResult(resultDiv, '✅ Отчёт открыт в новой вкладке', 'success');
        }
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}

function showResult(element, message, type) {
    element.textContent = message;
    element.className = `result-message show ${type}`;

    if (type === 'info') {
        setTimeout(() => {
            element.classList.remove('show');
        }, 5000);
    }
}

function closeReportModal() {
    document.getElementById('reportModal').style.display = 'none';
    document.getElementById('reportFrame').src = '';
}

document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const section = this.closest('.card');
            const button = section?.querySelector('.btn-primary');
            button?.click();
        }
    });
});