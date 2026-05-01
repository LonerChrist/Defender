const API_KEY = 'default_key_for_dev';
const API_BASE = '';

const auditState = {
    license: { valid: false },
    emailCheck: null,
    passwordAnalysis: null,
    portScan: null,
    recommendations: []
};

document.addEventListener('DOMContentLoaded', () => {
    checkLicenseStatus();
    bindEnterSubmit();
    bindNavState();
    updateDashboard();
});

function bindEnterSubmit() {
    document.querySelectorAll('.form-input').forEach((input) => {
        input.addEventListener('keypress', function(event) {
            if (event.key !== 'Enter') {
                return;
            }

            const panel = this.closest('.panel');
            const actionButton = panel?.querySelector('.btn-primary');
            actionButton?.click();
        });
    });
}

function bindNavState() {
    const links = Array.from(document.querySelectorAll('.nav-link'));
    const onScroll = () => {
        let current = links[0];

        links.forEach((link) => {
            const section = document.querySelector(link.getAttribute('href'));
            if (!section) {
                return;
            }

            const top = section.getBoundingClientRect().top;
            if (top <= 140) {
                current = link;
            }
        });

        links.forEach((link) => link.classList.toggle('active', link === current));
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
}

async function checkLicenseStatus() {
    try {
        const response = await fetch('/api/license/status', {
            headers: { 'X-API-Key': API_KEY }
        });
        const data = await response.json();

        auditState.license = data || { valid: false };

        const statusDot = document.querySelector('#licenseStatus .status-dot');
        const statusText = document.getElementById('licenseText');

        if (data.valid) {
            statusDot.classList.add('active');
            statusText.textContent = `Лицензия активна до ${data.expires || 'неизвестно'}`;
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
            body: JSON.stringify({ key })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showResult(resultDiv, 'Лицензия успешно активирована', 'success');
            document.getElementById('licenseKey').value = '';
            checkLicenseStatus();
        } else {
            showResult(resultDiv, data.error || 'Ошибка активации лицензии', 'error');
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

    showResult(resultDiv, 'Проверяем адрес...', 'info');
    breachesList.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE}/api/check/email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ email })
        });

        const data = await response.json();

        if (!response.ok) {
            showResult(resultDiv, `Ошибка: ${data.error || 'Неизвестная ошибка'}`, 'error');
            return;
        }

        const breaches = Array.isArray(data.breaches) ? data.breaches : [];
        const count = breaches.length;

        auditState.emailCheck = {
            email,
            breaches,
            breaches_count: count
        };

        if (count === 0) {
            showResult(resultDiv, 'Утечек не обнаружено', 'success');
        } else {
            showResult(resultDiv, `Найдено утечек: ${count}`, 'warning');
            breachesList.innerHTML = breaches.map((breach) => `
                <div class="breach-item">
                    <span class="breach-name">${escapeHtml(breach.name || 'Unknown')}</span>
                    <span class="breach-date">${escapeHtml(breach.date || 'Дата не указана')}</span>
                </div>
            `).join('');
        }

        updateDashboard();
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}

function togglePasswordMode() {
    const offline = document.getElementById('offlineMode').checked;
    const passwordInput = document.getElementById('passwordInput');
    passwordInput.placeholder = offline
        ? 'Введите пароль для оффлайн-анализа'
        : 'Введите пароль для анализа';
}

async function checkPassword() {
    const password = document.getElementById('passwordInput').value;
    const resultDiv = document.getElementById('passwordResult');
    const detailsDiv = document.getElementById('passwordDetails');
    const offline = document.getElementById('offlineMode').checked;

    if (!password) {
        showResult(resultDiv, 'Введите пароль для проверки', 'warning');
        return;
    }

    if (password.length < 6) {
        showResult(resultDiv, 'Пароль слишком короткий, минимум 6 символов', 'error');
        return;
    }

    showResult(resultDiv, 'Выполняется анализ...', 'info');
    detailsDiv.style.display = 'none';

    try {
        const endpoint = offline
            ? `${API_BASE}/api/check/password/offline`
            : `${API_BASE}/api/check/password`;

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ password })
        });

        const data = await response.json();

        if (!response.ok) {
            showResult(resultDiv, `Ошибка: ${data.error || 'Неизвестная ошибка'}`, 'error');
            return;
        }

        const strength = data.strength || data.ml_risk?.level || 'unknown';
        const score = Number(data.score || 0);
        let statusClass = 'info';
        let statusText = 'Анализ завершён';

        if (['very_strong', 'strong'].includes(strength)) {
            statusClass = 'success';
            statusText = 'Надёжный пароль';
        } else if (strength === 'medium') {
            statusClass = 'warning';
            statusText = 'Средний уровень надёжности';
        } else {
            statusClass = 'error';
            statusText = 'Слабый пароль';
        }

        showResult(resultDiv, `${statusText} (${score}/100)`, statusClass);

        document.getElementById('pwdLength').textContent = `${data.length || 0} символов`;
        document.getElementById('pwdEntropy').textContent = data.entropy !== undefined
            ? `${Number(data.entropy).toFixed(1)} бит`
            : '—';
        document.getElementById('pwdCrackTime').textContent = data.crack_time || '—';
        document.getElementById('pwdBreaches').textContent = data.breach_count !== undefined
            ? (data.breach_count > 0 ? `Да (${data.breach_count})` : 'Нет')
            : '—';

        detailsDiv.style.display = 'grid';

        auditState.passwordAnalysis = {
            ...data,
            score,
            strength,
            offline
        };

        if (Array.isArray(data.suggestions) && data.suggestions.length > 0) {
            const extra = data.suggestions.slice(0, 3).map((item) => `• ${escapeHtml(item)}`).join('<br>');
            resultDiv.innerHTML += `<div style="margin-top:8px"><strong>Что улучшить:</strong><br>${extra}</div>`;
        }

        updateDashboard();
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

    showResult(resultDiv, 'Сканирование портов запущено...', 'info');
    tableContainer.style.display = 'none';
    vulnsList.style.display = 'none';
    tableBody.innerHTML = '';
    vulnsContent.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE}/api/scan/ports`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ host })
        });

        const data = await response.json();

        if (!response.ok) {
            showResult(resultDiv, `Ошибка: ${data.error || 'Неизвестная ошибка'}`, 'error');
            return;
        }

        const openPorts = Array.isArray(data.open_ports) ? data.open_ports : [];
        const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];

        auditState.portScan = {
            host,
            open_ports: openPorts,
            vulnerabilities,
            total_ports: openPorts.length,
            total_vulnerabilities: vulnerabilities.length
        };

        if (openPorts.length === 0) {
            showResult(resultDiv, 'Открытые порты не обнаружены', 'success');
            updateDashboard();
            return;
        }

        showResult(resultDiv, `Открытых портов: ${openPorts.length}`, vulnerabilities.length ? 'warning' : 'success');

        tableBody.innerHTML = openPorts.map((port) => {
            const related = vulnerabilities.find((item) => item.port === port.port);
            const risk = related?.severity || 'low';
            const riskText = formatRiskText(risk);

            return `
                <tr>
                    <td>${escapeHtml(String(port.port))}</td>
                    <td>${escapeHtml(port.service || 'Unknown')}</td>
                    <td>${escapeHtml(port.state || 'open')}</td>
                    <td class="risk-${escapeHtml(risk)}">${escapeHtml(riskText)}</td>
                    <td>
                        ${related
                            ? `<button class="btn btn-secondary" style="min-height:38px;padding:0 12px" onclick="showVulnDetails('${encodeURIComponent(JSON.stringify(related))}')">Подробнее</button>`
                            : '—'}
                    </td>
                </tr>
            `;
        }).join('');

        tableContainer.style.display = 'block';

        if (vulnerabilities.length > 0) {
            vulnsContent.innerHTML = vulnerabilities.map((vuln) => {
                const cveHtml = vuln.cve
                    ? `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.cve)}" target="_blank" class="vuln-cve">${escapeHtml(vuln.cve)}</a>`
                    : '';

                return `
                    <div class="vuln-item">
                        <span class="vuln-title">Порт ${escapeHtml(String(vuln.port))} · ${escapeHtml(vuln.service || 'Unknown')}</span>
                        <div class="vuln-desc">${escapeHtml(vuln.description || 'Описание отсутствует')}</div>
                        ${cveHtml}
                        <div class="vuln-desc" style="margin-top:10px"><strong>Рекомендация:</strong> ${escapeHtml(vuln.recommendation || 'Не указана')}</div>
                    </div>
                `;
            }).join('');
            vulnsList.style.display = 'block';
        }

        updateDashboard();
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}

function showVulnDetails(encoded) {
    try {
        const vuln = JSON.parse(decodeURIComponent(encoded));
        alert(`Порт ${vuln.port}\n\n${vuln.description || 'Описание отсутствует'}\n\nРекомендация: ${vuln.recommendation || 'Не указана'}`);
    } catch (error) {
        console.log(error);
    }
}

async function generateReport(format) {
    const target = document.getElementById('reportTarget').value.trim() || 'Информационная система ИП';
    const resultDiv = document.getElementById('reportResult');

    showResult(resultDiv, 'Формируем отчёт...', 'info');

    const payload = buildReportPayload(target);

    try {
        const response = await fetch(`${API_BASE}/api/generate/pdf-report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            showResult(resultDiv, `Ошибка: ${data.error || 'Не удалось сформировать отчёт'}`, 'error');
            return;
        }

        document.getElementById('lastReportText').textContent = new Date().toLocaleTimeString('ru-RU', {
            hour: '2-digit',
            minute: '2-digit'
        });

        if (format === 'html') {
            window.open(`${API_BASE}/report/${data.session_id}`, '_blank');
            showResult(resultDiv, 'HTML-отчёт открыт в новой вкладке', 'success');
            return;
        }

        showResult(resultDiv, `PDF подготовлен: ${data.report_path}`, 'success');
        const link = document.createElement('a');
        link.href = `/download/${data.report_path}`;
        link.download = data.report_path;
        link.click();
    } catch (error) {
        showResult(resultDiv, `Ошибка соединения: ${error.message}`, 'error');
    }
}

function buildReportPayload(target) {
    const emailCheck = document.getElementById('includeEmail').checked ? (auditState.emailCheck || {}) : {};
    const passwordAnalysis = document.getElementById('includePassword').checked ? (auditState.passwordAnalysis || {}) : {};
    const portScan = document.getElementById('includePorts').checked ? (auditState.portScan || {}) : {};

    const criticalCount = countCriticalIssues();
    const warningCount = countWarningIssues();
    const overallScore = calculateOverallScore();
    const recommendations = collectRecommendations();

    return {
        target,
        overall_score: overallScore,
        critical_count: criticalCount,
        warning_count: warningCount,
        email_check: emailCheck,
        password_analysis: passwordAnalysis,
        port_scan: portScan,
        recommendations
    };
}

function calculateOverallScore() {
    let score = 100;

    if (auditState.emailCheck?.breaches_count) {
        score -= Math.min(35, auditState.emailCheck.breaches_count * 8);
    }

    if (auditState.passwordAnalysis) {
        const passwordScore = Number(auditState.passwordAnalysis.score || 0);
        score -= Math.max(0, 40 - Math.round(passwordScore / 2.5));
    }

    if (auditState.portScan?.vulnerabilities?.length) {
        score -= Math.min(30, auditState.portScan.vulnerabilities.length * 10);
    }

    return Math.max(0, Math.min(100, Math.round(score)));
}

function countCriticalIssues() {
    let count = 0;

    if (auditState.emailCheck?.breaches_count) {
        count += auditState.emailCheck.breaches_count;
    }

    if (auditState.passwordAnalysis) {
        const strength = auditState.passwordAnalysis.strength;
        if (!['strong', 'very_strong'].includes(strength)) {
            count += 1;
        }
    }

    if (auditState.portScan?.vulnerabilities?.length) {
        count += auditState.portScan.vulnerabilities.filter((item) => ['critical', 'high'].includes(item.severity)).length;
    }

    return count;
}

function countWarningIssues() {
    let count = 0;

    if (auditState.passwordAnalysis?.strength === 'medium') {
        count += 1;
    }

    if (auditState.portScan?.open_ports?.length) {
        count += auditState.portScan.open_ports.length;
    }

    return count;
}

function collectRecommendations() {
    const items = [];

    if (auditState.emailCheck?.breaches_count) {
        items.push('Смените пароль для проверенного email и включите двухфакторную аутентификацию.');
    }

    if (auditState.passwordAnalysis?.suggestions?.length) {
        items.push(...auditState.passwordAnalysis.suggestions.slice(0, 3));
    } else if (auditState.passwordAnalysis && !['strong', 'very_strong'].includes(auditState.passwordAnalysis.strength)) {
        items.push('Увеличьте длину пароля и добавьте символы разных типов.');
    }

    if (auditState.portScan?.vulnerabilities?.length) {
        auditState.portScan.vulnerabilities.slice(0, 3).forEach((item) => {
            if (item.recommendation) {
                items.push(item.recommendation);
            }
        });
    }

    if (!items.length) {
        items.push('Поддерживайте систему в актуальном состоянии и периодически повторяйте аудит.');
    }

    auditState.recommendations = Array.from(new Set(items));
    return auditState.recommendations;
}

function updateDashboard() {
    const checksCount = [auditState.emailCheck, auditState.passwordAnalysis, auditState.portScan].filter(Boolean).length;
    const openPorts = auditState.portScan?.open_ports?.length || 0;
    const issues = (auditState.emailCheck?.breaches_count || 0) + (auditState.portScan?.vulnerabilities?.length || 0) + (auditState.passwordAnalysis && !['strong', 'very_strong'].includes(auditState.passwordAnalysis.strength) ? 1 : 0);
    const score = calculateOverallScore();

    document.getElementById('checksCount').textContent = String(checksCount);
    document.getElementById('openPortsCount').textContent = String(openPorts);
    document.getElementById('issuesCount').textContent = String(issues);

    const riskValue = document.getElementById('overallRiskValue');
    const riskHint = document.getElementById('overallRiskHint');

    if (checksCount === 0) {
        riskValue.textContent = 'Не оценён';
        riskHint.textContent = 'Запустите хотя бы одну проверку';
        return;
    }

    let label = 'Низкий';
    if (score < 45) {
        label = 'Высокий';
    } else if (score < 70) {
        label = 'Средний';
    }

    riskValue.textContent = label;
    riskHint.textContent = `Итоговый балл: ${score}/100`;
}

function formatRiskText(risk) {
    switch (risk) {
        case 'critical':
            return 'Критический';
        case 'high':
            return 'Высокий';
        case 'medium':
            return 'Средний';
        default:
            return 'Низкий';
    }
}

function showResult(element, message, type) {
    element.innerHTML = message;
    element.className = `result-message show ${type}`;
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
