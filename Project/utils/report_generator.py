# -*- coding: utf-8 -*-
from reportlab.lib.pagesizes import A4, letter
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import (
    HexColor, black, white, red, green, blue, orange, yellow
)
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os


class PDFReportGenerator:
    """Генератор профессиональных PDF отчетов по безопасности"""

    def __init__(self, output_path='report.pdf'):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._register_fonts()
        self._create_custom_styles()

    def _register_fonts(self):
        """Регистрация шрифтов с поддержкой кириллицы"""
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        import os

        font_paths = {
            'Arial': [
                "C:/Windows/Fonts/arial.ttf",
                "C:/Windows/Fonts/ARIAL.TTF",
                "/usr/share/fonts/truetype/msttcorefonts/Arial.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/Library/Fonts/Arial.ttf",
            ],
            'Arial-Bold': [
                "C:/Windows/Fonts/arialbd.ttf",
                "C:/Windows/Fonts/ARIALBD.TTF",
                "/usr/share/fonts/truetype/msttcorefonts/Arial_Bold.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/Library/Fonts/Arial Bold.ttf",
            ],
            'Times-Roman': [
                "C:/Windows/Fonts/times.ttf",
                "C:/Windows/Fonts/TIMES.TTF",
                "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
            ],
            'Times-Bold': [
                "C:/Windows/Fonts/timesbd.ttf",
                "C:/Windows/Fonts/TIMESBD.TTF",
                "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
            ],
        }

        fonts_registered = 0

        for font_name, paths in font_paths.items():
            for font_path in paths:
                if os.path.exists(font_path):
                    try:
                        pdfmetrics.registerFont(TTFont(font_name, font_path))
                        fonts_registered += 1
                        print(f"Шрифт зарегистрирован: {font_name} -> {font_path}")
                        break
                    except Exception as e:
                        print(f"Ошибка регистрации шрифта {font_path}: {e}")
                        continue

        if fonts_registered < 2:
            print("⚠ ВНИМАНИЕ: Зарегистрировано менее 2 шрифтов. Кириллица может не отображаться!")
            print("Рекомендуется установить шрифты Microsoft Core Fonts или DejaVu")

    def _create_custom_styles(self):
        """Создание пользовательских стилей с поддержкой кириллицы"""
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        from reportlab.lib.colors import HexColor, black, white, red, green, blue, orange

        self.styles = getSampleStyleSheet()

        from reportlab.pdfbase import pdfmetrics
        try:
            pdfmetrics.getFont('Arial')
            base_font = 'Arial'
            bold_font = 'Arial-Bold'
        except:
            base_font = 'Arial'
            bold_font = 'Arial'

        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontName=base_font,
            fontSize=24,
            textColor=HexColor('#1A5276'),
            spaceAfter=30,
            alignment=TA_CENTER,
            leading=32,
            allowWidows=1,
            allowOrphans=1,
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontName=bold_font,
            fontSize=16,
            textColor=HexColor('#2E86C1'),
            spaceBefore=20,
            spaceAfter=10,
            leading=20,
        ))

        # Подзаголовок 3 уровня
        self.styles.add(ParagraphStyle(
            name='CustomHeading3',
            parent=self.styles['Heading3'],
            fontName=bold_font,
            fontSize=12,
            textColor=HexColor('#1F618D'),
            spaceBefore=12,
            spaceAfter=6,
            leading=14,
        ))

        # Обычный текст
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=black,
            alignment=TA_JUSTIFY,
            leading=14,
            spaceAfter=6,
            allowWidows=1,
            allowOrphans=1,
        ))

        # Текст для критических уязвимостей
        self.styles.add(ParagraphStyle(
            name='CriticalText',
            parent=self.styles['Normal'],
            fontName=bold_font,
            fontSize=10,
            textColor=red,
            leading=14,
            spaceAfter=6,
        ))

        # Текст для предупреждений
        self.styles.add(ParagraphStyle(
            name='WarningText',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=orange,
            leading=14,
            spaceAfter=6,
        ))

        # Текст для успешных проверок
        self.styles.add(ParagraphStyle(
            name='SuccessText',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=green,
            leading=14,
            spaceAfter=6,
        ))

    def generate_report(self, data):
        """
        Генерация полного отчета
        :param data: dict с данными аудита
        """
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm
        )

        elements = []

        elements.extend(self._create_title_page(data))
        elements.append(PageBreak())

        elements.extend(self._create_table_of_contents())
        elements.append(PageBreak())

        elements.extend(self._create_summary_section(data))

        if 'email_check' in data:
            elements.extend(self._create_email_section(data['email_check']))

        if 'password_analysis' in data:
            elements.extend(self._create_password_section(data['password_analysis']))

        if 'port_scan' in data:
            elements.extend(self._create_ports_section(data['port_scan']))

        if 'recommendations' in data:
            elements.extend(self._create_recommendations_section(data['recommendations']))

        elements.extend(self._create_appendix(data))

        doc.build(elements, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)

        return self.output_path

    def _create_title_page(self, data):
        """Создание титульной страницы отчёта"""
        elements = []

        elements.append(Paragraph(str("ОТЧЁТ ПО АУДИТУ КИБЕРБЕЗОПАСНОСТИ"), self.styles['CustomTitle']))

        text = "Дата формирования: {}".format(datetime.now().strftime('%d.%m.%Y %H:%M'))
        elements.append(Paragraph(text, self.styles['CustomNormal']))

        elements.append(Spacer(1, 0.5 * inch))

        # Название системы
        elements.append(Paragraph(
            "«Кибер-щит для ИП»",
            ParagraphStyle(
                name='SystemName',
                parent=self.styles['Heading2'],
                fontName='Arial',
                fontSize=18,
                textColor=HexColor('#2E86C1'),
                spaceAfter=20
            )
        ))

        elements.append(Spacer(1, 0.3 * inch))

        info_data = [
            ['Дата формирования:', datetime.now().strftime('%d.%m.%Y %H:%M')],
            ['Цель проверки:', data.get('target', 'Информационная система ИП')],
            ['Общий уровень безопасности:', self._get_risk_level(data.get('overall_score', 0))],
        ]

        info_table = Table(info_data, colWidths=[3 * inch, 3 * inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#BDC3C7')),
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#F8F9F9')),
        ]))

        elements.append(info_table)
        elements.append(Spacer(1, 1 * inch))

        # Индикатор критичности
        overall_score = data.get('overall_score', 0)
        if overall_score >= 80:
            status_text = "ХОРОШИЙ"
            status_color = green
        elif overall_score >= 60:
            status_text = "УДОВЛЕТВОРИТЕЛЬНЫЙ"
            status_color = orange
        else:
            status_text = "ТРЕБУЕТ ВНИМАНИЯ"
            status_color = red

        elements.append(Paragraph(
            f"ОБЩИЙ СТАТУС: {status_text}",
            ParagraphStyle(
                name='StatusStyle',
                parent=self.styles['Heading3'],
                fontName='Arial',
                fontSize=14,
                textColor=status_color,
                alignment=TA_CENTER,
                spaceAfter=20
            )
        ))

        if overall_score < 60:
            elements.append(Spacer(1, 0.2 * inch))
            elements.append(Paragraph(
                "⚠ ТРЕБУЕТСЯ НЕМЕДЛЕННОЕ УСТРАНЕНИЕ УЯЗВИМОСТЕЙ",
                ParagraphStyle(
                    name='CriticalWarning',
                    parent=self.styles['Normal'],
                    fontName='Arial',
                    fontSize=12,
                    textColor=red,
                    alignment=TA_CENTER
                )
            ))

        return elements

    def _create_vulnerabilities_section(self, vulnerabilities):
        """Создание раздела с уязвимостями и CVE ссылками"""
        elements = []
        elements.append(Paragraph("ВЫЯВЛЕННЫЕ УЯЗВИМОСТИ", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2 * inch))

        if not vulnerabilities:
            elements.append(Paragraph(
                "Уязвимости не обнаружены",
                self.styles['SuccessText']
            ))
            return elements

        # Группировка по критичности
        critical = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high = [v for v in vulnerabilities if v.get('severity') == 'high']
        medium = [v for v in vulnerabilities if v.get('severity') == 'medium']
        low = [v for v in vulnerabilities if v.get('severity') == 'low']

        # Критические уязвимости
        if critical:
            elements.append(Paragraph("🔴 КРИТИЧЕСКИЕ УЯЗВИМОСТИ", self.styles['CustomHeading3']))
            for i, vuln in enumerate(critical, 1):
                elements.extend(self._create_vulnerability_item(vuln, i))

        # Высокие уязвимости
        if high:
            elements.append(Paragraph("🟠 ВЫСОКАЯ КРИТИЧНОСТЬ", self.styles['CustomHeading3']))
            for i, vuln in enumerate(high, 1):
                elements.extend(self._create_vulnerability_item(vuln, i))

        # Средние уязвимости
        if medium:
            elements.append(Paragraph("🟡 СРЕДНЯЯ КРИТИЧНОСТЬ", self.styles['CustomHeading3']))
            for i, vuln in enumerate(medium, 1):
                elements.extend(self._create_vulnerability_item(vuln, i))

        # Низкие уязвимости
        if low:
            elements.append(Paragraph("🟢 НИЗКАЯ КРИТИЧНОСТЬ", self.styles['CustomHeading3']))
            for i, vuln in enumerate(low, 1):
                elements.extend(self._create_vulnerability_item(vuln, i))

        return elements

    def _create_vulnerability_item(self, vuln, num):
        """Создание элемента уязвимости с CVE ссылками"""
        elements = []

        # Заголовок уязвимости
        severity = vuln.get('severity', 'unknown').upper()
        title = vuln.get('title', 'Неизвестная уязвимость')

        elements.append(Paragraph(
            f"{num}. {title} [{severity}]",
            ParagraphStyle(
                name=f'VulnTitle{num}',
                parent=self.styles['Normal'],
                fontName='Arial',
                fontSize=11,
                textColor=red if severity == 'CRITICAL' else orange if severity == 'HIGH' else blue,
                spaceAfter=6
            )
        ))

        # Описание
        description = vuln.get('description', 'Нет описания')
        elements.append(Paragraph(
            f"<b>Описание:</b> {description}",
            self.styles['CustomNormal']
        ))

        # Affected component
        if vuln.get('component'):
            elements.append(Paragraph(
                f"<b>Компонент:</b> {vuln.get('component')}",
                self.styles['CustomNormal']
            ))

        # CVE ссылки
        if vuln.get('cve_id'):
            cve_id = vuln.get('cve_id')
            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            elements.append(Paragraph(
                f"<b>CVE:</b> <a href='{cve_url}' color='#1976D2'>{cve_id}</a>",
                self.styles['CustomNormal']
            ))

        if vuln.get('recommendation'):
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph(
                f"<b>Рекомендации по устранению:</b>",
                ParagraphStyle(
                    name='RecTitle',
                    parent=self.styles['Normal'],
                    fontName='Arial',
                    fontSize=10,
                    textColor=green,
                    spaceAfter=4
                )
            ))
            elements.append(Paragraph(
                vuln.get('recommendation'),
                self.styles['CustomNormal']
            ))

        if vuln.get('references'):
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph(
                "<b>Полезные ссылки:</b>",
                ParagraphStyle(
                    name='RefsTitle',
                    parent=self.styles['Normal'],
                    fontName='Arial',
                    fontSize=10,
                    spaceAfter=4
                )
            ))
            for ref in vuln.get('references', []):
                elements.append(Paragraph(
                    f"• <a href='{ref}' color='#1976D2'>{ref}</a>",
                    self.styles['CustomNormal']
                ))

        elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _get_risk_level(self, score):
        """Получение текстового уровня риска"""
        if score >= 90:
            return "ОТЛИЧНЫЙ"
        elif score >= 80:
            return "ХОРОШИЙ"
        elif score >= 70:
            return "ВЫШЕ СРЕДНЕГО"
        elif score >= 60:
            return "СРЕДНИЙ"
        elif score >= 50:
            return "НИЖЕ СРЕДНЕГО"
        else:
            return "НИЗКИЙ"

    def _create_title_page(self, data):
        """Создание титульной страницы"""
        elements = []

        elements.append(Paragraph("ОТЧЕТ", self.styles['CustomTitle']))
        elements.append(Paragraph("по аудиту кибербезопасности", self.styles['CustomTitle']))
        elements.append(Spacer(1, 0.5 * inch))

        elements.append(Paragraph("«Кибер-щит для ИП»", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(
            Paragraph(f"Дата формирования: {datetime.now().strftime('%d.%m.%Y %H:%M')}", self.styles['CustomNormal']))
        elements.append(
            Paragraph(f"Цель проверки: {data.get('target', 'Информационная система ИП')}", self.styles['CustomNormal']))
        elements.append(Spacer(1, 1 * inch))

        overall_score = data.get('overall_score', 0)
        if overall_score >= 80:
            status = "ХОРОШИЙ"
            color = green
        elif overall_score >= 60:
            status = "УДОВЛЕТВОРИТЕЛЬНЫЙ"
            color = orange
        else:
            status = "ТРЕБУЕТ ВНИМАНИЯ"
            color = red

        elements.append(Paragraph(f"Общий уровень безопасности: {status}", ParagraphStyle(
            name='StatusStyle',
            parent=self.styles['Heading3'],
            fontName='Arial',
            textColor=color,
            alignment=TA_CENTER
        )))

        return elements

    def _create_table_of_contents(self):
        """Создание оглавления"""
        elements = []
        elements.append(Paragraph("СОДЕРЖАНИЕ", self.styles['CustomHeading2']))
        elements.append(Spacer(1, 0.2 * inch))

        toc_data = [
            ['1.', 'Общая информация', '3'],
            ['2.', 'Проверка email на утечки', '4'],
            ['3.', 'Анализ надежности паролей', '5'],
            ['4.', 'Сканирование сетевых портов', '6'],
            ['5.', 'Рекомендации по устранению уязвимостей', '7'],
            ['6.', 'Приложения', '8'],
        ]

        toc_table = Table(toc_data, colWidths=[0.5 * inch, 5 * inch, 0.5 * inch])
        toc_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(toc_table)
        return elements

    def _create_summary_section(self, data):
        """Создание раздела с общей информацией"""
        elements = []
        elements.append(Paragraph("1. ОБЩАЯ ИНФОРМАЦИЯ", self.styles['CustomHeading2']))

        summary_data = [
            ['Параметр', 'Значение'],
            ['Дата проверки', datetime.now().strftime('%d.%m.%Y %H:%M:%S')],
            ['Цель аудита', str(data.get('target', 'Не указана'))],
            ['Общий балл безопасности', f"{data.get('overall_score', 0)}/100"],
            ['Критических уязвимостей', str(data.get('critical_count', 0))],
            ['Предупреждений', str(data.get('warning_count', 0))],
        ]

        table = Table(summary_data, colWidths=[3 * inch, 3 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2E86C1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#F8F9F9')]),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

        return elements

    def _create_email_section(self, email_data):
        """Создание раздела проверки email"""
        elements = []
        elements.append(Paragraph("2. ПРОВЕРКА EMAIL НА УТЕЧКИ", self.styles['CustomHeading2']))

        elements.append(
            Paragraph(f"Проверяемый email: <b>{email_data.get('email', 'N/A')}</b>", self.styles['CustomNormal']))
        elements.append(Spacer(1, 0.2 * inch))

        breaches = email_data.get('breaches', [])

        if breaches:
            elements.append(Paragraph(f"Найдено утечек: <b>{len(breaches)}</b>", self.styles['CriticalText']))
            elements.append(Spacer(1, 0.2 * inch))

            table_data = [['Сервис', 'Дата утечки', 'Скомпрометированные данные']]
            for breach in breaches:
                table_data.append([
                    breach.get('name', 'Unknown'),
                    breach.get('date', 'N/A'),
                    ', '.join(breach.get('data_classes', []))
                ])

            table = Table(table_data, colWidths=[2 * inch, 1.5 * inch, 2.5 * inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#E74C3C')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#BDC3C7')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))

            elements.append(table)
        else:
            elements.append(Paragraph("Утечек не обнаружено", self.styles['SuccessText']))

        elements.append(Spacer(1, 0.3 * inch))
        return elements

    def _create_password_section(self, password_data):
        """Создание раздела анализа паролей"""
        elements = []
        elements.append(Paragraph("3. АНАЛИЗ НАДЕЖНОСТИ ПАРОЛЕЙ", self.styles['CustomHeading2']))

        strength = password_data.get('strength', 'unknown')
        score = password_data.get('score', 0)

        if strength == 'very_strong':
            status_text = "ОЧЕНЬ НАДЕЖНЫЙ"
            style = self.styles['SuccessText']
        elif strength == 'strong':
            status_text = "НАДЕЖНЫЙ"
            style = self.styles['SuccessText']
        elif strength == 'medium':
            status_text = "СРЕДНИЙ УРОВЕНЬ"
            style = self.styles['WarningText']
        else:
            status_text = "СЛАБЫЙ"
            style = self.styles['CriticalText']

        elements.append(Paragraph(f"Оценка надежности: <b>{status_text}</b> ({score}/100)", style))
        elements.append(Spacer(1, 0.2 * inch))

        details_data = [
            ['Длина пароля', f"{password_data.get('length', 0)} символов"],
            ['Энтропия', f"{password_data.get('entropy', 0):.1f} бит"],
            ['Время взлома', password_data.get('crack_time', 'N/A')],
        ]

        table = Table(details_data, colWidths=[2.5 * inch, 3.5 * inch])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#BDC3C7')),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 0.2 * inch))

        issues = password_data.get('issues', [])
        if issues:
            elements.append(Paragraph("Выявленные проблемы:", self.styles['CustomHeading3']))
            for issue in issues:
                elements.append(Paragraph(f"• {issue}", self.styles['CriticalText']))
            elements.append(Spacer(1, 0.2 * inch))

        suggestions = password_data.get('suggestions', [])
        if suggestions:
            elements.append(Paragraph("Рекомендации:", self.styles['CustomHeading3']))
            for suggestion in suggestions:
                elements.append(Paragraph(f"• {suggestion}", self.styles['CustomNormal']))

        elements.append(Spacer(1, 0.3 * inch))
        return elements

    def _create_ports_section(self, port_data):
        """Создание раздела сканирования портов"""
        elements = []
        elements.append(Paragraph("4. СКАНИРОВАНИЕ СЕТЕВЫХ ПОРТОВ", self.styles['CustomHeading2']))

        open_ports = port_data.get('open_ports', [])
        vulnerabilities = port_data.get('vulnerabilities', [])

        elements.append(Paragraph(f"Найдено открытых портов: <b>{len(open_ports)}</b>", self.styles['CustomNormal']))
        elements.append(Spacer(1, 0.2 * inch))

        if open_ports:
            table_data = [['Порт', 'Сервис', 'Статус', 'Риск']]
            for port in open_ports:
                risk = 'Низкий'
                for vuln in vulnerabilities:
                    if vuln.get('port') == port.get('port'):
                        risk = vuln.get('severity', 'Unknown').upper()
                        break

                table_data.append([
                    str(port.get('port')),
                    port.get('service', 'Unknown'),
                    port.get('state', 'open'),
                    risk
                ])

            table = Table(table_data, colWidths=[1 * inch, 2 * inch, 1.5 * inch, 1.5 * inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2E86C1')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#BDC3C7')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 0.3 * inch))

        if vulnerabilities:
            elements.append(Paragraph("Выявленные уязвимости:", self.styles['CustomHeading3']))
            for vuln in vulnerabilities:
                elements.append(Paragraph(
                    f"<b>Порт {vuln.get('port')} ({vuln.get('service')}):</b> {vuln.get('description')}",
                    self.styles['CriticalText'] if vuln.get('severity') == 'critical' else self.styles['WarningText']
                ))
                elements.append(Paragraph(
                    f"Рекомендация: {vuln.get('recommendation')}",
                    self.styles['CustomNormal']
                ))
                elements.append(Spacer(1, 0.1 * inch))

        elements.append(Spacer(1, 0.3 * inch))
        return elements

    def _create_recommendations_section(self, recommendations):
        """Создание раздела с рекомендациями"""
        elements = []
        elements.append(Paragraph("5. РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ УЯЗВИМОСТЕЙ", self.styles['CustomHeading2']))

        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec.get('title', 'Рекомендация')}", self.styles['CustomHeading3']))
            elements.append(Paragraph(rec.get('description', ''), self.styles['CustomNormal']))

            if rec.get('cve_links'):
                elements.append(Paragraph("Полезные ссылки:", self.styles['CustomHeading3']))
                for link in rec.get('cve_links', []):
                    elements.append(Paragraph(f"• {link}", ParagraphStyle(
                        parent=self.styles['CustomNormal'],
                        textColor=blue,
                        underline=True
                    )))

            elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _create_appendix(self, data):
        """Создание приложений"""
        elements = []
        elements.append(Paragraph("6. ПРИЛОЖЕНИЯ", self.styles['CustomHeading2']))

        elements.append(Paragraph("A. Использованные источники данных:", self.styles['CustomHeading3']))
        elements.append(Paragraph("• Have I Been Pwned API", self.styles['CustomNormal']))
        elements.append(Paragraph("• CVE/NVD Database", self.styles['CustomNormal']))
        elements.append(Paragraph("• Локальные базы уязвимостей", self.styles['CustomNormal']))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("B. Методология оценки:", self.styles['CustomHeading3']))
        elements.append(Paragraph("Отчет сформирован автоматизированной системой «Кибер-щит для ИП» "
                                  "на основе анализа актуальных угроз кибербезопасности и лучших практик "
                                  "защиты информации для малого бизнеса.", self.styles['CustomNormal']))

        return elements

    def _add_header_footer(self, canvas, doc):
        """Добавление шапки и подвала на страницы"""
        canvas.saveState()

        canvas.setFont('Arial', 8)
        canvas.setFillColor(HexColor('#1A5276'))
        canvas.drawString(2 * cm, doc.pagesize[1] - 1 * cm, "Отчет по аудиту кибербезопасности")
        canvas.drawString(doc.pagesize[0] - 10 * cm, doc.pagesize[1] - 1 * cm,
                          f"Страница {doc.page}")

        canvas.setFillColor(HexColor('#7F8C8D'))
        canvas.drawString(2 * cm, 1 * cm, "© 2026 Кибер-щит для ИП. Все права защищены.")
        canvas.drawString(doc.pagesize[0] - 8 * cm, 1 * cm,
                          f"Сформирован: {datetime.now().strftime('%d.%m.%Y')}")

        canvas.restoreState()
