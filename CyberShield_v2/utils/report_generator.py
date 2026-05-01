# -*- coding: utf-8 -*-
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white, red, green, blue, orange
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
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
        self.styles = getSampleStyleSheet()

        try:
            pdfmetrics.getFont('Arial')
            base_font = 'Arial'
            bold_font = 'Arial-Bold'
        except Exception:
            base_font = 'Helvetica'
            bold_font = 'Helvetica-Bold'

        self.base_font = base_font
        self.bold_font = bold_font

        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontName=bold_font,
            fontSize=24,
            textColor=HexColor('#1A5276'),
            spaceAfter=18,
            alignment=TA_CENTER,
            leading=30,
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontName=bold_font,
            fontSize=16,
            textColor=HexColor('#2E86C1'),
            spaceBefore=18,
            spaceAfter=10,
            leading=20,
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading3',
            parent=self.styles['Heading3'],
            fontName=bold_font,
            fontSize=12,
            textColor=HexColor('#1F618D'),
            spaceBefore=10,
            spaceAfter=6,
            leading=14,
        ))

        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=black,
            alignment=TA_JUSTIFY,
            leading=14,
            spaceAfter=6,
        ))

        self.styles.add(ParagraphStyle(
            name='SmallMuted',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=9,
            textColor=HexColor('#607085'),
            alignment=TA_LEFT,
            leading=12,
            spaceAfter=5,
        ))

        self.styles.add(ParagraphStyle(
            name='CriticalText',
            parent=self.styles['Normal'],
            fontName=bold_font,
            fontSize=10,
            textColor=red,
            leading=14,
            spaceAfter=6,
        ))

        self.styles.add(ParagraphStyle(
            name='WarningText',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=orange,
            leading=14,
            spaceAfter=6,
        ))

        self.styles.add(ParagraphStyle(
            name='SuccessText',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=green,
            leading=14,
            spaceAfter=6,
        ))

        self.styles.add(ParagraphStyle(
            name='TableLabel',
            parent=self.styles['Normal'],
            fontName=bold_font,
            fontSize=10,
            textColor=HexColor('#34495E'),
            leading=13,
            alignment=TA_JUSTIFY,
            spaceAfter=0,
        ))

        self.styles.add(ParagraphStyle(
            name='TableValue',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=10,
            textColor=black,
            leading=13,
            alignment=TA_JUSTIFY,
            spaceAfter=0,
        ))

        self.styles.add(ParagraphStyle(
            name='TableValueSmall',
            parent=self.styles['Normal'],
            fontName=base_font,
            fontSize=9,
            textColor=black,
            leading=12,
            alignment=TA_JUSTIFY,
            spaceAfter=0,
        ))

    def _as_dict(self, value):
        return value if isinstance(value, dict) else {}

    def _as_list(self, value):
        return value if isinstance(value, list) else []

    def _safe_text(self, value, default='N/A'):
        if value is None:
            return default
        return str(value)

    def _get_risk_level(self, score):
        try:
            score = int(score)
        except Exception:
            score = 0

        if score >= 80:
            return 'Низкий'
        if score >= 60:
            return 'Средний'
        return 'Высокий'

    def generate_report(self, data):
        data = self._as_dict(data)

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

        elements.extend(self._create_executive_summary(data))
        elements.extend(self._create_insurance_section(data))
        elements.extend(self._create_summary_section(data))
        elements.extend(self._create_email_section(data.get('email_check')))
        elements.extend(self._create_password_section(data.get('password_analysis')))
        elements.extend(self._create_ports_section(data.get('port_scan')))
        elements.extend(self._create_findings_section(data.get('findings')))
        elements.extend(self._create_recommendations_section(data.get('recommendations')))
        elements.extend(self._create_appendix(data))

        doc.build(elements, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        return self.output_path

    def _create_title_page(self, data):
        elements = []
        generated_at = self._safe_text(data.get('generated_at', datetime.now().strftime('%d.%m.%Y %H:%M:%S')))
        score = int(data.get('overall_score', 0) or 0)

        if score >= 80:
            status = 'БАЗОВО ПРИЕМЛЕМЫЙ РИСК'
            color = green
        elif score >= 60:
            status = 'ТРЕБУЕТ ПЛАНА КОРРЕКТИРУЮЩИХ МЕР'
            color = orange
        else:
            status = 'ТРЕБУЕТ ПРИОРИТЕТНОГО УСТРАНЕНИЯ РИСКОВ'
            color = red

        elements.append(Paragraph('ОТЧЁТ ПО АУДИТУ КИБЕРБЕЗОПАСНОСТИ', self.styles['CustomTitle']))
        elements.append(Paragraph('сводка результатов и выявленных рисков', self.styles['CustomHeading3']))
        elements.append(Spacer(1, 0.35 * inch))
        elements.append(Paragraph(f"Объект оценки: {self._safe_text(data.get('target', 'Информационная система ИП'))}", self.styles['CustomNormal']))
        elements.append(Paragraph(f"Дата формирования: {generated_at}", self.styles['CustomNormal']))
        elements.append(Paragraph(f"Итоговый балл защищённости: {score}/100", self.styles['CustomNormal']))
        elements.append(Spacer(1, 0.45 * inch))

        elements.append(Paragraph(
            f"ИТОГОВОЕ ЗАКЛЮЧЕНИЕ: {status}",
            ParagraphStyle(
                name='StatusStyle',
                parent=self.styles['Heading3'],
                fontName=self.bold_font,
                fontSize=13,
                textColor=color,
                alignment=TA_CENTER,
                spaceAfter=16
            )
        ))

        elements.append(Paragraph(
            'Документ отражает результаты выполненных проверок, перечень выявленных рисков и рекомендуемые корректирующие меры.',
            self.styles['CustomNormal']
        ))

        return elements

    def _create_table_of_contents(self):
        elements = [Paragraph('СОДЕРЖАНИЕ', self.styles['CustomHeading2']), Spacer(1, 0.2 * inch)]

        toc_data = [
            ['1.', 'Краткое резюме', '3'],
            ['2.', 'Блок для страховой оценки', '3'],
            ['3.', 'Сводные показатели аудита', '4'],
            ['4.', 'Результаты проверок', '5'],
            ['5.', 'Реестр выявленных рисков', '6'],
            ['6.', 'План корректирующих мер', '7'],
            ['7.', 'Приложения и ограничения', '8'],
        ]

        toc_table = Table(toc_data, colWidths=[0.5 * inch, 5.2 * inch, 0.4 * inch])
        toc_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), self.base_font),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(toc_table)
        return elements

    def _create_executive_summary(self, data):
        elements = [Paragraph('1. КРАТКОЕ РЕЗЮМЕ', self.styles['CustomHeading2'])]
        elements.append(Paragraph(
            self._safe_text(data.get('executive_summary', 'Отчёт отражает текущее состояние по выбранным проверкам и выделяет приоритетные меры снижения риска.')),
            self.styles['CustomNormal']
        ))

        findings = self._as_list(data.get('findings'))
        if findings:
            top_findings = findings[:3]
            elements.append(Paragraph('Ключевые наблюдения:', self.styles['CustomHeading3']))
            for item in top_findings:
                item = self._as_dict(item)
                elements.append(Paragraph(
                    f"• {self._safe_text(item.get('severity_label', 'Средний'))} риск — {self._safe_text(item.get('title', 'Выявлено замечание'))}",
                    self.styles['CustomNormal']
                ))
        else:
            elements.append(Paragraph('Критичных замечаний по выполненным проверкам не зафиксировано.', self.styles['SuccessText']))

        elements.append(Spacer(1, 0.2 * inch))
        return elements

    def _create_insurance_section(self, data):
        profile = self._as_dict(data.get('insurance_profile'))
        elements = [Paragraph('2. БЛОК ДЛЯ СТРАХОВОЙ ОЦЕНКИ', self.styles['CustomHeading2'])]

        if not profile:
            elements.append(Paragraph('Дополнительные данные для страховой оценки не подготовлены.', self.styles['CustomNormal']))
            return elements

        summary_data = [
            [Paragraph('Объект оценки', self.styles['TableLabel']), Paragraph(self._safe_text(profile.get('target', 'Не указан')), self.styles['TableValue'])],
            [Paragraph('Основание оценки', self.styles['TableLabel']), Paragraph(self._safe_text(profile.get('assessment_basis', 'Экспресс-аудит')), self.styles['TableValue'])],
            [Paragraph('Общий уровень риска', self.styles['TableLabel']), Paragraph(self._safe_text(profile.get('overall_risk', 'Не определён')), self.styles['TableValue'])],
            [Paragraph('Андеррайтинговый вывод', self.styles['TableLabel']), Paragraph(self._safe_text(profile.get('underwriting_posture', 'Требует рассмотрения')), self.styles['TableValue'])],
        ]

        table = Table(summary_data, colWidths=[2.15 * inch, 3.95 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#F8FBFF')),
            ('GRID', (0, 0), (-1, -1), 0.7, HexColor('#D9E6F2')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 7),
            ('RIGHTPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#EEF4FB')),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.18 * inch))

        negatives = self._as_list(profile.get('negative_factors'))
        positives = self._as_list(profile.get('positive_factors'))

        if negatives:
            elements.append(Paragraph('Факторы, повышающие страховой риск:', self.styles['CustomHeading3']))
            for item in negatives:
                elements.append(Paragraph(f"• {self._safe_text(item, '')}", self.styles['CustomNormal']))

        if positives:
            elements.append(Paragraph('Факторы, снижающие риск:', self.styles['CustomHeading3']))
            for item in positives:
                elements.append(Paragraph(f"• {self._safe_text(item, '')}", self.styles['CustomNormal']))

        elements.append(Paragraph(self._safe_text(profile.get('insurer_summary', '')), self.styles['SmallMuted']))
        elements.append(Paragraph(self._safe_text(profile.get('residual_risk_note', '')), self.styles['SmallMuted']))
        return elements

    def _create_summary_section(self, data):
        elements = [Paragraph('3. СВОДНЫЕ ПОКАЗАТЕЛИ АУДИТА', self.styles['CustomHeading2'])]

        summary_data = [
            ['Параметр', 'Значение'],
            ['Дата проверки', self._safe_text(data.get('generated_at', datetime.now().strftime('%d.%m.%Y %H:%M:%S')))],
            ['Цель аудита', self._safe_text(data.get('target', 'Не указана'))],
            ['Общий балл безопасности', f"{self._safe_text(data.get('overall_score', 0), '0')}/100"],
            ['Критических уязвимостей', self._safe_text(data.get('critical_count', 0), '0')],
            ['Предупреждений', self._safe_text(data.get('warning_count', 0), '0')],
            ['Уровень риска', self._get_risk_level(data.get('overall_score', 0))],
        ]

        table = Table(summary_data, colWidths=[2.7 * inch, 3.5 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2E86C1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, -1), self.base_font),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#BDC3C7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#F8F9F9')]),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.2 * inch))
        return elements

    def _create_email_section(self, email_data):
        email_data = self._as_dict(email_data)
        elements = [Paragraph('4. РЕЗУЛЬТАТЫ ПРОВЕРОК', self.styles['CustomHeading2']), Paragraph('Проверка email на участие в утечках', self.styles['CustomHeading3'])]

        if not email_data:
            elements.append(Paragraph('Данные по проверке email не включены.', self.styles['SmallMuted']))
            return elements

        email = self._safe_text(email_data.get('email', 'N/A'))
        breaches = self._as_list(email_data.get('breaches', []))
        count = email_data.get('breaches_count', len(breaches) if breaches else 0)

        elements.append(Paragraph(f'Проверяемый адрес: <b>{email}</b>', self.styles['CustomNormal']))

        if count:
            elements.append(Paragraph(f'Обнаружено упоминаний в публичных утечках: <b>{count}</b>', self.styles['CriticalText']))
            elements.append(Paragraph(
                'Это не означает автоматический взлом прямо сейчас, но повышает вероятность атак через повторное использование старых паролей и подбор доступа к связанным сервисам.',
                self.styles['CustomNormal']
            ))
        else:
            elements.append(Paragraph('Утечек по указанному адресу не обнаружено.', self.styles['SuccessText']))

        elements.append(Spacer(1, 0.12 * inch))
        return elements

    def _create_password_section(self, password_data):
        password_data = self._as_dict(password_data)
        elements = [Paragraph('Анализ устойчивости пароля', self.styles['CustomHeading3'])]

        if not password_data:
            elements.append(Paragraph('Данные по анализу пароля не включены.', self.styles['SmallMuted']))
            return elements

        strength = self._safe_text(password_data.get('strength', 'unknown'), 'unknown')
        score = int(password_data.get('score', 0) or 0)

        if strength in ('very_strong', 'strong'):
            style = self.styles['SuccessText']
            status_text = 'Пароль имеет приемлемую или высокую стойкость.'
        elif strength == 'medium':
            style = self.styles['WarningText']
            status_text = 'Пароль имеет среднюю стойкость и требует усиления.'
        else:
            style = self.styles['CriticalText']
            status_text = 'Пароль недостаточно устойчив и требует замены.'

        elements.append(Paragraph(f'Итоговая оценка: <b>{score}/100</b>', self.styles['CustomNormal']))
        elements.append(Paragraph(status_text, style))
        elements.append(Paragraph(
            'Оценка опирается на длину, разнообразие символов, предполагаемую сложность подбора и дополнительные признаки риска.',
            self.styles['CustomNormal']
        ))
        elements.append(Spacer(1, 0.12 * inch))
        return elements

    def _create_ports_section(self, port_data):
        port_data = self._as_dict(port_data)
        elements = [Paragraph('Сканирование сетевых портов', self.styles['CustomHeading3'])]

        if not port_data:
            elements.append(Paragraph('Данные по сканированию портов не включены.', self.styles['SmallMuted']))
            return elements

        open_ports = self._as_list(port_data.get('open_ports', []))
        vulnerabilities = self._as_list(port_data.get('vulnerabilities', []))
        host = self._safe_text(port_data.get('host', 'Проверяемый хост'), 'Проверяемый хост')

        elements.append(Paragraph(f'Проверяемый хост: <b>{host}</b>', self.styles['CustomNormal']))
        elements.append(Paragraph(f'Количество открытых портов из стандартного набора проверки: <b>{len(open_ports)}</b>', self.styles['CustomNormal']))

        if vulnerabilities:
            elements.append(Paragraph(f'Дополнительной оценки требуют сервисы: <b>{len(vulnerabilities)}</b>', self.styles['WarningText']))
        elif open_ports:
            elements.append(Paragraph('Критичных сетевых замечаний по стандартной логике сопоставления не обнаружено.', self.styles['SuccessText']))
        else:
            elements.append(Paragraph('Открытые порты из стандартного списка не обнаружены.', self.styles['SuccessText']))

        return elements

    def _create_findings_section(self, findings):
        findings = self._as_list(findings)
        elements = [Paragraph('5. РЕЕСТР ВЫЯВЛЕННЫХ РИСКОВ', self.styles['CustomHeading2'])]

        if not findings:
            elements.append(Paragraph('Риски, требующие отдельного описания, не выявлены.', self.styles['SuccessText']))
            return elements

        table_data = [['Приоритет', 'Категория', 'Описание риска', 'Актив / область']]
        for item in findings:
            item = self._as_dict(item)
            table_data.append([
                self._safe_text(item.get('severity_label', 'Средний')),
                self._safe_text(item.get('category', 'Общее')),
                self._safe_text(item.get('title', 'Выявлено замечание')),
                self._safe_text(item.get('asset', '—')),
            ])

        registry = Table(table_data, colWidths=[1.0 * inch, 1.5 * inch, 2.9 * inch, 1.0 * inch])
        registry.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#244B74')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, -1), self.base_font),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.8, HexColor('#CFD9E6')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(registry)
        elements.append(Spacer(1, 0.14 * inch))

        for index, item in enumerate(findings, 1):
            item = self._as_dict(item)
            elements.append(Paragraph(f"{index}. {self._safe_text(item.get('title', 'Выявленный риск'))}", self.styles['CustomHeading3']))
            elements.append(Paragraph(f"<b>Категория:</b> {self._safe_text(item.get('category', 'Общее'))}", self.styles['CustomNormal']))
            elements.append(Paragraph(f"<b>Суть риска:</b> {self._safe_text(item.get('description', 'Описание отсутствует'))}", self.styles['CustomNormal']))
            elements.append(Paragraph(f"<b>Возможный вектор атаки:</b> {self._safe_text(item.get('attack_vector', 'Не указан'))}", self.styles['CustomNormal']))
            elements.append(Paragraph(f"<b>Влияние на бизнес:</b> {self._safe_text(item.get('business_impact', 'Не указано'))}", self.styles['CustomNormal']))
            elements.append(Paragraph(f"<b>Пояснение для неподготовленного пользователя:</b> {self._safe_text(item.get('user_guidance', 'Не указано'))}", self.styles['CustomNormal']))
            elements.append(Paragraph(f"<b>Значение для страховой оценки:</b> {self._safe_text(item.get('insurer_relevance', 'Не указано'))}", self.styles['SmallMuted']))
            elements.append(Spacer(1, 0.12 * inch))

        return elements

    def _create_recommendations_section(self, recommendations):
        recommendations = self._as_list(recommendations)
        elements = [Paragraph('6. ПЛАН КОРРЕКТИРУЮЩИХ МЕР', self.styles['CustomHeading2'])]

        if not recommendations:
            elements.append(Paragraph('Рекомендации отсутствуют.', self.styles['CustomNormal']))
            return elements

        for index, rec in enumerate(recommendations, 1):
            rec = self._as_dict(rec) if isinstance(rec, dict) else {'title': f'Рекомендация {index}', 'description': self._safe_text(rec, '')}
            elements.append(Paragraph(f"{index}. {self._safe_text(rec.get('title', f'Рекомендация {index}'))}", self.styles['CustomHeading3']))
            elements.append(Paragraph(f"<b>Приоритет:</b> {self._safe_text(rec.get('priority', 'Плановый приоритет'))}", self.styles['CustomNormal']))
            elements.append(Paragraph(f"<b>Что нужно сделать:</b> {self._safe_text(rec.get('description', 'Не указано'))}", self.styles['CustomNormal']))

            rationale = rec.get('rationale')
            if rationale:
                elements.append(Paragraph(f"<b>Почему это важно:</b> {self._safe_text(rationale)}", self.styles['CustomNormal']))

            business_effect = rec.get('business_effect')
            if business_effect:
                elements.append(Paragraph(f"<b>Какой риск это снижает:</b> {self._safe_text(business_effect)}", self.styles['CustomNormal']))

            simple_help = rec.get('for_non_technical_user')
            if simple_help:
                elements.append(Paragraph(f"<b>Как действовать простыми словами:</b> {self._safe_text(simple_help)}", self.styles['CustomNormal']))

            elements.append(Spacer(1, 0.14 * inch))

        return elements

    def _create_appendix(self, data):
        elements = [Paragraph('7. ПРИЛОЖЕНИЯ И ОГРАНИЧЕНИЯ', self.styles['CustomHeading2'])]
        elements.append(Paragraph('Использованные источники данных:', self.styles['CustomHeading3']))
        elements.append(Paragraph('• Have I Been Pwned API', self.styles['CustomNormal']))
        elements.append(Paragraph('• Локальная логика анализа пароля', self.styles['CustomNormal']))
        elements.append(Paragraph('• Локальная логика анализа открытых портов и типовых сетевых рисков', self.styles['CustomNormal']))
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph('Ограничения отчёта:', self.styles['CustomHeading3']))
        elements.append(Paragraph(
            'Документ не является полным тестом на проникновение и не подтверждает отсутствие всех возможных уязвимостей. '
            'Он отражает результат конкретных автоматизированных проверок на момент формирования.',
            self.styles['CustomNormal']
        ))
        return elements

    def _add_header_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFont(self.base_font, 8)
        canvas.setFillColor(HexColor('#1A5276'))
        canvas.drawString(2 * cm, doc.pagesize[1] - 1 * cm, 'Отчёт по аудиту кибербезопасности')
        canvas.drawString(doc.pagesize[0] - 10 * cm, doc.pagesize[1] - 1 * cm, f'Страница {doc.page}')
        canvas.setFillColor(HexColor('#7F8C8D'))
        canvas.drawString(2 * cm, 1 * cm, '© 2026 Кибер-щит для ИП. Все права защищены.')
        canvas.drawString(doc.pagesize[0] - 8 * cm, 1 * cm, f"Сформирован: {datetime.now().strftime('%d.%m.%Y')}")
        canvas.restoreState()
