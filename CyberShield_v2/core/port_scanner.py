import socket
import threading
from datetime import datetime

class PortScanner:
    """Сканер открытых портов для выявления уязвимых сервисов"""

    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Proxy'
    }

    def __init__(self, host='localhost', timeout=1):
        self.host = host
        self.timeout = timeout
        self.open_ports = []

    def scan_port(self, port):
        """Проверка одного порта"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))

            if result == 0:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                self.open_ports.append({
                    'port': port,
                    'service': service,
                    'state': 'open'
                })
            sock.close()
        except Exception:
            pass

    def scan(self, ports=None):
        """
        Сканирование портов
        :param ports: список портов для проверки (None = стандартные)
        :return: список открытых портов
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())

        self.open_ports = []
        threads = []

        for port in ports:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return self.open_ports

    def get_vulnerabilities(self):
        """Анализ уязвимостей открытых портов"""
        vulnerabilities = []

        dangerous_ports = {
            21: {'severity': 'high', 'desc': 'FTP передает данные в открытом виде'},
            23: {'severity': 'critical', 'desc': 'Telnet не использует шифрование'},
            445: {'severity': 'high', 'desc': 'SMB часто эксплуатируется (wannacry)'},
            3389: {'severity': 'medium', 'desc': 'RDP требует усиленной аутентификации'},
            3306: {'severity': 'medium', 'desc': 'MySQL не должен быть доступен извне'},
            5432: {'severity': 'medium', 'desc': 'PostgreSQL требует ограничения доступа'}
        }

        for port_info in self.open_ports:
            port = port_info['port']
            if port in dangerous_ports:
                vuln = dangerous_ports[port]
                vulnerabilities.append({
                    'port': port,
                    'service': port_info['service'],
                    'severity': vuln['severity'],
                    'description': vuln['desc'],
                    'recommendation': f'Закройте порт {port} или ограничьте доступ через фаервол'
                })

        return vulnerabilities