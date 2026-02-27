"""
Alerts moduli — Xavfli trafik, DDoS, port scanning va anomaliyalarni aniqlash.
Kuchaytirilgan xavfsizlik tizimi.
"""

import database
from collections import defaultdict
import time

# ==================== KONFIGURATSIYA ====================

# Xavfli portlar
SUSPICIOUS_PORTS = {
    23: ("Telnet", "HIGH", "Shifrlanmagan masofaviy ulanish"),
    21: ("FTP", "MEDIUM", "Shifrlanmagan fayl uzatish"),
    445: ("SMB", "HIGH", "Windows fayl almashish — WannaCry xavfi"),
    3389: ("RDP", "HIGH", "Masofaviy ish stoli — brute force xavfi"),
    1433: ("MSSQL", "HIGH", "MS SQL tashqi ulanish"),
    3306: ("MySQL", "HIGH", "MySQL tashqi ulanish"),
    5432: ("PostgreSQL", "HIGH", "PostgreSQL tashqi ulanish"),
    5900: ("VNC", "HIGH", "Masofaviy ish stoli"),
    4444: ("Metasploit", "CRITICAL", "Metasploit standart porti"),
    6667: ("IRC", "MEDIUM", "IRC — botnet tarmog'i xavfi"),
    8080: ("HTTP-Proxy", "LOW", "Ochiq HTTP proksi"),
    1080: ("SOCKS", "MEDIUM", "SOCKS proksi — anonim ulanish"),
    31337: ("BackOrifice", "CRITICAL", "Troyan standart porti"),
    12345: ("NetBus", "CRITICAL", "Troyan standart porti"),
    27374: ("SubSeven", "CRITICAL", "Troyan standart porti"),
}

# Chegaralar
DDOS_THRESHOLD = 150            # Bitta IP dan paketlar limiti
LARGE_PACKET_SIZE = 10000       # Katta paket chegarasi (baytlarda)
PORT_SCAN_THRESHOLD = 15        # Bitta IP dan turli portlar soni

# ==================== TRACKING ====================

_alerted_ddos = set()
_alerted_ports = set()
_alerted_large = set()
_alerted_scan = set()

# Port scan tracker: ip -> set(ports)
_port_access = defaultdict(set)
_port_access_time = defaultdict(float)

# Alert callback
alert_callback = None


def set_alert_callback(callback):
    global alert_callback
    alert_callback = callback


def _send_alert(alert_type, severity, source_ip, dest_ip, port, message):
    """Alertni bazaga saqlash va GUI ga yuborish."""
    database.save_alert(alert_type, severity, source_ip, dest_ip, port, message)
    print(f"[ALERT] [{severity}] {message}")
    if alert_callback:
        alert_callback(alert_type, severity, source_ip, message)


# ==================== TEKSHIRISH FUNKSIYALARI ====================

def check_ddos(source_ip, packet_count):
    """DDoS / flood hujumini aniqlash."""
    if packet_count >= DDOS_THRESHOLD and source_ip not in _alerted_ddos:
        _alerted_ddos.add(source_ip)
        msg = f"🔴 DDoS/Flood shubhasi: {source_ip} dan {packet_count}+ paket yuborildi!"
        _send_alert("DDoS", "CRITICAL", source_ip, "", 0, msg)


def check_suspicious_port(source_ip, dest_ip, port):
    """Xavfli port ulanishini aniqlash."""
    if port in SUSPICIOUS_PORTS:
        combo = f"{source_ip}:{port}"
        if combo not in _alerted_ports:
            _alerted_ports.add(combo)
            name, severity, reason = SUSPICIOUS_PORTS[port]
            msg = f"⚠️ Xavfli port: {source_ip} → {dest_ip}:{port} ({name} — {reason})"
            _send_alert("Suspicious Port", severity, source_ip, dest_ip, port, msg)


def check_large_packet(source_ip, dest_ip, size):
    """Haddan tashqari katta paketni aniqlash."""
    if size >= LARGE_PACKET_SIZE:
        combo = f"{source_ip}-large"
        if combo not in _alerted_large:
            _alerted_large.add(combo)
            msg = f"📦 Katta paket: {source_ip} → {dest_ip} | {database.format_bytes(size)}"
            _send_alert("Large Packet", "MEDIUM", source_ip, dest_ip, 0, msg)


def check_port_scan(source_ip, dest_port):
    """Port scanning hujumini aniqlash."""
    now = time.time()

    # Eski ma'lumotlarni tozalash (5 daqiqadan eski)
    if now - _port_access_time.get(source_ip, 0) > 300:
        _port_access[source_ip].clear()
        _port_access_time[source_ip] = now

    _port_access[source_ip].add(dest_port)

    if len(_port_access[source_ip]) >= PORT_SCAN_THRESHOLD and source_ip not in _alerted_scan:
        _alerted_scan.add(source_ip)
        port_count = len(_port_access[source_ip])
        msg = f"🔍 Port scan aniqlandi: {source_ip} {port_count} ta turli portga ulanmoqda!"
        _send_alert("Port Scan", "HIGH", source_ip, "", 0, msg)


def reset_alerts():
    """Barcha alert tracker larni tozalash."""
    _alerted_ddos.clear()
    _alerted_ports.clear()
    _alerted_large.clear()
    _alerted_scan.clear()
    _port_access.clear()
    _port_access_time.clear()


def get_severity_color(severity):
    """Alert darajasi uchun rang qaytaradi."""
    return {
        "CRITICAL": "#ff1744",
        "HIGH": "#ff6b6b",
        "MEDIUM": "#feca57",
        "LOW": "#48dbfb",
    }.get(severity, "#e0e0e0")
