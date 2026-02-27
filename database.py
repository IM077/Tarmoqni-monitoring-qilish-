"""
Database moduli — SQLite bazani yaratish va ma'lumotlar bilan ishlash.
traffic_logs, alerts va sessions jadvallarini boshqaradi.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic.db")


def get_connection():
    """Bazaga ulanishni qaytaradi."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def create_database():
    """Bazani yaratadi (jadvallar mavjud bo'lmasa)."""
    conn = get_connection()
    cursor = conn.cursor()

    # Eski baza sxemasini tekshirish va migratsiya
    try:
        cursor.execute("PRAGMA table_info(traffic_logs)")
        columns = [row[1] for row in cursor.fetchall()]
        if columns and 'dest_port' not in columns:
            print("[DB] Eski sxema aniqlandi — jadvallar yangilanmoqda...")
            cursor.execute("DROP TABLE IF EXISTS traffic_logs")
            cursor.execute("DROP TABLE IF EXISTS alerts")
            cursor.execute("DROP TABLE IF EXISTS sessions")
            conn.commit()
    except Exception:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            source_port INTEGER DEFAULT 0,
            dest_port INTEGER DEFAULT 0,
            protocol TEXT DEFAULT 'Unknown',
            app_protocol TEXT DEFAULT '',
            size INTEGER DEFAULT 0,
            info TEXT DEFAULT '',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT DEFAULT 'MEDIUM',
            source_ip TEXT,
            dest_ip TEXT DEFAULT '',
            port INTEGER DEFAULT 0,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active'
        )
    """)

    # Indekslar — tezlikni oshirish uchun
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON traffic_logs(source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_dest_ip ON traffic_logs(dest_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_protocol ON traffic_logs(protocol)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON traffic_logs(timestamp)")

    conn.commit()
    conn.close()
    print("[DB] Database tayyor.")


# ==================== PACKET OPERATIONS ====================

def save_packet(source_ip, dest_ip, source_port, dest_port, protocol, app_protocol, size, info=""):
    """Bitta paket ma'lumotini bazaga saqlaydi."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO traffic_logs 
            (source_ip, dest_ip, source_port, dest_port, protocol, app_protocol, size, info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (source_ip, dest_ip, source_port, dest_port, protocol, app_protocol, size, info))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Xato: {e}")


def get_all_logs(limit=1000):
    """Oxirgi N ta trafik loglarini qaytaradi."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, source_ip, dest_ip, source_port, dest_port, 
               protocol, app_protocol, size, info, timestamp
        FROM traffic_logs ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


# ==================== STATISTICS ====================

def get_total_packets():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM traffic_logs")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_total_size():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COALESCE(SUM(size), 0) FROM traffic_logs")
    total = cursor.fetchone()[0]
    conn.close()
    return total


def get_unique_ips():
    """Noyob IP manzillar sonini qaytaradi."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(DISTINCT source_ip) + COUNT(DISTINCT dest_ip) FROM traffic_logs
    """)
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_stats_by_protocol():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT protocol, COUNT(*) as count, SUM(size) as total_size
        FROM traffic_logs GROUP BY protocol ORDER BY count DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [(row[0], row[1], row[2]) for row in rows]


def get_stats_by_app_protocol():
    """Ilova protokollari bo'yicha statistika."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT app_protocol, COUNT(*) as count
        FROM traffic_logs WHERE app_protocol != ''
        GROUP BY app_protocol ORDER BY count DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [(row[0], row[1]) for row in rows]


def get_top_ips(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT source_ip, COUNT(*) as count, SUM(size) as total_size
        FROM traffic_logs GROUP BY source_ip ORDER BY count DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [(row[0], row[1], row[2]) for row in rows]


def get_top_dest_ips(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT dest_ip, COUNT(*) as count, SUM(size) as total_size
        FROM traffic_logs GROUP BY dest_ip ORDER BY count DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [(row[0], row[1], row[2]) for row in rows]


def get_top_ports(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT dest_port, COUNT(*) as count
        FROM traffic_logs WHERE dest_port > 0
        GROUP BY dest_port ORDER BY count DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [(row[0], row[1]) for row in rows]


def get_traffic_over_time():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT strftime('%H:%M', timestamp) as minute, 
               COUNT(*) as count, SUM(size) as total_size
        FROM traffic_logs GROUP BY minute ORDER BY minute
    """)
    rows = cursor.fetchall()
    conn.close()
    return [(row[0], row[1], row[2]) for row in rows]


def get_packets_per_second(seconds=30):
    """Oxirgi N soniya ichida paketlar tezligini qaytaradi."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM traffic_logs
        WHERE timestamp >= datetime('now', '-' || ? || ' seconds')
    """, (seconds,))
    count = cursor.fetchone()[0]
    conn.close()
    return count / max(seconds, 1)


def get_bandwidth_per_second(seconds=30):
    """Oxirgi N soniya ichida o'rtacha tarmoq tezligini qaytaradi."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COALESCE(SUM(size), 0) FROM traffic_logs
        WHERE timestamp >= datetime('now', '-' || ? || ' seconds')
    """, (seconds,))
    total = cursor.fetchone()[0]
    conn.close()
    return total / max(seconds, 1)


# ==================== ALERTS ====================

def save_alert(alert_type, severity, source_ip, dest_ip, port, message):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (alert_type, severity, source_ip, dest_ip, port, message)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (alert_type, severity, source_ip, dest_ip, port, message))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Alert xato: {e}")


def get_alerts(limit=200):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, alert_type, severity, source_ip, dest_ip, port, message, timestamp
        FROM alerts ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_alert_count():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    conn.close()
    return count


# ==================== SESSIONS ====================

def start_session():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO sessions (status) VALUES ('active')")
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return session_id


def end_session(session_id, total_packets, total_bytes):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE sessions SET end_time = CURRENT_TIMESTAMP, 
        total_packets = ?, total_bytes = ?, status = 'completed'
        WHERE id = ?
    """, (total_packets, total_bytes, session_id))
    conn.commit()
    conn.close()


# ==================== UTILITY ====================

def get_ip_packet_count(ip, seconds=60):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM traffic_logs
        WHERE source_ip = ? AND timestamp >= datetime('now', '-' || ? || ' seconds')
    """, (ip, seconds))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def search_logs(query, limit=500):
    """IP, port yoki protokol bo'yicha qidirish."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, source_ip, dest_ip, source_port, dest_port,
               protocol, app_protocol, size, info, timestamp
        FROM traffic_logs 
        WHERE source_ip LIKE ? OR dest_ip LIKE ? 
              OR protocol LIKE ? OR app_protocol LIKE ?
              OR CAST(dest_port AS TEXT) LIKE ?
        ORDER BY id DESC LIMIT ?
    """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def clear_logs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM traffic_logs")
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


def format_bytes(b):
    """Baytlarni odam o'qiy oladigan formatga o'tkazish."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / (1024 ** 2):.2f} MB"
    else:
        return f"{b / (1024 ** 3):.2f} GB"


if __name__ == "__main__":
    create_database()
