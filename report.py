"""
Report moduli — Trafik loglarini CSV va TXT formatda eksport qilish.
Professional hisobot generatsiyasi.
"""

import csv
import os
from datetime import datetime
import database


def export_traffic_csv(filepath=None):
    """Barcha trafik loglarini CSV faylga eksport qiladi."""
    if filepath is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"traffic_report_{timestamp}.csv"
        )

    logs = database.get_all_logs(limit=50000)

    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "Source IP", "Dest IP", "Source Port", "Dest Port",
            "Protocol", "App Protocol", "Size (bytes)", "Info", "Timestamp"
        ])
        for row in logs:
            writer.writerow([row[0], row[1], row[2], row[3], row[4],
                             row[5], row[6], row[7], row[8], row[9]])

    print(f"[REPORT] CSV saqlandi: {filepath}")
    return filepath


def export_full_report(filepath=None):
    """To'liq statistik hisobotni CSV ga eksport qiladi."""
    if filepath is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"full_report_{timestamp}.csv"
        )

    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)

        # Sarlavha
        writer.writerow(["=" * 50])
        writer.writerow(["TARMOQ TRAFIK MONITORING HISOBOTI"])
        writer.writerow([f"Sana: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow(["=" * 50])
        writer.writerow([])

        # Umumiy statistika
        writer.writerow(["### UMUMIY STATISTIKA ###"])
        writer.writerow(["Ko'rsatkich", "Qiymat"])
        writer.writerow(["Jami paketlar", f"{database.get_total_packets():,}"])
        writer.writerow(["Jami trafik", database.format_bytes(database.get_total_size())])
        writer.writerow(["Noyob IP lar", database.get_unique_ips()])
        writer.writerow([])

        # Protokollar
        writer.writerow(["### PROTOKOLLAR ###"])
        writer.writerow(["Protokol", "Paketlar", "Hajm"])
        for proto, count, size in database.get_stats_by_protocol():
            writer.writerow([proto, f"{count:,}", database.format_bytes(size)])
        writer.writerow([])

        # Ilova protokollari
        writer.writerow(["### ILOVA PROTOKOLLARI ###"])
        writer.writerow(["Protokol", "Paketlar"])
        for proto, count in database.get_stats_by_app_protocol():
            writer.writerow([proto, f"{count:,}"])
        writer.writerow([])

        # Top Source IP
        writer.writerow(["### TOP 10 MANBA IP ###"])
        writer.writerow(["IP", "Paketlar", "Hajm"])
        for ip, count, size in database.get_top_ips(10):
            writer.writerow([ip, f"{count:,}", database.format_bytes(size)])
        writer.writerow([])

        # Top Dest IP
        writer.writerow(["### TOP 10 MANZIL IP ###"])
        writer.writerow(["IP", "Paketlar", "Hajm"])
        for ip, count, size in database.get_top_dest_ips(10):
            writer.writerow([ip, f"{count:,}", database.format_bytes(size)])
        writer.writerow([])

        # Top Portlar
        writer.writerow(["### TOP 10 PORTLAR ###"])
        writer.writerow(["Port", "Paketlar"])
        for port, count in database.get_top_ports(10):
            writer.writerow([port, f"{count:,}"])
        writer.writerow([])

        # Alertlar
        alerts = database.get_alerts(50)
        if alerts:
            writer.writerow(["### ALERTLAR ###"])
            writer.writerow(["Turi", "Daraja", "IP", "Xabar", "Vaqt"])
            for a in alerts:
                writer.writerow([a[1], a[2], a[3], a[6], a[7]])

    print(f"[REPORT] To'liq hisobot saqlandi: {filepath}")
    return filepath


if __name__ == "__main__":
    export_traffic_csv()
    export_full_report()
