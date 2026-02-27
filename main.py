"""
Network Traffic Monitor v2.0 — Professional
Kompyuter tarmog'i trafikini monitoring qilish va tahlil qilish dasturi

Ishga tushirish:
    1. CMD ni Administrator sifatida oching
    2. python main.py

Talablar:
    - Python 3.10+
    - Npcap (https://npcap.com)
    - scapy, matplotlib (pip install -r requirements.txt)
"""

import sys
import database
import gui

def print_banner():
    print()
    print("  ========================================================")
    print("  |                                                      |")
    print("  |    NETWORK TRAFFIC MONITOR  v2.0  Professional       |")
    print("  |                                                      |")
    print("  |    Kompyuter tarmog'i trafikini                      |")
    print("  |    monitoring qilish va tahlil qilish dasturi        |")
    print("  |                                                      |")
    print("  |    Python + SQLite + Scapy + Tkinter                 |")
    print("  |                                                      |")
    print("  ========================================================")
    print()


def check_requirements():
    missing = []
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    try:
        import matplotlib
    except ImportError:
        missing.append("matplotlib")

    if missing:
        print(f"  [!] Kutubxonalar topilmadi: {', '.join(missing)}")
        print(f"  [!] O'rnating: pip install {' '.join(missing)}")
        return False
    return True


def main():
    print_banner()

    print("  [1/3] Kutubxonalar tekshirilmoqda...")
    if not check_requirements():
        sys.exit(1)
    print("  [OK]  Barcha kutubxonalar mavjud")

    print("  [2/3] Database tayyorlanmoqda...")
    database.create_database()
    print("  [OK]  SQLite baza tayyor")

    print("  [3/3] Dashboard ishga tushirilmoqda...")
    print()
    print("  +------------------------------------------+")
    print("  |  MUHIM ESLATMALAR:                       |")
    print("  |                                          |")
    print("  |  1. Administrator huquqi kerak            |")
    print("  |  2. Npcap o'rnatilgan bo'lishi kerak      |")
    print("  |     https://npcap.com                     |")
    print("  |                                          |")
    print("  |  Dastur tayyor! GUI oynasi ochilyapti... |")
    print("  +------------------------------------------+")
    print()

    gui.run_gui()


if __name__ == "__main__":
    main()
