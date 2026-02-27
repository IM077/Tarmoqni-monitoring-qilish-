"""
Monitor moduli — Scapy yordamida tarmoq paketlarini real vaqtda ushlash.
TCP, UDP, ICMP, DNS, HTTP, HTTPS va boshqa protokollarni batafsil aniqlaydi.
"""

import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, conf, get_if_list
import database
import alerts as alert_module

# Windows da Npcap
conf.use_pcap = True

# Ma'lum portlar va ilova protokollari
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1434: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB", 6379: "Redis",
}


def get_available_interfaces():
    """Mavjud tarmoq interfeyslarini qaytaradi."""
    try:
        ifaces = get_if_list()
        return ifaces if ifaces else ["default"]
    except Exception:
        return ["default"]


def identify_app_protocol(packet, dest_port, source_port):
    """Ilova protokolini aniqlash."""
    # DNS
    if packet.haslayer(DNS):
        return "DNS"

    # Port asosida
    port = dest_port if dest_port in WELL_KNOWN_PORTS else source_port
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]

    # HTTP aniqlash (payload ichida)
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load[:50].decode('utf-8', errors='ignore')
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'HTTP/')):
                return "HTTP"
        except Exception:
            pass

    return ""


class NetworkMonitor:
    """Tarmoq monitoring sinfi — professional paket ushlash va tahlil."""

    def __init__(self, packet_callback=None, stats_callback=None):
        self.is_running = False
        self.sniffer_thread = None
        self.packet_callback = packet_callback
        self.stats_callback = stats_callback

        # Hisoblagichlar
        self.packet_count = 0
        self.total_bytes = 0
        self.start_time = None
        self.session_id = None

        # Tezlik hisoblash
        self._packets_last_second = 0
        self._bytes_last_second = 0
        self._last_rate_time = time.time()
        self.packets_per_second = 0
        self.bytes_per_second = 0

        # IP tracker (alertlar uchun)
        self._ip_counter = {}

        # Protokol counter
        self.protocol_counts = {}

        # Interfeys
        self.interface = None

    def process_packet(self, packet):
        """Bitta paketni qayta ishlaydi."""
        if not self.is_running:
            return

        if not packet.haslayer(IP):
            return

        try:
            ip_layer = packet[IP]
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst
            size = len(packet)
            ttl = ip_layer.ttl
            protocol = "Other"
            source_port = 0
            dest_port = 0
            info = ""

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                protocol = "TCP"
                source_port = tcp.sport
                dest_port = tcp.dport
                flags = str(tcp.flags)
                info = f"Flags: [{flags}] TTL:{ttl}"

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                protocol = "UDP"
                source_port = udp.sport
                dest_port = udp.dport
                info = f"Len:{udp.len} TTL:{ttl}"

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                protocol = "ICMP"
                icmp_type = icmp.type
                icmp_code = icmp.code
                type_names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
                type_name = type_names.get(icmp_type, f"Type:{icmp_type}")
                info = f"{type_name} Code:{icmp_code} TTL:{ttl}"

            # Ilova protokolini aniqlash
            app_protocol = identify_app_protocol(packet, dest_port, source_port)

            # DNS query ma'lumotlari
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                try:
                    qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                    info = f"Query: {qname}"
                except Exception:
                    pass

            # Bazaga saqlash
            database.save_packet(source_ip, dest_ip, source_port, dest_port,
                                 protocol, app_protocol, size, info)

            # Hisoblagichlar
            self.packet_count += 1
            self.total_bytes += size
            self._packets_last_second += 1
            self._bytes_last_second += size

            # Protokol counter
            self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1

            # IP counter
            self._ip_counter[source_ip] = self._ip_counter.get(source_ip, 0) + 1

            # Tezlik hisoblash
            now = time.time()
            elapsed = now - self._last_rate_time
            if elapsed >= 1.0:
                self.packets_per_second = self._packets_last_second / elapsed
                self.bytes_per_second = self._bytes_last_second / elapsed
                self._packets_last_second = 0
                self._bytes_last_second = 0
                self._last_rate_time = now

            # Alert tekshirish
            alert_module.check_ddos(source_ip, self._ip_counter.get(source_ip, 0))
            alert_module.check_suspicious_port(source_ip, dest_ip, dest_port)
            alert_module.check_large_packet(source_ip, dest_ip, size)

            # GUI callback
            if self.packet_callback:
                self.packet_callback(source_ip, dest_ip, source_port, dest_port,
                                     protocol, app_protocol, size, info)

        except Exception as e:
            pass  # Xatolarni jimgina o'tkazamiz

    def _sniff_packets(self):
        """Sniffing jarayoni."""
        try:
            kwargs = {
                'prn': self.process_packet,
                'store': False,
                'stop_filter': lambda x: not self.is_running,
            }
            if self.interface:
                kwargs['iface'] = self.interface

            sniff(**kwargs)
        except PermissionError:
            print("[MONITOR] XATO: Administrator huquqi kerak!")
            self.is_running = False
        except Exception as e:
            print(f"[MONITOR] XATO: {e}")
            self.is_running = False

    def start(self, interface=None):
        """Monitoringni boshlash."""
        if self.is_running:
            return False

        self.interface = interface
        self.is_running = True
        self.start_time = time.time()
        self.session_id = database.start_session()
        self._last_rate_time = time.time()

        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()
        print(f"[MONITOR] >> Monitoring boshlandi")
        return True

    def stop(self):
        """Monitoringni to'xtatish."""
        if not self.is_running:
            return

        self.is_running = False

        if self.session_id:
            database.end_session(self.session_id, self.packet_count, self.total_bytes)

        elapsed = time.time() - self.start_time if self.start_time else 0
        print(f"[MONITOR] To'xtatildi | {self.packet_count} paket | "
              f"{database.format_bytes(self.total_bytes)} | {elapsed:.0f}s")

    def reset_counters(self):
        """Hisoblagichlarni nolga qaytaradi."""
        self.packet_count = 0
        self.total_bytes = 0
        self.packets_per_second = 0
        self.bytes_per_second = 0
        self._ip_counter.clear()
        self.protocol_counts.clear()

    def get_uptime(self):
        """Monitoring vaqtini qaytaradi."""
        if not self.start_time or not self.is_running:
            return "00:00:00"
        elapsed = int(time.time() - self.start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


if __name__ == "__main__":
    database.create_database()

    def on_packet(src, dst, sp, dp, proto, app, size, info):
        print(f"  {src}:{sp} → {dst}:{dp} | {proto}/{app} | {size}B | {info}")

    mon = NetworkMonitor(packet_callback=on_packet)
    print("Interfeyslar:", get_available_interfaces())
    mon.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mon.stop()
