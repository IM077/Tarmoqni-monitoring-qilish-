"""
Analysis moduli — Professional dark theme grafiklar.
Matplotlib bilan 6 xil grafik: protokol, IP, port, timeline, pie, hajm.
"""

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import database

# ==================== DIZAYN ====================

COLORS = ['#00d2ff', '#7b2ff7', '#ff6b6b', '#feca57', '#48dbfb',
          '#ff9ff3', '#54a0ff', '#5f27cd', '#01a3a4', '#f368e0',
          '#00e676', '#ff5252', '#ea80fc', '#64ffda', '#ffab40']

BG_COLOR = '#0f0f1a'
CARD_BG = '#1a1a2e'
TEXT_COLOR = '#e0e0e0'
GRID_COLOR = '#2d2d4a'
ACCENT = '#00d2ff'


def _dark_style(ax):
    """Dark theme qo'llash."""
    ax.set_facecolor(CARD_BG)
    ax.tick_params(colors=TEXT_COLOR, labelsize=8)
    ax.xaxis.label.set_color(TEXT_COLOR)
    ax.yaxis.label.set_color(TEXT_COLOR)
    ax.title.set_color('#ffffff')
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(True, alpha=0.12, color=GRID_COLOR, linestyle='--')


def _add_value_labels(ax, bars, color=TEXT_COLOR):
    """Bar grafiklarga qiymat yozish."""
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, height,
                    f'{int(height):,}', ha='center', va='bottom',
                    color=color, fontsize=8, fontweight='bold')


def _add_hbar_labels(ax, bars, values, color=TEXT_COLOR):
    """Gorizontal bar grafiklarga qiymat yozish."""
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + bar.get_width() * 0.02, 
                bar.get_y() + bar.get_height() / 2,
                f'{int(val):,}', ha='left', va='center',
                color=color, fontsize=8, fontweight='bold')


# ==================== INDIVIDUAL CHARTS ====================

def show_protocol_chart():
    """Protokol bo'yicha trafik."""
    data = database.get_stats_by_protocol()
    if not data:
        return

    protocols = [r[0] for r in data]
    counts = [r[1] for r in data]
    sizes = [r[2] for r in data]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle("📊 PROTOKOLLAR BO'YICHA TRAFIK TAHLILI", fontsize=14,
                 fontweight='bold', color='white', y=0.98)

    # Bar chart
    bars = ax1.bar(protocols, counts, color=COLORS[:len(protocols)],
                   edgecolor='white', linewidth=0.3, width=0.6)
    ax1.set_title("Paketlar soni", fontsize=11, pad=10)
    ax1.set_ylabel("Soni")
    _dark_style(ax1)
    _add_value_labels(ax1, bars)

    # Pie chart
    explode = [0.05] * len(protocols)
    wedges, texts, autotexts = ax2.pie(counts, labels=protocols, autopct='%1.1f%%',
                                        colors=COLORS[:len(protocols)], explode=explode,
                                        textprops={'color': TEXT_COLOR, 'fontsize': 9},
                                        pctdistance=0.75, startangle=90)
    for t in autotexts:
        t.set_fontweight('bold')
    ax2.set_title("Foiz taqsimoti", fontsize=11, color='white', pad=10)
    ax2.set_facecolor(CARD_BG)

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    plt.show(block=False)


def show_top_ips_chart():
    """Top IP manzillar."""
    src = database.get_top_ips(10)
    dst = database.get_top_dest_ips(10)
    if not src and not dst:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle("🌐 TOP IP MANZILLAR", fontsize=14,
                 fontweight='bold', color='white', y=0.98)

    # Source IPs
    if src:
        ips = [r[0] for r in src][::-1]
        counts = [r[1] for r in src][::-1]
        bars = ax1.barh(range(len(ips)), counts, color=COLORS[:len(ips)],
                        edgecolor='white', linewidth=0.3, height=0.6)
        ax1.set_yticks(range(len(ips)))
        ax1.set_yticklabels(ips, fontsize=8)
        _add_hbar_labels(ax1, bars, counts)
    ax1.set_title("📤 Manba (Source) IP", fontsize=11, pad=10)
    _dark_style(ax1)

    # Dest IPs
    if dst:
        ips = [r[0] for r in dst][::-1]
        counts = [r[1] for r in dst][::-1]
        bars = ax2.barh(range(len(ips)), counts, color=COLORS[:len(ips)],
                        edgecolor='white', linewidth=0.3, height=0.6)
        ax2.set_yticks(range(len(ips)))
        ax2.set_yticklabels(ips, fontsize=8)
        _add_hbar_labels(ax2, bars, counts)
    ax2.set_title("📥 Manzil (Dest) IP", fontsize=11, pad=10)
    _dark_style(ax2)

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    plt.show(block=False)


def show_top_ports_chart():
    """Top portlar."""
    data = database.get_top_ports(10)
    if not data:
        return

    ports = [str(r[0]) for r in data]
    counts = [r[1] for r in data]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor(BG_COLOR)

    bars = ax.bar(ports, counts, color=COLORS[:len(ports)],
                  edgecolor='white', linewidth=0.3, width=0.6)
    ax.set_title("🔌 TOP 10 PORTLAR", fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel("Port raqami")
    ax.set_ylabel("Paketlar soni")
    _dark_style(ax)
    _add_value_labels(ax, bars)

    plt.tight_layout()
    plt.show(block=False)


def show_traffic_timeline():
    """Vaqt bo'yicha trafik."""
    data = database.get_traffic_over_time()
    if not data:
        return

    times = [r[0] for r in data]
    counts = [r[1] for r in data]
    sizes = [r[2] / 1024 for r in data]  # KB

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 7), sharex=True)
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle("📈 VAQT BO'YICHA TRAFIK DINAMIKASI", fontsize=14,
                 fontweight='bold', color='white', y=0.98)

    x = range(len(times))

    # Paketlar
    ax1.fill_between(x, counts, alpha=0.25, color=ACCENT)
    ax1.plot(x, counts, color=ACCENT, linewidth=2, marker='o', markersize=3)
    ax1.set_title("Paketlar soni", fontsize=11, pad=10)
    ax1.set_ylabel("Soni")
    _dark_style(ax1)

    # Hajm
    ax2.fill_between(x, sizes, alpha=0.25, color='#7b2ff7')
    ax2.plot(x, sizes, color='#7b2ff7', linewidth=2, marker='o', markersize=3)
    ax2.set_title("Trafik hajmi (KB)", fontsize=11, pad=10)
    ax2.set_ylabel("KB")
    ax2.set_xticks(range(0, len(times), max(1, len(times) // 10)))
    ax2.set_xticklabels([times[i] for i in range(0, len(times), max(1, len(times) // 10))],
                        rotation=45, fontsize=7)
    _dark_style(ax2)

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    plt.show(block=False)


# ==================== ALL-IN-ONE DASHBOARD ====================

def show_all_charts():
    """Barcha grafiklarni bir oynada — 2x3 grid."""
    proto = database.get_stats_by_protocol()
    top_ips = database.get_top_ips(8)
    top_ports = database.get_top_ports(8)
    timeline = database.get_traffic_over_time()
    app_proto = database.get_stats_by_app_protocol()

    fig = plt.figure(figsize=(16, 11))
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle("📊  TARMOQ TRAFIK MONITORING — TO'LIQ TAHLIL  📊",
                 fontsize=16, fontweight='bold', color='white', y=0.99)

    # ---- 1. Protokol bar chart ----
    ax1 = fig.add_subplot(2, 3, 1)
    if proto:
        p = [r[0] for r in proto]
        c = [r[1] for r in proto]
        bars = ax1.bar(p, c, color=COLORS[:len(p)], edgecolor='white', linewidth=0.3)
        _add_value_labels(ax1, bars)
    ax1.set_title("Protokollar", fontsize=10, fontweight='bold', pad=8)
    _dark_style(ax1)

    # ---- 2. Protokol pie ----
    ax2 = fig.add_subplot(2, 3, 2)
    if proto:
        p = [r[0] for r in proto]
        c = [r[1] for r in proto]
        wedges, texts, atext = ax2.pie(c, labels=p, autopct='%1.0f%%',
                                        colors=COLORS[:len(p)],
                                        textprops={'color': TEXT_COLOR, 'fontsize': 8},
                                        pctdistance=0.78, startangle=90)
        for t in atext:
            t.set_fontweight('bold')
            t.set_fontsize(7)
    ax2.set_title("Protokol taqsimoti", fontsize=10, fontweight='bold',
                  color='white', pad=8)
    ax2.set_facecolor(CARD_BG)

    # ---- 3. Top IP lar ----
    ax3 = fig.add_subplot(2, 3, 3)
    if top_ips:
        ips = [r[0][-15:] for r in top_ips][::-1]
        cnt = [r[1] for r in top_ips][::-1]
        bars = ax3.barh(range(len(ips)), cnt, color=COLORS[:len(ips)],
                        edgecolor='white', linewidth=0.3, height=0.55)
        ax3.set_yticks(range(len(ips)))
        ax3.set_yticklabels(ips, fontsize=7)
        _add_hbar_labels(ax3, bars, cnt)
    ax3.set_title("Top IP manzillar", fontsize=10, fontweight='bold', pad=8)
    _dark_style(ax3)

    # ---- 4. Top portlar ----
    ax4 = fig.add_subplot(2, 3, 4)
    if top_ports:
        ports = [str(r[0]) for r in top_ports]
        cnt = [r[1] for r in top_ports]
        bars = ax4.bar(ports, cnt, color=COLORS[:len(ports)],
                       edgecolor='white', linewidth=0.3, width=0.55)
        _add_value_labels(ax4, bars)
    ax4.set_title("Top portlar", fontsize=10, fontweight='bold', pad=8)
    _dark_style(ax4)

    # ---- 5. Timeline ----
    ax5 = fig.add_subplot(2, 3, 5)
    if timeline:
        t = [r[0] for r in timeline]
        c = [r[1] for r in timeline]
        x = range(len(t))
        ax5.fill_between(x, c, alpha=0.25, color=ACCENT)
        ax5.plot(x, c, color=ACCENT, linewidth=1.5, marker='o', markersize=2)
        step = max(1, len(t) // 5)
        ax5.set_xticks(range(0, len(t), step))
        ax5.set_xticklabels([t[i] for i in range(0, len(t), step)], rotation=45, fontsize=6)
    ax5.set_title("Vaqt bo'yicha trafik", fontsize=10, fontweight='bold', pad=8)
    _dark_style(ax5)

    # ---- 6. App protokollar ----
    ax6 = fig.add_subplot(2, 3, 6)
    if app_proto:
        ap = [r[0] for r in app_proto[:8]]
        ac = [r[1] for r in app_proto[:8]]
        bars = ax6.bar(ap, ac, color=COLORS[:len(ap)], edgecolor='white', linewidth=0.3, width=0.55)
        _add_value_labels(ax6, bars)
        ax6.tick_params(axis='x', rotation=30)
    ax6.set_title("Ilova protokollari", fontsize=10, fontweight='bold', pad=8)
    _dark_style(ax6)

    plt.tight_layout(rect=[0, 0.02, 1, 0.95])
    plt.show(block=False)


if __name__ == "__main__":
    show_all_charts()
