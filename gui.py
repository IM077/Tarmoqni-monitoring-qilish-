"""
GUI Dashboard — Premium Tkinter interfeys.
Professional dark theme, real-time monitoring, grafiklar, alertlar, qidiruv va statistika.
Real-time embedded charts bilan.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
from datetime import datetime

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

import database
import monitor
import analysis
import report
import alerts


class NetworkMonitorGUI:
    """Professional tarmoq monitoring dashboardi."""

    # ==================== RANGLAR ====================
    BG = "#0a0a14"
    BG2 = "#0f0f1e"
    CARD = "#151528"
    CARD2 = "#1a1a35"
    CARD_HOVER = "#1f1f3a"
    SIDEBAR_BG = "#0d0d1a"
    ACCENT = "#00d2ff"
    ACCENT2 = "#7b2ff7"
    GREEN = "#00e676"
    RED = "#ff5252"
    YELLOW = "#ffd740"
    ORANGE = "#ff9100"
    PINK = "#ff4081"
    TEXT = "#e8e8f0"
    TEXT2 = "#a0a0c0"
    TEXT3 = "#6a6a8a"
    BORDER = "#252545"
    GLOW = "#00d2ff"

    PROTO_COLORS = {
        "TCP": "#00d2ff",
        "UDP": "#7b2ff7",
        "ICMP": "#ffd740",
        "Other": "#ff4081",
    }

    # Chart colors
    CHART_COLORS = ['#00d2ff', '#7b2ff7', '#ff6b6b', '#feca57', '#48dbfb',
                    '#ff9ff3', '#54a0ff', '#5f27cd', '#01a3a4', '#f368e0',
                    '#00e676', '#ff5252', '#ea80fc', '#64ffda', '#ffab40']
    CHART_BG = '#0f0f1a'
    CHART_CARD_BG = '#1a1a2e'
    CHART_TEXT = '#e0e0e0'
    CHART_GRID = '#2d2d4a'

    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Monitor v2.0")
        self.root.geometry("1300x800")
        self.root.minsize(1100, 700)
        self.root.configure(bg=self.BG)
        self.root.option_add("*Font", "Segoe\\ UI 9")

        # Monitor
        self.net_monitor = monitor.NetworkMonitor(packet_callback=self.on_packet)
        alerts.set_alert_callback(self.on_alert)

        # State
        self.packet_display_count = 0
        self.max_rows = 800
        self.is_dark = True
        self.search_var = tk.StringVar()
        self.filter_proto = tk.StringVar(value="ALL")
        self.alert_count = 0

        # Chart state
        self.chart_fig = None
        self.chart_canvas = None
        self.chart_axes = {}
        self._chart_update_counter = 0

        # Build UI
        self._build_sidebar()
        self._build_main()
        self._periodic_update()

    # ================================================================
    #                          SIDEBAR
    # ================================================================
    def _build_sidebar(self):
        """Chap panel — navigatsiya va boshqaruv."""
        self.sidebar = tk.Frame(self.root, bg=self.SIDEBAR_BG, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo
        logo_frame = tk.Frame(self.sidebar, bg=self.SIDEBAR_BG, pady=15)
        logo_frame.pack(fill="x")

        tk.Label(logo_frame, text="🛡️", font=("Segoe UI", 28),
                 bg=self.SIDEBAR_BG, fg=self.ACCENT).pack()
        tk.Label(logo_frame, text="NETWORK", font=("Segoe UI", 14, "bold"),
                 bg=self.SIDEBAR_BG, fg=self.TEXT).pack()
        tk.Label(logo_frame, text="TRAFFIC MONITOR", font=("Segoe UI", 8),
                 bg=self.SIDEBAR_BG, fg=self.TEXT3).pack()

        # Separator
        tk.Frame(self.sidebar, bg=self.BORDER, height=1).pack(fill="x", padx=15, pady=5)

        # Monitoring controls
        ctrl_label = tk.Label(self.sidebar, text="MONITORING", font=("Segoe UI", 8, "bold"),
                              bg=self.SIDEBAR_BG, fg=self.TEXT3, anchor="w")
        ctrl_label.pack(fill="x", padx=20, pady=(12, 4))

        self.btn_start = self._sidebar_btn("▶  Boshlash", self.start_monitoring, self.GREEN)
        self.btn_stop = self._sidebar_btn("⏹  To'xtatish", self.stop_monitoring, self.RED)
        self.btn_stop.configure(state="disabled")

        # Separator
        tk.Frame(self.sidebar, bg=self.BORDER, height=1).pack(fill="x", padx=15, pady=8)

        # Analysis
        tk.Label(self.sidebar, text="TAHLIL", font=("Segoe UI", 8, "bold"),
                 bg=self.SIDEBAR_BG, fg=self.TEXT3, anchor="w").pack(fill="x", padx=20, pady=(8, 4))

        self._sidebar_btn("📊  Barcha grafiklar", self._show_all_charts, self.ACCENT2)
        self._sidebar_btn("📈  Protokollar", self._show_proto, "#01a3a4")
        self._sidebar_btn("🌐  Top IP lar", self._show_ips, "#54a0ff")
        self._sidebar_btn("🔌  Top portlar", self._show_ports, "#f368e0")
        self._sidebar_btn("📉  Timeline", self._show_timeline, "#ff9ff3")

        # Separator
        tk.Frame(self.sidebar, bg=self.BORDER, height=1).pack(fill="x", padx=15, pady=8)

        # Tools
        tk.Label(self.sidebar, text="ASBOBLAR", font=("Segoe UI", 8, "bold"),
                 bg=self.SIDEBAR_BG, fg=self.TEXT3, anchor="w").pack(fill="x", padx=20, pady=(8, 4))

        self._sidebar_btn("📄  CSV Eksport", self.export_csv, self.YELLOW)
        self._sidebar_btn("📋  To'liq hisobot", self.export_full_report, self.ORANGE)
        self._sidebar_btn("🗑  Tozalash", self.clear_data, "#ff5252")

        # Version
        tk.Label(self.sidebar, text="v2.0 Professional", font=("Segoe UI", 7),
                 bg=self.SIDEBAR_BG, fg=self.TEXT3).pack(side="bottom", pady=8)

        # Status indicator
        self.sidebar_status = tk.Label(self.sidebar, text="● Kutish rejimi",
                                        font=("Segoe UI", 9), bg=self.SIDEBAR_BG,
                                        fg=self.RED, anchor="w")
        self.sidebar_status.pack(side="bottom", fill="x", padx=20, pady=4)

    def _sidebar_btn(self, text, command, color):
        """Sidebar tugma yaratish."""
        btn = tk.Button(self.sidebar, text=text, command=command,
                        bg=self.SIDEBAR_BG, fg=self.TEXT2,
                        activebackground=self.CARD2, activeforeground=self.TEXT,
                        font=("Segoe UI", 9), relief="flat", cursor="hand2",
                        anchor="w", padx=20, pady=7, bd=0, highlightthickness=0)
        btn.pack(fill="x", padx=8, pady=1)

        def on_enter(e, b=btn, c=color):
            b.configure(bg=self.CARD2, fg=c)

        def on_leave(e, b=btn):
            b.configure(bg=self.SIDEBAR_BG, fg=self.TEXT2)

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    # ================================================================
    #                        MAIN AREA
    # ================================================================
    def _build_main(self):
        """O'ng tomon — asosiy kontent."""
        main = tk.Frame(self.root, bg=self.BG)
        main.pack(side="right", fill="both", expand=True)

        # ---------- HEADER / STATS ----------
        self._build_header(main)

        # ---------- TOOLBAR ----------
        self._build_toolbar(main)

        # ---------- TABS ----------
        self._build_tabs(main)

        # ---------- STATUS BAR ----------
        self._build_statusbar(main)

    def _build_header(self, parent):
        """Statistika kartalari."""
        header = tk.Frame(parent, bg=self.BG, pady=8)
        header.pack(fill="x", padx=12)

        cards = [
            ("📦", "PAKETLAR", "0", "stat_packets", self.ACCENT),
            ("📊", "HAJM", "0 B", "stat_size", self.ACCENT2),
            ("⚡", "TEZLIK", "0 p/s", "stat_speed", self.GREEN),
            ("🌐", "IP LAR", "0", "stat_ips", "#54a0ff"),
            ("⏱️", "VAQT", "00:00:00", "stat_uptime", self.YELLOW),
            ("⚠️", "ALERTLAR", "0", "stat_alerts", self.RED),
        ]

        self.stat_labels = {}

        for icon, title, value, key, color in cards:
            card = tk.Frame(header, bg=self.CARD, padx=14, pady=10,
                            highlightbackground=self.BORDER, highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=3)

            top_row = tk.Frame(card, bg=self.CARD)
            top_row.pack(fill="x")
            tk.Label(top_row, text=icon, font=("Segoe UI", 12),
                     bg=self.CARD, fg=color).pack(side="left")
            tk.Label(top_row, text=title, font=("Segoe UI", 7, "bold"),
                     bg=self.CARD, fg=self.TEXT3).pack(side="left", padx=(5, 0))

            lbl = tk.Label(card, text=value, font=("Segoe UI", 16, "bold"),
                           bg=self.CARD, fg=color, anchor="w")
            lbl.pack(fill="x", pady=(3, 0))
            self.stat_labels[key] = lbl

    def _build_toolbar(self, parent):
        """Qidiruv va filtr paneli."""
        toolbar = tk.Frame(parent, bg=self.BG2, pady=6)
        toolbar.pack(fill="x", padx=12, pady=(0, 4))

        # Qidiruv
        search_frame = tk.Frame(toolbar, bg=self.CARD, padx=2, pady=2,
                                highlightbackground=self.BORDER, highlightthickness=1)
        search_frame.pack(side="left", padx=4)

        tk.Label(search_frame, text="🔍", font=("Segoe UI", 10),
                 bg=self.CARD, fg=self.ACCENT).pack(side="left", padx=4)

        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                                      bg=self.CARD, fg=self.TEXT, insertbackground=self.ACCENT,
                                      font=("Consolas", 10), relief="flat", width=25, bd=0)
        self.search_entry.pack(side="left", padx=4, ipady=4)
        self.search_entry.insert(0, "IP, port yoki protokol qidirish...")
        self.search_entry.bind("<FocusIn>", self._on_search_focus)
        self.search_entry.bind("<FocusOut>", self._on_search_unfocus)
        self.search_entry.bind("<Return>", self._do_search)

        btn_search = tk.Button(search_frame, text="Qidirish", command=self._do_search,
                               bg=self.ACCENT, fg="white", font=("Segoe UI", 8, "bold"),
                               relief="flat", padx=10, cursor="hand2", bd=0)
        btn_search.pack(side="left", padx=2)

        btn_reset = tk.Button(search_frame, text="✕", command=self._reset_search,
                              bg=self.RED, fg="white", font=("Segoe UI", 8, "bold"),
                              relief="flat", padx=6, cursor="hand2", bd=0)
        btn_reset.pack(side="left", padx=2)

        # Protokol filtr
        filter_frame = tk.Frame(toolbar, bg=self.BG2)
        filter_frame.pack(side="left", padx=12)

        tk.Label(filter_frame, text="Filtr:", font=("Segoe UI", 9),
                 bg=self.BG2, fg=self.TEXT3).pack(side="left")

        for proto in ["ALL", "TCP", "UDP", "ICMP"]:
            color = self.PROTO_COLORS.get(proto, self.ACCENT)
            rb = tk.Radiobutton(filter_frame, text=proto, variable=self.filter_proto,
                                value=proto, bg=self.BG2, fg=self.TEXT2,
                                selectcolor=self.CARD, activebackground=self.BG2,
                                activeforeground=color, font=("Segoe UI", 8, "bold"),
                                indicatoron=0, padx=10, pady=3, relief="flat",
                                cursor="hand2", bd=0, highlightthickness=0)
            rb.pack(side="left", padx=2)

        # Paketlar soni
        self.packet_count_label = tk.Label(toolbar, text="Jadvalda: 0 ta",
                                            font=("Segoe UI", 8), bg=self.BG2, fg=self.TEXT3)
        self.packet_count_label.pack(side="right", padx=10)

    def _build_tabs(self, parent):
        """Tab paneli — jadval, grafiklar, alertlar, log."""
        style = ttk.Style()
        style.theme_use("clam")

        # Treeview
        style.configure("Pro.Treeview",
                         background=self.CARD,
                         foreground=self.TEXT,
                         fieldbackground=self.CARD,
                         borderwidth=0,
                         font=("Consolas", 9),
                         rowheight=22)
        style.configure("Pro.Treeview.Heading",
                         background=self.CARD2,
                         foreground=self.ACCENT,
                         font=("Segoe UI", 9, "bold"),
                         borderwidth=0, relief="flat")
        style.map("Pro.Treeview",
                   background=[("selected", "#2a2a5a")],
                   foreground=[("selected", "#ffffff")])

        # Notebook
        style.configure("Pro.TNotebook", background=self.BG, borderwidth=0)
        style.configure("Pro.TNotebook.Tab",
                         background=self.CARD,
                         foreground=self.TEXT3,
                         padding=[18, 7],
                         font=("Segoe UI", 9, "bold"))
        style.map("Pro.TNotebook.Tab",
                   background=[("selected", self.CARD2)],
                   foreground=[("selected", self.ACCENT)])

        notebook = ttk.Notebook(parent, style="Pro.TNotebook")
        notebook.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        # === TAB 1: TRAFIK ===
        tab1 = tk.Frame(notebook, bg=self.BG)
        notebook.add(tab1, text="  📋  Trafik Jadvali  ")

        tree_frame = tk.Frame(tab1, bg=self.CARD)
        tree_frame.pack(fill="both", expand=True)

        columns = ("no", "source", "dest", "sport", "dport",
                    "proto", "app", "size", "info", "time")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings",
                                  style="Pro.Treeview", selectmode="browse")

        headers = {
            "no": ("#", 45),
            "source": ("Manba IP", 120),
            "dest": ("Manzil IP", 120),
            "sport": ("S.Port", 55),
            "dport": ("D.Port", 55),
            "proto": ("Proto", 55),
            "app": ("Ilova", 65),
            "size": ("Hajm", 65),
            "info": ("Ma'lumot", 200),
            "time": ("Vaqt", 130),
        }

        for col, (heading, width) in headers.items():
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, minwidth=40, anchor="center")

        # Protokol ranglar uchun taglar
        self.tree.tag_configure("TCP", foreground="#00d2ff")
        self.tree.tag_configure("UDP", foreground="#b388ff")
        self.tree.tag_configure("ICMP", foreground="#ffd740")
        self.tree.tag_configure("Other", foreground="#ff4081")

        # Scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        # Paket tafsilotlari
        detail_frame = tk.Frame(tab1, bg=self.CARD2, height=50, pady=4)
        detail_frame.pack(fill="x")
        detail_frame.pack_propagate(False)

        self.detail_label = tk.Label(detail_frame,
                                      text="💡 Paketni tanlang — batafsil ma'lumot shu yerda chiqadi",
                                      font=("Consolas", 9), bg=self.CARD2, fg=self.TEXT3,
                                      anchor="w", padx=12)
        self.detail_label.pack(fill="both", expand=True)

        self.tree.bind("<<TreeviewSelect>>", self._on_select_packet)

        # === TAB 2: REAL-TIME GRAFIKLAR ===
        tab_charts = tk.Frame(notebook, bg=self.CHART_BG)
        notebook.add(tab_charts, text="  📊  Real-Time Grafiklar  ")
        self._build_charts_tab(tab_charts)

        # === TAB 3: ALERTLAR ===
        tab2 = tk.Frame(notebook, bg=self.BG)
        notebook.add(tab2, text="  ⚠️  Alertlar  ")

        alert_toolbar = tk.Frame(tab2, bg=self.BG, pady=4)
        alert_toolbar.pack(fill="x")

        self.alert_counter_label = tk.Label(alert_toolbar, text="Alertlar: 0",
                                             font=("Segoe UI", 10, "bold"),
                                             bg=self.BG, fg=self.RED)
        self.alert_counter_label.pack(side="left", padx=10)

        self.alert_text = tk.Text(tab2, bg=self.CARD, fg=self.TEXT,
                                   font=("Consolas", 9), wrap="word",
                                   insertbackground=self.ACCENT, bd=0,
                                   padx=12, pady=8, state="disabled",
                                   spacing1=2, spacing3=2)
        self.alert_text.pack(fill="both", expand=True, padx=4, pady=4)

        # Alert ranglari
        self.alert_text.tag_configure("CRITICAL", foreground="#ff1744",
                                       font=("Consolas", 10, "bold"))
        self.alert_text.tag_configure("HIGH", foreground="#ff6b6b",
                                       font=("Consolas", 9, "bold"))
        self.alert_text.tag_configure("MEDIUM", foreground="#ffd740",
                                       font=("Consolas", 9))
        self.alert_text.tag_configure("LOW", foreground="#48dbfb",
                                       font=("Consolas", 9))
        self.alert_text.tag_configure("time", foreground=self.TEXT3,
                                       font=("Consolas", 8))

        # === TAB 4: LOG ===
        tab3 = tk.Frame(notebook, bg=self.BG)
        notebook.add(tab3, text="  📜  Tizim Logi  ")

        self.log_text = tk.Text(tab3, bg=self.CARD, fg=self.TEXT2,
                                 font=("Consolas", 9), wrap="word", bd=0,
                                 padx=12, pady=8, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)

        self._log("Dastur ishga tushdi.")
        self._log("Monitoring boshlash uchun ▶ Boshlash tugmasini bosing.")
        self._log("⚠️ Administrator rejimi va Npcap talab qilinadi.")

    # ================================================================
    #                    EMBEDDED CHARTS TAB
    # ================================================================
    def _build_charts_tab(self, parent):
        """Real-time grafiklar tab — 6 ta subplot 2x3 grid."""
        self.chart_fig = Figure(figsize=(14, 8), dpi=90)
        self.chart_fig.patch.set_facecolor(self.CHART_BG)
        self.chart_fig.suptitle("📊  REAL-TIME TARMOQ MONITORING  📊",
                                fontsize=14, fontweight='bold', color='white', y=0.99)

        # 6 ta subplot yaratish
        self.chart_axes['proto_bar'] = self.chart_fig.add_subplot(2, 3, 1)
        self.chart_axes['proto_pie'] = self.chart_fig.add_subplot(2, 3, 2)
        self.chart_axes['top_ips'] = self.chart_fig.add_subplot(2, 3, 3)
        self.chart_axes['top_ports'] = self.chart_fig.add_subplot(2, 3, 4)
        self.chart_axes['timeline'] = self.chart_fig.add_subplot(2, 3, 5)
        self.chart_axes['app_proto'] = self.chart_fig.add_subplot(2, 3, 6)

        # Dastlabki bo'sh stil qo'llash
        for key, ax in self.chart_axes.items():
            if key != 'proto_pie':
                self._apply_dark_style(ax)
            else:
                ax.set_facecolor(self.CHART_CARD_BG)
            ax.set_title(self._get_chart_title(key), fontsize=10,
                         fontweight='bold', color='white', pad=8)

        self.chart_fig.tight_layout(rect=[0, 0.02, 1, 0.95])

        # Canvas yaratish va joylashtirish
        self.chart_canvas = FigureCanvasTkAgg(self.chart_fig, master=parent)
        self.chart_canvas.draw()
        self.chart_canvas.get_tk_widget().pack(fill="both", expand=True)

    def _get_chart_title(self, key):
        """Chart nomi."""
        titles = {
            'proto_bar': '📊 Protokollar',
            'proto_pie': '🥧 Protokol taqsimoti',
            'top_ips': '🌐 Top IP manzillar',
            'top_ports': '🔌 Top portlar',
            'timeline': '📈 Vaqt bo\'yicha trafik',
            'app_proto': '📱 Ilova protokollari',
        }
        return titles.get(key, '')

    def _apply_dark_style(self, ax):
        """Dark theme qo'llash."""
        ax.set_facecolor(self.CHART_CARD_BG)
        ax.tick_params(colors=self.CHART_TEXT, labelsize=7)
        ax.xaxis.label.set_color(self.CHART_TEXT)
        ax.yaxis.label.set_color(self.CHART_TEXT)
        ax.title.set_color('#ffffff')
        for spine in ax.spines.values():
            spine.set_color(self.CHART_GRID)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(True, alpha=0.12, color=self.CHART_GRID, linestyle='--')

    def _update_charts(self):
        """Barcha 6 ta chartni bazadan ma'lumot bilan yangilash."""
        if self.chart_fig is None or self.chart_canvas is None:
            return

        try:
            # Ma'lumotlarni olish
            proto_data = database.get_stats_by_protocol()
            top_ips_data = database.get_top_ips(8)
            top_ports_data = database.get_top_ports(8)
            timeline_data = database.get_traffic_over_time()
            app_proto_data = database.get_stats_by_app_protocol()

            # 1. Protokol bar chart
            ax = self.chart_axes['proto_bar']
            ax.clear()
            if proto_data:
                protocols = [r[0] for r in proto_data]
                counts = [r[1] for r in proto_data]
                bars = ax.bar(protocols, counts,
                              color=self.CHART_COLORS[:len(protocols)],
                              edgecolor='white', linewidth=0.3)
                for bar in bars:
                    h = bar.get_height()
                    if h > 0:
                        ax.text(bar.get_x() + bar.get_width() / 2, h,
                                f'{int(h):,}', ha='center', va='bottom',
                                color=self.CHART_TEXT, fontsize=7, fontweight='bold')
            else:
                ax.text(0.5, 0.5, "Ma'lumot kutilmoqda...",
                        transform=ax.transAxes, ha='center', va='center',
                        color=self.TEXT3, fontsize=10)
            ax.set_title('📊 Protokollar', fontsize=10, fontweight='bold',
                         color='white', pad=8)
            self._apply_dark_style(ax)

            # 2. Protokol pie chart
            ax = self.chart_axes['proto_pie']
            ax.clear()
            if proto_data:
                protocols = [r[0] for r in proto_data]
                counts = [r[1] for r in proto_data]
                explode = [0.04] * len(protocols)
                wedges, texts, autotexts = ax.pie(
                    counts, labels=protocols, autopct='%1.0f%%',
                    colors=self.CHART_COLORS[:len(protocols)],
                    explode=explode,
                    textprops={'color': self.CHART_TEXT, 'fontsize': 8},
                    pctdistance=0.78, startangle=90)
                for t in autotexts:
                    t.set_fontweight('bold')
                    t.set_fontsize(7)
            else:
                ax.text(0.5, 0.5, "Ma'lumot kutilmoqda...",
                        transform=ax.transAxes, ha='center', va='center',
                        color=self.TEXT3, fontsize=10)
            ax.set_title('🥧 Protokol taqsimoti', fontsize=10,
                         fontweight='bold', color='white', pad=8)
            ax.set_facecolor(self.CHART_CARD_BG)

            # 3. Top IP lar
            ax = self.chart_axes['top_ips']
            ax.clear()
            if top_ips_data:
                ips = [r[0][-15:] for r in top_ips_data][::-1]
                cnt = [r[1] for r in top_ips_data][::-1]
                bars = ax.barh(range(len(ips)), cnt,
                               color=self.CHART_COLORS[:len(ips)],
                               edgecolor='white', linewidth=0.3, height=0.55)
                ax.set_yticks(range(len(ips)))
                ax.set_yticklabels(ips, fontsize=7)
                for bar, val in zip(bars, cnt):
                    ax.text(bar.get_width() + bar.get_width() * 0.02,
                            bar.get_y() + bar.get_height() / 2,
                            f'{int(val):,}', ha='left', va='center',
                            color=self.CHART_TEXT, fontsize=7, fontweight='bold')
            else:
                ax.text(0.5, 0.5, "Ma'lumot kutilmoqda...",
                        transform=ax.transAxes, ha='center', va='center',
                        color=self.TEXT3, fontsize=10)
            ax.set_title('🌐 Top IP manzillar', fontsize=10,
                         fontweight='bold', color='white', pad=8)
            self._apply_dark_style(ax)

            # 4. Top portlar
            ax = self.chart_axes['top_ports']
            ax.clear()
            if top_ports_data:
                ports = [str(r[0]) for r in top_ports_data]
                cnt = [r[1] for r in top_ports_data]
                bars = ax.bar(ports, cnt,
                              color=self.CHART_COLORS[:len(ports)],
                              edgecolor='white', linewidth=0.3, width=0.55)
                for bar in bars:
                    h = bar.get_height()
                    if h > 0:
                        ax.text(bar.get_x() + bar.get_width() / 2, h,
                                f'{int(h):,}', ha='center', va='bottom',
                                color=self.CHART_TEXT, fontsize=7, fontweight='bold')
                ax.tick_params(axis='x', rotation=30)
            else:
                ax.text(0.5, 0.5, "Ma'lumot kutilmoqda...",
                        transform=ax.transAxes, ha='center', va='center',
                        color=self.TEXT3, fontsize=10)
            ax.set_title('🔌 Top portlar', fontsize=10,
                         fontweight='bold', color='white', pad=8)
            self._apply_dark_style(ax)

            # 5. Timeline
            ax = self.chart_axes['timeline']
            ax.clear()
            if timeline_data:
                times = [r[0] for r in timeline_data]
                counts = [r[1] for r in timeline_data]
                x = range(len(times))
                ax.fill_between(x, counts, alpha=0.25, color=self.ACCENT)
                ax.plot(x, counts, color=self.ACCENT, linewidth=1.5,
                        marker='o', markersize=2)
                if len(times) > 1:
                    step = max(1, len(times) // 5)
                    ax.set_xticks(range(0, len(times), step))
                    ax.set_xticklabels(
                        [times[i] for i in range(0, len(times), step)],
                        rotation=45, fontsize=6)
            else:
                ax.text(0.5, 0.5, "Ma'lumot kutilmoqda...",
                        transform=ax.transAxes, ha='center', va='center',
                        color=self.TEXT3, fontsize=10)
            ax.set_title("📈 Vaqt bo'yicha trafik", fontsize=10,
                         fontweight='bold', color='white', pad=8)
            self._apply_dark_style(ax)

            # 6. App protokollar
            ax = self.chart_axes['app_proto']
            ax.clear()
            if app_proto_data:
                ap = [r[0] for r in app_proto_data[:8]]
                ac = [r[1] for r in app_proto_data[:8]]
                bars = ax.bar(ap, ac,
                              color=self.CHART_COLORS[:len(ap)],
                              edgecolor='white', linewidth=0.3, width=0.55)
                for bar in bars:
                    h = bar.get_height()
                    if h > 0:
                        ax.text(bar.get_x() + bar.get_width() / 2, h,
                                f'{int(h):,}', ha='center', va='bottom',
                                color=self.CHART_TEXT, fontsize=7, fontweight='bold')
                ax.tick_params(axis='x', rotation=30)
            else:
                ax.text(0.5, 0.5, "Ma'lumot kutilmoqda...",
                        transform=ax.transAxes, ha='center', va='center',
                        color=self.TEXT3, fontsize=10)
            ax.set_title('📱 Ilova protokollari', fontsize=10,
                         fontweight='bold', color='white', pad=8)
            self._apply_dark_style(ax)

            # Joylashtirish va chizish
            self.chart_fig.tight_layout(rect=[0, 0.02, 1, 0.95])
            self.chart_canvas.draw_idle()

        except Exception as e:
            pass  # Xatolarni jimgina o'tkazamiz

    def _build_statusbar(self, parent):
        """Pastki status bar."""
        status = tk.Frame(parent, bg=self.CARD2, height=28)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)

        self.status_dot = tk.Label(status, text="●", font=("Segoe UI", 10),
                                    bg=self.CARD2, fg=self.RED)
        self.status_dot.pack(side="left", padx=(12, 4))

        self.status_text = tk.Label(status, text="Kutish rejimi",
                                     font=("Segoe UI", 8), bg=self.CARD2, fg=self.TEXT3)
        self.status_text.pack(side="left")

        self.status_right = tk.Label(status, text="",
                                      font=("Segoe UI", 8), bg=self.CARD2, fg=self.TEXT3)
        self.status_right.pack(side="right", padx=12)

    # ================================================================
    #                      MONITORING CONTROL
    # ================================================================
    def start_monitoring(self):
        try:
            success = self.net_monitor.start()
            if success:
                self.btn_start.configure(state="disabled")
                self.btn_stop.configure(state="normal")
                self.sidebar_status.configure(text="● Monitoring ishlayapti", fg=self.GREEN)
                self.status_dot.configure(fg=self.GREEN)
                self.status_text.configure(text="Monitoring ishlayapti — paketlar ushlanyapti",
                                           fg=self.GREEN)
                self._log("▶ Monitoring boshlandi.")
                self._pulse_animation()
        except Exception as e:
            messagebox.showerror("Xato",
                                 f"Monitoring boshlanmadi:\n{e}\n\n"
                                 "1. CMD ni Administrator sifatida oching\n"
                                 "2. Npcap o'rnatilganligini tekshiring")

    def stop_monitoring(self):
        self.net_monitor.stop()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.sidebar_status.configure(text="● To'xtatildi", fg=self.YELLOW)
        self.status_dot.configure(fg=self.YELLOW)
        self.status_text.configure(text="Monitoring to'xtatildi", fg=self.YELLOW)
        self._log(f"⏹ To'xtatildi. Jami: {self.net_monitor.packet_count} paket")

    def _pulse_animation(self):
        """Status nuqtasini miltillatish."""
        if self.net_monitor.is_running:
            current = self.status_dot.cget("fg")
            new_color = self.BG if current == self.GREEN else self.GREEN
            self.status_dot.configure(fg=new_color)
            self.root.after(800, self._pulse_animation)

    # ================================================================
    #                      PACKET HANDLING
    # ================================================================
    def on_packet(self, src, dst, sp, dp, proto, app, size, info):
        """Monitor dan paket kelganda."""
        self.root.after(0, self._add_to_tree, src, dst, sp, dp, proto, app, size, info)

    def _add_to_tree(self, src, dst, sp, dp, proto, app, size, info):
        """Jadvalga paket qo'shish."""
        # Filtr tekshirish
        current_filter = self.filter_proto.get()
        if current_filter != "ALL" and proto != current_filter:
            return

        self.packet_display_count += 1
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        tag = proto if proto in self.PROTO_COLORS else "Other"
        size_str = database.format_bytes(size)

        self.tree.insert("", 0, values=(
            self.packet_display_count, src, dst, sp, dp,
            proto, app, size_str, info[:60], now
        ), tags=(tag,))

        # Limit
        children = self.tree.get_children()
        if len(children) > self.max_rows:
            for child in children[self.max_rows:]:
                self.tree.delete(child)

        self.packet_count_label.configure(text=f"Jadvalda: {len(self.tree.get_children())} ta")

    def _on_select_packet(self, event):
        """Paket tanlanganda tafsilot ko'rsatish."""
        sel = self.tree.selection()
        if sel:
            values = self.tree.item(sel[0], 'values')
            if values:
                detail = (f"#{values[0]}  |  {values[1]}:{values[3]} → {values[2]}:{values[4]}  |  "
                          f"{values[5]}/{values[6]}  |  {values[7]}  |  {values[8]}  |  {values[9]}")
                self.detail_label.configure(text=detail, fg=self.ACCENT)

    # ================================================================
    #                      ALERT HANDLING
    # ================================================================
    def on_alert(self, alert_type, severity, source_ip, message):
        self.root.after(0, self._add_alert, severity, message)

    def _add_alert(self, severity, message):
        self.alert_count += 1
        self.alert_text.configure(state="normal")
        now = datetime.now().strftime("%H:%M:%S")

        self.alert_text.insert("1.0", f"\n", "time")
        self.alert_text.insert("1.0", f"  {message}\n", severity)
        self.alert_text.insert("1.0", f"[{now}] [{severity}]", "time")
        self.alert_text.configure(state="disabled")

        self.alert_counter_label.configure(text=f"Alertlar: {self.alert_count}")
        self._log(f"⚠️ ALERT [{severity}]: {message}")

    # ================================================================
    #                      SEARCH & FILTER
    # ================================================================
    def _on_search_focus(self, e):
        if self.search_entry.get() == "IP, port yoki protokol qidirish...":
            self.search_entry.delete(0, "end")
            self.search_entry.configure(fg=self.TEXT)

    def _on_search_unfocus(self, e):
        if not self.search_entry.get():
            self.search_entry.insert(0, "IP, port yoki protokol qidirish...")
            self.search_entry.configure(fg=self.TEXT3)

    def _do_search(self, event=None):
        query = self.search_var.get().strip()
        if not query or query == "IP, port yoki protokol qidirish...":
            return

        # Jadvalni tozalash
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Bazadan qidirish
        results = database.search_logs(query, 500)
        for i, row in enumerate(results):
            proto = row[5]
            tag = proto if proto in self.PROTO_COLORS else "Other"
            self.tree.insert("", "end", values=(
                i + 1, row[1], row[2], row[3], row[4],
                row[5], row[6], database.format_bytes(row[7]),
                str(row[8])[:60], str(row[9])
            ), tags=(tag,))

        self.packet_count_label.configure(text=f"Natija: {len(results)} ta")
        self._log(f"🔍 Qidiruv: '{query}' — {len(results)} natija topildi")

    def _reset_search(self):
        self.search_var.set("")
        self.search_entry.delete(0, "end")
        self.search_entry.insert(0, "IP, port yoki protokol qidirish...")
        self.search_entry.configure(fg=self.TEXT3)

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packet_count_label.configure(text="Jadvalda: 0 ta")

    # ================================================================
    #                      CHARTS (Separate windows)
    # ================================================================
    def _show_all_charts(self):
        try:
            if not database.get_total_packets():
                messagebox.showinfo("Ma'lumot yo'q",
                    "Hali hech qanday trafik ma'lumoti yo'q.\n"
                    "Avval monitoring boshlang va biroz kuting.")
                return
            analysis.show_all_charts()
            self._log("📊 Barcha grafiklar ko'rsatildi")
        except Exception as e:
            messagebox.showerror("Xato", f"Grafiklar chiqarishda xato:\n{e}")

    def _show_proto(self):
        try:
            if not database.get_stats_by_protocol():
                messagebox.showinfo("Ma'lumot yo'q",
                    "Protokol ma'lumotlari topilmadi.\n"
                    "Avval monitoring boshlang va biroz kuting.")
                return
            analysis.show_protocol_chart()
            self._log("📈 Protokol grafigi ko'rsatildi")
        except Exception as e:
            messagebox.showerror("Xato", f"Protokol grafigida xato:\n{e}")

    def _show_ips(self):
        try:
            if not database.get_top_ips(10):
                messagebox.showinfo("Ma'lumot yo'q",
                    "IP ma'lumotlari topilmadi.\n"
                    "Avval monitoring boshlang va biroz kuting.")
                return
            analysis.show_top_ips_chart()
            self._log("🌐 Top IP grafigi ko'rsatildi")
        except Exception as e:
            messagebox.showerror("Xato", f"IP grafigida xato:\n{e}")

    def _show_ports(self):
        try:
            if not database.get_top_ports(10):
                messagebox.showinfo("Ma'lumot yo'q",
                    "Port ma'lumotlari topilmadi.\n"
                    "Avval monitoring boshlang va biroz kuting.")
                return
            analysis.show_top_ports_chart()
            self._log("🔌 Top portlar grafigi ko'rsatildi")
        except Exception as e:
            messagebox.showerror("Xato", f"Port grafigida xato:\n{e}")

    def _show_timeline(self):
        try:
            if not database.get_traffic_over_time():
                messagebox.showinfo("Ma'lumot yo'q",
                    "Vaqt bo'yicha ma'lumot topilmadi.\n"
                    "Avval monitoring boshlang va biroz kuting.")
                return
            analysis.show_traffic_timeline()
            self._log("📉 Timeline grafigi ko'rsatildi")
        except Exception as e:
            messagebox.showerror("Xato", f"Timeline grafigida xato:\n{e}")

    # ================================================================
    #                      EXPORT & TOOLS
    # ================================================================
    def export_csv(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            title="Trafik loglarni saqlash")
        if filepath:
            report.export_traffic_csv(filepath)
            messagebox.showinfo("Tayyor", f"CSV saqlandi:\n{filepath}")
            self._log(f"📄 CSV eksport: {filepath}")

    def export_full_report(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            title="To'liq hisobotni saqlash")
        if filepath:
            report.export_full_report(filepath)
            messagebox.showinfo("Tayyor", f"To'liq hisobot saqlandi:\n{filepath}")
            self._log(f"📋 To'liq hisobot: {filepath}")

    def clear_data(self):
        if messagebox.askyesno("Tasdiqlash", "Barcha ma'lumotlar o'chiriladi!\nDavom etasizmi?"):
            database.clear_logs()
            alerts.reset_alerts()
            self.net_monitor.reset_counters()
            self.packet_display_count = 0
            self.alert_count = 0

            for item in self.tree.get_children():
                self.tree.delete(item)

            self.alert_text.configure(state="normal")
            self.alert_text.delete("1.0", "end")
            self.alert_text.configure(state="disabled")

            self.alert_counter_label.configure(text="Alertlar: 0")
            self._log("🗑 Barcha ma'lumotlar tozalandi")
            messagebox.showinfo("Tayyor", "Ma'lumotlar tozalandi!")

    # ================================================================
    #                      PERIODIC UPDATES
    # ================================================================
    def _periodic_update(self):
        """Har 1.5 soniyada statistika yangilash, har 3 soniyada grafiklar yangilash."""
        try:
            packets = database.get_total_packets()
            total_size = database.get_total_size()
            unique_ips = database.get_unique_ips()
            alert_count = database.get_alert_count()

            self.stat_labels["stat_packets"].configure(text=f"{packets:,}")
            self.stat_labels["stat_size"].configure(text=database.format_bytes(total_size))
            self.stat_labels["stat_ips"].configure(text=f"{unique_ips:,}")
            self.stat_labels["stat_alerts"].configure(text=str(alert_count))

            # Tezlik
            if self.net_monitor.is_running:
                pps = self.net_monitor.packets_per_second
                bps = self.net_monitor.bytes_per_second
                self.stat_labels["stat_speed"].configure(
                    text=f"{pps:.0f} p/s | {database.format_bytes(int(bps))}/s")
                self.stat_labels["stat_uptime"].configure(
                    text=self.net_monitor.get_uptime())

                # Status bar
                self.status_right.configure(
                    text=f"📦 {packets:,}  |  📊 {database.format_bytes(total_size)}  |  "
                         f"⚡ {pps:.0f} p/s  |  ⏱️ {self.net_monitor.get_uptime()}")
            else:
                self.stat_labels["stat_speed"].configure(text="— p/s")

            # Alert rangi
            if alert_count > 0:
                self.stat_labels["stat_alerts"].configure(fg=self.RED)
            else:
                self.stat_labels["stat_alerts"].configure(fg=self.TEXT3)

            # Grafiklar yangilash — har 2-chi cycleda (har 3 soniyada)
            self._chart_update_counter += 1
            if self._chart_update_counter >= 2:
                self._chart_update_counter = 0
                self._update_charts()

        except Exception:
            pass

        self.root.after(1500, self._periodic_update)

    # ================================================================
    #                      LOG
    # ================================================================
    def _log(self, message):
        """Tizim logiga yozish."""
        self.log_text.configure(state="normal")
        now = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{now}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ================================================================
    #                      CLEANUP
    # ================================================================
    def on_closing(self):
        if self.net_monitor.is_running:
            self.net_monitor.stop()
        # Matplotlib oynalarni yopish
        try:
            plt.close('all')
        except Exception:
            pass
        self.root.destroy()


def run_gui():
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    database.create_database()
    run_gui()
