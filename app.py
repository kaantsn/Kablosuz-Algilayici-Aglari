import tkinter as tk
from tkinter import ttk
import threading
import time
import random
import datetime

class AdvancedWSNPentestEnvironment:
    def __init__(self, root):
        self.root = root
        self.root.title("WSN Routing Protocol Security & Exploitation Framework")
        self.root.geometry("1500x850")
        self.root.configure(bg="#0d1117")

        self.saldiri_aktif = False
        self.rx_paket_sayisi = 0
        self.drop_paket_sayisi = 0
        self.sistem_dongusu = True

        self.arayuz_olustur()
        threading.Thread(target=self.ag_trafiğini_simule_et, daemon=True).start()

    def arayuz_olustur(self):
        # ==========================================
        # SOL ANA PANEL (İKİYE BÖLÜNMÜŞ İZLEME EKRANLARI)
        # ==========================================
        self.sol_ana_frame = tk.Frame(self.root, bg="#0d1117", width=900)
        self.sol_ana_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ------------------------------------------
        # SOL ÜST: HEDEF SUNUCU (SINK NODE) EKRANI
        # ------------------------------------------
        self.hedef_frame = tk.Frame(self.sol_ana_frame, bg="#161b22", highlightbackground="#30363d", highlightthickness=1)
        self.hedef_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(0, 5))

        tk.Label(self.hedef_frame, text="[TARGET SINK NODE] - wpan0 Interface Monitor", 
                 bg="#161b22", fg="#58a6ff", font=("Consolas", 11, "bold"), anchor="w").pack(fill=tk.X, padx=10, pady=5)

        # Hedef Sunucu - Yönlendirme Tablosu
        stil = ttk.Style()
        stil.theme_use("clam")
        stil.configure("Treeview", background="#0d1117", foreground="#c9d1d9", fieldbackground="#0d1117", font=("Consolas", 9))
        stil.configure("Treeview.Heading", background="#21262d", foreground="#ffffff", font=("Consolas", 9, "bold"))

        sutunlar_route = ("hedef", "ag_gecidi", "bayraklar", "sekans", "sekme")
        self.tablo_hedef_route = ttk.Treeview(self.hedef_frame, columns=sutunlar_route, show="headings", height=4)
        for col in sutunlar_route: self.tablo_hedef_route.heading(col, text=col.upper())
        self.tablo_hedef_route.column("hedef", width=180); self.tablo_hedef_route.column("ag_gecidi", width=180)
        self.tablo_hedef_route.column("bayraklar", width=60); self.tablo_hedef_route.column("sekans", width=100)
        self.tablo_hedef_route.column("sekme", width=80)
        self.tablo_hedef_route.pack(fill=tk.X, padx=10, pady=2)

        self.normal_routing = [
            ("192.168.10.11", "192.168.10.2", "UG", "104", "2"),
            ("192.168.10.12", "192.168.10.2", "UG", "112", "2"),
            ("192.168.10.15", "192.168.10.5", "UG", "98", "3"),
            ("0.0.0.0", "0.0.0.0", "U", "0", "0")
        ]
        self.tablo_veri_guncelle(self.tablo_hedef_route, self.normal_routing)

        # Hedef Sunucu - Gelen Trafik
        tk.Label(self.hedef_frame, text="Kernel Log: rx_bytes (Application Layer)", bg="#161b22", fg="#8b949e", font=("Consolas", 10)).pack(anchor="w", padx=10)
        sutunlar_hedef_trafik = ("zaman", "mac", "proto", "payload")
        self.tablo_hedef_trafik = ttk.Treeview(self.hedef_frame, columns=sutunlar_hedef_trafik, show="headings", height=8)
        for col in sutunlar_hedef_trafik: self.tablo_hedef_trafik.heading(col, text=col.upper())
        self.tablo_hedef_trafik.column("zaman", width=100); self.tablo_hedef_trafik.column("mac", width=140)
        self.tablo_hedef_trafik.column("proto", width=60); self.tablo_hedef_trafik.column("payload", width=350)
        self.tablo_hedef_trafik.pack(fill=tk.BOTH, expand=True, padx=10, pady=2)

        # ------------------------------------------
        # SOL ALT: SALDIRGAN (ROGUE NODE) EKRANI
        # ------------------------------------------
        self.saldırgan_frame = tk.Frame(self.sol_ana_frame, bg="#161b22", highlightbackground="#30363d", highlightthickness=1)
        self.saldırgan_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, pady=(5, 0))

        # Saldırgan İstatistik Barı
        ist_bar = tk.Frame(self.saldırgan_frame, bg="#161b22")
        ist_bar.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(ist_bar, text="[ROGUE NODE] - Blackhole Interception Engine (wlan1mon)", 
                 bg="#161b22", fg="#ff7b72", font=("Consolas", 11, "bold")).pack(side=tk.LEFT)
        self.lbl_stats = tk.Label(ist_bar, text="Status: IDLE | Intercepted: 0 | Dropped: 0", 
                                  bg="#161b22", fg="#8b949e", font=("Consolas", 10, "bold"))
        self.lbl_stats.pack(side=tk.RIGHT)

        # Saldırgan - Ele Geçirilen Trafik (Interception Log)
        self.tablo_saldırgan_trafik = ttk.Treeview(self.saldırgan_frame, columns=sutunlar_hedef_trafik, show="headings", height=10)
        for col in sutunlar_hedef_trafik: self.tablo_saldırgan_trafik.heading(col, text=col.upper())
        self.tablo_saldırgan_trafik.column("zaman", width=100); self.tablo_saldırgan_trafik.column("mac", width=140)
        self.tablo_saldırgan_trafik.column("proto", width=60); self.tablo_saldırgan_trafik.column("payload", width=350)
        self.tablo_saldırgan_trafik.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # ==========================================
        # SAĞ PANEL (GÖREV YÖNERGESİ VE TERMİNAL)
        # ==========================================
        self.sag_frame = tk.Frame(self.root, bg="#0d1117", width=550)
        self.sag_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        # --- PLAYBOOK (Kopyalanabilir Alan) ---
        adimlar_frame = tk.Frame(self.sag_frame, bg="#161b22", highlightbackground="#3fb950", highlightthickness=1)
        adimlar_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))
        
        tk.Label(adimlar_frame, text="OPERATIONAL PLAYBOOK", bg="#3fb950", fg="black", font=("Consolas", 11, "bold")).pack(fill=tk.X)
        
        self.adimlar_text = tk.Text(adimlar_frame, height=9, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 10), relief=tk.FLAT)
        self.adimlar_text.pack(fill=tk.BOTH, padx=5, pady=5)
        
        adimlar_metni = (
            "PHASE 1: Interface Initialization\n"
            "> zbid\n\n"
            "PHASE 2: Network Reconnaissance (Sniffing)\n"
            "> zbstumbler\n\n"
            "PHASE 3: Route Poisoning & Interception\n"
            "> python3 wsn_exploit.py --target 0x1A2B --spoof-seq max"
        )
        self.adimlar_text.insert(tk.END, adimlar_metni)
        self.adimlar_text.config(state=tk.DISABLED)

        # --- TERMİNAL ---
        self.term_output = tk.Text(self.sag_frame, bg="#0d1117", fg="#3fb950", font=("Consolas", 11), state=tk.DISABLED, wrap=tk.WORD)
        self.term_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(self.sag_frame, bg="#0d1117")
        input_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(input_frame, text="root@kali:~#", bg="#0d1117", fg="#ff7b72", font=("Consolas", 12, "bold")).pack(side=tk.LEFT)
        self.cmd_input = tk.Entry(input_frame, bg="#0d1117", fg="#ffffff", font=("Consolas", 12), insertbackground="white", relief=tk.FLAT)
        self.cmd_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.cmd_input.bind("<Return>", self.komut_isleme)
        self.cmd_input.focus()

        self.terminal_yaz("WSN Exploit Module Loaded. Awaiting commands.\n\n", "#58a6ff")

    def tablo_veri_guncelle(self, tablo, veriler):
        for item in tablo.get_children(): tablo.delete(item)
        for satir in veriler: tablo.insert("", tk.END, values=satir)

    def terminal_yaz(self, metin, renk="#3fb950"):
        self.term_output.config(state=tk.NORMAL)
        self.term_output.insert(tk.END, metin)
        tag = str(hash(metin))
        self.term_output.tag_add(tag, "end-%dc" % (len(metin) + 1), "end")
        self.term_output.tag_config(tag, foreground=renk)
        self.term_output.see(tk.END)
        self.term_output.config(state=tk.DISABLED)

    def komut_isleme(self, event):
        komut = self.cmd_input.get().strip()
        self.cmd_input.delete(0, tk.END)
        self.terminal_yaz(f"root@kali:~# {komut}\n", "#ffffff")
        
        if komut == "": return
        if komut == "clear":
            self.term_output.config(state=tk.NORMAL)
            self.term_output.delete('1.0', tk.END)
            self.term_output.config(state=tk.DISABLED)

        elif komut == "zbid":
            self.terminal_yaz("DevNode\t\tString\n/dev/ttyUSB0\tTI CC2531 Sniffer (UP)\n", "#c9d1d9")

        elif komut == "zbstumbler":
            self.terminal_yaz("[*] Scanning 802.15.4 frequencies...\n", "#d2a8ff")
            self.root.update(); time.sleep(1)
            self.terminal_yaz("PAN_ID\tMAC_ADDRESS\t\tCH\tSIGNAL\n0x1A2B\t00:13:A2:00:41:B2:3C\t15\t-42dBm\n", "#c9d1d9")

        elif komut == "python3 wsn_exploit.py --target 0x1A2B --spoof-seq max":
            self.terminal_yaz("[*] Initializing Route Poisoning Module.\n", "#58a6ff")
            self.root.update(); time.sleep(1)
            self.terminal_yaz("[+] Target PAN ID: 0x1A2B located.\n", "#3fb950")
            self.root.update(); time.sleep(0.5)
            self.terminal_yaz("[*] Constructing spoofed AODV RREP packet...\n", "#d2a8ff")
            self.terminal_yaz("    > Dest_IP : 0.0.0.0 (Global)\n    > Seq_Num : 4294967295\n    > Hop_Cnt : 1\n", "#c9d1d9")
            self.root.update(); time.sleep(1)
            
            self.terminal_yaz("[+] Packet injected successfully.\n", "#3fb950")
            self.terminal_yaz("[*] Routing tables altered. Operating in BLACKHOLE mode.\n\n", "#ff7b72")
            
            self.saldiri_aktif = True
            self.hedef_sunucu_yonlendirmesini_boz()
            self.lbl_stats.config(text="Status: ACTIVE (INTERCEPTING) | Intercepted: 0 | Dropped: 0", fg="#ff7b72")
        else:
            self.terminal_yaz(f"bash: {komut}: command not found\n", "#ff7b72")

    def hedef_sunucu_yonlendirmesini_boz(self):
        # Hedef sunucunun tablosu zehirlenir, tüm ağ trafiği saldırgan MAC'ine döner.
        zehirli_routing = [
            ("0.0.0.0", "DE:AD:BE:EF:13:37", "UG", "4294967295", "1"),
            ("0.0.0.0", "DE:AD:BE:EF:13:37", "UG", "4294967295", "1"),
            ("0.0.0.0", "DE:AD:BE:EF:13:37", "UG", "4294967295", "1"),
            ("0.0.0.0", "DE:AD:BE:EF:13:37", "U", "4294967295", "1")
        ]
        self.tablo_veri_guncelle(self.tablo_hedef_route, zehirli_routing)
        
        # Hedef ekranı uyarı rengine (Kırmızı/Gri) geçer
        stil = ttk.Style()
        stil.configure("Treeview", background="#161b22", foreground="#ff7b72", fieldbackground="#161b22")

    def ag_trafiğini_simule_et(self):
        # Hem hedefi hem de saldırgan arayüzünü güncelleyen motor
        while self.sistem_dongusu:
            zaman = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            sens_id = random.randint(1, 8)
            mac = f"00:13:A2:00:41:{random.randint(10,99)}:{random.randint(10,99)}"
            is_aodv = random.choice([True, False, False, False])

            if not self.saldiri_aktif:
                # NORMAL DURUM: Hedef sunucu verileri sorunsuz alır. Saldırgan kördür (boş).
                if is_aodv:
                    payload = f"AODV: Route Request (RREQ) from Sensor-{sens_id}"
                else:
                    payload = f"IoT_DATA: {{\"node\": {sens_id}, \"temp\": {round(random.uniform(20,30), 1)}, \"bat\": {random.randint(60,100)}}} -> [PROCESSED]"
                
                self.tablo_hedef_trafik.insert("", 0, values=(zaman, mac, "AODV" if is_aodv else "UDP", payload))
                self.rx_paket_sayisi += 1
                
            else:
                # SALDIRI DURUMU: 
                # 1. Hedef Sunucu (Sink) sadece AODV zehirleme paketlerini görür, veri alamaz (Kördür).
                hedef_payload = f"AODV_ERR: Route timeout. No application data received."
                self.tablo_hedef_trafik.insert("", 0, values=(zaman, "N/A", "AODV", hedef_payload))
                
                # 2. Saldırgan (Rogue Node) hedefe giden tüm veriyi kendi ekranına çeker ve yok eder.
                if not is_aodv:
                    saldırgan_payload = f"EXTRACTED: {{\"node\": {sens_id}, \"temp\": {round(random.uniform(20,30), 1)}}} -> [ACTION: DROPPED]"
                    self.tablo_saldırgan_trafik.insert("", 0, values=(zaman, mac, "UDP", saldırgan_payload))
                    self.drop_paket_sayisi += 1
                    self.rx_paket_sayisi += 1
                    self.lbl_stats.config(text=f"Status: ACTIVE (INTERCEPTING) | Intercepted: {self.rx_paket_sayisi} | Dropped: {self.drop_paket_sayisi}")

            # Tabloların boyutunu sabit tut (Son 10-15 kayıt)
            for tablo in [self.tablo_hedef_trafik, self.tablo_saldırgan_trafik]:
                cocuklar = tablo.get_children()
                if len(cocuklar) > 12: tablo.delete(cocuklar[-1])
                
            time.sleep(random.uniform(0.6, 1.4))

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedWSNPentestEnvironment(root)
    root.mainloop()