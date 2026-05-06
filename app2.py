import tkinter as tk
from tkinter import ttk
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.offsetbox import OffsetImage, AnnotationBbox 
from PIL import Image 
import numpy as np
import threading
import time
import random
import datetime
import os
import sys # EXE İÇİN EKLENDİ

# EXE YAPILDIĞINDA DOSYA YOLUNU BULMAK İÇİN EKLENEN FONKSİYON
def resource_path(relative_path):
    """ Program exe haline getirildiğinde dosyaların geçici yolunu bulur """
    try:
        # PyInstaller geçici klasör yolu
        base_path = sys._MEIPASS
    except Exception:
        # Normal Python çalıştırması yolu
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class WSNAdvancedSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("WSN Karadelik Saldırısı & Wireshark Paket Analizörü")
        self.root.geometry("1300x850")
        self.root.configure(bg="#eceff1")
        
        self.topolojiler = ["Mesh (Ağ)", "Star (Yıldız)", "Ring (Halka)", "Tree (Ağaç)", "Grid (Izgara)"]
        self.mevcut_topoloji_idx = 0
        self.graf = nx.Graph()
        self.pos = None
        self.kaynak_dugum = 0
        self.hedef_dugum = None
        
        self.aktif_saldirganlar = [] 
        self.izole_edilenler = []
        self.simulasyon_calisiyor = False
        self.paket_no = 0
        
        self.arayuz_kur()
        self.topoloji_olustur()

    def arayuz_kur(self):
        ust_frame = ttk.Frame(self.root)
        ust_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.sol_frame = ttk.Frame(ust_frame, width=850)
        self.sol_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.fig, self.ax = plt.subplots(figsize=(8, 5))
        self.fig.patch.set_facecolor('#ffffff') 
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.sol_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.sag_frame = ttk.Frame(ust_frame, width=400)
        self.sag_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        ttk.Label(self.sag_frame, text="Kontrol Paneli", font=("Helvetica", 14, "bold")).pack(pady=5)

        self.lbl_topoloji = ttk.Label(self.sag_frame, text="Mevcut Topoloji: Mesh", font=("Helvetica", 11))
        self.lbl_topoloji.pack(pady=2)

        ttk.Button(self.sag_frame, text="🔄 Topolojiyi Değiştir", command=self.topoloji_degistir).pack(fill=tk.X, pady=2)
        ttk.Separator(self.sag_frame, orient='horizontal').pack(fill=tk.X, pady=5)

        ttk.Label(self.sag_frame, text="Simülasyon Senaryoları", font=("Helvetica", 11, "bold")).pack(pady=2)
        
        ttk.Button(self.sag_frame, text="🟢 1. Normal İletişim", command=lambda: self.simulasyon_baslat("normal")).pack(fill=tk.X, pady=2)
        ttk.Button(self.sag_frame, text="🔴 2. Tekli Karadelik Saldırısı", command=lambda: self.simulasyon_baslat("tekli_saldiri")).pack(fill=tk.X, pady=2)
        ttk.Button(self.sag_frame, text="🩸 3. İşbirlikçi (Sürü) Saldırı", command=lambda: self.simulasyon_baslat("isbirlikci_saldiri")).pack(fill=tk.X, pady=2)
        
        ttk.Separator(self.sag_frame, orient='horizontal').pack(fill=tk.X, pady=5)
        ttk.Button(self.sag_frame, text="🛡️ 4. SAVUNMAYI AKTİFLEŞTİR", command=lambda: self.simulasyon_baslat("savunma")).pack(fill=tk.X, pady=2)
        ttk.Separator(self.sag_frame, orient='horizontal').pack(fill=tk.X, pady=5)

        ttk.Label(self.sag_frame, text="Simülasyon Hızı", font=("Helvetica", 10, "bold")).pack(pady=2)
        self.hiz_slider = ttk.Scale(self.sag_frame, from_=0.2, to_=0.01, orient=tk.HORIZONTAL) 
        self.hiz_slider.set(0.06) 
        self.hiz_slider.pack(fill=tk.X, pady=2)

        ttk.Separator(self.sag_frame, orient='horizontal').pack(fill=tk.X, pady=5)

        ttk.Label(self.sag_frame, text="Ağ İstatistikleri", font=("Helvetica", 12, "bold")).pack(pady=5)
        ist_frame = ttk.Frame(self.sag_frame)
        ist_frame.pack(fill=tk.X)

        self.lbl_gonderilen = ttk.Label(ist_frame, text="Veri Paketi (Tx): 0", font=("Helvetica", 11))
        self.lbl_gonderilen.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.lbl_ulasan = ttk.Label(ist_frame, text="Başarılı (Rx): 0", font=("Helvetica", 11), foreground="green")
        self.lbl_ulasan.grid(row=1, column=0, sticky=tk.W, pady=2)
        
        self.lbl_dusen = ttk.Label(ist_frame, text="Düşen (Drop): 0", font=("Helvetica", 11), foreground="red")
        self.lbl_dusen.grid(row=2, column=0, sticky=tk.W, pady=2)
        
        self.lbl_pdr = ttk.Label(ist_frame, text="İletim Oranı (PDR): %0.00", font=("Helvetica", 12, "bold"))
        self.lbl_pdr.grid(row=3, column=0, sticky=tk.W, pady=5)

        self.lbl_gecikme = ttk.Label(ist_frame, text="Uçtan Uca Gecikme: 0.0 ms", font=("Helvetica", 11, "bold"), foreground="#673AB7")
        self.lbl_gecikme.grid(row=4, column=0, sticky=tk.W, pady=2)

        alt_frame = ttk.Frame(self.root)
        alt_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=False, padx=10, pady=10)
        
        ttk.Label(alt_frame, text="Wireshark Ağ Paket İzleyicisi (Payload İçerikli)", font=("Helvetica", 11, "bold")).pack(anchor=tk.W)
        
        tablo_scroll = ttk.Scrollbar(alt_frame)
        tablo_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        sutunlar = ("no", "zaman", "kaynak", "hedef", "protokol", "bilgi")
        self.paket_tablosu = ttk.Treeview(alt_frame, columns=sutunlar, show="headings", height=8, yscrollcommand=tablo_scroll.set)
        
        self.paket_tablosu.heading("no", text="No.")
        self.paket_tablosu.heading("zaman", text="Zaman")
        self.paket_tablosu.heading("kaynak", text="Kaynak")
        self.paket_tablosu.heading("hedef", text="Hedef")
        self.paket_tablosu.heading("protokol", text="Protokol")
        self.paket_tablosu.heading("bilgi", text="Paket İçeriği (Info & Payload)")

        self.paket_tablosu.column("no", width=50, anchor=tk.CENTER)
        self.paket_tablosu.column("zaman", width=100, anchor=tk.CENTER)
        self.paket_tablosu.column("kaynak", width=80, anchor=tk.CENTER)
        self.paket_tablosu.column("hedef", width=80, anchor=tk.CENTER)
        self.paket_tablosu.column("protokol", width=80, anchor=tk.CENTER)
        self.paket_tablosu.column("bilgi", width=550, anchor=tk.W)

        self.paket_tablosu.pack(fill=tk.BOTH, expand=True)
        tablo_scroll.config(command=self.paket_tablosu.yview)

        self.paket_tablosu.tag_configure("rreq", background="#e6e6fa") 
        self.paket_tablosu.tag_configure("rrep", background="#fffacd") 
        self.paket_tablosu.tag_configure("data_ok", background="#e0ffe0") 
        self.paket_tablosu.tag_configure("data_drop", background="#ffe0e0", foreground="red") 
        self.paket_tablosu.tag_configure("alert", background="black", foreground="white") 

    def wireshark_log_ekle(self, kaynak, hedef, protokol, bilgi, tag="data_ok"):
        self.paket_no += 1
        zaman = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        if kaynak == self.hedef_dugum: kaynak_str = "SUNUCU"
        elif kaynak not in ["Broadcast", "SYSTEM", "WATCHDOG"]: kaynak_str = f"Node {kaynak}"
        else: kaynak_str = kaynak
        
        if hedef == self.hedef_dugum: hedef_str = "SUNUCU"
        elif hedef not in ["Broadcast", "ALL"]: hedef_str = f"Node {hedef}"
        else: hedef_str = hedef
        
        self.paket_tablosu.insert("", tk.END, values=(self.paket_no, zaman, kaynak_str, hedef_str, protokol, bilgi), tags=(tag,))
        self.paket_tablosu.yview_moveto(1) 
        self.root.update()

    def istatistik_guncelle(self, gonderilen, ulasan, dusen, toplam_gecikme):
        pdr = (ulasan / gonderilen) * 100 if gonderilen > 0 else 0
        self.lbl_gonderilen.config(text=f"Veri Paketi (Tx): {gonderilen}")
        self.lbl_ulasan.config(text=f"Başarılı (Rx): {ulasan}")
        self.lbl_dusen.config(text=f"Düşen (Drop): {dusen}")
        
        renk = "green" if pdr >= 50 else "red"
        self.lbl_pdr.config(text=f"İletim Oranı (PDR): %{pdr:.2f}", foreground=renk)

        ort_gecikme = (toplam_gecikme / ulasan) if ulasan > 0 else 0
        self.lbl_gecikme.config(text=f"Uçtan Uca Gecikme: {ort_gecikme:.1f} ms")
        self.root.update()

    def topoloji_degistir(self):
        if self.simulasyon_calisiyor: return
        self.mevcut_topoloji_idx = (self.mevcut_topoloji_idx + 1) % len(self.topolojiler)
        self.aktif_saldirganlar = []
        self.topoloji_olustur()

    def topoloji_olustur(self):
        tip = self.topolojiler[self.mevcut_topoloji_idx]
        self.lbl_topoloji.config(text=f"Mevcut Topoloji: {tip}")
        self.ax.clear()

        if tip == "Mesh (Ağ)": self.graf = nx.barabasi_albert_graph(20, 3)
        elif tip == "Star (Yıldız)": self.graf = nx.star_graph(20)
        elif tip == "Ring (Halka)": self.graf = nx.cycle_graph(20)
        elif tip == "Tree (Ağaç)": self.graf = nx.balanced_tree(2, 4)
        elif tip == "Grid (Izgara)": self.graf = nx.convert_node_labels_to_integers(nx.grid_2d_graph(4, 5))

        self.pos = nx.spring_layout(self.graf, seed=42)
        self.hedef_dugum = len(self.graf.nodes) - 1
        nx.set_node_attributes(self.graf, 100, 'guven_skoru')

        self.izole_edilenler = []
        self.istatistik_guncelle(0, 0, 0, 0)
        self.grafik_ciz()
        
        for item in self.paket_tablosu.get_children():
            self.paket_tablosu.delete(item)
        self.paket_no = 0

    def grafik_ciz(self, aktif_yol=[], islem_goren=None):
        self.ax.clear()
        self.ax.set_title("Kablosuz Sensör Ağı ve Sunucu (Sink Node) Bağlantısı", fontsize=13, fontweight='bold')
        
        renkler_normal = []
        normal_dugumler = [n for n in self.graf.nodes if n != self.hedef_dugum]
        
        for node in normal_dugumler:
            if node == self.kaynak_dugum: renkler_normal.append('#4CAF50') 
            elif node in self.izole_edilenler: renkler_normal.append('#000000') 
            elif node in self.aktif_saldirganlar: renkler_normal.append('#F44336') 
            elif node == islem_goren: renkler_normal.append('#FFEB3B') 
            elif node in aktif_yol: renkler_normal.append('#FF9800') 
            else: renkler_normal.append('#B0BEC5') 

        nx.draw_networkx_edges(self.graf, self.pos, ax=self.ax, edge_color='#D3D3D3')
        
        if len(aktif_yol) > 1:
            rota = [(aktif_yol[i], aktif_yol[i+1]) for i in range(len(aktif_yol)-1)]
            nx.draw_networkx_edges(self.graf, self.pos, ax=self.ax, edgelist=rota, edge_color='#FF9800', width=3.0)

        # 1. NORMAL SENSÖRLERİ ÇİZ
        nx.draw_networkx_nodes(self.graf, self.pos, ax=self.ax, nodelist=normal_dugumler, node_color=renkler_normal, node_size=400, edgecolors='#424242')
        
        # 2. ÖZEL SUNUCU LOGOSUNU (GÖRSEL) ÇİZ
        sx, sy = self.pos[self.hedef_dugum]
        
        # LOGO YOLU GÜNCELLENDİ: EXE içindeyken de çalışacak şekilde resource_path kullanılıyor
        logo_yolu = resource_path("sunucu_logo.jpg") 
        
        if os.path.exists(logo_yolu):
            try:
                img = Image.open(logo_yolu)
                img_array = np.array(img)
                imagebox = OffsetImage(img_array, zoom=0.07) 
                imagebox.image.axes = self.ax
                ab = AnnotationBbox(imagebox, (sx, sy), frameon=False, pad=0)
                self.ax.add_artist(ab)
            except Exception as e:
                print(f"Logo okunamadı: {e}")
                nx.draw_networkx_nodes(self.graf, self.pos, ax=self.ax, nodelist=[self.hedef_dugum], node_color=['#1565C0'], node_size=1200, node_shape='s')
        else:
            nx.draw_networkx_nodes(self.graf, self.pos, ax=self.ax, nodelist=[self.hedef_dugum], node_color=['#1565C0'], node_size=1200, node_shape='s')

        # NORMAL DÜĞÜM NUMARALARINI ÇİZ
        etiketler = {n: str(n) for n in normal_dugumler}
        nx.draw_networkx_labels(self.graf, self.pos, labels=etiketler, ax=self.ax, font_size=8, font_weight="bold", font_color="white")
        
        # SUNUCU İsmine Özel Yüzen Etiket
        y_min, y_max = self.ax.get_ylim()
        offset = (y_max - y_min) * 0.08 
        self.ax.text(sx, sy - offset, "SUNUCU", fontsize=9, fontweight='bold', color='black', ha='center', va='top', 
                     bbox=dict(facecolor='#E3F2FD', edgecolor='#1565C0', boxstyle='round,pad=0.3', alpha=0.9))

        self.canvas.draw_idle()

    def simulasyon_baslat(self, mod):
        if self.simulasyon_calisiyor: return
        self.simulasyon_calisiyor = True
        
        nx.set_node_attributes(self.graf, 100, 'guven_skoru')
        self.izole_edilenler = []
        self.istatistik_guncelle(0, 0, 0, 0)
        
        for item in self.paket_tablosu.get_children():
            self.paket_tablosu.delete(item)
        self.paket_no = 0

        potansiyel_dugumler = list(self.graf.nodes)
        potansiyel_dugumler.remove(self.kaynak_dugum)
        potansiyel_dugumler.remove(self.hedef_dugum)

        if mod == "normal":
            self.aktif_saldirganlar = []
            savunma_acik = False
            self.wireshark_log_ekle("SYSTEM", "ALL", "SYS", "Senaryo Başlatıldı: Sensörden Sunucuya Güvenli İletişim", "rrep")
            
        elif mod == "tekli_saldiri":
            self.aktif_saldirganlar = random.sample(potansiyel_dugumler, 1) 
            savunma_acik = False
            self.wireshark_log_ekle("SYSTEM", "ALL", "SYS", f"Senaryo Başlatıldı: Sunucu Bağlantısına Karadelik Sızdı (Node {self.aktif_saldirganlar[0]})", "data_drop")
            
        elif mod == "isbirlikci_saldiri":
            self.aktif_saldirganlar = random.sample(potansiyel_dugumler, 3) 
            savunma_acik = False
            self.wireshark_log_ekle("SYSTEM", "ALL", "SYS", f"Senaryo Başlatıldı: Sürü Saldırısı Aktif {self.aktif_saldirganlar}", "data_drop")
            
        elif mod == "savunma":
            savunma_acik = True
            if not self.aktif_saldirganlar:
                self.aktif_saldirganlar = random.sample(potansiyel_dugumler, 3)
            self.wireshark_log_ekle("SYSTEM", "ALL", "SYS", "SAVUNMA SİSTEMİ DEVREDE (Watchdog Algorithm)", "alert")

        threading.Thread(target=self.motor_calistir, args=(savunma_acik,), daemon=True).start()

    def motor_calistir(self, savunma_acik):
        toplam_paket = 100
        ulasan_paket = 0
        dusen_paket = 0
        toplam_gecikme = 0 

        self.grafik_ciz()
        time.sleep(1)

        try:
            for pkt_id in range(1, toplam_paket + 1):
                gecici_graf = self.graf.copy()
                gecici_graf.remove_nodes_from(self.izole_edilenler)
                
                try:
                    gercek_rota = nx.shortest_path(gecici_graf, self.kaynak_dugum, self.hedef_dugum)
                except nx.NetworkXNoPath:
                    self.wireshark_log_ekle("SYSTEM", "ALL", "ERROR", "Ağ bütünlüğü bozuldu. Sunucuya giden yol bulunamıyor.", "data_drop")
                    break

                ulasilabilir_bh = [bh for bh in self.aktif_saldirganlar if bh not in self.izole_edilenler]
                saldiri_var_mi = False
                hedef_bh = None
                aktif_rota = gercek_rota
                isbirlikci_aktif = False
                
                sicaklik = round(random.uniform(20.0, 35.0), 1)
                nem = random.randint(40, 80)
                payload = f"[Sıcaklık: {sicaklik}°C, Nem: %{nem}]"
                
                if pkt_id == 1 or (pkt_id % 20 == 0):
                    self.wireshark_log_ekle(self.kaynak_dugum, "Broadcast", "AODV", f"Route Request (RREQ) for SUNUCU (Seq: 10{pkt_id})", "rreq")
                    time.sleep(0.05)

                if ulasilabilir_bh:
                    mesafeler = {}
                    for bh in ulasilabilir_bh:
                        try:
                            mesafeler[bh] = nx.shortest_path(gecici_graf, self.kaynak_dugum, bh)
                        except nx.NetworkXNoPath:
                            continue
                    
                    if mesafeler:
                        saldiri_var_mi = True
                        
                        if len(ulasilabilir_bh) > 1:
                            isbirlikci_aktif = True
                            secilen_bh = ulasilabilir_bh[pkt_id % len(ulasilabilir_bh)]
                            if secilen_bh not in mesafeler:
                                secilen_bh = list(mesafeler.keys())[0]
                        else:
                            secilen_bh = list(mesafeler.keys())[0]

                        aktif_rota = mesafeler[secilen_bh]
                        hedef_bh = secilen_bh
                        
                        if pkt_id == 1 or (pkt_id % 20 == 0):
                            self.wireshark_log_ekle(secilen_bh, self.kaynak_dugum, "AODV", f"Route Reply (RREP) - Ben Sunucuyum! (Fake Seq: 99999)", "rrep")
                        
                        if isbirlikci_aktif:
                            ortaklar = [b for b in ulasilabilir_bh if b != secilen_bh]
                            ortak_mesafeler = {}
                            for ob in ortaklar:
                                try:
                                    ortak_mesafeler[ob] = nx.shortest_path(gecici_graf, secilen_bh, ob)
                                except nx.NetworkXNoPath:
                                    pass
                                    
                            if ortak_mesafeler:
                                ikinci_bh = min(ortak_mesafeler, key=lambda k: len(ortak_mesafeler[k]))
                                aktif_rota = aktif_rota + ortak_mesafeler[ikinci_bh][1:]
                                hedef_bh = ikinci_bh 

                self.grafik_ciz(aktif_yol=aktif_rota)
                time.sleep(self.hiz_slider.get()) 

                if saldiri_var_mi:
                    dusen_paket += 1
                    info_msg = f"Data id:{pkt_id} {payload} [DROPPED - SUNUCUYA ULAŞAMADI]"
                    if isbirlikci_aktif:
                        info_msg = f"Data id:{pkt_id} {payload} [COOP-DROPPED] Node {secilen_bh} -> Node {hedef_bh}"
                    
                    self.wireshark_log_ekle(self.kaynak_dugum, hedef_bh, "TCP/DATA", info_msg, "data_drop")
                    
                    if savunma_acik:
                        mevcut_guven = self.graf.nodes[hedef_bh]['guven_skoru']
                        yeni_guven = mevcut_guven - 35
                        self.graf.nodes[hedef_bh]['guven_skoru'] = yeni_guven

                        if yeni_guven <= 0:
                            self.izole_edilenler.append(hedef_bh)
                            self.wireshark_log_ekle("WATCHDOG", hedef_bh, "ALERT", f"Düğüm Güven Skoru %0. AĞDAN İZOLE EDİLDİ!", "alert")
                            self.grafik_ciz()
                            time.sleep(1)
                else:
                    ulasan_paket += 1
                    gecikme = (len(aktif_rota) * 12.0) + (random.uniform(1, 5))
                    toplam_gecikme += gecikme
                    self.wireshark_log_ekle(self.kaynak_dugum, self.hedef_dugum, "TCP/DATA", f"Data id:{pkt_id} {payload} [SUNUCUYA ULAŞTI] Delay: {gecikme:.1f}ms", "data_ok")

                self.istatistik_guncelle(pkt_id, ulasan_paket, dusen_paket, toplam_gecikme)

        finally:
            self.simulasyon_calisiyor = False
            self.wireshark_log_ekle("SYSTEM", "ALL", "INFO", "--- SİMÜLASYON İŞLEMİ TAMAMLANDI ---", "rrep")

if __name__ == "__main__":
    root = tk.Tk()
    app = WSNAdvancedSimulator(root)
    root.mainloop()