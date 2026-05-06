# 🛡️ Blackhole Saldırısı Simülasyonu

Bu bölümde, ağ üzerindeki trafik akışının normal seyrini (Base) ve bir Blackhole saldırısı altındaki değişimini (Attack) içeren simülasyon sonuçları yer almaktadır.

---

## 📊 Simülasyon Senaryoları

| 🟢 Senaryo 1: Base (Normal Durum) | 🔴 Senaryo 2: Attack (Saldırı Anı) |
| :--- | :--- |
| Ağdaki düğümlerin normal protokol kurallarına göre veri paketlerini ilettiği simülasyon. | Kötü niyetli bir düğümün paketleri yutarak ağ trafiğini kestiği simülasyon. |
| <video src="https://github.com/user-attachments/assets/d4b61905-eaed-495b-8d30-ede911573b13" width="100%"> </video> | <video src="https://github.com/user-attachments/assets/cdec47d8-424d-4d3e-bac8-f74e0faf9e20" width="100%"> </video> |

---

### 🔍 Karşılaştırma Analizi

* **Base Senaryosu:** Paket iletim oranı (PDR) yüksektir, veri kaybı minimum düzeydedir ve ağ topolojisi kararlı çalışır.
* **Attack Senaryosu:** Saldırgan düğüm (Blackhole node), komşu düğümlere en kısa yolu kendisiymiş gibi göstererek paketleri üzerine çeker ve imha eder. Videoda paketlerin belli bir noktada toplandığı ve hedefe ulaşamadığı gözlemlenebilir.

---
