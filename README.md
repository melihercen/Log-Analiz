# 🛡️ Log Analiz Aracı

Bu proje, **web sunucusu erişim loglarını (access.log)** analiz ederek olası saldırıları tespit eder.  
Tespit edilen saldırılar MITRE ATT&CK framework’ü ile eşleştirilir ve detaylı rapor hazırlanır.  
İsteğe bağlı olarak Excel formatında rapor çıktısı alınabilir.


## 🚀 Özellikler
- [x] **Log Analizi:** Apache/Nginx access.log formatını parse eder  
- [x] **Saldırı Tespitleri:**
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - SSRF (Server-Side Request Forgery)
  - Path Traversal
  - Command Injection
- [x] **Coğrafi Konum Analizi:** IP adreslerini GeoLite2-City veritabanı ile ülke/şehir bazında raporlar.İndirme linki : https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/  
- [x] **Saldırı Aracı Tespiti:** `User-Agent` üzerinden sqlmap, Burp Suite, OWASP ZAP, Nikto tespiti  
- [x] **MITRE ATT&CK Mapping:** Her saldırıyı MITRE teknikleri ve taktikleri ile eşleştirir  
- [x] **Excel Raporlama:** Otomatik sütun genişliği ayarlı rapor (`.xlsx`) oluşturur  
- [x] **Zaman Filtresi:** Belirtilen tarih aralığında analiz yapar

## 💻 Kod terminalde çalişip tarih bilgileri ve excel raporu istenip istenilmediği sorulduktan sonra özet bir rapor gösterir

<img width="528" height="257" alt="image" src="https://github.com/user-attachments/assets/94946b05-45c0-486f-9e8a-6b3db7e99df6" />



