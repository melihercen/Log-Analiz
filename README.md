# 🛡️ Web Log Attack Analyzer

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
- [x] **Coğrafi Konum Analizi:** IP adreslerini GeoLite2-City veritabanı ile ülke/şehir bazında raporlar  
- [x] **Saldırı Aracı Tespiti:** `User-Agent` üzerinden sqlmap, Burp Suite, OWASP ZAP, Nikto tespiti  
- [x] **MITRE ATT&CK Mapping:** Her saldırıyı MITRE teknikleri ve taktikleri ile eşleştirir  
- [x] **Excel Raporlama:** Otomatik sütun genişliği ayarlı rapor (`.xlsx`) oluşturur  
- [x] **Zaman Filtresi:** Belirtilen tarih aralığında analiz yapar

# Kod terminalde çalişip tarih bilgileri ve excel raporu istenip istenilmediği sorulduktan sonra özet bir rapor gösteriyor.


İstediğiniz zaman aralığını girin.
Başlangıç tarihi ve saati (YYYY-AA-GG HH:MM:SS formatında, boş bırakırsanız filtresiz):
Bitiş tarihi ve saati (YYYY-AA-GG HH:MM:SS formatında, boş bırakırsanız filtresiz): 
Excel raporu oluşturulsun mu? (E/H): h
============================================================
ANALİZ ÖZET RAPORU
Excel raporu oluşturuldu
Toplam Belirlenen Attak : 42
Saldırı Tipi Dağılımı:
Command Injection : 5 adet
SQL Injection : 20 adet
XSS : 17 adet
Şüpheli IPler:
192.168.1.10 : 25 adet şüpheli aktivite

