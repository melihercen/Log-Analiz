import re
import geoip2.database
from datetime import datetime
from datetime import timezone
import pandas as pd


def parse_log_datetime(datetime_str):
    #19/Aug/2025:19:39:43 +0300 -> 2025-08-19 19:39:43+00:00
    try:
        date=datetime.strptime(datetime_str,'%d/%b/%Y:%H:%M:%S %z')
        return date.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    
def convert_to_utc(dt_str):
    try:
        dt=datetime.strptime(dt_str,'%Y-%m-%d %H:%M:%S')
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        print(f"Hata Geçersiz tarih formatı - {dt_str}")
        return None
    
def get_attacker_location(ip_address):
    db_path="GeoLite2-City.mmdb"

    try:
        reader=geoip2.database.Reader(db_path)
        response=reader.city(ip_address)

        country=response.country.name
        city=response.city.name

        reader.close()
        return country,city
    except geoip2.errors.AddressNotFoundError:
        return "Bilinmiyor","bilinmiyor"
    
def get_attack_tool(user_agent):
    #Buradaki toolar artırılabılır
    tools={
        "sqlmap": "sqlmap",
        "ZAP":"OWASP ZAP",
        "Burp":"Burp Suite",
        "nikto":"Nikto"
    }
    for key,value in tools.items():
        if key.lower() in user_agent.lower():
            return value
    return "Bilinmiyor"

def save_to_excel(attack_data,filename="saldiri_raporu.xlsx"):
    if not attack_data:
        print("Kaydedilecek saldırı verisi bulunmadı.")
        return False
    
    file=pd.DataFrame(attack_data)

    try:
        with pd.ExcelWriter(filename,engine="openpyxl") as writer:
            file.to_excel(writer,sheet_name="Saldırılar",index=False)

         
            worksheet=writer.sheets['Saldırılar']

            for column in worksheet.columns:
                max_length=0
                column_letter=column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length=len(str(cell.value))
                    except:
                        pass
                    adjusted_width=min(max_length+2,50)
                    worksheet.column_dimensions[column_letter].width=adjusted_width
            return True
    except Exception as e:
        print(f"Hata {e}")
        return False

def map_to_mitre(attack_type):
    mitre_map={
        "SQL Injection":{
            "Taktik":"Inıtal Access",
            "Teknik":"T1190 - Exploit Public-Facing Application"
        },
        "XSS":{
            "Taktik":"Inıtal Access / Execution",
            "Teknik":"T1059 - Command and Scripting Interpreter"
        },
        "SSRF":{
            "Taktik":"Inıtal Access",
            "Teknik":"T1190 - Exploit Public-Facing Application"
        },
        "Path Traversal":{
            "Taktik":"Collection",
            "Teknik":"T1005 - Data from Local System"
        },
        "Command Injection":{
            "Taktik":"Execution",
            "Teknik":"T1059 - Command and Scripting Interpreter"
        }

    }
    return mitre_map.get(attack_type,{"Taktik":"Bilinmiyor","Teknik":"Bilinmiyor"})


def parse_log_entry(log_line):
    pattern=r'(?P<ip>\S+) \S+ \S+ \[(?P<tarih>.*?)\] "(?P<metod>\S+) (?P<url>[^"]+) \S+" (?P<durum_kodu>\S+) (?P<boyut>\S+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"'

    match=re.match(pattern,log_line)
    if match:
        return match.groupdict()
    return None

def analyze_log_file(file_path,start_time_str=None,end_time_str=None,export_excel=False):
    start_time=None
    end_time=None
    if start_time_str:
        start_time=convert_to_utc(start_time_str)
        if not start_time:
            return
    if end_time_str:
        end_time=convert_to_utc(end_time_str)
        if not end_time:
            return
        
    if start_time and end_time and end_time < start_time:
        print("Hata Başlangıç tarihi bitiş tarihinden sonra olamaz")
        return
    
    attack_count=0
    attack_data=[]

    print(f"Log dosyası analiz ediliyor: {file_path}")
    if start_time:
        print(f"Başlangıç : {start_time}")
    if end_time:
        print(f"Bitiş: {end_time}")


    with open(file_path,"r") as f:
        for line in f:
            log_data=parse_log_entry(line)

            if log_data:
                ip=log_data["ip"]
                url=log_data["url"]
                user_agent=log_data["user_agent"]
                status_code=log_data["durum_kodu"]
                log_datetime_str=log_data["tarih"]
                log_datetime=parse_log_datetime(log_datetime_str)
                if start_time and end_time:
                    if start_time and log_datetime:
                        if log_datetime < start_time:
                            continue
                    if end_time and log_datetime:
                        if end_time < log_datetime:
                            continue
                elif start_time:
                    if log_datetime < start_time:
                            continue
                elif end_time:
                    if end_time < log_datetime:
                            continue


    

                attack_type=None
                if detect_sql_injection(url):
                    attack_type="SQL Injection"
                
                elif detect_xss(url):
                    attack_type="XSS"

                elif detect_ssrf(url):
                    attack_type="SSRF"

                elif detect_pathtraversal(url):
                    attack_type="Path Traversal"
                
                elif detect_commandinjection(url):
                    attack_type="Command Injection"

                
                if attack_type:
                    country,city=get_attacker_location(ip)
                    attack_tool=get_attack_tool(user_agent)
                    mitre_info=map_to_mitre(attack_type)
                    attack_count+=1

                    attack_data.append({
                        "Saldırı Tipi": attack_type,
                        "IP Adresi": ip ,
                        "URL": url[:100],
                        "Zaman": log_datetime_str,
                        "Ülke": country,
                        "Şehir": city,
                        "Saldırı Aracı": attack_tool,
                        "MITRE Taktık": mitre_info['Taktik'],
                        "MITRE Teknik": mitre_info['Teknik'],
                        "User-Agent": user_agent[:50],
                        "Durum Kodu": status_code,
                    })

    excel_success=False
    if export_excel and attack_data:
        excel_filename=f"saldiri_raporu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        excel_success=save_to_excel(attack_data,excel_filename)
                 
    print(f"\n{'='*60}")
    print("ANALİZ ÖZET RAPORU")
    if excel_success:
        print("Excel raporu oluşturuldu")
    if attack_data:
        print(f"Toplam Belirlene Attak : {attack_count}")
        attack_types=[data["Saldırı Tipi"] for data in attack_data]
        print("Saldırı Tipi Dağılımı:")
        for attack_type in sorted(set(attack_types)):
                count=attack_types.count(attack_type)
                print(f"{attack_type} : {count} adet")

        ip_address=[data["IP Adresi"] for data in attack_data]
        print("Şüphelı Ipler")
        for ip_address1 in sorted(set(ip_address)):
            count=ip_address.count(ip_address1)
            if count>20:
                print(f"{ip_address1} : {count} adet süpheli aktivite")
            
    
                



#Burada Zafiyet belirleme patternleri arrtırılabılır düzenlenebilir
def detect_sql_injection(url):
    sql_patterns=[
        r"('|\").*?(OR|AND).*?'1'='1",
        r"ORDER.*?BY",
        r"(?:'|\"|\s)(?:OR|AND)\s+\d+\s*=\s*\d+",
        r"(?:'|\"|\s)UNION(?:\s+ALL)?\s+SELECT",
        r"(?:'|\"|\s)SELECT\s+.*?\s+FROM",
        r"(?:'|\"|\s)UPDATE\s+.*?SET",
        r"(?:'|\"|\s)DELETE\s+.*?FROM",
        r"(?:'|\"|\s)INSERT\s+.*?INTO",
        r"(?:'|\"|\s)DROP\s+(?:TABLE|DATABASE)",
        r"(?:'|\"|\s)EXEC(?:UTE)?",
        r"(?:'|\"|\s)SLEEP\(\d+\)",
        r"(?:'|\"|\s)pg_sleep\(\d+\)",
        r"(?:'|\"|\s)BENCHMARK\(",
        r"(?:'|\"|\s)WAITFOR\s+DELAY",
        r"information_schema",
        r"@@version",
        r"database\(",
        r"--\s*\w+",
        r"#\s*\w+",
        r";\s*--",
        r"%27%20(?:OR|AND)%20",
        r"%20OR%201%3D1",        
        r"%27\s*OR\s*%27\s*=\s*%27"
    ]
    for pattern in sql_patterns:
        if re.search(pattern,url,re.IGNORECASE):
            return True
    return False

def detect_xss(url):
    xss_patterns=[
        r"<script>",
        r"javascript:",
        r"onload",
        r"alert",
        r"<iframe",          
        r"src='javascript:",  
        r"onerror='",       
        r"eval\(",           
        r"document.cookie",  
        r"location='http",   
        r"vbscript:",        
        r"cookie=",          
        r"<img src=",     
        r"<svg onload=", 
        r"%3Cscript%3E",
        r"\balert\b",   
        r"prompt\b",     
        r"confirm\b"    
    ]
    for pattern in xss_patterns:
        if re.search(pattern,url,re.IGNORECASE):
            return True
    return False

def detect_ssrf(url):
    ssrf_patterns=[
        r"127\.0\.0\.1",
        r"192\.168\.\d{1,3}\.\d{1,3}",
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}",
        r"169\.254\.169\.254",
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        r'localhost',
        r'http://',
        r'file://'
    ]
    for pattern in ssrf_patterns:
        if re.search(pattern,url,re.IGNORECASE):
            return True
    return False

def detect_pathtraversal(url):
    pathtraversal_patterns=[
        r"\.\./",          
        r"\\.\\",          
        r"%2e%2e%2f",      
        r"%2e%2e%5c",     
        r"\.\.%2f",        
        r"\.\.%5c",      
        r"etc/passwd",
        r"windows/win.ini"
    ]

    for pattern in pathtraversal_patterns:
        if re.search(pattern,url,re.IGNORECASE):
            return True
    return False
def detect_commandinjection(url):
    command_injection_patterns=[
        r";",    
        r"\|",        
        r"&&",      
        r"\|\|",     
        r"`",        
        r"\$\(",     
        r"\b(system|exec|shell_exec|passthru|popen)\b"
    ]
    for pattern in command_injection_patterns:
        if re.search(pattern,url,re.IGNORECASE):
            return True
    return False


if __name__=="__main__":
    log_file=input("Log Dosyası Yolu: ").strip()
    print("İstediğiniz zaman aralığını girin.")
    start_input=input("Başlangıç tarihi ve saati (YYYY-AA-GG HH:MM:SS formatında, boş bırakırsanız filtresiz): ").strip()
    end_input = input("Bitiş tarihi ve saati (YYYY-AA-GG HH:MM:SS formatında, boş bırakırsanız filtresiz): ").strip()

    excel = input("Excel raporu oluşturulsun mu? (E/H): ").strip().lower()
    excel =excel if excel == 'e' or excel == 'evet' else False

    start_dt_str=start_input if start_input else None
    end_dt_str=end_input if end_input else None

    analyze_log_file(log_file,start_time_str=start_dt_str,end_time_str=end_dt_str,export_excel=excel)