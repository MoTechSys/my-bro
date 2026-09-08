# UC-07 — دمج YARA للكشف عن البرمجيات الخبيثة (FIM → Active Response)

**المصدر:** S2 ص39–55؛ S5 القسم الثالث (img20–img29). **الملفات:** `wazuh/agents/linux/active-response/yara.sh`, `wazuh/agents/windows/active-response/{yara.bat,download_yara_rules.py}`, `wazuh/manager/{rules,decoders}`, `ossec.conf.d/40-active-response-yara.xml`.

## التدفق
FIM realtime على مجلد → 100300/100301 (L7) → AR `yara_linux` → `yara.sh` يفحص الملف → يكتب `wazuh-yara: INFO - Scan result: <rule> <file>` في `active-responses.log` → decoder `yara_decoder` → 108000 → **108001 (L12)**.

## Linux (kali1)
```bash
# 1) بناء YARA 4.5.5 من المصدر (Debian/Kali — لا تستخدم yum! ISSUE-024)
sudo apt update && sudo apt install -y make gcc autoconf libtool libssl-dev pkg-config jq
sudo curl -LO https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz
sudo tar -xvzf v4.5.5.tar.gz -C /usr/local/bin/ && rm -f v4.5.5.tar.gz
cd /usr/local/bin/yara-4.5.5/ && sudo ./bootstrap.sh && sudo ./configure && sudo make && sudo make install && sudo make check
yara --version      # إن ظهر libyara.so.9 not found: echo "/usr/local/lib" | sudo tee -a /etc/ld.so.conf && sudo ldconfig

# 2) القواعد — ISSUE-020: خارج /tmp كي لا تُمسح عند الإقلاع
sudo mkdir -p /var/ossec/etc/yara/rules
sudo curl 'https://valhalla.nextron-systems.com/api/v1/get' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed \
  -H 'Referer: https://valhalla.nextron-systems.com/' -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
  --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
  -o /var/ossec/etc/yara/rules/yara_rules.yar
# (ISSUE-025: مجموعة demo محدودة)

# 3) السكربت
sudo cp yara.sh /var/ossec/active-response/bin/yara.sh
sudo chown root:wazuh /var/ossec/active-response/bin/yara.sh && sudo chmod 750 /var/ossec/active-response/bin/yara.sh

# 4) FIM
sudo mkdir -p /tmp/yara/malware
sudo nano /var/ossec/etc/ossec.conf     # <directories realtime="yes">/tmp/yara/malware</directories>
sudo systemctl restart wazuh-agent
```

## Manager
1. `local_decoder.xml` ← `yara_decoder`, `yara_decoder1`.
2. `local_rules.xml` ← 100300/100301 (**مرة واحدة فقط** — ISSUE-010) + 108000/108001.
3. `ossec.conf` ← `<command name=yara_linux>` بـ `extra_args -yara_path /usr/local/bin -yara_rules /var/ossec/etc/yara/rules/yara_rules.yar` + `<active-response rules_id=100300,100301>`.
4. `sudo systemctl restart wazuh-manager`.

## محاكاة
```bash
sudo bash scripts/attack-emulation/malware_downloader.sh     # عينات Mirai/Xbash/VPNFilter/WebShell من توثيق Wazuh (بيئة معزولة فقط!)
# أو ملف EICAR في /tmp/yara/malware
```

## التحقق
Threat Hunting → `rule.groups: yara` → "File "/tmp/yara/malware/mirai" is a positive match. Yara rule: …" Level 12.
`sudo tail /var/ossec/logs/active-responses.log` على الوكيل.

## Windows (win1) — ⚠️ ISSUE-006: مكتوب ولم يُثبَت تنفيذه
1. Python 3 + Visual C++ Redistributable.
2. `yara64.exe` من `v4.5.5-win64.zip` → `C:\Program Files (x86)\ossec-agent\active-response\bin\yara\`.
3. `pip install valhallaAPI` → `python download_yara_rules.py` → `...\yara\rules\yara_rules.yar`.
4. `yara.bat` → `...\active-response\bin\`.
5. FIM على `C:\Users\<USER_NAME>\Downloads` → `Restart-Service -Name wazuh`.
6. Manager: 100303/100304 + `<command name=yara_windows>`.
7. اختبار: EICAR zip → Downloads.

## أخطاء معروفة
- ISSUE-018: في S5 img27 مسار `/tmp/home/kali/omar` — تحقق من المسار الفعلي في `ossec.conf`.
- `yara.sh` يستخدم مساراً نسبياً `logs/active-responses.log` — يعمل لأن execd يشغّله من `/var/ossec`.
