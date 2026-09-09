# Attack emulation — للعرض أمام اللجنة (معمل معزول فقط)
| سكربت | UC | التنبيه المتوقَّع |
|-------|----|-------------------|
| `eicar_test.sh [dir]` | 03 | 87105 → 100092 (L12) + حذف الملف |
| `nmap_scan.sh [target]` | 04 | 86601 NMAP SYN Scan |
| `netcat_tests.sh` | 05 + 08 | 100210 (L12) ثم 100051 (L7) |
| `shellshock_test.sh [target]` | 06 | 31168 (L15) |
| `malware_downloader.sh` | 07 | 108001 (L12) لكل عينة |

ترتيب مقترح للعرض (≈10 دقائق): 06 → 05 → 08 → 03 → 07 → 04. احتفظ بلقطات احتياطية في `docs/lab/evidence/`.
