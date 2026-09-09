# Attack emulation — للعرض أمام اللجنة (معمل معزول فقط)
| سكربت | UC | التنبيه المتوقَّع |
|-------|----|-------------------|
| `eicar_test.sh --lab EXISTING_MONITORED_DIRECTORY` | 03 | 87105 → 100092 (L12) + حذف الملف |
| `nmap_scan.sh --lab PRIVATE_IPV4` (sudo) | 04 | 86601 NMAP SYN Scan |
| `netcat_tests.sh --lab` | 05 + 08 | 100210 (L12) ثم 100051 (L7) |
| `shellshock_test.sh --lab PRIVATE_IPV4` | 06 | 31168 (L15) |
| `malware_downloader.sh --lab COMMIT_40HEX SHA256_MANIFEST EXISTING_YARA_DIR` | 07 | 108001 إن طابقت القواعد؛ ليس مضموناً |

ترتيب مقترح للعرض (≈10 دقائق): 06 → 05 → 08 → 03 → 07 → 04. احتفظ بلقطات احتياطية في `docs/lab/evidence/`.

الواجهات كاملة في tests/SECURITY_REVIEW.md §6. EICAR ونص YARA اصطناعي فقط للديمو/القياس؛ لا تنزيل عينات حقيقية ضمن TEST_PLAN. PRIVATE_IPV4 ليس تفويضاً؛ يلزم معمل مصرح، snapshot وخطة استعادة. لا تنفذ العينات.
