# معمل الـSandbox (بديل البيئة السحابية) — 2026-09-28

> البيئة السحابية (Azure) لم تعد متاحة. هذا هو المعمل الحي الحالي الذي نُفِّذت عليه كل الاختبارات.

## ما هو شغّال
| المكوّن | الإصدار | الحالة |
|---|---|---|
| wazuh-manager | 4.14.7 (حزمة رسمية apt) | active؛ analysisd/remoted/execd/integratord/apid |
| wazuh-agent `kali1` (id 001) | 4.14.7 | **active** — داخل mount namespace مستقل (`/srv/agent1/ossec` مربوط على `/var/ossec`) |
| sshd (منفذ 2222) + rsyslog | Debian 13 / OpenSSH (`sshd-session`) | UC-11 |
| Apache 2.4 (10.99.0.1:8081) | 2.4.68 | UC-06/09 |
| استقبال syslog UDP 514 | remoted, allowed-ips 10.99.0.2 | UC-12/13 |
| Telegram mock (127.0.0.1:8765) | — | UC-10 (بدون توكن حقيقي) |
| LLM | gpt-5-mini عبر بوابة OpenAI-compatible | T-70 |

عناوين: المدير 10.99.0.1، "الراوتر" 10.99.0.2، مصدر غير مسموح 10.99.0.3 (كلها على `lo`).
كلمة مرور Wazuh API غُيّرت عن الافتراضية وتُحفظ في `~/.soc_lab_api.env` (600، خارج Git).

## إعادة البناء من الصفر
```bash
# 1) manager
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update && sudo apt-get install -y wazuh-manager=4.14.7-1
# 2) محتوى المستودع
sudo bash scripts/lab/deploy_manager_local.sh --restart
# 3) كتل ossec.conf.d/30,50,60,70 تُلصق يدوياً (راجع تعليق كل ملف)
# 4) الاختبارات
python3 -m pytest tests -q                       # 178 + 28 تُتخطّى بدون Wazuh
sudo python3 -m pytest tests/test_wazuh_engine.py -q   # 28 على المحرك الحقيقي
```

## ⚠️ حادثة القرص (2026-09-28) — لازم قبل أي إعادة بناء
وحدة Vulnerability Detection في wazuh-manager 4.14.7 تنزّل feed ضخماً إلى `queue/vd` و`queue/vd_updater` (**~18 GB** خلال ساعتين) فامتلأ القرص 29 GB وفشلت الاختبارات بـ`No space left on device` (ليست أخطاء كود).
الحل المطبَّق (غير لازم لنطاق المشروع؛ لا indexer هنا):
```bash
sudo sed -i '0,/<vulnerability-detection>/{n;s#<enabled>yes#<enabled>no#}' /var/ossec/etc/ossec.conf
sudo sed -i '0,/<indexer>/{n;s#<enabled>yes#<enabled>no#}' /var/ossec/etc/ossec.conf
sudo bash -c 'cd /var/ossec/queue && rm -rf vd/* vd_updater/* indexer/*'
```
النتيجة: 14 GB محررة، القرص 53% مستقر، kali1 active، 178 + 28 اختباراً ناجحة. في معمل الفريق الحقيقي (مع Indexer) يمكن إبقاؤها مفعلة مع قرص ≥ 50 GB.

## ما تم إثباته حياً (end-to-end)
| UC | المسار المُثبَت | الدليل |
|---|---|---|
| 02/03 | FIM 100201 → 87105 → soc_ar.py حذف → 100092 (1.6 ث)؛ 4 مدخلات خبيثة → 100093 والملفات سليمة | alerts.json |
| 04 | eve.json → 86601 | logtest |
| 05 | auditd execve nc → 100210 L12 | logtest |
| 06 | Apache حقيقي → 31168 L15 | alerts |
| 07 | 108001 + Windows 100304 (FIM عبر queue) | alerts/logtest |
| 08 | 100051 لـ9 صيغ netcat، 0 إنذار كاذب على 6 | logtest |
| 09 | Apache حقيقي + sqli_test.sh → 31103 ×3 | alerts |
| 10 | integratord → custom-telegram → mock (87105, 100092) | integrations.log |
| 11 | sshd حقيقي → 5712 → firewall-drop → iptables DROP → فك تلقائي بعد 300 ث؛ white_list محترم | iptables/alerts |
| 12/13 | UDP 514 → 11 قاعدة MikroTik؛ مصدر غير مسموح مُسقَط | alerts |
| T-70 | L1 gpt-5-mini مُسنَد؛ L3 حظر بموافقة بشرية على agent 001 خلال 0.79 ث | audit.jsonl + iptables |

## حدود صريحة (تُكتب في الفصل 5)
- VirusTotal: نتيجة 87105 **محقونة** بصيغة integratord الحقيقية (لا مفتاح VT)؛ بقية السلسلة حقيقية.
- MikroTik: محاكي RouterOS بصيغة syslog الحقيقية، لا راوتر فعلي.
- لا Windows حقيقي: قواعد Windows مُثبتة على المحرك، سكربت AR لـWindows غير مبني.
- Suricata/auditd/YARA: القواعد مُثبتة بـlogtest، البرامج نفسها غير مثبتة هنا.
- المعمل لا يستمر بعد انتهاء الـsandbox؛ خطوات إعادة البناء أعلاه.
