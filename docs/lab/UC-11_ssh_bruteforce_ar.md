# UC-11 — SSH brute force + حظر آلي (firewall-drop)

**الحالة:** ✅ مُثبت حياً end-to-end 2026-09-28 (sshd حقيقي + rsyslog + Wazuh 4.14.7).

## السلسلة
محاولات دخول فاشلة → `/var/log/auth.log` (OpenSSH الحديث يكتب `sshd-session[...]`، يفكه Wazuh 4.14.7) →
- مستخدم **غير موجود**: 5710 ×7 → **5712** (L10)
- مستخدم **موجود**: 5760 ×7 → **5763** (L10)
→ AR `firewall-drop` (local) → `iptables -A INPUT -s IP -j DROP` → 651 → بعد 300 ث `delete` → 652.

> ⚠️ **ISSUE-066:** الخطة القديمة ربطت الحظر بـ5763 فقط؛ هجمات القاموس (hydra) تستخدم أسماء غير موجودة فتُطلق 5712 ولن تُحظر أبداً. الإعداد الآن `5712,5763`.

## الإعداد
`wazuh/manager/ossec.conf.d/50-active-response-firewall-drop.xml` داخل ossec.conf للمدير. **أضف IP الإدارة إلى `<global><white_list>`** قبل التفعيل.

## المحاكاة
```bash
bash scripts/attack-emulation/ssh_bruteforce_test.sh --lab 192.168.100.108 10    # SSH_PORT=2222 لمنفذ آخر
```
أسماء مستخدمين غير موجودة فقط (`socbf_invalid_N`) — لا يُقفل حساب حقيقي.

## الدليل الحي
```
16:43:56.239 5712 10 sshd: brute force trying to get access to the system. Non existent user.
16:43:58.239  651  3 Host Blocked by firewall-drop Active Response
iptables: -A INPUT -s 10.99.0.1/32 -j DROP        (ثم أُزيل تلقائياً ~16:49)
```
- IP في white_list (198.51.100.10): 5712 أُطلقت، **لا حظر** ✅
- التحقق: `tests/test_wazuh_engine.py::test_uc11_*` (3 اختبارات).

## استعادة يدوية
`sudo iptables -D INPUT -s <IP> -j DROP; sudo iptables -D FORWARD -s <IP> -j DROP`
