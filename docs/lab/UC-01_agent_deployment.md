# UC-01 — نشر وكلاء Wazuh (Windows + Linux)

**المصدر:** S2 ص1–6، لقطات `p01_1`, `p02_0`, `p04_0`, `p04_1`, `p05_0..3`, `p06_0..2`.

## الهدف
ربط `win1` و`kali1` بالمدير `192.168.100.105` وظهورهما `active` في Agents management.

## الخطوات (من اللوحة)
1. `https://192.168.100.105` → login `admin`.
2. **Agents management → Summary → Deploy new agent**.
3. اختيار OS → Server address `192.168.100.105` → Agent name (`win1` / `kali1`) → Group `default`.
4. تنفيذ الأمر المولَّد:

**Windows (PowerShell admin)** — من `p05_3.png`:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.100.105' WAZUH_AGENT_NAME='win1'
NET START Wazuh
```
**Linux (Kali)** — من `p06_1.png`:
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.7-1_amd64.deb \
 && sudo WAZUH_MANAGER='192.168.100.105' WAZUH_AGENT_NAME='kali1' dpkg -i ./wazuh-agent_4.14.7-1_amd64.deb
sudo systemctl daemon-reload && sudo systemctl enable wazuh-agent && sudo systemctl start wazuh-agent
```

## النتيجة الفعلية (`p04_0.png`)
| ID | Name | IP | OS | Version | Status |
|----|------|----|----|---------|--------|
| 001 | win1 | 192.168.100.106 | Windows 10 Education 10.0.19045.2006 | v4.14.7 | disconnected ⚠️ |
| 002 | kali1 | 192.168.100.108 | Kali GNU/Linux 2025.4 | v4.14.7 | active |

## الأخطاء المعروفة
- ISSUE-014: `wget: Temporary failure in name resolution` — DNS في VM؛ تحقق `ping packages.wazuh.com` أو `resolvectl status`.
- ISSUE-026: `win1` disconnected — تحقق من خدمة Wazuh على ويندوز وجدار الحماية (1514/tcp خارج).
- ISSUE-002: Windows 10 وليس 11 كما في الرسالة.

## استعلام اللوحة
Agents management → Summary. أو `sudo /var/ossec/bin/agent_control -l` على المدير.
