# UC-10 — إشعار Telegram للتنبيهات L≥12

**الحالة:** ✅ مُثبت حياً عبر integratord إلى **mock** لـapi.telegram.org (لا توكن حقيقي بعد). يُغلق ISSUE-016.

## الملفات
- `wazuh/manager/integrations/custom-telegram` (launcher) + `custom-telegram.py` (stdlib فقط)
- `wazuh/manager/ossec.conf.d/60-integration-telegram.xml` (`<level>12</level>`)
- `tests/test_telegram.py` (11 اختباراً)

## التثبيت
```bash
sudo install -o root -g wazuh -m 750 wazuh/manager/integrations/custom-telegram* /var/ossec/integrations/
# ألصق كتلة 60-integration-telegram.xml في ossec.conf واستبدل:
#   YOUR_TELEGRAM_BOT_TOKEN  (من @BotFather)   YOUR_TELEGRAM_CHAT_ID (رقم المحادثة)
sudo systemctl restart wazuh-manager
```
الحصول على chat id: أرسل `/start` للبوت ثم `https://api.telegram.org/bot<TOKEN>/getUpdates`.

## خصائص الأمان
| الخاصية | التنفيذ |
|---|---|
| لا أسرار في Git | placeholders؛ الاختبار يفحص ذلك |
| التوكن لا يُسجَّل | حتى عند الفشل (اختبار) |
| تنقيح المحتوى | password/token/api_key/Bearer → `[REDACTED]`؛ HTML escape |
| منع التكرار | نفس (rule, agent, object) خلال 60 ث يُسقط |
| شبكة محدودة | مهلة 10 ث، 3 محاولات، احترام 429 retry_after، لا إعادة على 4xx |
| الإشعار ≠ إذن | L≥12 يُخطر فقط؛ لا يحذف ولا يحظر |

## الدليل الحي
```
2026/09/28 16:53:21 custom-telegram: sent rule 87105 level 12 in 1 attempt(s)
2026/09/28 16:53:21 custom-telegram: sent rule 100092 level 12 in 1 attempt(s)
```
نص الرسالة المستلمة في الـmock: عنوان L12، القاعدة، الوكيل، MITRE، الوقت، الملف.

## المتبقي
توكن حقيقي + chat id من الفريق لإثبات الاستلام على هاتف فعلي (5 دقائق عمل).
