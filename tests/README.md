# tests — الاختبارات وعقد القياس

> المالك ASTRA؛ 2026-09-09؛ الحالة اختبارات محلية وخطة، بلا نتائج معملية. المرجع TEST_PLAN.md (T-10).

- TEST_PLAN.md: عشر محاولات لكل سيناريو/OS/config بعد PILOT؛ baseline ساعة موثقة، وسجل مستقل عن alerts.json.
- SECURITY_REVIEW.md وtest_security.py: حدود الأمن واختبارات محلية، لا native acceptance.
- T-11 محجوز: scripts/measure/mttd.py سيقرأ المحاولات والتنبيهات وmanifest الزمن/الإعداد والأدلة؛ لا طرح timestamp من @timestamp ولا استبدال المفقود بصفر.
- ISSUE-019 لا يغلق بالخطة أو fixtures اصطناعية. النتائج الحقيقية فقط تغذي الفصل الخامس.

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
bash scripts/validate/validate_all.sh
```
