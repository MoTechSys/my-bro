#!/usr/bin/env python3
"""Private offline C4 report from verified runner artifacts, AI 2026-09-18.

No model/network, external assets, JavaScript or response executor. HTML output
contains potentially linkable case IDs/metrics: private by default, not a website.
"""
import argparse
import hashlib
import html
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_report_runner', HERE/'runner.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def build(store, manifest_sha256, reviews_path=None, reviews_sha256=None, *, no_reviews=False):
    if no_reviews is not True and reviews_path is None:
        raise ValueError('EXPLICIT_REVIEW_INPUT_REQUIRED')
    if no_reviews and (reviews_path is not None or reviews_sha256 is not None):
        raise ValueError('CONFLICTING_REVIEW_INPUT')
    if reviews_path is None:
        reviews, review_hash = [], None
    else:
        r.e.sha256(reviews_sha256)
        path = Path(reviews_path).absolute()
        fd = r.directory(path.parent)
        try: raw = r.read_at(fd, path.name)
        finally: r.os.close(fd)
        review_hash = r.digest(raw)
        if review_hash != reviews_sha256: raise ValueError('REVIEW_HASH_MISMATCH')
        reviews = r.a.strict_json(raw)
    imported = r.export_attempts(store, manifest_sha256)
    # Reopen the immutable-by-convention manifest and recheck its expected bytes.
    # The imported snapshot is already detached; later writes cannot change it.
    with r.store_lock(store) as fd:
        raw_manifest = r.read_at(fd, 'manifest.json')
    if r.digest(raw_manifest) != manifest_sha256: raise ValueError('MANIFEST_CHANGED')
    manifest = r.a.strict_json(raw_manifest)
    evaluation = r.e.evaluate(manifest, imported['attempts'], reviews)
    return {'schema_version': 1, 'evaluation': evaluation,
            'evidence_verification': {
                'manifest_sha256': manifest_sha256,
                'reviews_file_sha256': review_hash,
                'reviews_explicitly_omitted': no_reviews,
                'stored_artifact_bytes_verified': imported['stored_artifact_bytes_verified'],
                'batches': imported['batches'],
                'reporter_sha256': hashlib.sha256(r.read_bytes(Path(__file__))).hexdigest()},
            'execution_authority': 'none', 'acceptance_approved': False,
            'human_independence_verified': False, 'model_runtime_identity_verified': False,
            'notice': 'Byte verification is not authenticity, model attestation, trusted timing or human approval. '
                      'The normalized evaluator alone still does not read source artifacts.'}


def esc(value):
    return html.escape(str(value), quote=True)


def table(headers, rows):
    return ('<table><thead><tr>' + ''.join('<th scope="col">' + esc(v) + '</th>' for v in headers) +
            '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in row) +
                                            '</tr>' for row in rows) + '</tbody></table>')


def rate_text(value):
    if value['value'] is None: return 'غير متاح — مقام صفر'
    return f"{value['numerator']} / {value['denominator']} ({100 * value['value']:.2f}%)"


def render(value):
    """Render only aggregate metrics and case outcomes, never raw logs/labels/reviewer identities."""
    e = value['evaluation']; evidence = value['evidence_verification']
    count_rows = [[status, e['counts'][status]] for status in (*r.e.STATUSES, 'missing')]
    metric_rows = [[title, rate_text(e[key])] for title, key in [
        ('اكتمال الإجابات / جميع الحالات', 'completion_rate'),
        ('التصنيف الصحيح / جميع الحالات', 'classification_all_planned'),
        ('التصنيف الصحيح / المكتملة فقط', 'classification_completed_only'),
        ('مطابقة MITRE / جميع الحالات', 'mitre_exact_all_planned'),
        ('مطابقة MITRE / المكتملة فقط', 'mitre_exact_completed_only')]]
    h = e['human_review']
    metric_rows.append(['ادعاءات غير مسندة / الادعاءات المحكّمة فقط',
                        rate_text(h['unsupported_claim_rate_reviewed_only'])])
    case_rows = [[v['case_id'], v['status'],
                  'نعم' if v['classification_correct'] else ('لا' if v['status'] == 'completed' else 'غير متاح'),
                  'نعم' if v['mitre_exact'] else ('لا' if v['status'] == 'completed' else 'غير متاح')]
                 for v in e['cases']]
    latency_rows = [[status, row['n'],
                     'غير متاح' if row['mean_seconds'] is None else f"{row['mean_seconds']:.3f}",
                     'غير متاح' if row['p95_seconds'] is None else f"{row['p95_seconds']:.3f}"]
                    for status, row in e['latency_by_status'].items()]
    batch_rows = [[v['batch_id'], v['status'], v['reason'], v.get('validation_code') or '—',
                   ', '.join(v['unverified_artifacts']) or '—'] for v in evidence['batches']]
    verify = 'تم فحص بايتات المرفقات الموجودة المرتبطة بالبصمات' if evidence['stored_artifact_bytes_verified'] else 'توجد مرفقات يتيمة غير مرتبطة بسجل نهائي؛ لا تحقق شامل'
    warning = ('بيانات اصطناعية — ليست نتائج تجربة أصلية' if e['dataset_kind'] == 'synthetic' else
               'بيانات مصرح بأنها حقيقية — أصالتها واستقلالها غير مثبتين آلياً')
    body = ('<header><p class="eyebrow">SOC / C4 — تقرير خاص دون اتصال</p><h1>تقرير تقييم محلل التنبيهات</h1>'
            '<p>التجربة: <bdi>' + esc(e['evaluation_id']) + '</bdi></p></header>'
            '<aside role="note"><strong>' + esc(warning) + '</strong><p>ليس اعتماداً أمنياً أو قرار قبول. '
            'لا صلاحية تنفيذ أو موافقة آلية. لا يوجد نموذج أو اتصال شبكة في توليد هذا التقرير.</p></aside>'
            '<h2>اكتمال العينة</h2><p>الحالات المخططة: ' + esc(e['planned_cases']) + '</p>' +
            table(['الحالة', 'العدد'], count_rows) + '<h2>المقاييس والمقامات</h2>' +
            table(['المقياس', 'القيمة'], metric_rows) +
            '<p>المكتملة دون تحكيم: ' + esc(h['unreviewed_completed']) +
            '؛ حالات التحكيم دون ادعاءات: ' + esc(h['zero_claim_reviews']) +
            '. نقص التحكيم لا يعني غياب الهلاوس. الأعلام الخاصة باستقلال البشر تصريحات وليست تحقق هوية.</p>'
            '<h2>الزمن لكل حالة حسب الحالة التشغيلية</h2>' +
            table(['الحالة', 'n', 'المتوسط بالثواني', 'p95 بالثواني'], latency_rows) +
            '<p>طريقة p95: nearest-rank. الزمن قد يتكرر لحالات الدفعة؛ ليس عدد استدعاءات مستقلة أو MTTD. '
            'المحاولات المسجلة بلا توقيت: ' + esc(e['untimed_recorded_attempts']) + '</p>'
            '<h2>فواصل عدم اليقين</h2><p>' + esc(e['intervals']['method']) + ' — ' +
            esc(e['intervals']['reason']) + '</p>' +
            table(['المقياس', 'Wilson95 المشروط'],
                  [[key, 'محجوب / غير متاح' if e[key]['wilson_95'] is None else str(e[key]['wilson_95'])]
                   for key in ('completion_rate', 'classification_all_planned', 'mitre_exact_all_planned')]) +
            '<h2>سلامة الأدلة وحدودها</h2><p>' + esc(verify) + '</p>' +
            table(['البصمة', 'SHA256'], [['manifest', evidence['manifest_sha256']],
                   ['reviews', evidence['reviews_file_sha256'] or 'لم يقدم ملف تحكيم'],
                   ['reporter', evidence['reporter_sha256']]]) +
            '<p>' + esc(value['notice']) + '</p><h2>حالات الدفعات</h2>' +
            table(['الدفعة', 'الحالة', 'سبب التشغيل', 'كود التحقق', 'مرفقات غير متحققة'], batch_rows) +
            '<h2>نتائج الحالات</h2>' + table(['الحالة المرجعية', 'التشغيل', 'التصنيف صحيح', 'MITRE مطابق'], case_rows) +
            '<footer>ملف خاص: معرفات الحالات والتوقيت والبصمات قد تسمح بالربط. راجع التنقيح قبل المشاركة. '
            'لا سجلات خام أو إجابات مرجعية أو أسماء محكّمين في هذه الواجهة.</footer>')
    style = ('body{font:16px/1.7 system-ui,sans-serif;background:#f4f6f8;color:#152331;margin:0}'
             'main{max-width:1100px;margin:32px auto;padding:32px;background:white;border-radius:12px}'
             'h1,h2{line-height:1.4}h2{margin-top:32px}.eyebrow{color:#456}'
             'aside{padding:16px;border-right:5px solid #ad6c00;background:#fff3d8}'
             'table{width:100%;border-collapse:collapse;font-size:14px;table-layout:fixed}'
             'th,td{padding:10px;text-align:start;border:1px solid #dce2e7;overflow-wrap:anywhere}'
             'th{background:#eaf0f4}footer{margin-top:32px;color:#456;border-top:1px solid #ccd;padding-top:16px}'
             '@media(max-width:700px){main{margin:0;padding:14px}th,td{padding:5px;font-size:12px}}'
             '@media print{body{background:white}main{margin:0;padding:0}tr{break-inside:avoid}}')
    return ('<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
            'base-uri \'none\'; form-action \'none\'">'
            '<title>تقرير C4 الخاص</title><style>' + style + '</style></head><body><main>' + body + '</main></body></html>')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    review = parser.add_mutually_exclusive_group(required=True)
    review.add_argument('--reviews')
    review.add_argument('--no-reviews', action='store_true')
    parser.add_argument('--reviews-sha256')
    parser.add_argument('--format', choices=('json', 'html'), default='json')
    args = parser.parse_args(argv)
    try:
        value = build(args.store, args.manifest_sha256, args.reviews, args.reviews_sha256, no_reviews=args.no_reviews)
        output = render(value) if args.format == 'html' else r.a.encoded(value).decode('ascii')
        print(output)
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        print('{"status":"rejected","acceptance_approved":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
