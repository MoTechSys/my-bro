"""Review-build regressions, not academic/visual approval. No renderer required in CI."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

from test_visibility_observer import ROOT, load

b = load('thesis_build_test', ROOT/'scripts/build_thesis.py')


class ThesisBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='.thesis-tests-')
        self.addCleanup(self.tmp.cleanup); self.base = Path(self.tmp.name)
        self.output = self.base/'output'; self.output.mkdir(mode=0o700)
        self.sources = {name: ('# الفصل ' + str(i) + '\n\nنص اختبار.\n').encode()
                        for i, name in enumerate(b.CHAPTERS, 1)}

    def docx(self, path, headings, *, notice=True, macro=False):
        ns = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
        doc = ET.Element('{' + ns + '}document'); body = ET.SubElement(doc, '{' + ns + '}body')
        for text in (['مسودة مراجعة'] if notice else []) + list(headings):
            p = ET.SubElement(body, '{' + ns + '}p'); run = ET.SubElement(p, '{' + ns + '}r')
            ET.SubElement(run, '{' + ns + '}t').text = text
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('word/document.xml', ET.tostring(doc, encoding='utf-8'))
            if macro: archive.writestr('word/vbaProject.bin', b'not allowed')

    def fake_tool(self, command, runtime, seconds=120):
        self.assertTrue(str(runtime).startswith(str(self.output)))
        if '--version' in command: return b'SYNTHETIC_TOOL_VERSION\n'
        if '-o' in command:
            headings = [(ROOT/'docs/thesis'/name).read_text().splitlines()[0][2:] for name in b.CHAPTERS]
            self.docx(Path(command[command.index('-o') + 1]), headings)
        else:
            (self.output/'thesis-review.pdf').write_bytes(b'%PDF-synthetic-not-a-real-document')
        return b''

    def test_fixed_chapters_order_hashes_and_review_notice(self):
        raw, manifest = b.assemble(self.sources)
        self.assertEqual(len(manifest['headings']), 5)
        self.assertIn('ليست النسخة الجامعية النهائية', raw.decode())
        self.assertFalse(manifest['acceptance_approved']); self.assertFalse(manifest['human_review_complete'])
        self.assertEqual(manifest['source_sha256'][b.CHAPTERS[0]], b.r.digest(self.sources[b.CHAPTERS[0]]))
        self.assertLess(raw.index('الفصل 1'.encode()), raw.index('الفصل 5'.encode()))

    def test_missing_and_extra_chapters_refused(self):
        for sources in ({}, dict(self.sources, extra=b'# wrong')):
            with self.assertRaises(ValueError): b.assemble(sources)

    def test_embedded_resources_invalid_utf8_and_damage_refused(self):
        for text in ('# title\n![x](https://example.invalid/x.png)', '# title\n<img src="file:///etc/passwd">',
                     '# title\n<iframe src="x">', '# title\n\ufffd', '# title\n\x00', '# title\n```unclosed'):
            sources = dict(self.sources); sources[b.CHAPTERS[0]] = text.encode()
            with self.subTest(text=text), self.assertRaises(ValueError): b.assemble(sources)
        sources = dict(self.sources); sources[b.CHAPTERS[0]] = b'\xff'
        with self.assertRaises(UnicodeError): b.assemble(sources)

    def test_mermaid_is_counted_and_never_claimed_rendered(self):
        sources = dict(self.sources); sources[b.CHAPTERS[0]] += b'```mermaid\ngraph LR\n A --> B\n```\n'
        raw, manifest = b.assemble(sources)
        self.assertIn(b'graph LR', raw)
        self.assertEqual(len(manifest['diagrams']), 1)
        self.assertFalse(manifest['diagrams'][0]['rendered'])

    def test_assembly_is_byte_repeatable(self):
        self.assertEqual(b.assemble(self.sources), b.assemble(self.sources))

    def test_docx_requires_notice_and_all_headings(self):
        path = self.base/'test.docx'
        self.docx(path, ['one', 'two'])
        self.assertEqual(b.check_docx(path, ['one', 'two'])['headings_verified'], 2)
        with self.assertRaisesRegex(ValueError, 'HEADINGS'): b.check_docx(path, ['missing'])
        self.docx(path, ['one'], notice=False)
        with self.assertRaises(ValueError): b.check_docx(path, ['one'])

    def test_docx_macro_refused(self):
        path = self.base/'test.docx'; self.docx(path, ['one'], macro=True)
        with self.assertRaisesRegex(ValueError, 'MACRO'): b.check_docx(path, ['one'])

    def test_review_build_receipts_and_permissions(self):
        with patch.object(b.shutil, 'which', return_value='/synthetic/tool'), patch.object(b, 'run_tool', side_effect=self.fake_tool):
            result = b.build(self.output, pdf=True)
        self.assertEqual(result['status'], 'review_build_complete')
        self.assertEqual(len(result['outputs']), 3)
        for name, receipt in result['outputs'].items():
            path = self.output/name
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(b.r.digest(path.read_bytes()), receipt['sha256'])
        self.assertFalse(result['university_template_approved'])
        self.assertFalse(result['docx_check']['visual_review_complete'])

    def test_tool_failure_keeps_failed_build_receipt(self):
        with patch.object(b.shutil, 'which', return_value='/synthetic/tool'), \
             patch.object(b, 'run_tool', side_effect=ValueError('private-detail')):
            with self.assertRaises(ValueError): b.build(self.output)
        result = json.loads((self.output/'build-result.json').read_bytes())
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('private-detail', (self.output/'build-result.json').read_text())
        self.assertTrue((self.output/'build-intent.json').exists())

    def test_never_overwrites_previous_build(self):
        (self.output/'existing').write_bytes(b'keep')
        with patch.object(b.shutil, 'which', return_value='/synthetic/tool'), self.assertRaises(ValueError): b.build(self.output)
        self.assertEqual((self.output/'existing').read_bytes(), b'keep')

    def test_missing_tools_do_not_create_partial_build(self):
        with patch.object(b.shutil, 'which', return_value=None), self.assertRaises(ValueError): b.build(self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_bounded_tool_env_uses_private_runtime(self):
        with patch.object(b.shutil, 'which', return_value='/usr/bin/env'), \
             patch.object(b.r, 'bounded_process', return_value={'reason': 'OK', 'output': b'ok'}) as call:
            self.assertEqual(b.run_tool(['/bin/tool', '--version'], self.base), b'ok')
        argv, timeout = call.call_args.args
        self.assertIn('HOME=' + str(self.base), argv)
        self.assertIn('TMPDIR=' + str(self.base), argv)
        self.assertEqual(timeout, 120)

    def test_concurrent_build_is_refused(self):
        with b.r.store_lock(self.output), patch.object(b.shutil, 'which', return_value='/synthetic/tool'):
            with self.assertRaises(BlockingIOError): b.build(self.output)


if __name__ == '__main__': unittest.main()
