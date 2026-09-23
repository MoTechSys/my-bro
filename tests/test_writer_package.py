"""Writer package regressions: synthetic geometry / repository contracts, not SOC results."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('writer_build', ROOT/'scripts/build_writer_package.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class WriterPackageTests(unittest.TestCase):
    def setUp(self):
        self.diagrams = w.catalog()
        self.graph = copy.deepcopy(self.diagrams[0])
        self.seq = copy.deepcopy(next(s for s in self.diagrams if s['kind'] == 'sequence'))

    def test_all_derivatives_match_catalog(self):
        self.assertEqual(len(self.diagrams), 15)
        self.assertEqual(len(w.check()), 31)

    def test_render_repeatable_and_accessible(self):
        for s in self.diagrams:
            with self.subTest(id=s['id']):
                self.assertEqual(w.render(s), w.render(copy.deepcopy(s)))
                svg = ET.fromstring(w.render(s))
                self.assertEqual(svg.attrib['role'], 'img')
                self.assertEqual(svg.find('{'+w.SVG+'}title').text, s['title'])
                self.assertIn(s['caption_ar'], svg.find('{'+w.SVG+'}desc').text)

    def test_svg_elements_attributes_and_urls_are_passive(self):
        allowed = {'svg', 'title', 'desc', 'rect', 'text', 'defs', 'marker', 'path', 'polyline', 'line'}
        for s in self.diagrams:
            for node in ET.fromstring(w.render(s)).iter():
                self.assertIn(node.tag.split('}')[-1], allowed)
                for key, value in node.attrib.items():
                    self.assertFalse(key.lower().startswith('on'))
                    self.assertNotIn('href', key)
                    if 'url(' in value:
                        self.assertEqual(value, 'url(#arrow)')

    def test_xml_text_is_escaped_not_executed(self):
        self.graph['nodes'][0]['lines'] = ['<script>&"test"']
        raw = w.render(self.graph)
        self.assertIn(b'&lt;script&gt;', raw)
        self.assertNotIn(b'<script>', raw)
        self.assertEqual(len(ET.fromstring(raw).findall('.//{'+w.SVG+'}script')), 0)

    def test_unknown_schema_fields_rejected(self):
        self.graph['remote_font'] = 'https://example.invalid/font'
        with self.assertRaisesRegex(ValueError, 'diagram fields'):
            w.validate(self.graph)

    def test_duplicate_identifiers_rejected(self):
        self.graph['nodes'][1]['id'] = self.graph['nodes'][0]['id']
        with self.assertRaisesRegex(ValueError, 'duplicate node'):
            w.validate(self.graph)

    def test_overlong_and_control_text_rejected(self):
        for line in ['x'*30, 'bad\nline', '\x00']:
            s = copy.deepcopy(self.graph); s['nodes'][0]['lines'] = [line]
            with self.subTest(line=repr(line)), self.assertRaises(ValueError):
                w.validate(s)

    def test_node_overlap_rejected(self):
        self.graph['nodes'][1]['y'] = self.graph['nodes'][0]['y']+50
        with self.assertRaisesRegex(ValueError, 'node overlap'):
            w.validate(self.graph)

    def test_out_of_bounds_and_boolean_geometry_rejected(self):
        for value in [-1, 1200, True, 0.5]:
            s = copy.deepcopy(self.graph); s['nodes'][0]['x'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'coordinate bounds'):
                w.validate(s)

    def test_edge_label_clipping_rejected(self):
        self.graph['edges'][0]['label_at'][0] = 15
        with self.assertRaisesRegex(ValueError, 'edge label outside canvas'):
            w.validate(self.graph)

    def test_edge_label_on_node_rejected(self):
        self.graph['edges'][0]['label_at'] = [580, 210]
        with self.assertRaisesRegex(ValueError, 'edge label overlaps node'):
            w.validate(self.graph)

    def test_missing_endpoint_rejected(self):
        self.graph['edges'][0]['to'] = 'missing'
        with self.assertRaisesRegex(ValueError, 'edge endpoint'):
            w.validate(self.graph)

    def test_detached_or_diagonal_edge_rejected(self):
        for points in [[[580,270],[590,350]], [[581,269],[580,350]]]:
            s = copy.deepcopy(self.graph); s['edges'][0]['points'] = points
            with self.subTest(points=points), self.assertRaises(ValueError):
                w.validate(s)

    def test_edge_crossing_node_rejected(self):
        s = copy.deepcopy(self.graph)
        s['edges'][0].update({'to': 'n2', 'points': [[580,270],[580,530]]})
        with self.assertRaisesRegex(ValueError, 'edge crosses node'):
            w.validate(s)

    def test_sequence_unknown_participant_rejected(self):
        self.seq['messages'][0]['from'] = 'unknown'
        with self.assertRaisesRegex(ValueError, 'message endpoint'):
            w.validate(self.seq)

    def test_sequence_duplicate_participant_rejected(self):
        self.seq['participants'][1]['id'] = self.seq['participants'][0]['id']
        with self.assertRaisesRegex(ValueError, 'duplicate participant'):
            w.validate(self.seq)

    def test_source_paths_confined_and_links_refused(self):
        for path in ['../README.md', '/etc/passwd', '.git/config', 'build/private.json', 'docs//x']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                w.source_file(path)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory); (base/'a').write_text('data'); (base/'link').symlink_to(base/'a')
            with self.assertRaisesRegex(ValueError, 'source file'):
                w.source_file('link', base)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            json.loads('{"id":1,"id":2}', object_pairs_hook=w.strict_pairs)

    def test_chapter_blocks_match_first_eight_diagrams(self):
        chapter = (ROOT/'docs/thesis/ch3_methodology.md').read_text()
        blocks = re.findall(r'```mermaid\n(.*?)```', chapter, flags=re.S)
        self.assertEqual(len(blocks), 8)
        self.assertEqual(blocks, [w.mermaid(s).decode() for s in self.diagrams[:8]])
        for s in self.diagrams[:8]:
            self.assertIn('figures/'+s['id']+'.svg', chapter)

    def test_explicit_semantic_guardrails(self):
        by_id = {s['id']: s for s in self.diagrams}
        vt = w.mermaid(by_id['fig06_vt_sequence']).decode()
        yara = w.mermaid(by_id['fig07_yara_sequence']).decode()
        self.assertIn('check_keys', vt); self.assertIn('MD5', vt); self.assertIn('os.unlink', vt)
        self.assertNotIn('rm -f', vt)
        self.assertIn('yara -w -a 10 -l 100 RULES /proc/self/fd/FD', yara)
        self.assertNotIn('yara -w -r', yara)
        architecture = by_id['fig02_architecture']
        self.assertFalse(any(e['from'] == 'advisory' and e['to'] == 'ar' for e in architecture['edges']))
        self.assertIn('HISTORICAL', by_id['fig08_topology']['status'])
        self.assertEqual(by_id['fig15_timeline']['edges'], [])
        self.assertTrue(all(e['direction'] == 'none' for e in by_id['fig12_c4_model']['edges']))

    def test_render_requires_no_process_or_network(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no renderer process')):
            self.assertEqual(len(w.generated()), 31)

    def test_stale_artifact_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            (base/'x.svg').write_bytes(b'old')
            with patch.object(w, 'FIGURES', base), patch.object(w, 'generated', return_value={'x.svg': b'new'}):
                with self.assertRaisesRegex(ValueError, 'stale figure'):
                    w.check()

    def test_bundle_receipt_covers_content_and_no_private_trees(self):
        files = w.bundle_files(); receipt = json.loads(files['MANIFEST.json'])
        self.assertFalse(receipt['acceptance_approved']); self.assertFalse(receipt['native_results_included'])
        for name, data in files.items():
            self.assertFalse(set(Path(name).parts) & {'.git', 'build', 'runtime', '__pycache__'})
            self.assertFalse(name.endswith(('.docx', '.pdf', '.key')))
            if name not in ('MANIFEST.json', 'START_HERE.md'):
                self.assertEqual(receipt['files'][name], {'bytes': len(data), 'sha256': w.digest(data)})
        self.assertIn('docs/thesis/thesis_writer_draft.md', files)
        self.assertEqual(sum(n.endswith('.svg') for n in files), 15)

    def test_combined_draft_preserves_order_and_notices(self):
        files = w.bundle_files(); draft = files['docs/thesis/thesis_writer_draft.md'].decode()
        positions = [draft.index(files['docs/thesis/'+name].decode().strip()) for name in w.CHAPTERS]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('ليست نتائج', draft)

    def test_archive_repeatable_private_and_no_overwrite(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            a,b = Path(directory)/'a.zip',Path(directory)/'b.zip'
            first,second = w.package(a), w.package(b)
            self.assertEqual(first['sha256'], second['sha256'])
            self.assertEqual(stat.S_IMODE(a.stat().st_mode), 0o600)
            original = a.read_bytes()
            with self.assertRaises(FileExistsError):
                w.package(a)
            self.assertEqual(a.read_bytes(), original)
            with zipfile.ZipFile(a) as z:
                self.assertIsNone(z.testzip())
                self.assertEqual(len(z.namelist()), first['files'])

    def test_archive_outside_workspace_and_symlink_refused(self):
        with self.assertRaisesRegex(ValueError, 'workspace output required'):
            w.package('/tmp/forbidden.zip')
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory); target=base/'original'; target.write_bytes(b'original')
            (base/'link.zip').symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'new zip required'):
                w.package(base/'link.zip')
            self.assertEqual(target.read_bytes(), b'original')

    def test_catalog_read_uses_source_guard(self):
        with patch.object(w, 'source_file', side_effect=ValueError('source file')) as guard:
            with self.assertRaisesRegex(ValueError, 'source file'):
                w.catalog()
            guard.assert_called_once_with('docs/thesis/figures/catalog.json')

    def test_catalog_change_during_bundle_is_rejected(self):
        original = Path.read_bytes
        reads = 0
        def changed(path):
            nonlocal reads
            raw = original(path)
            if path == w.FIGURES/'catalog.json':
                reads += 1
                if reads > 1:
                    return raw + b'\n'
            return raw
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'catalog changed'):
                w.bundle_files()

    def test_mermaid_delimiters_rejected_and_entities_encoded(self):
        for delimiter in '|\\[]{}#`':
            s = copy.deepcopy(self.graph); s['nodes'][0]['lines'] = ['test'+delimiter]
            with self.subTest(delimiter=delimiter), self.assertRaisesRegex(ValueError, 'Mermaid delimiter'):
                w.validate(s)
        self.graph['nodes'][0]['lines'] = ['a;b < c & d']
        self.assertIn(b'a#59;b #60; c #38; d', w.mermaid(self.graph))

    def test_render_staging_failure_preserves_old_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory); (base/'a.svg').write_bytes(b'old')
            with patch.object(w, 'FIGURES', base), patch.object(w, 'generated', return_value={'a.svg': b'new'}), \
                    patch.object(w.os, 'fsync', side_effect=OSError('staging fault')):
                with self.assertRaisesRegex(OSError, 'staging fault'):
                    w.render_all()
            self.assertEqual((base/'a.svg').read_bytes(), b'old')

    def test_render_partial_group_rejected_not_truncated(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            for name in ('a.svg', 'b.svg'):
                (base/name).write_bytes(b'old')
            replace = w.os.replace; calls = 0
            def fail_second(src, dst):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError('publish fault')
                return replace(src, dst)
            outputs = {'a.svg': b'complete new a', 'b.svg': b'complete new b'}
            with patch.object(w, 'FIGURES', base), patch.object(w, 'generated', return_value=outputs):
                with patch.object(w.os, 'replace', fail_second), self.assertRaisesRegex(OSError, 'publish fault'):
                    w.render_all()
                self.assertEqual((base/'a.svg').read_bytes(), b'complete new a')
                self.assertEqual((base/'b.svg').read_bytes(), b'old')
                with self.assertRaisesRegex(ValueError, 'stale figure'):
                    w.check()

    def test_zip_write_failure_has_no_final_name(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory)/'new.zip'
            with patch.object(zipfile.ZipFile, 'writestr', side_effect=OSError('write fault')):
                with self.assertRaisesRegex(OSError, 'write fault'):
                    w.package(out)
            self.assertFalse(out.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_zip_fsync_failure_before_publication_has_no_final_name(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory)/'new.zip'
            with patch.object(w.os, 'fsync', side_effect=OSError('sync fault')):
                with self.assertRaisesRegex(OSError, 'sync fault'):
                    w.package(out)
            self.assertFalse(out.exists())

    def test_zip_namespace_sync_failure_keeps_complete_archive(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory)/'new.zip'; real = w.os.fsync
            def fail_directory(fd):
                if stat.S_ISDIR(w.os.fstat(fd).st_mode):
                    raise OSError('directory sync fault')
                return real(fd)
            with patch.object(w.os, 'fsync', fail_directory), self.assertRaisesRegex(OSError, 'directory sync fault'):
                w.package(out)
            with zipfile.ZipFile(out) as z:
                self.assertIsNone(z.testzip())
            self.assertEqual(list(Path(directory).iterdir()), [out])

    def test_core_writer_links_resolve_inside_bundle(self):
        import posixpath
        files = w.bundle_files()
        names = ['START_HERE.md', 'docs/thesis/WRITER_HANDOFF.md', 'docs/thesis/figures/INDEX.md']
        names += ['docs/thesis/'+c for c in w.CHAPTERS]
        for name in names:
            for link in re.findall(r'\]\(([^)]+)\)', files[name].decode()):
                if link.startswith(('https:', 'http:', '#')):
                    continue
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), link.split('#')[0]))
                self.assertIn(target, files, (name, link))

    def test_real_check_cli(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT/'scripts/build_writer_package.py'), '--check'],
                                cwd=ROOT, capture_output=True, timeout=20, check=True)
        self.assertEqual(json.loads(result.stdout)['verified_files'], 31)


if __name__ == '__main__':
    unittest.main()
