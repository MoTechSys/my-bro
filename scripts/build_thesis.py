#!/usr/bin/env python3
"""Repeatable, traceable thesis REVIEW build, not university/native acceptance.

Fixed repository chapters only. No remote images, filters, macros, model calls or
package installation. Pandoc required; LibreOffice optional via --pdf. Draft
Mermaid source remains visible until figures are independently rendered/reviewed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('_thesis_storage', ROOT/'ai_agent/runner.py')
r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r)
CHAPTERS = ('ch1_introduction.md', 'ch2_literature_review.md', 'ch3_methodology.md',
            'ch4_implementation.md', 'ch5_results_conclusion.md')
NOTICE = ('# مسودة مراجعة — ليست النسخة الجامعية النهائية\n\n'
          'الفصول التالية مسودات، وليست شهادة قبول للمعمل أو نتائج قياس أصلية. '
          'لم تعتمد بيانات الغلاف أو قالب الجامعة أو المراجع أو الرسوم نهائياً. '
          'مخططات Mermaid تبقى نصوصاً مصدرية في هذه النسخة، ولا تعد رسوماً مصيّرة.\n\n')


def require(condition, code):
    if not condition: raise ValueError(code)


def assemble(sources):
    require(set(sources) == set(CHAPTERS), 'FIVE_CHAPTERS_REQUIRED')
    chunks, hashes, diagrams, headings = [NOTICE], {}, [], []
    for name in CHAPTERS:
        raw = sources[name]
        require(isinstance(raw, bytes) and len(raw) <= 1024 * 1024, 'CHAPTER_SIZE')
        text = raw.decode('utf-8')
        require('\ufffd' not in text and '\x00' not in text, 'DAMAGED_SOURCE_TEXT')
        require(text.startswith('# '), 'CHAPTER_HEADING_REQUIRED')
        # Reject all Markdown images/HTML media, even local paths, rather than
        # let Pandoc fetch resources implicitly. Raw HTML/TeX are disabled below.
        require(not re.search(r'!\[|<(?:img|iframe|object|embed|script)\b', text, re.I), 'EMBEDDED_RESOURCE_REFUSED')
        require(text.count('```') % 2 == 0, 'UNBALANCED_FENCE')
        headings.append(text.splitlines()[0][2:])
        hashes[name] = hashlib.sha256(raw).hexdigest()
        for i, block in enumerate(re.findall(r'^```mermaid\s*\n(.*?)^```\s*$', text, re.M | re.S)):
            diagrams.append({'chapter': name, 'index': i + 1, 'sha256': r.digest(block.encode('utf-8')),
                             'rendered': False})
        chunks.append(text.rstrip() + '\n\n')
    return ''.join(chunks).encode('utf-8'), {'source_sha256': hashes, 'headings': headings, 'diagrams': diagrams,
        'acceptance_approved': False, 'university_template_approved': False, 'human_review_complete': False}


def check_docx(path, headings):
    with zipfile.ZipFile(path) as archive:
        require('word/document.xml' in archive.namelist(), 'DOCX_DOCUMENT_MISSING')
        require(all(not name.endswith('vbaProject.bin') for name in archive.namelist()), 'DOCX_MACRO_REFUSED')
        info = archive.getinfo('word/document.xml')
        require(info.file_size <= 16 * 1024 * 1024, 'DOCX_XML_LIMIT')
        xml = ET.fromstring(archive.read(info))
        ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
        text = ''.join(node.text or '' for node in xml.findall('.//w:t', ns))
        require('مسودة مراجعة' in text and all(h in text for h in headings), 'DOCX_HEADINGS_MISSING')
        return {'headings_verified': len(headings), 'has_bidi_markup': bool(xml.findall('.//w:bidi', ns)),
                'visual_review_complete': False}


def run_tool(command, runtime, seconds=120):
    env = shutil.which('env')
    require(env is not None, 'ENV_TOOL_REQUIRED')
    result = r.bounded_process([env, 'HOME=' + str(runtime), 'TMPDIR=' + str(runtime),
        'XDG_CACHE_HOME=' + str(runtime/'cache'), 'XDG_CONFIG_HOME=' + str(runtime/'config'), *command], seconds)
    require(result['reason'] == 'OK', 'DOCUMENT_TOOL_FAILED')
    return result['output']


def build(output, *, pdf=False):
    pandoc = shutil.which('pandoc'); office = shutil.which('libreoffice') if pdf else None
    require(pandoc is not None and (not pdf or office is not None), 'DOCUMENT_TOOLS_REQUIRED')
    output = Path(os.path.abspath(output))
    sources = {name: (ROOT/'docs/thesis'/name).read_bytes() for name in CHAPTERS}
    combined, manifest = assemble(sources)
    manifest.update(schema_version=1, build_script_sha256=r.digest(Path(__file__).read_bytes()),
                    storage_source_sha256={name: r.digest((ROOT/'ai_agent'/name).read_bytes()) for name in r.SOURCE_NAMES},
                    status='incomplete', reproducibility='fixed inputs and recorded tools; not bit-identical DOCX/PDF')
    with r.store_lock(output) as fd:
        require(not os.listdir(fd), 'NEW_EMPTY_BUILD_DIRECTORY_REQUIRED')
        r.write_once(fd, 'build-intent.json', r.json_bytes(manifest))
        r.write_once(fd, 'thesis-review.md', combined)
        runtime = output/'runtime'; runtime.mkdir(mode=0o700)
        previous = os.umask(0o077)
        try:
            manifest['pandoc_version'] = run_tool([pandoc, '--version'], runtime).decode('utf-8').splitlines()[0]
            docx = output/'thesis-review.docx'
            # Only the fixed, prechecked repository text is processed. No filters,
            # citeproc, remote resources or arbitrary input paths are accepted.
            run_tool([pandoc, str(output/'thesis-review.md'), '-f', 'markdown-raw_html-raw_tex',
                      '-t', 'docx', '--standalone', '--metadata=lang:ar', '--metadata=dir:rtl',
                      '--resource-path=' + str(runtime), '-o', str(docx)], runtime)
            manifest['docx_check'] = check_docx(docx, manifest['headings'])
            artifacts = ['thesis-review.md', 'thesis-review.docx']
            if pdf:
                manifest['libreoffice_version'] = run_tool([office, '--version'], runtime).decode('utf-8').strip()
                run_tool([office, '-env:UserInstallation=' + (runtime/'profile').as_uri(), '--headless',
                          '--convert-to', 'pdf', '--outdir', str(output), str(docx)], runtime)
                document = output/'thesis-review.pdf'
                require(document.is_file() and document.read_bytes().startswith(b'%PDF-'), 'PDF_MISSING_OR_INVALID')
                artifacts.append(document.name)
            manifest['outputs'] = {}
            for name in artifacts:
                path = output/name; path.chmod(0o600)
                raw = path.read_bytes()
                require(len(raw) <= 32 * 1024 * 1024, 'DOCUMENT_OUTPUT_LIMIT')
                with path.open('rb') as stream: os.fsync(stream.fileno())
                manifest['outputs'][name] = {'sha256': r.digest(raw), 'bytes': len(raw)}
            manifest['status'] = 'review_build_complete'
        except Exception:
            manifest['status'] = 'failed'
            manifest['failure'] = 'BUILD_OR_VALIDATION_FAILED'
            raise
        finally:
            os.umask(previous)
            r.write_once(fd, 'build-result.json', r.json_bytes(manifest))
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, help='existing private empty directory, outside Git evidence')
    parser.add_argument('--pdf', action='store_true', help='also use installed LibreOffice; no installation or downloads')
    args = parser.parse_args(argv)
    try:
        result = build(args.output_dir, pdf=args.pdf)
        print(json.dumps({'status': result['status'], 'acceptance_approved': False,
                          'unrendered_diagrams': len(result['diagrams']), 'outputs': result['outputs']}))
        return 0
    except Exception:
        print('{"status":"failed","acceptance_approved":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
