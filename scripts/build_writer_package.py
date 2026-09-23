#!/usr/bin/env python3
"""Offline Markdown/SVG writer package. Trusted repository inputs, not lab evidence.

JSON is the editable diagram source. SVG and Mermaid are deterministic derivatives.
No renderer install, JavaScript, remote assets, fonts or document converters.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / 'docs/thesis/figures'
CHAPTERS = ('ch1_introduction.md', 'ch2_literature_review.md', 'ch3_methodology.md',
            'ch4_implementation.md', 'ch5_results_conclusion.md')
SVG = 'http://www.w3.org/2000/svg'
COLORS = {'process': '#eaf3ff', 'store': '#e8f7ef', 'actor': '#fff4dc',
          'decision': '#fff0e9', 'pending': '#f3edf9'}
ET.register_namespace('', SVG)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def text(value, maximum=90):
    require(isinstance(value, str) and 0 < len(value) <= maximum, 'text length')
    require(all(ord(c) >= 32 and ord(c) != 127 for c in value), 'text control character')
    return value


def ident(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,59}', value), 'identifier')
    return value


def number(value, low, high):
    require(type(value) is int and low <= value <= high, 'coordinate bounds')


def source_file(name, root=ROOT):
    require(isinstance(name, str) and not name.startswith('/') and
            all(p not in ('', '.', '..', '.git', 'build') for p in name.split('/')), 'source path')
    path = root / name
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]), 'source file')
    return path


def validate(spec, root=ROOT):
    common = {'id', 'title', 'caption_ar', 'status', 'sources', 'kind'}
    fields = {'nodes', 'edges', 'height'} if spec.get('kind') == 'graph' else {'participants', 'messages'}
    require(set(spec) == common | fields, 'diagram fields')
    ident(spec['id']); text(spec['title'], 76); text(spec['caption_ar'], 1600); text(spec['status'], 110)
    require(isinstance(spec['sources'], list) and 1 <= len(spec['sources']) <= 12, 'source list')
    for name in spec['sources']:
        source_file(name, root)
    if spec['kind'] == 'graph':
        number(spec['height'], 400, 3000)
        require(isinstance(spec['nodes'], list) and 1 <= len(spec['nodes']) <= 30, 'node count')
        nodes = {}
        for node in spec['nodes']:
            require(set(node) == {'id', 'x', 'y', 'kind', 'lines'}, 'node fields')
            ident(node['id']); require(node['id'] not in nodes, 'duplicate node')
            number(node['x'], 30, 830); number(node['y'], 150, spec['height'] - 180)
            require(node['kind'] in COLORS, 'node kind')
            require(isinstance(node['lines'], list) and 1 <= len(node['lines']) <= 4, 'node lines')
            for line in node['lines']:
                text(line, 29)
            for other in nodes.values():
                require(abs(node['x']-other['x']) >= 310 or abs(node['y']-other['y']) >= 110, 'node overlap')
            nodes[node['id']] = node
        require(isinstance(spec['edges'], list) and len(spec['edges']) <= 50, 'edge count')
        for edge in spec['edges']:
            require(set(edge) == {'from', 'to', 'label', 'points', 'label_at', 'direction'}, 'edge fields')
            require(edge['from'] in nodes and edge['to'] in nodes, 'edge endpoint')
            text(edge['label'], 56)
            require(edge['direction'] in ('forward', 'both', 'none'), 'edge direction')
            require(isinstance(edge['points'], list) and 2 <= len(edge['points']) <= 8, 'edge points')
            for point in edge['points'] + [edge['label_at']]:
                require(isinstance(point, list) and len(point) == 2, 'point')
                number(point[0], 15, 1145); number(point[1], 140, spec['height'] - 65)
            for key, point in [('from', edge['points'][0]), ('to', edge['points'][-1])]:
                n = nodes[edge[key]]; x, y = point
                require(((x in (n['x'], n['x']+300) and n['y'] <= y <= n['y']+100) or
                         (y in (n['y'], n['y']+100) and n['x'] <= x <= n['x']+300)), 'edge attachment')
            for a, b in zip(edge['points'], edge['points'][1:]):
                require(a != b and (a[0] == b[0] or a[1] == b[1]), 'orthogonal segment required')
                for n in nodes.values():
                    x, y = n['x'], n['y']
                    crosses = ((a[0] == b[0] and x < a[0] < x+300 and max(min(a[1], b[1]), y) < min(max(a[1], b[1]), y+100)) or
                               (a[1] == b[1] and y < a[1] < y+100 and max(min(a[0], b[0]), x) < min(max(a[0], b[0]), x+300)))
                    require(not crosses, 'edge crosses node')
    else:
        require(spec['kind'] == 'sequence', 'diagram kind')
        require(isinstance(spec['participants'], list) and 2 <= len(spec['participants']) <= 6, 'participants')
        ids = set()
        for p in spec['participants']:
            require(set(p) == {'id', 'label'}, 'participant fields')
            ident(p['id']); text(p['label'], 20); require(p['id'] not in ids, 'duplicate participant'); ids.add(p['id'])
        require(isinstance(spec['messages'], list) and 1 <= len(spec['messages']) <= 25, 'message count')
        for msg in spec['messages']:
            require(set(msg) == {'from', 'to', 'label'}, 'message fields')
            require(msg['from'] in ids and msg['to'] in ids, 'message endpoint'); text(msg['label'], 90)
    return spec


def element(parent, tag, **attrs):
    return ET.SubElement(parent, '{' + SVG + '}' + tag, {k.replace('_', '-'): str(v) for k, v in attrs.items()})


def label(parent, x, y, value, size=16, anchor='middle', color='#19324b', **attrs):
    el = element(parent, 'text', x=x, y=y, font_size=size, text_anchor=anchor, fill=color, **attrs)
    el.text = value
    return el


def render(spec):
    validate(spec)
    height = spec['height'] if spec['kind'] == 'graph' else 280 + 88 * len(spec['messages'])
    svg = ET.Element('{' + SVG + '}svg', {'viewBox': f'0 0 1160 {height}', 'width': '1160',
                     'height': str(height), 'role': 'img', 'aria-labelledby': 'title description',
                     'font-family': 'DejaVu Sans Mono, monospace'})
    element(svg, 'title', id='title').text = spec['title']
    element(svg, 'desc', id='description').text = spec['caption_ar'] + ' ' + spec['status']
    element(svg, 'rect', width=1160, height=height, fill='#ffffff')
    element(svg, 'rect', width=1160, height=124, fill='#102b45')
    label(svg, 35, 43, spec['id'].upper(), 14, 'start', '#93d6dd')
    label(svg, 35, 76, spec['title'], 22, 'start', '#ffffff')
    label(svg, 35, 105, spec['status'], 14, 'start', '#dbe8f3')
    defs = element(svg, 'defs')
    marker = element(defs, 'marker', id='arrow', viewBox='0 0 10 10', refX=9, refY=5,
                     markerWidth=7, markerHeight=7, orient='auto-start-reverse')
    element(marker, 'path', d='M 0 0 L 10 5 L 0 10 z', fill='#366581')
    if spec['kind'] == 'graph':
        for edge in spec['edges']:
            element(svg, 'polyline', points=' '.join(f'{x},{y}' for x, y in edge['points']),
                    fill='none', stroke='#366581', stroke_width=2,
                    marker_end='url(#arrow)' if edge['direction'] != 'none' else 'none',
                    marker_start='url(#arrow)' if edge['direction'] == 'both' else 'none')
        for node in spec['nodes']:
            x, y = node['x'], node['y']
            element(svg, 'rect', x=x, y=y, width=300, height=100, rx=22 if node['kind'] == 'process' else 4,
                    fill=COLORS[node['kind']], stroke='#45657b', stroke_width=1.5)
            if node['kind'] == 'store':
                element(svg, 'path', d=f'M {x+8} {y+8} V {y+92} M {x+292} {y+8} V {y+92}',
                        fill='none', stroke='#45657b')
            label(svg, x+12, y+17, node['kind'].upper(), 10, 'start', '#476273')
            start = y + 42 - (len(node['lines'])-2)*8
            for i, line in enumerate(node['lines']):
                label(svg, x+150, start+i*20, line, 15)
        for edge in spec['edges']:
            x, y = edge['label_at']
            label(svg, x, y, edge['label'], 13, stroke='white', stroke_width=5, paint_order='stroke')
    else:
        count = len(spec['participants'])
        xs = {p['id']: 105 + i*950//(count-1) for i, p in enumerate(spec['participants'])}
        for p in spec['participants']:
            x = xs[p['id']]
            element(svg, 'rect', x=x-95, y=150, width=190, height=46, rx=6, fill='#eaf3ff', stroke='#45657b')
            label(svg, x, 179, p['label'], 14)
            element(svg, 'line', x1=x, x2=x, y1=196, y2=height-70, stroke='#91a6b5', stroke_dasharray='5 5')
        for i, msg in enumerate(spec['messages']):
            y = 240+i*88; a, b = xs[msg['from']], xs[msg['to']]
            # Separate full-width numbered message band avoids tiny labels on
            # short arrows and preserves readable left-to-right technical text.
            element(svg, 'rect', x=20, y=y-25, width=1120, height=28, fill='#f7fafc')
            label(svg, 580, y-6, f'{i+1:02d}. ' + msg['label'], 14)
            points = [(a, y+15), (b, y+15)] if a != b else [(a, y+10), (a+45, y+10), (a+45, y+34), (a, y+34)]
            element(svg, 'polyline', points=' '.join(f'{x},{z}' for x, z in points), fill='none',
                    stroke='#366581', stroke_width=2, marker_end='url(#arrow)')
    label(svg, 35, height-25, 'Code/design reference only | No native acceptance or measured results implied', 13, 'start', '#486172')
    return ET.tostring(svg, encoding='utf-8', xml_declaration=True) + b'\n'


def mermaid(spec):
    # Technical labels deliberately exclude Mermaid syntax. SVG supports escaped
    # XML text; Mermaid is a convenient derivative, not a second truth source.
    def safe(s):
        return s.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
    if spec['kind'] == 'graph':
        lines = ['flowchart TB']
        for n in spec['nodes']:
            lines.append(f'    {n["id"]}["{safe(" / ".join(n["lines"]))}"]')
        for e in spec['edges']:
            arrow = {'forward': '-->', 'both': '<-->', 'none': '---'}[e['direction']]
            lines.append(f'    {e["from"]} {arrow}|"{safe(e["label"])}"| {e["to"]}')
    else:
        lines = ['sequenceDiagram']
        lines += [f'    participant {p["id"]} as {safe(p["label"])}' for p in spec['participants']]
        lines += [f'    {m["from"]}->>{m["to"]}: {safe(m["label"])}' for m in spec['messages']]
    return ('\n'.join(lines) + '\n').encode()


def catalog():
    raw = (FIGURES / 'catalog.json').read_bytes()
    require(len(raw) <= 1024*1024, 'catalog size')
    data = json.loads(raw, object_pairs_hook=strict_pairs)
    require(set(data) == {'schema_version', 'diagrams'} and type(data['schema_version']) is int
            and data['schema_version'] == 1, 'catalog version')
    require(isinstance(data['diagrams'], list) and 1 <= len(data['diagrams']) <= 40, 'catalog count')
    specs = [validate(s) for s in data['diagrams']]
    require(len({s['id'] for s in specs}) == len(specs), 'duplicate diagram')
    return specs


def generated():
    outputs = {}
    index = ['# فهرس المخططات ومصادرها\n',
             'مولد من `catalog.json` بواسطة `scripts/build_writer_package.py`. المصادر القابلة للتحرير JSON، وMermaid مشتق للعلاقات لا لتطابق التخطيط.\n',
             'الأشكال تصميم/شرح للكود وليست لقطات تشغيل أو نتائج تجارب. النص التقني داخل SVG بالإنجليزية، والوصف العربي أسفل كل شكل.\n']
    for s in catalog():
        outputs[s['id']+'.svg'] = render(s)
        outputs[s['id']+'.mmd'] = mermaid(s)
        index += [f'## {s["id"]} — {s["title"]}\n', f'![{s["title"]}]({s["id"]}.svg)\n',
                  s['caption_ar']+'\n', '**الحالة:** '+s['status']+'\n',
                  f'[SVG]({s["id"]}.svg) · [Mermaid]({s["id"]}.mmd) · المصدر: كائن `{s["id"]}` في [catalog.json](catalog.json).\n',
                  '**المراجع داخل المستودع:** '+', '.join('`'+p+'`' for p in s['sources'])+'\n']
    outputs['INDEX.md'] = ('\n'.join(index)+'\n').encode()
    return outputs


def check():
    outputs = generated()
    for name, raw in outputs.items():
        path = FIGURES / name
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw, 'stale figure: '+name)
    actual = {p.name for p in FIGURES.iterdir() if p.suffix in ('.svg', '.mmd')}
    require(actual == {p for p in outputs if p.endswith(('.svg', '.mmd'))}, 'unexpected figure')
    return outputs


def bundle_files():
    outputs = check()
    paths = ['docs/thesis/'+c for c in CHAPTERS]
    paths += ['docs/thesis/WRITER_HANDOFF.md', 'docs/thesis/figures/catalog.json',
              'scripts/build_writer_package.py', 'tests/test_writer_package.py']
    # Explicit allowlist: never traverse the repository, .git, runtime or raw evidence.
    paths += ['docs/thesis/figures/'+name for name in outputs]
    for s in catalog():
        paths.extend(s['sources'])
    files = {p: source_file(p).read_bytes() for p in sorted(set(paths))}
    draft = ('# مسودة الكاتب المجمعة — ليست نتائج أو قبولاً نهائياً\n\n'
             'اقرأ [دليل الكاتب](WRITER_HANDOFF.md) و[فهرس الأشكال](figures/INDEX.md) أولاً.\n\n')
    for name in CHAPTERS:
        draft += files['docs/thesis/'+name].decode('utf-8').rstrip() + '\n\n'
    files['docs/thesis/thesis_writer_draft.md'] = draft.encode('utf-8')
    receipt = {'schema_version': 1, 'kind': 'markdown_svg_writer_handoff',
               'acceptance_approved': False, 'native_results_included': False,
               'files': {p: {'bytes': len(b), 'sha256': digest(b)} for p, b in files.items()}}
    files['MANIFEST.json'] = canonical(receipt)
    files['START_HERE.md'] = ('# حزمة كاتب المستندات\n\nابدأ بـ [دليل الكاتب](docs/thesis/WRITER_HANDOFF.md)، ثم [فهرس الأشكال](docs/thesis/figures/INDEX.md).\n\n'
                            'هذه حزمة Markdown + SVG ومصادر مختارة للتدقيق، لا نسخة تشغيل كاملة للمستودع ولا نتائج أصلية.\n').encode()
    return files


def package(output):
    output = Path(output).absolute()
    require(output.parent.resolve().is_relative_to(ROOT) and output.parent.is_dir(), 'workspace output required')
    require(output.suffix == '.zip' and not output.is_symlink(), 'new zip required')
    files = bundle_files()
    # Exclusive creation; partial output after I/O failure remains for inspection.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, raw in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(2026, 9, 23, 0, 0, 0))
                info.create_system = 3; info.external_attr = 0o100600 << 16
                archive.writestr(info, raw)
        stream.flush(); os.fsync(stream.fileno())
    return {'path': str(output), 'sha256': digest(output.read_bytes()), 'files': len(files)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--render', action='store_true', help='refresh tracked SVG/Mermaid/index from trusted JSON')
    group.add_argument('--check', action='store_true', help='fail if any generated figure is stale')
    group.add_argument('--package', metavar='NEW_ZIP', help='exclusive allowlisted Markdown/SVG writer archive')
    args = parser.parse_args(argv)
    try:
        if args.render:
            outputs = generated()
            for name, raw in outputs.items():
                path = FIGURES / name
                require(not path.is_symlink(), 'symlink output')
                path.write_bytes(raw)
            print(json.dumps({'rendered_diagrams': len(catalog())}))
        elif args.check:
            print(json.dumps({'verified_files': len(check()), 'acceptance_approved': False}))
        else:
            print(json.dumps(package(args.package)))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Writer build failed: '+str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
