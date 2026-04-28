#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path('/workspace/SIMTester')
OUT = ROOT / 'python_rewrite'
SRC_DIRS = [ROOT / 'SIMLibrary' / 'src', ROOT / 'SIMTester' / 'src']

CLASS_RE = re.compile(r'\b(class|interface|enum)\s+(\w+)')
METHOD_RE = re.compile(r'\b(public|protected|private)\s+(?:static\s+)?(?:final\s+)?[\w\<\>\[\], ?]+\s+(\w+)\s*\(([^)]*)\)')


def ensure_package(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    cur = path
    while cur != OUT.parent and str(cur).startswith(str(OUT)):
        init = cur / '__init__.py'
        if not init.exists():
            init.write_text('')
        if cur == OUT:
            break
        cur = cur.parent


def java_params_to_py(param_str: str):
    param_str = param_str.strip()
    if not param_str:
        return ''
    out = []
    used = set()
    for i, raw in enumerate(param_str.split(','), start=1):
        p = raw.strip()
        if not p:
            continue
        name = p.split()[-1].replace('[]', '_arr')
        name = re.sub(r'[^a-zA-Z0-9_]', '', name)
        if not name:
            name = f'arg{i}'
        if name in {'class', 'def', 'return', 'from', 'import', 'pass', 'global', 'nonlocal'}:
            name = name + '_arg'
        base = name
        n = 2
        while name in used:
            name = f'{base}_{n}'
            n += 1
        used.add(name)
        out.append(name)
    return ', '.join(out)


def convert(java_file: Path):
    rel = java_file.relative_to(ROOT)
    text = java_file.read_text(errors='ignore')

    package_match = re.search(r'^\s*package\s+([\w\.]+);', text, re.MULTILINE)
    package = package_match.group(1) if package_match else ''

    classes = CLASS_RE.findall(text)
    methods = METHOD_RE.findall(text)

    if package:
        package_path = OUT / Path(package.replace('.', '/'))
    else:
        package_path = OUT
    ensure_package(package_path)

    out_file = package_path / f"{java_file.stem}.py"

    lines = []
    lines.append('"""Auto-generated Python skeleton from Java source.')
    lines.append(f'Original file: {rel}')
    lines.append('This is a mechanical baseline for a manual port."""')
    lines.append('')

    if not classes:
        lines.append('# No class/interface declarations detected; manual port required.')
    else:
        for kind, name in classes:
            py_kind = 'class'
            lines.append(f'{py_kind} {name}:')
            lines.append(f'    """Port target for Java {kind} `{name}`."""')

            own_methods = [m for m in methods if m[1] != name]
            emitted_any = False
            for _, mname, params in own_methods:
                if mname in {'if', 'for', 'while', 'switch', 'catch', 'return', 'new'}:
                    continue
                param_list = java_params_to_py(params)
                sig = 'self'
                if param_list:
                    sig += ', ' + param_list
                lines.append(f'    def {mname}({sig}):')
                lines.append('        raise NotImplementedError("Manual port required")')
                lines.append('')
                emitted_any = True
            if not emitted_any:
                lines.append('    pass')
                lines.append('')

    out_file.write_text('\n'.join(lines).rstrip() + '\n')


def main():
    OUT.mkdir(exist_ok=True)
    java_files = []
    for src in SRC_DIRS:
        java_files.extend(src.rglob('*.java'))
    for jf in sorted(java_files):
        convert(jf)

    manifest = OUT / 'MANIFEST.md'
    py_files = sorted([p.relative_to(OUT) for p in OUT.rglob('*.py')])
    manifest.write_text(
        '# Python Rewrite Manifest\n\n'
        f'Generated from {len(java_files)} Java files.\n\n'
        '## Generated modules\n' +
        '\n'.join(f'- `{p}`' for p in py_files) + '\n'
    )


if __name__ == '__main__':
    main()
