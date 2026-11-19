#!/usr/bin/env python3
"""Переводы TwoKey: какие строки интерфейса нужно перевести и всё ли переведено.

  python tools/i18n.py extract   русские строки (ключи i18n.json) → stdout, JSON
  python tools/i18n.py check     у каждого языка в i18n.json есть все строки и те же {плейсхолдеры}; иначе код 1
"""
import ast, html.parser, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import guardian as g  # noqa: E402

CYR = re.compile(r"[А-Яа-яЁё]")


def strings():
    found = set()

    def add(s):
        if isinstance(s, str) and CYR.search(s) and s.strip():
            found.add(s.strip())

    tree = ast.parse(open(os.path.join(ROOT, "guardian.py"), encoding="utf-8").read())
    for node in ast.walk(tree):  # аргументы tr(...) и ValueError(...): соседние литералы парсер уже склеил
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            if getattr(node.func, "id", getattr(node.func, "attr", "")) in ("tr", "ValueError"):
                add(node.args[0].value)
    for _, _, _, _, why, fix in g.BUILTIN:
        add(why), add(fix)
    for s in g.RU + [v[1] for v in g.CHOICES.values()] + list(g.REASONS.values()) + [g.HELP, g.BOT_ABOUT, g.BOT_SHORT]:
        add(s)
    for _, d in g.BOT_COMMANDS:
        add(d)

    class Page(html.parser.HTMLParser):
        skip = 0

        def handle_starttag(self, tag, attrs):
            self.skip += tag in ("script", "style", "code", "pre")
            for k, v in attrs:
                if k in ("placeholder", "aria-label", "title"):
                    add(v)

        def handle_endtag(self, tag):
            self.skip -= tag in ("script", "style", "code", "pre")

        def handle_data(self, data):
            if not self.skip:
                add(data)

    page = open(os.path.join(ROOT, "ui.html"), encoding="utf-8").read()
    Page().feed(page)
    for m in re.finditer(r"'((?:[^'\\\n]|\\.)*)'|\"((?:[^\"\\\n]|\\.)*)\"|`([^`$\n]*)`", page[page.index("<script nonce"):]):
        add(next(x for x in m.groups() if x is not None))
    return sorted(found)


def check():
    need, bad = strings(), 0
    for lang, table in sorted(g.I18N.items()):
        missing = [s for s in need if s not in table]
        broken = [s for s in need if s in table and sorted(re.findall(r"\{\w+\}", s)) != sorted(re.findall(r"\{\w+\}", table[s]))]
        print(f"{lang}: {len(need) - len(missing)}/{len(need)} строк, без перевода: {len(missing)}, с битыми {{плейсхолдерами}}: {len(broken)}")
        for s in (missing + broken)[:20]:
            print("   ", s[:100].replace("\n", " "))
        bad += len(missing) + len(broken)
    return bad == 0 and set(g.I18N) >= {"en", "kk"}


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    if sys.argv[1:] == ["extract"]:
        print(json.dumps(strings(), ensure_ascii=False, indent=1))
    elif sys.argv[1:] == ["check"]:
        sys.exit(0 if check() else 1)
    else:
        print(__doc__)
