"""Inventory: function names that exist in two or more of desktop/web/phone/server."""
import re, subprocess, collections, os, sys

ROOT = sys.argv[1]
files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()

def side(f):
    if f.startswith("src/sezam/") and f.endswith(".py") and "/gui/" not in f and "/mcp/" not in f and "/i18n/" not in f:
        return "py"
    if f.startswith("web/static/js/") and f.endswith(".js") and "vendor" not in f and "i18n" not in f:
        return "js"
    if f.startswith("mobile/lib/") and f.endswith(".dart") and "/screens/" not in f and "/widgets/" not in f and "l10n" not in f:
        return "dart"
    if f.startswith("server/app/") and f.endswith(".py"):
        return "srv"
    return None

PAT = {
    "py": re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M),
    "srv": re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M),
    "js": re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{\s*$|const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\()", re.M),
    "dart": re.compile(r"^\s*(?:static\s+)?(?:Future<[^>]*>|[A-Za-z_<>?,\[\] ]+)\s+([a-z_][A-Za-z0-9_]*)\s*\([^;{]*\)\s*(?:async\s*)?\{", re.M),
}
KW = {"if", "for", "while", "switch", "catch", "return", "function", "constructor", "main", "build", "toString", "dispose", "initState"}

def norm(n):
    return n.lstrip("_$").replace("_", "").lower()

where = collections.defaultdict(lambda: collections.defaultdict(set))
for f in files:
    s = side(f)
    if not s:
        continue
    try:
        txt = open(os.path.join(ROOT, f), encoding="utf-8").read()
    except Exception:
        continue
    for m in PAT[s].finditer(txt):
        n = next(g for g in m.groups() if g)
        if n in KW or len(n) < 5:
            continue
        where[norm(n)][s].add(f.split("/")[-1])

multi = {k: v for k, v in where.items() if len(v) >= 2}
bymod = collections.Counter()
for k, v in sorted(multi.items(), key=lambda kv: (-len(kv[1]), kv[0])):
    sides = ",".join(sorted(v))
    files_ = "; ".join(f"{s}:{'/'.join(sorted(fs))}" for s, fs in sorted(v.items()))
    print(f"{len(v)} {k:40s} {files_}")
    for s, fs in v.items():
        for fn in fs:
            bymod[(s, fn)] += 1
print("\n== modules by count of shared names ==")
for (s, fn), c in bymod.most_common(60):
    print(f"{c:4d} {s:5s} {fn}")
print("\nTOTAL shared names:", len(multi), " in all 3 clients:", sum(1 for v in multi.values() if {'py','js','dart'} <= set(v)))
