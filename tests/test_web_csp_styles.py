"""Idea #6: the web UI renders under its own Content-Security-Policy.

style-src has no 'unsafe-inline', so a style="..." attribute or a <style>
block in markup (templates, HTML built in JS, the print window, which
inherits the page's policy) is dropped by the browser. The share page's
policy is default-src 'self', so app.css must not pull fonts from another
origin. Styles set through CSSOM (element.style) are allowed and not checked.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKUP_SOURCES = [
    *sorted((ROOT / "web" / "templates").glob("*.html")),
    *sorted(p for p in (ROOT / "web" / "static" / "js").glob("*.js")),
]
INLINE_STYLE = re.compile(r"""\sstyle\s*=\s*["'$]|<style[\s>]""", re.IGNORECASE)
EXTERNAL_URL = re.compile(r"https?://", re.IGNORECASE)


def test_no_inline_style_in_markup():
    found = []
    for path in MARKUP_SOURCES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if INLINE_STYLE.search(line):
                found.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:90]}")
    assert found == []


def test_share_page_loads_nothing_from_another_origin():
    css = (ROOT / "web" / "static" / "css" / "app.css").read_text(encoding="utf-8")
    assert not re.search(r"@import", css)
    assert not re.search(r"""url\(\s*["']?https?://""", css, re.IGNORECASE)
    share = (ROOT / "web" / "templates" / "share.html").read_text(encoding="utf-8")
    hrefs = re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)""", share)
    assert hrefs and not [h for h in hrefs if EXTERNAL_URL.match(h)]
