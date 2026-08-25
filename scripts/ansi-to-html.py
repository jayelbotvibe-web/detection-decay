#!/usr/bin/env python3
"""Render ANSI terminal output to a standalone HTML page for screenshotting.

Used to regenerate screenshots/decay-cli.webp so the README never drifts from
what the tool actually prints. See the "generated artifacts" note in CLAUDE.md
for the full pipeline.

    ./decay score --evidence evidence.json | python3 scripts/ansi-to-html.py > cli.html

Renders at 2x and expects to be downsampled: box-drawing characters do not tile
cleanly at small sizes, and the horizontal rules come out dashed.

Only the codes cmd/decay/main.go actually emits are handled; anything else is
dropped rather than guessed at, so an unhandled code shows as plain text instead
of silently mis-colouring the output.
"""
import html, re, sys

# Mirrors colour() in cmd/decay/main.go, mapped onto the dashboard palette so the
# terminal shot and the HTML shot read as the same tool.
CODES = {
    "0":  None,                 # reset
    "1":  ("bold", None),
    "32": (None, "#3fb950"),    # green   / healthy
    "31": (None, "#f85149"),    # red     / dead-source
    "33": (None, "#d2991d"),    # yellow  / degraded
    "90": (None, "#8b949e"),    # gray
    "36": (None, "#58a6ff"),    # cyan    / header
    "35": (None, "#a371f7"),    # magenta / probe-error
    "38;5;208": (None, "#f0883e"),  # amber / dead-field
}
TOKEN = re.compile(r"\033\[([0-9;]*)m")

def convert(text):
    out, bold, colour = [], False, None
    pos = 0
    def open_span():
        s = []
        if bold: s.append("font-weight:700")
        if colour: s.append(f"color:{colour}")
        return f'<span style="{";".join(s)}">' if s else "<span>"

    out.append(open_span())
    for m in TOKEN.finditer(text):
        out.append(html.escape(text[pos:m.start()]))
        pos = m.end()
        raw = m.group(1)
        # "1;36" is bold+colour; "38;5;208" is a single 256-colour code.
        parts = [raw] if raw.startswith("38;5;") else (raw.split(";") if raw else ["0"])
        for p in parts:
            if p == "" or p == "0":
                bold, colour = False, None
            elif p in CODES and CODES[p]:
                b, c = CODES[p]
                if b: bold = True
                if c: colour = c
        out.append("</span>")
        out.append(open_span())
    out.append(html.escape(text[pos:]))
    out.append("</span>")
    return "".join(out)

body = convert(sys.stdin.read().rstrip("\n"))
print(f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
@page {{ margin: 0 }}
html,body {{ margin:0; padding:0; background:#0d1117 }}
pre {{
  margin:0; padding:36px 40px; background:#0d1117; color:#c9d1d9;
  font-family:"DejaVu Sans Mono","Liberation Mono",Menlo,monospace;
  font-size:26px; line-height:1.45; white-space:pre; display:inline-block;
}}
</style></head><body><pre>{body}</pre></body></html>""")
