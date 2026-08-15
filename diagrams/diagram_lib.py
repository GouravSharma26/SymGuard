"""
gen_diagrams.py
Generates two clean, white-background SVG architecture diagrams for the
Static Vulnerability Analyzer project:

  1. system_architecture.svg  -- full-stack view (dashboard/CLI -> API ->
     core reasoning engine -> outputs -> CI/CD)
  2. engine_dataflow.svg      -- detailed internal data flow of the core
     engine (AST parser -> symbolic executor/taint tracker -> Z3 encoder ->
     solver -> verdict)

Boxes and arrows are placed on a fixed coordinate grid computed in Python
(not hand-typed SVG), so alignment is exact. Style is deliberately plain:
white background, thin black strokes, no gradients/icons/shadows.
"""

FONT = "font-family='Helvetica, Arial, sans-serif'"

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def box(x, y, w, h, lines, fill="#ffffff", stroke="#1a1a1a", stroke_width=1.5,
        text_size=13, bold=False, rx=6, text_color="#1a1a1a"):
    """A rectangle with 1+ lines of centered text."""
    cx = x + w / 2
    n = len(lines)
    line_h = text_size + 5
    start_y = y + h / 2 - (n - 1) * line_h / 2 + text_size / 3
    weight = "600" if bold else "400"
    svg = [f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='{rx}' "
           f"fill='{fill}' stroke='{stroke}' stroke-width='{stroke_width}'/>"]
    for i, line in enumerate(lines):
        ty = start_y + i * line_h
        svg.append(f"<text x='{cx}' y='{ty}' {FONT} font-size='{text_size}' "
                    f"font-weight='{weight}' fill='{text_color}' "
                    f"text-anchor='middle'>{esc(line)}</text>")
    return "\n".join(svg), (x, y, w, h)

def group_box(x, y, w, h, title, stroke="#1a1a1a", dash=None, fill="none",
              title_size=13):
    d = f" stroke-dasharray='{dash}'" if dash else ""
    svg = [f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='8' "
           f"fill='{fill}' stroke='{stroke}' stroke-width='1.5'{d}/>"]
    svg.append(f"<text x='{x + 14}' y='{y - 10}' {FONT} font-size='{title_size}' "
               f"font-weight='600' fill='#1a1a1a'>{esc(title)}</text>")
    return "\n".join(svg)

def edge_pts(b1, b2, side1="auto", side2="auto"):
    """Return (x1,y1,x2,y2) connecting the nearest sides of two boxes."""
    x1, y1, w1, h1 = b1
    x2, y2, w2, h2 = b2
    c1 = (x1 + w1 / 2, y1 + h1 / 2)
    c2 = (x2 + w2 / 2, y2 + h2 / 2)
    # decide primary direction
    dx = c2[0] - c1[0]
    dy = c2[1] - c1[1]
    if abs(dx) >= abs(dy):
        if dx >= 0:
            p1 = (x1 + w1, c1[1])
            p2 = (x2, c2[1])
        else:
            p1 = (x1, c1[1])
            p2 = (x2 + w2, c2[1])
    else:
        if dy >= 0:
            p1 = (c1[0], y1 + h1)
            p2 = (c2[0], y2)
        else:
            p1 = (c1[0], y1)
            p2 = (c2[0], y2 + h2)
    return p1[0], p1[1], p2[0], p2[1]

def arrow(b1, b2, label=None, dashed=False, color="#333333", label_size=11,
          label_bg=True, label_offset=(0, -8)):
    """Straight connector between the nearest sides of two boxes.
    `label` may be a string or a list of strings (multi-line)."""
    x1, y1, x2, y2 = edge_pts(b1, b2)
    dash = " stroke-dasharray='6,4'" if dashed else ""
    line = (f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' "
            f"stroke='{color}' stroke-width='1.6' "
            f"marker-end='url(#arrowhead)'{dash}/>")
    out = [line]
    if label:
        lines = label if isinstance(label, list) else [label]
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        lx, ly = mx + label_offset[0], my + label_offset[1]
        line_h = label_size + 4
        top_y = ly - (len(lines) - 1) * line_h
        if label_bg:
            w_est = max(max(len(l) for l in lines) * label_size * 0.58, 20)
            h_est = len(lines) * line_h + 4
            out.append(f"<rect x='{lx - w_est/2}' y='{top_y - label_size}' "
                       f"width='{w_est}' height='{h_est}' fill='#ffffff'/>")
        for i, l in enumerate(lines):
            out.append(f"<text x='{lx}' y='{top_y + i*line_h}' {FONT} "
                       f"font-size='{label_size}' fill='#333333' "
                       f"text-anchor='middle'>{esc(l)}</text>")
    return "\n".join(out)

def plain_line(x1, y1, x2, y2, color="#333333", dashed=False):
    dash = " stroke-dasharray='6,4'" if dashed else ""
    return (f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' "
            f"stroke='{color}' stroke-width='1.6'{dash}/>")

def edge_point(x, y):
    """A zero-size 'box' used as an arrow endpoint at an exact coordinate
    (e.g. a specific point on a container's border)."""
    return (x, y, 0, 0)

def defs():
    return """<defs>
  <marker id='arrowhead' markerWidth='10' markerHeight='10' refX='8' refY='3'
          orient='auto' markerUnits='strokeWidth'>
    <path d='M0,0 L0,6 L9,3 z' fill='#333333'/>
  </marker>
</defs>"""

def svg_wrap(width, height, body, title=None):
    parts = [f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {height}' "
             f"width='{width}' height='{height}'>",
             f"<rect x='0' y='0' width='{width}' height='{height}' fill='#ffffff'/>",
             defs()]
    if title:
        parts.append(f"<text x='{width/2}' y='28' {FONT} font-size='20' "
                     f"font-weight='700' fill='#111111' text-anchor='middle'>{esc(title)}</text>")
    parts.append(body)
    parts.append("</svg>")
    return "\n".join(parts)
