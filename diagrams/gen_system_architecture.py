import sys
sys.path.insert(0, "/home/claude/diagrams")
from diagram_lib import box, group_box, arrow, svg_wrap, edge_point

W, H = 1300, 840
parts = []

# ---- Entry points (left column) ----
b_dashboard, bx_dashboard = box(40, 60, 220, 60, ["Web Dashboard", "(React / Next.js, browser)"])
b_cli, bx_cli = box(40, 190, 220, 60, ["CLI", "analyzer.py --format json"])
parts += [b_dashboard, b_cli]

# ---- API layer ----
b_api, bx_api = box(340, 90, 200, 60, ["Backend API", "(Flask / FastAPI)"])
parts.append(b_api)
parts.append(arrow(bx_dashboard, bx_api, "POST /analyze  {code}"))

# ---- Core Reasoning Engine group ----
group_x, group_y, group_w, group_h = 620, 70, 480, 350
parts.append(group_box(group_x, group_y, group_w, group_h, "Core Reasoning Engine  (analyzer.py)"))

eb_w, eb_h = 400, 62
b_ast, bx_ast = box(group_x + 40, group_y + 30, eb_w, eb_h,
                     ["1. AST Parser", "ast.parse(source)  ->  Abstract Syntax Tree"])
b_sym, bx_sym = box(group_x + 40, group_y + 130, eb_w, eb_h,
                     ["2. Symbolic Executor + Taint Tracker",
                      "forks on if/else; propagates taint via SymVal env"])
b_z3, bx_z3 = box(group_x + 40, group_y + 230, eb_w, eb_h,
                   ["3. Z3 Encoder + SMT Solver",
                    "path constraints + sink condition  ->  solver.check()"])
parts += [b_ast, b_sym, b_z3]
parts.append(arrow(bx_ast, bx_sym))
parts.append(arrow(bx_sym, bx_z3))

# API feeds the top of the engine; CLI bypasses the API and calls the
# engine module directly (both terminate on the group's left border).
parts.append(arrow(bx_api, bx_ast, "source code (str)"))
parts.append(arrow(bx_cli, edge_point(group_x, group_y + 110), "direct function call", dashed=True))

# ---- Findings -> JSON, straight down the engine's centerline ----
engine_cx = group_x + group_w / 2
b_findings, bx_findings = box(engine_cx - 170, 460, 340, 60,
                               ["Finding objects",
                                "vuln_type, sink, verdict, Z3 model / counterexample"])
parts.append(b_findings)
parts.append(arrow(bx_z3, bx_findings, ["SAT -> counterexample", "UNSAT -> safety proof"],
                    label_offset=(0, 42)))

b_json, bx_json = box(engine_cx - 100, 560, 200, 60, ["JSON Report", "findings.json"])
parts.append(b_json)
parts.append(arrow(bx_findings, bx_json))

# ---- Consumers, fanned out below the JSON report ----
b_ci, bx_ci = box(engine_cx - 380, 680, 220, 60, ["CI/CD Pipeline", "GitHub Actions (pass/fail gate)"])
b_ui, bx_ui = box(engine_cx - 110, 680, 220, 60, ["Dashboard Rendering", "highlighted lines + Z3 model"])
b_console, bx_console = box(engine_cx + 160, 680, 220, 60, ["Console Report", "human-readable summary"])
parts += [b_ci, b_ui, b_console]
parts.append(arrow(bx_json, bx_ci))
parts.append(arrow(bx_json, bx_ui))
parts.append(arrow(bx_json, bx_console))

# ---- legend ----
leg_y = 800
parts.append(f"<line x1='40' y1='{leg_y}' x2='80' y2='{leg_y}' stroke='#333333' stroke-width='1.6' marker-end='url(#arrowhead)'/>")
parts.append(f"<text x='88' y='{leg_y+4}' font-family='Helvetica, Arial, sans-serif' font-size='12' fill='#333333'>data flow</text>")
parts.append(f"<line x1='200' y1='{leg_y}' x2='240' y2='{leg_y}' stroke='#333333' stroke-width='1.6' stroke-dasharray='6,4' marker-end='url(#arrowhead)'/>")
parts.append(f"<text x='248' y='{leg_y+4}' font-family='Helvetica, Arial, sans-serif' font-size='12' fill='#333333'>alternate entry path (CLI)</text>")

body = "\n".join(parts)
svg = svg_wrap(W, H, body, title="Static Vulnerability Analyzer — System Architecture")

with open("/mnt/user-data/outputs/vuln_analyzer/diagrams_system_architecture.svg", "w") as f:
    f.write(svg)
print("written")
