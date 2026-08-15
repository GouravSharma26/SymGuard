import sys
sys.path.insert(0, "/home/claude/diagrams")
from diagram_lib import box, group_box, arrow, plain_line, svg_wrap, edge_point

W, H = 1300, 1300
parts = []

cx = W / 2  # main spine center-x

def col_box(y, w, h, lines, cx_=cx, **kw):
    return box(cx_ - w/2, y, w, h, lines, **kw)

# 1. Source
b_src, bx_src = col_box(40, 260, 50, ["source.py"])
parts.append(b_src)

# 2. ast.parse
b_parse, bx_parse = col_box(120, 300, 55, ["ast.parse(source)"])
parts.append(b_parse)
parts.append(arrow(bx_src, bx_parse))

# 3. AST
b_ast, bx_ast = col_box(205, 300, 55, ["Abstract Syntax Tree", "(Module / If / Assign / Call nodes)"])
parts.append(b_ast)
parts.append(arrow(bx_parse, bx_ast))

# 4. Symbolic executor group (the recursive exec_block engine)
sg_x, sg_y, sg_w, sg_h = cx - 460, 300, 920, 330
parts.append(group_box(sg_x, sg_y, sg_w, sg_h, "Symbolic Executor  (exec_block, recursive, one call per branch)"))
parts.append(arrow(bx_ast, edge_point(cx, sg_y)))

b_env, bx_env = box(sg_x + 30, sg_y + 40, 260, 60,
                     ["Environment (env)", "name -> SymVal(kind, z3 expr, tainted)"])
b_taint, bx_taint = box(sg_x + 30, sg_y + 140, 260, 60,
                         ["Taint Catalog", "input(), sys.argv, os.environ,", "request.args/form (sources)"])
b_path, bx_path = box(sg_x + 30, sg_y + 240, 260, 60,
                       ["Path Constraints", "list of z3 BoolRef, one per", "branch taken to reach here"])
parts += [b_env, b_taint, b_path]
parts.append(arrow(bx_env, bx_taint))
parts.append(arrow(bx_taint, bx_path))

b_if, bx_if = box(sg_x + 350, sg_y + 40, 240, 70, ["ast.If node?", "fork execution"])
parts.append(b_if)
b_true, bx_true = box(sg_x + 330, sg_y + 150, 130, 55, ["path + [cond]", "-> exec_block(body)"])
b_false, bx_false = box(sg_x + 480, sg_y + 150, 130, 55, ["path + [Not(cond)]", "-> exec_block(orelse)"])
parts += [b_true, b_false]
parts.append(arrow(bx_if, bx_true))
parts.append(arrow(bx_if, bx_false))

b_call, bx_call = box(sg_x + 650, sg_y + 40, 240, 70, ["ast.Call node?", "sink or source lookup"])
parts.append(b_call)

sg_bottom = sg_y + sg_h

# 5. Sink check -- both the accumulated path constraints and a call-site
#    match feed into sink detection. The call->sink link exits the group
#    via a clean vertical-then-diagonal elbow instead of cutting across
#    the group's interior.
sink_y = sg_bottom + 40
b_sink, bx_sink = col_box(sink_y, 340, 65,
                           ["Sink Detection",
                            "eval/exec, os.system, cursor.execute,",
                            "list[idx] -- is any argument tainted?"])
parts.append(b_sink)
parts.append(arrow(bx_path, bx_sink))

call_cx = sg_x + 650 + 120
elbow_y = sg_bottom + 18
parts.append(plain_line(call_cx, sg_y + 40 + 70, call_cx, elbow_y))
parts.append(arrow(edge_point(call_cx, elbow_y), bx_sink))

b_skip, bx_skip = box(cx + 420, sink_y, 220, 65,
                       ["not tainted", "-> no finding, continue exec_block"])
parts.append(b_skip)
parts.append(arrow(bx_sink, bx_skip, "no"))

# 6. Z3 encode + solve
z3_y = sink_y + 65 + 45
b_encode, bx_encode = col_box(z3_y, 380, 60,
                               ["Z3 Encoding",
                                "constraint = And(*path_constraints)"])
parts.append(b_encode)
parts.append(arrow(bx_sink, bx_encode, "tainted"))

solve_y = z3_y + 60 + 45
b_solve, bx_solve = col_box(solve_y, 300, 55, ["solver.check()"])
parts.append(b_solve)
parts.append(arrow(bx_encode, bx_solve))

# 7. Branch on result
d_y = solve_y + 55 + 55
b_sat, bx_sat = box(cx - 380, d_y, 260, 70,
                     ["SAT", "counterexample = solver.model()", "concrete exploit input values"])
b_unsat, bx_unsat = box(cx + 120, d_y, 260, 70,
                         ["UNSAT", "path proven infeasible", "sink certified safe on this path"])
parts += [b_sat, b_unsat]
parts.append(arrow(bx_solve, bx_sat, "sat"))
parts.append(arrow(bx_solve, bx_unsat, "unsat"))

# 8. Finding
finding_y = d_y + 70 + 45
b_finding, bx_finding = col_box(finding_y, 380, 70,
                                 ["Finding", "vuln_type, location, sink, tainted_source,",
                                  "verdict, model"])
parts.append(b_finding)
parts.append(arrow(bx_sat, bx_finding))
parts.append(arrow(bx_unsat, bx_finding))

# 9. Report
report_y = finding_y + 70 + 45
b_report, bx_report = col_box(report_y, 300, 55, ["findings[] -> report", "(console / JSON)"])
parts.append(b_report)
parts.append(arrow(bx_finding, bx_report))

H = int(report_y + 55 + 40)

body = "\n".join(parts)
svg = svg_wrap(W, H, body, title="Core Reasoning Engine — Detailed Data Flow")

with open("/mnt/user-data/outputs/vuln_analyzer/diagrams_engine_dataflow.svg", "w") as f:
    f.write(svg)
print("written, H =", H)
