# -*- coding: utf-8 -*-
"""Build the expanded 25-slide KTLT-Defender presentation (English).

Design system reused from the validated 14-slide deck:
NAVY/TEAL/GREEN(detected)/RED(gap) palette, Cambria headings + Calibri body, 16:9.
Content from the workflow spec (4 report-grounded designers + critic); critic
fixes applied inline (slide 23 overclaim, slide 14/16 trims, slide 4 ON/OFF tags,
slide 15 declutter). Title(1) + dividers(6/12/20) built in code.
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn
from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION

MONO = "Consolas"

NAVY = RGBColor(0x0D, 0x22, 0x40)
NAVY2 = RGBColor(0x12, 0x2E, 0x55)
TEAL = RGBColor(0x1C, 0x72, 0x93)
ICE = RGBColor(0xCA, 0xDC, 0xFC)
GREEN = RGBColor(0x2E, 0x8B, 0x57)
RED = RGBColor(0xC0, 0x39, 0x2B)
AMBER = RGBColor(0xE6, 0x7E, 0x22)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
INK = RGBColor(0x1A, 0x1A, 0x1A)
GRAY = RGBColor(0x5A, 0x65, 0x72)
LIGHT = RGBColor(0xEE, 0xF3, 0xFA)
HEAD = "Cambria"
BODY = "Calibri"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]
SW, SH = prs.slide_width, prs.slide_height


def slide(bg=WHITE):
    s = prs.slides.add_slide(BLANK)
    r = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SW, SH)
    r.fill.solid(); r.fill.fore_color.rgb = bg
    r.line.fill.background(); r.shadow.inherit = False
    r._element.spPr.insert(0, r._element.spPr.find(qn('a:prstGeom')))
    return s


def rect(s, x, y, w, h, fill, line=None, radius=False, lw=1.0):
    shp = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
                             Inches(x), Inches(y), Inches(w), Inches(h))
    shp.fill.solid(); shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line; shp.line.width = Pt(lw)
    shp.shadow.inherit = False
    return shp


def circle(s, x, y, d, fill):
    shp = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    shp.fill.solid(); shp.fill.fore_color.rgb = fill
    shp.line.fill.background(); shp.shadow.inherit = False
    return shp


def txt(s, x, y, w, h, runs, size=16, color=INK, bold=False, align=PP_ALIGN.LEFT,
        font=BODY, anchor=MSO_ANCHOR.TOP, italic=False, sp=None):
    tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame; tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Emu(0)
    tf.margin_top = tf.margin_bottom = Emu(0)
    items = runs if isinstance(runs, list) else [(runs, {})]
    first = True
    for line, opt in items:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.alignment = opt.get("align", align)
        if sp is not None:
            p.space_after = Pt(sp)
        if opt.get("bullet"):
            _bullet(p)
        r = p.add_run(); r.text = line
        f = r.font
        f.size = Pt(opt.get("size", size)); f.name = opt.get("font", font)
        f.bold = opt.get("bold", bold); f.italic = opt.get("italic", italic)
        f.color.rgb = opt.get("color", color)
    return tb


def _bullet(p):
    pPr = p._pPr if p._pPr is not None else p.get_or_add_pPr()
    bu = pPr.makeelement(qn('a:buChar'), {'char': '•'})
    pPr.append(bu)


def notes(s, text):
    if text:
        s.notes_slide.notes_text_frame.text = text


def table(s, x, y, w, col_w, rows, header_fill=TEAL, body_size=12, head_size=12,
          zebra=LIGHT, row_h=0.34):
    nrows, ncols = len(rows), len(rows[0])
    gt = s.shapes.add_table(nrows, ncols, Inches(x), Inches(y), Inches(w),
                            Inches(row_h * nrows)).table
    gt.first_row = False; gt.horz_banding = False
    for ci, cw in enumerate(col_w):
        gt.columns[ci].width = Inches(cw)
    for ri, row in enumerate(rows):
        for ci, val in enumerate(row):
            cell = gt.cell(ri, ci)
            cell.margin_left = Inches(0.07); cell.margin_right = Inches(0.07)
            cell.margin_top = Inches(0.02); cell.margin_bottom = Inches(0.02)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            if ri == 0:
                cell.fill.solid(); cell.fill.fore_color.rgb = header_fill
            else:
                cell.fill.solid()
                cell.fill.fore_color.rgb = WHITE if (ri % 2 == 1) else zebra
            tf = cell.text_frame; tf.word_wrap = True
            p = tf.paragraphs[0]
            txt_val, col = (val if isinstance(val, tuple) else (val, None))
            r = p.add_run(); r.text = str(txt_val)
            f = r.font
            f.size = Pt(head_size if ri == 0 else body_size)
            f.name = BODY
            f.bold = (ri == 0) or isinstance(val, tuple)
            f.color.rgb = WHITE if ri == 0 else (col or INK)
    return gt


def kicker(s, label, title, size=29):
    txt(s, 0.7, 0.42, 12.0, 0.3, label.upper(), size=12.5, color=TEAL, bold=True, font=BODY)
    txt(s, 0.7, 0.74, 12.0, 0.95, title, size=size, color=NAVY, bold=True, font=HEAD)


def evidence_card(s, x, y, w, h, title, lines, size=10.5):
    """A dark 'terminal' card that renders REAL captured output (monospace).
    A line starting with '+' is highlighted green, '-' red, '#'/'=>' amber/ice."""
    rect(s, x, y, w, h, RGBColor(0x0B, 0x1A, 0x30), radius=True)
    for i, c in enumerate((RED, AMBER, GREEN)):
        circle(s, x + 0.24 + i * 0.22, y + 0.17, 0.11, c)
    txt(s, x + 1.05, y + 0.12, w - 1.25, 0.3, title, size=10.5, color=ICE, font=MONO, bold=True)
    rect(s, x, y + 0.46, w, 0.012, RGBColor(0x24, 0x3A, 0x5A))
    items = []
    for ln in lines:
        c = ICE
        if ln.startswith("+"):
            c = GREEN; ln = " " + ln[1:]
        elif ln.startswith("-"):
            c = RED; ln = " " + ln[1:]
        elif ln.startswith("=>"):
            c = AMBER
        items.append((ln, {"size": size, "font": MONO, "color": c}))
    txt(s, x + 0.3, y + 0.6, w - 0.55, h - 0.72, items, sp=3.5)


def coverage_bar(s, x, y, w, cells, h=0.5, lsize=8):
    """11-cell coverage strip: cells = [(label, detected_bool), ...]."""
    n = len(cells)
    cw = w / n
    for i, (lab, det) in enumerate(cells):
        cx = x + i * cw
        rect(s, cx + 0.015, y, cw - 0.03, h, GREEN if det else RED)
        txt(s, cx - 0.1, y + h + 0.06, cw + 0.2, 0.3, lab, size=lsize, color=ICE,
            align=PP_ALIGN.CENTER)


def native_doughnut(s, x, y, w, h, detected, missed, center_label):
    cd = CategoryChartData()
    cd.categories = ["Detected", "Missed"]
    cd.add_series("Axis B", (detected, missed))
    gf = s.shapes.add_chart(XL_CHART_TYPE.DOUGHNUT, Inches(x), Inches(y), Inches(w), Inches(h), cd)
    ch = gf.chart
    ch.has_title = False
    ch.font.size = Pt(11); ch.font.color.rgb = ICE
    ch.has_legend = True
    ch.legend.position = XL_LEGEND_POSITION.BOTTOM
    ch.legend.include_in_layout = False
    plot = ch.plots[0]
    plot.has_data_labels = False
    pts = plot.series[0].points
    for pt, col in zip(pts, (GREEN, RED)):
        pt.format.fill.solid(); pt.format.fill.fore_color.rgb = col
        pt.format.line.color.rgb = NAVY; pt.format.line.width = Pt(1.5)
    # center label overlay
    txt(s, x, y + h / 2 - 0.55, w, 0.6, center_label, size=30, color=WHITE, bold=True,
        align=PP_ALIGN.CENTER, font=HEAD, anchor=MSO_ANCHOR.MIDDLE)


def _groups(body):
    """Split body lines into [(header, [subs...]), ...]. Non-indented line = header;
    lines starting with two spaces/tab = subs of the current header."""
    groups, cur = [], None
    for ln in body:
        if ln.startswith("  ") or ln.startswith("\t"):
            if cur is None:
                cur = ["", []]
                groups.append(cur)
            cur[1].append(ln.strip())
        else:
            cur = [ln.strip(), []]
            groups.append(cur)
    return [(h, s) for h, s in groups]


# ===================== static slides =====================

def build_title():
    s = slide(NAVY)
    rect(s, 0.9, 2.55, 0.14, 2.0, TEAL)
    txt(s, 1.25, 1.35, 11.0, 0.35, "ACADEMY OF CRYPTOGRAPHY TECHNIQUES  ·  KTLT COURSE PROJECT",
        size=13, color=ICE, bold=True)
    txt(s, 1.25, 2.5, 10.9, 2.1,
        "Automated Evaluation of Windows Defender Detection on Windows 11",
        size=38, color=WHITE, bold=True, font=HEAD)
    txt(s, 1.25, 4.35, 10.9, 0.6, "and a Supplementary YARA / Sigma Rule Set",
        size=23, color=ICE, bold=False, font=HEAD, italic=True)
    txt(s, 1.25, 5.65, 11.3, 0.9, [
        ("Team: Tran Quang Huy · Nguyen Van Thanh · Nguyen Viet Nhat Long · Nguyen Viet Hieu",
         {"size": 15, "color": WHITE}),
        ("Supervisor: Nguyen Manh Thang", {"size": 15, "color": ICE}),
    ], sp=4)
    notes(s, "Title. An automated, reproducible tool that measures Windows Defender's real "
             "detection coverage on Windows 11, plus a supplementary YARA/Sigma rule set for the "
             "techniques it misses.")


def build_divider(label, title, sub):
    s = slide(NAVY)
    rect(s, 0.9, 2.7, 0.16, 1.7, TEAL)
    txt(s, 1.3, 2.28, 10.5, 0.4, label.upper(), size=15, color=TEAL, bold=True)
    txt(s, 1.3, 2.75, 11.2, 1.4, title, size=36, color=WHITE, bold=True, font=HEAD)
    txt(s, 1.3, 4.35, 10.8, 0.7, sub, size=16, color=ICE, italic=True)
    notes(s, "Section: " + title)


# ===================== renderers =====================

def render_list(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    lines = [ln.strip() for ln in spec["body"]]
    for i, ln in enumerate(lines):
        y = 1.95 + i * 0.73
        # status chip?  "... [ON] ..." or "[OFF...]"
        chip = None
        if "[ON]" in ln:
            chip = ("ON", GREEN); ln = ln.replace(" [ON]", "").replace("[ON] ", "").replace("[ON]", "")
        elif "[OFF" in ln:
            k = ln[ln.index("[OFF"):].split("]")[0] + "]"
            label = k.strip("[]")
            chip = (label, AMBER); ln = ln.replace(" " + k, "").replace(k + " ", "").replace(k, "")
        head, _, rest = ln.partition(" — ")
        cx = 0.75
        if chip:
            cw = 1.15 if len(chip[0]) > 3 else 0.62
            rect(s, cx, y + 0.02, cw, 0.34, chip[1], radius=True)
            txt(s, cx, y + 0.04, cw, 0.3, chip[0], size=11, color=WHITE, bold=True,
                align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
            tx = cx + cw + 0.2
        else:
            circle(s, cx, y + 0.08, 0.18, TEAL)
            tx = cx + 0.37
        if rest:
            txt(s, tx, y, 12.6 - tx, 0.4, head, size=16.5, bold=True, color=NAVY, font=HEAD)
            txt(s, tx, y + 0.34, 12.6 - tx, 0.4, rest, size=13, color=INK)
        else:
            txt(s, tx, y, 12.6 - tx, 0.5, ln, size=16.5, color=INK, anchor=MSO_ANCHOR.MIDDLE)
    notes(s, spec.get("notes"))


def render_cards(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    groups = _groups(spec["body"])[:3]
    palette = [TEAL, NAVY, GREEN]
    gap = 0.32
    cw = (11.9 - gap * (len(groups) - 1)) / len(groups)
    for i, (h, subs) in enumerate(groups):
        x = 0.7 + i * (cw + gap)
        rect(s, x, 1.9, cw, 4.45, WHITE, line=ICE, radius=True)
        circle(s, x + 0.3, 2.2, 0.8, palette[i % 3])
        txt(s, x + 0.3, 2.31, 0.8, 0.6, "0" + str(i + 1), size=22, color=WHITE, bold=True,
            align=PP_ALIGN.CENTER, font=HEAD)
        txt(s, x + 0.3, 3.18, cw - 0.55, 0.5, h, size=17, color=NAVY, bold=True, font=HEAD)
        txt(s, x + 0.3, 3.78, cw - 0.55, 2.4,
            [(t, {"size": 13, "color": INK, "bullet": True}) for t in subs], sp=7)
    notes(s, spec.get("notes"))


def _panel(s, x, y, w, h, head, subs, fill=LIGHT, head_c=TEAL, body_c=INK, sub_c=GRAY,
           hsize=15, bsize=13.5):
    rect(s, x, y, w, h, fill, radius=True)
    txt(s, x + 0.3, y + 0.2, w - 0.55, 0.5, head, size=hsize, bold=True, color=head_c, font=HEAD)
    items = []
    for t in subs:
        items.append((t, {"size": bsize, "color": body_c, "bullet": True}))
    txt(s, x + 0.3, y + 0.72, w - 0.55, h - 0.9, items, sp=6)


def render_panels(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    body = spec["body"]
    callout = spec.get("callout", [])
    indented = any(ln.startswith("  ") for ln in body)
    if not indented:
        # flat bullets left + callout panel right (e.g. slide 3)
        txt(s, 0.7, 1.95, 7.0, 4.4,
            [(ln.strip(), {"size": 16, "color": INK, "bullet": True}) for ln in body], sp=12)
        if callout:
            rect(s, 8.1, 1.9, 4.5, 4.5, NAVY, radius=True)
            txt(s, 8.42, 2.15, 3.9, 0.5, callout[0], size=16, bold=True, color=ICE, font=HEAD)
            txt(s, 8.42, 2.8, 3.95, 3.4,
                [(c, {"size": 14.5, "color": WHITE}) for c in callout[1:]], sp=8)
        notes(s, spec.get("notes"))
        return
    groups = _groups(body)
    band = bool(callout)
    ph = 3.9 if band else 4.55
    if len(groups) <= 1:
        # single content group: left = the list, right = callout as a stats panel
        g = groups[0] if groups else ("", [])
        if callout:
            _panel(s, 0.7, 1.8, 6.4, 4.55, g[0], g[1], bsize=14)
            rect(s, 7.5, 1.8, 5.1, 4.55, LIGHT, radius=True)
            txt(s, 7.82, 2.05, 4.5, 0.5, callout[0], size=15, bold=True, color=TEAL, font=HEAD)
            ci = []
            for c in callout[1:]:
                is_stat = any(ch.isdigit() for ch in c) and ("/" in c or "%" in c or "=" in c)
                ci.append((c, {"size": 15 if is_stat else 13,
                               "color": GREEN if is_stat else INK,
                               "bold": is_stat, "bullet": not is_stat}))
            txt(s, 7.82, 2.68, 4.55, 3.5, ci, sp=9)
            notes(s, spec.get("notes"))
            return
        _panel(s, 0.7, 1.8, 11.9, ph, g[0], g[1])
    elif len(groups) == 2:
        _panel(s, 0.7, 1.8, 5.75, ph, groups[0][0], groups[0][1])
        _panel(s, 6.85, 1.8, 5.75, ph, groups[1][0], groups[1][1])
    else:  # 3 groups (slide 8): left tall + right stacked two
        _panel(s, 0.7, 1.8, 5.75, ph, groups[0][0], groups[0][1])
        rh = (ph - 0.15) / 2
        _panel(s, 6.85, 1.8, 5.75, rh, groups[1][0], groups[1][1], hsize=14, bsize=12.5)
        _panel(s, 6.85, 1.8 + rh + 0.15, 5.75, rh, groups[2][0], groups[2][1], hsize=14, bsize=12.5)
    if band:
        rect(s, 0.7, 5.88, 11.9, 0.82, NAVY, radius=True)
        txt(s, 1.05, 5.95, 11.2, 0.7, " ".join(callout), size=13.5, color=ICE, italic=True,
            anchor=MSO_ANCHOR.MIDDLE)
    notes(s, spec.get("notes"))


def render_content(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    has_call = bool(spec.get("callout"))
    bw = 7.15 if has_call else 11.9
    items = []
    for ln in spec["body"]:
        if ln.startswith("  "):
            items.append((ln.strip(), {"size": 14, "color": GRAY, "bullet": True}))
        else:
            items.append((ln.strip(), {"size": 15.5, "color": INK, "bullet": True}))
    txt(s, 0.7, 1.95, bw, 4.6, items, sp=10)
    if has_call:
        c = spec["callout"]
        rect(s, 8.1, 1.95, 4.5, 4.4, LIGHT, radius=True)
        txt(s, 8.42, 2.18, 3.9, 0.5, c[0], size=16, bold=True, color=TEAL, font=HEAD)
        txt(s, 8.42, 2.78, 3.95, 3.3, [(x, {"size": 14, "color": INK}) for x in c[1:]], sp=8)
    notes(s, spec.get("notes"))


def render_table(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    intro = spec.get("body", [])
    y0 = 1.78
    if intro:
        txt(s, 0.7, y0, 11.9, 0.7,
            [(ln, {"size": 13, "color": GRAY, "italic": True}) for ln in intro], sp=2)
        y0 += 0.3 + 0.26 * len(intro)
    headers = spec["table_headers"]
    rows = [headers] + [_color_row(r) for r in spec["table_rows"]]
    has_call = bool(spec.get("callout"))
    tw = 7.7 if has_call else 11.9
    ncol = len(headers)
    first = tw * (0.34 if ncol >= 4 else 0.40)
    col_w = [first] + [(tw - first) / (ncol - 1)] * (ncol - 1)
    rh = 0.86 if len(rows) <= 5 else (0.62 if len(rows) <= 7 else 0.56)
    table(s, 0.7, y0, tw, col_w, rows, body_size=12, head_size=12.5, row_h=rh)
    if has_call:
        rect(s, 8.6, y0, 4.0, min(4.5, rh * len(rows) + 0.3), LIGHT, radius=True)
        c = spec["callout"]
        txt(s, 8.9, y0 + 0.22, 3.45, 0.5, c[0], size=15, bold=True, color=TEAL, font=HEAD)
        txt(s, 8.9, y0 + 0.78, 3.5, 3.4,
            [(x, {"size": 13, "color": INK, "bullet": True}) for x in c[1:]], sp=8)
    notes(s, spec.get("notes"))


def _color_row(r):
    out = []
    for v in r:
        low = str(v).lower()
        if low == "detected" or str(v).startswith("DETECTED"):
            out.append((str(v), GREEN))
        elif low.startswith("not_detected") or low.startswith("not detected"):
            out.append((str(v), RED))
        else:
            out.append(v)
    return out


def render_architecture(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    blocks = [("Block 1", "Sample Generation", "4 C# payload variants (v0-v3), EICAR encoded in source, csc.exe build", TEAL),
              ("Block 2", "Behaviour Engine", "Invoke-AtomicRedTeam G1-G5; 'Executing test' marker gate", NAVY),
              ("Block 3", "Measurement Station", "run_measure drives each trial end-to-end, scores, writes SQLite", GREEN)]
    for i, (a, b, c, col) in enumerate(blocks):
        x = 0.7 + i * 4.12
        rect(s, x, 1.9, 3.8, 1.95, col, radius=True)
        txt(s, x + 0.25, 2.08, 3.3, 0.35, a, size=13, color=ICE, bold=True)
        txt(s, x + 0.25, 2.42, 3.3, 0.5, b, size=17, color=WHITE, bold=True, font=HEAD)
        txt(s, x + 0.25, 2.98, 3.35, 0.8, c, size=12, color=WHITE)
    rect(s, 0.7, 4.35, 11.9, 1.95, LIGHT, radius=True)
    txt(s, 1.0, 4.52, 11.3, 0.4, "Per-measurement loop  —  deterministic and fully logged",
        size=15, bold=True, color=TEAL, font=HEAD)
    steps = ["reset", "build / arm", "trigger", "collect logs", "fidelity", "score (1 of 4)", "write DB"]
    for i, st in enumerate(steps):
        x = 0.95 + i * 1.66
        rect(s, x, 5.08, 1.4, 0.72, WHITE, line=TEAL, radius=True)
        txt(s, x, 5.14, 1.4, 0.6, st, size=11.5, color=NAVY, bold=True,
            align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        if i < len(steps) - 1:
            txt(s, x + 1.4, 5.14, 0.26, 0.6, "›", size=20, color=TEAL,
                align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    txt(s, 1.0, 5.98, 11.3, 0.3,
        "Each stored row = sample SHA-256 + timestamp + signature version → any measurement reconstructs exactly.",
        size=12.5, italic=True, color=GRAY)
    notes(s, spec.get("notes"))


def render_stat(spec):
    s = slide(NAVY)
    txt(s, 0.7, 0.5, 11.9, 0.35, spec["kicker"].upper(), size=13, color=ICE, bold=True)
    txt(s, 0.7, 0.85, 11.9, 0.7, spec["title"], size=32, color=WHITE, bold=True, font=HEAD)
    # native doughnut (editable chart): 2 detected / 9 missed
    native_doughnut(s, 0.65, 1.95, 3.35, 3.35, 2, 9, "18.2%")
    txt(s, 0.5, 5.35, 3.65, 0.35, "2 of 11 techniques · fidelity 1.0", size=12.5, color=ICE,
        align=PP_ALIGN.CENTER)
    # two wins band
    rect(s, 4.4, 1.95, 8.2, 1.62, NAVY2, radius=True)
    txt(s, 4.72, 2.12, 7.7, 0.4, "Defender's 2 wins — two distinct runtime / self-defence layers",
        size=14, bold=True, color=GREEN)
    txt(s, 4.72, 2.62, 7.7, 0.9, [
        ("T1059.001  (Mimikatz / PowerShell)  →  AMSI, ~3.8 s", {"size": 14.5, "color": WHITE}),
        ("T1562.001  (disable Defender)  →  Tamper Protection (state-verified)", {"size": 14.5, "color": WHITE}),
    ], sp=4)
    # per-technique coverage strip
    txt(s, 4.4, 3.85, 8.2, 0.35, "Per-technique coverage — 2 detected, 9 missed (across the kill chain)",
        size=13, bold=True, color=AMBER)
    cells = [("59.001", True), ("62.001", True), ("1082", False), ("1057", False), ("1218", False),
             ("59.003", False), ("1547", False), ("1053", False), ("1003", False), ("1555", False), ("1140", False)]
    coverage_bar(s, 4.4, 4.35, 8.2, cells)
    txt(s, 4.4, 5.35, 8.2, 0.7,
        "Gaps hold under the cloud-ON and LSASS-ASR spot-checks — not a cloud-OFF config artefact.",
        size=13.5, italic=True, color=ICE)
    notes(s, spec.get("notes"))


def render_axisa_table(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    txt(s, 0.7, 1.78, 11.9, 0.4,
        [(ln, {"size": 13, "color": GRAY, "italic": True}) for ln in spec.get("body", [])], sp=2)
    headers = spec["table_headers"]
    rows = [headers] + [_color_row(r) for r in spec["table_rows"]]
    table(s, 0.7, 2.35, 7.1, [1.0, 4.1, 2.0], rows, body_size=12.5, head_size=12.5, row_h=0.72)
    evidence_card(s, 8.05, 2.35, 4.55, 3.95, "db/results.sqlite  ·  run_id=2 (Axis A)", [
        " id var state         layer  threat",
        "+ 1 v0  detected      static Virus:DOS/EICAR_Test_File",
        "- 4 v1  not_detected   -     (clean)",
        "+ 5 v2  detected      static Virus:DOS/EICAR_Test_File",
        "- 6 v3  not_detected   -     (clean)",
        "",
        "=> fidelity=1.0 on all 4 — the misses are",
        "   real evasions, not failed executions",
    ], size=10)
    notes(s, spec.get("notes"))


def render_twowins(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    groups = _groups(spec["body"])
    _panel(s, 0.7, 1.8, 5.75, 3.35, groups[0][0], groups[0][1], bsize=13.5)
    _panel(s, 6.85, 1.8, 5.75, 3.35, groups[1][0], groups[1][1], bsize=13.5)
    evidence_card(s, 0.7, 5.35, 11.9, 1.55, "vm/watch_rtp.ps1  ·  T1562.001 direct RTP-state check", [
        "trigger  Set-MpPreference -DisableRealtimeMonitoring 1   @23:15:17",
        "+ RTP     never left True for the whole window",
        "  log     5013 Tamper Protection BLOCKED change @23:15:17  (no 5007, no 5001)",
        "=> Tamper Protection blocked the disable  —  Defender WIN",
    ], size=10.5)
    notes(s, spec.get("notes"))


def render_yara(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    groups = _groups(spec["body"])
    _panel(s, 0.7, 1.8, 6.1, 4.55, groups[0][0], groups[0][1], bsize=14)
    evidence_card(s, 7.15, 1.8, 5.45, 3.2, "python rules/fp_scan.py  ·  yara-python 4.5.4", [
        "corpus   System32 + SysWOW64 + .NET Framework",
        "scanned  12,450 files   skipped 0   time 67.2s",
        "+ false positives ................ 0",
        "  .NET calls FromBase64String yet none match",
        "  (rule also requires the project's blob)",
    ], size=10.5)
    rect(s, 7.15, 5.15, 2.62, 1.2, GREEN, radius=True)
    txt(s, 7.15, 5.32, 2.62, 0.6, "0 FP", size=30, color=WHITE, bold=True,
        align=PP_ALIGN.CENTER, font=HEAD)
    txt(s, 7.15, 5.92, 2.62, 0.3, "/ 12,450 goodware", size=11, color=WHITE, align=PP_ALIGN.CENTER)
    rect(s, 10.0, 5.15, 2.6, 1.2, TEAL, radius=True)
    txt(s, 10.0, 5.32, 2.6, 0.6, "5 / 5", size=30, color=WHITE, bold=True,
        align=PP_ALIGN.CENTER, font=HEAD)
    txt(s, 10.0, 5.92, 2.6, 0.3, "true positives (incl. v3)", size=11, color=WHITE, align=PP_ALIGN.CENTER)
    notes(s, spec.get("notes"))


def render_killchain(spec):
    s = slide()
    kicker(s, spec["kicker"], spec["title"])
    tactics = [("Discovery", TEAL), ("Execution", NAVY), ("Persistence", TEAL),
               ("Cred Access", NAVY), ("Defense Evasion", TEAL)]
    n = len(tactics)
    cw = 2.15
    gap = (12.0 - n * cw) / (n - 1)
    for i, (t, col) in enumerate(tactics):
        x = 0.7 + i * (cw + gap)
        rect(s, x, 1.85, cw, 0.62, col, radius=True)
        txt(s, x, 1.9, cw, 0.52, t, size=13, color=WHITE, bold=True,
            align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE, font=HEAD)
        if i < n - 1:
            txt(s, x + cw, 1.9, gap, 0.52, "›", size=20, color=GRAY,
                align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    # per-tactic rows
    for i, ln in enumerate(spec["body"]):
        y = 2.95 + i * 0.78
        tac, _, rest = ln.partition(" - ")
        circle(s, 0.75, y + 0.06, 0.16, RED)
        techs, _, conseq = rest.partition(":")
        txt(s, 1.1, y, 11.4, 0.4,
            [(tac.strip() + "  ", {"size": 15.5, "bold": True, "color": NAVY, "font": HEAD}),
             (techs.strip(), {"size": 14, "bold": True, "color": RED})])
        if conseq:
            txt(s, 1.1, y + 0.36, 11.4, 0.4, conseq.strip(), size=13, color=INK)
    notes(s, spec.get("notes"))


# ===================== content specs (critic fixes applied) =====================

S = {
 2: {"n":2,"title":"Agenda","kicker":"Roadmap","layout":"list","body":[
    "Context & objectives — why Defender must be measured per-layer",
    "Methodology & system design — the two-axis harness, scoring, fidelity",
    "Measurement results — Axis A payload variants and Axis B techniques",
    "Validity & hardening — spot-checks and three fixes found on real data",
    "Supplementary rules & mitigation — YARA/Sigma for every measured gap",
    "Conclusion — findings, limitations, and recommendations"],
    "notes":"This talk runs in six parts: why Defender needs per-layer measurement and our objectives; the two-axis methodology and system design; results on both axes; how we proved the gaps are real and hardened the harness; the supplementary YARA/Sigma rules and mitigation map; and conclusions."},

 3: {"n":3,"title":"Measuring what the default defender misses","kicker":"Why","layout":"two-panel","body":[
    "Defender is the default, always-on, and often the only AV on consumer and SMB endpoints",
    "Aggregate lab scores give one opaque pass rate, not per-technique verdicts",
    "They rarely isolate which engine layer caught it: signature, AMSI, ASR, or cloud",
    "They rarely tie a result to a specific MITRE ATT&CK technique",
    "They are not reproducible on an analyst's own machine",
    "Defenders need to know which technique slips through, at which layer, and how fast"],
    "callout":["What we deliver","An automated tool that produces per-sample, per-technique, traceable verdicts — and turns each blind spot into deployable YARA/Sigma detection content."],
    "notes":"Defender is the default and often the only AV on consumer and small-org machines, so what it misses matters directly. Aggregate lab scores give one opaque number; they don't tell you which technique slips through, at which layer, or how fast, and you can't reproduce them on your own machine. Our tool answers exactly those questions and turns every gap into deployable detection content."},

 4: {"n":4,"title":"Defender is a stack, not one scanner","kicker":"Background","layout":"list","body":[
    "Signature / static scan [ON] — matches file bytes at rest (on-demand MpCmdRun)",
    "Real-time protection (RTP) [ON] — on-access scan as files are written, read, or run",
    "AMSI script scanning [ON] — inspects script content after in-memory de-obfuscation",
    "Behaviour monitoring [ON] — flags malicious action sequences, not malicious bytes",
    "Attack Surface Reduction (ASR) [OFF by default] — policy rules blocking abuse classes",
    "Tamper Protection [ON] — Defender's self-defence against impair-defenses",
    "Cloud-delivered protection [OFF for baseline] — online reputation / ML verdicts"],
    "notes":"Defender is not one scanner but a stack of seven cooperating layers, each inspecting something different: bytes at rest, bytes on access, script content in memory, behaviour, policy classes, the product's own integrity, and the cloud. The baseline ran a near-default consumer config — signature, RTP, AMSI, behaviour and Tamper ON; cloud OFF; ASR off by default. That is why the two wins are AMSI and Tamper, not signature, and why ASR had to be spot-checked separately."},

 5: {"n":5,"title":"Three contributions","kicker":"Objectives","layout":"cards","body":[
    "The tool",
    "  Reproducible two-axis harness: reset → build/arm → trigger → collect → score → write",
    "  Four-state verdicts: error / inconclusive / detected / not_detected",
    "  Operational-log evidence per verdict, gated by a fidelity score",
    "The validated picture",
    "  Real coverage on an isolated Azure Windows 11 VM",
    "  Which forms and techniques are caught, at which layer, how fast",
    "  Axis A: raw on-disk caught, obfuscated + fileless missed; Axis B 2/11 = 18.2%",
    "The rule set",
    "  2 YARA + 7 Sigma tied to the exact measured gaps",
    "  False-positive study: 0 across 12,450 goodware files",
    "  Mitigation map links each gap to its Defender layer and remedy"],
    "notes":"The project delivers three things: the measurement tool (a reproducible harness with four-state verdicts, event-log evidence, and a fidelity gate); a validated empirical picture of what Defender actually caught on an isolated VM, attributed by layer and latency; and a supplementary rule set of two YARA and seven Sigma rules that closes the exact gaps we measured, with a zero-false-positive study and a mitigation map."},

 7: {"n":7,"title":"Two measurement axes","kicker":"Design","layout":"two-panel","body":[
    "Axis A — static / file dimension",
    "  v0  bare EICAR on disk: baseline signature match",
    "  v1  XOR 0x5A + Base64 on disk: obfuscation test",
    "  v2  decode-to-disk: on-write scan of a plaintext artefact",
    "  v3  in-memory / fileless: never-on-disk test",
    "  EICAR kept encoded in source → repo + binaries stay AV-clean",
    "  Built with csc.exe .NET Framework v4.0.30319 (no Visual Studio)",
    "Axis B — runtime / behaviour dimension",
    "  Invoke-AtomicRedTeam v2.3.0, scenario groups G1-G5",
    "  11 MITRE ATT&CK techniques, Atomic test #1 each",
    "  Exercises RTP, AMSI, behaviour, ASR, Tamper Protection",
    "  Reacts to the technique performed, not a file on disk"],
    "callout":["Two orthogonal axes, two separate questions: does obfuscation beat the file scanner, and does Defender react to behaviour?"],
    "notes":"We split the experiment on purpose so the static signature layer and the runtime layers are never confounded. Axis A hands Defender the same EICAR proxy in four increasingly evasive forms, from a bare file to a fileless loader. Axis B drives eleven real ATT&CK techniques with Invoke-AtomicRedTeam to probe RTP, AMSI, behaviour monitoring, ASR and Tamper Protection. Keeping EICAR encoded in source means the committee can clone the repo without a single Defender alert."},

 8: {"n":8,"title":"Four states, one fidelity gate","kicker":"Scoring","layout":"two-panel","body":[
    "Four scoring states — db_writer asserts the state",
    "  error: harness failed at build/trigger/collect; says nothing about Defender",
    "  inconclusive: ran, but evidence can't decide detected vs not",
    "  detected: an in-window Defender detection against the stimulus",
    "  not_detected: stimulus reached Defender, no detection — a genuine gap",
    "Fidelity model — valid only when score ≥ 0.5",
    "  reset_ok, technique_ran, collect_window_complete, clean_before",
    "  Proves the atomic RAN, not that the malicious effect occurred",
    "Two rules learned on real data",
    "  A Defender block counts as delivery + detection (outranks error/fidelity gates)",
    "  A non-run never scores not_detected (requires the 'Executing test' marker)"],
    "callout":["The four states exist to separate a real coverage gap from a measurement failure."],
    "notes":"Every trial resolves to exactly one of four states, and db_writer refuses to store anything else. The crucial pair is detected versus not_detected: a not_detected is only earned once we can prove the stimulus actually reached Defender. Fidelity, built from four boolean conditions, is the gate that certifies a trial was well-formed; below 0.5 we discard the result. Both scoring rules were forced on us by real data, and they keep honest gaps from being buried as errors."},

 9: {"n":9,"title":"Architecture: three blocks, one loop","kicker":"System","layout":"architecture","body":[],
    "notes":"The tool is three cooperating blocks over one repeatable loop. Blocks one and two produce the stimulus — the payload variants and the behavioural atomics — while block three, the measurement station, runs every trial through the same seven-stage pipeline and writes the verdict to SQLite. Because each stage is deterministic and logged, any single measurement can be reconstructed from its row. It is plain Python 3.12 with only pyyaml added, and 61 unit tests cover the scorer, fidelity and orchestrator."},

 10: {"n":10,"title":"Evidence and traceability","kicker":"Evidence","layout":"two-panel","body":[
    "Defender Operational log — event IDs the scorer reads",
    "  1116 / 1117: malware detected / remediation action taken",
    "  1015 / 1119: behaviour-monitoring detection",
    "  5013: Tamper Protection block — a config event, NOT a detection",
    "  2010: cloud-protection (MAPS) lookup performed",
    "  1121: ASR rule block",
    "  Sysmon (EID 10, process access) UNAVAILABLE — image-level VM bug",
    "Traceability — every measurement is self-describing",
    "  Row = sample SHA-256 + trigger timestamp + Defender signature version",
    "  SQLite runs / measurements: state, fidelity, layer, latency, event IDs",
    "  Pinning the signature separates a real gap from signature churn"],
    "callout":["Verdicts come from OS telemetry, never from the exit code of the tool under test."],
    "notes":"Detections are grounded in the Windows Defender Operational log, not tool exit codes. Only the true-detection families — 1116/1117 and 1015/1119 — move a verdict to detected; 5013 is explicit Tamper-Protection noise and is deliberately ignored, which matters because our own reset emits it. Sysmon was meant to corroborate the behaviour axis via EID 10 but was unavailable owing to an image defect, and we state that plainly. Every row carries the hash, timestamp and pinned signature version, so a later reader can tell a real gap from signature drift."},

 11: {"n":11,"title":"Isolated VM, locked config, safety boundary","kicker":"Environment","layout":"two-panel","body":[
    "cloud-vm — the only place official measurements run",
    "  Azure Windows 11 Pro, Insider build 26300",
    "  RTP ON, Tamper ON, cloud-delivered protection OFF (baseline)",
    "  Defender AMEngine 1.1.26100.4, signature 1.463.490.0 (pinned)",
    "  Restored from a clean snapshot before every invasive run",
    "Safety boundary — config.yaml machine_label lock",
    "  dev-win11: build + smoke-test only; runner BLOCKS all invasive techniques",
    "  dev-win11: reset.ps1 never touches Defender or its logs",
    "  cloud-vm: invasive techniques + all official runs, network-isolated",
    "  One variable changed per spot-check; revert to snapshot if state looks wrong"],
    "callout":["A single config lock keeps destructive work off the dev machine and on the isolated VM."],
    "notes":"All invasive work — LSASS dumps, disabling Defender, persistence, credential theft — runs only on a network-isolated Azure VM restored from a clean snapshot. The baseline is a near-default consumer configuration: RTP and Tamper on, cloud off, engine and signature pinned for reproducibility. A single machine_label in config.yaml enforces the boundary: on the dev box the runner refuses every invasive technique and reset never touches Defender. That let us run genuinely dangerous procedures safely while keeping the dev machine — and the committee's own clone — untouched."},

 13: {"n":13,"title":"Axis A: signature vs form","kicker":"Results · Axis A","layout":"axisa","body":[
    "Same C# payload, four presentations to Defender's static engine; fidelity 1.0 on every variant."],
    "table_headers":["Variant","Form presented to Defender","Result"],
    "table_rows":[["v0","Bare sample, raw bytes on disk","DETECTED"],
                  ["v1","String-encoded on disk (XOR 0x5A + Base64)","not_detected"],
                  ["v2","Decode-to-disk, then present raw","DETECTED"],
                  ["v3","In-memory / fileless, never on disk","not_detected"]],
    "callout":["Takeaway","Signature fires only when cleartext bytes land on disk (v0, v2).","Encoding (v1) and fileless (v3) pass clean."],
    "notes":"The Axis A result in one table. We built four C# variants around EICAR as a benign proxy; the only thing that changes is how the sample is presented to Defender. The two that write raw bytes to disk — v0 and v2 — are detected. The two that don't expose raw bytes — v1 (stays encoded) and v3 (never touches disk) — are missed. Fidelity is 1.0 for all four, so the misses are real evasions, not failed executions."},

 14: {"n":14,"title":"Why obfuscation and fileless win","kicker":"Results · Axis A","layout":"content","body":[
    "Identical logic payload in all four variants — only the form differs.",
    "Detection reduces to one mechanism: on-disk signature matching of cleartext bytes.",
    "v2 is the built-in control: the same raw bytes are caught the instant they hit disk.",
    "v1 keeps bytes encoded (XOR 0x5A + Base64) — the file scan reads nothing malicious.",
    "v3 never writes the sample — there is no file for the scanner to open.",
    "So v1 and v3 are the same sample routed around one check, not stronger malware.",
    "These two gaps are exactly what the two supplementary YARA rules target."],
    "callout":["Why it matters","v2 proves the bytes are in the signature set —","so v1/v3 are evasions of a single mechanism,","not a harder detection problem."],
    "notes":"Here I interpret the Axis A table rather than just report it. The malicious logic is constant across all four variants — what changes is purely the form presented to the engine. v2 acts as a built-in control: it decodes to disk and is immediately detected, proving the bytes themselves are known to the signature set. So v1 and v3 are not harder malware — they are the same sample routed around a single mechanism, on-disk signature matching. That is precisely why we wrote two YARA rules: one for the encoded-on-disk form and one for the fileless loader."},

 15: {"n":15,"title":"Defender stopped 2, missed 9","kicker":"Results · Axis B","layout":"stat","body":[],
    "notes":"The headline of the whole study. Across eleven ATT&CK techniques — Atomic test #1 of each — Defender detected two and missed nine, an 18.2% detection rate on the behaviour axis. The two it caught came from two different layers, neither signature: AMSI caught the Mimikatz PowerShell in about 3.8 seconds, and Tamper Protection blocked the attempt to disable Defender. The nine it missed span discovery, LOLBins, persistence, credential access and deobfuscation — and every one survived our cloud-ON and ASR spot-checks, so they are genuine coverage gaps, not an artefact of cloud being off."},

 16: {"n":16,"title":"The two wins, two layers","kicker":"Results · Axis B","layout":"twowins","body":[
    "T1059.001 — Mimikatz via PowerShell",
    "  Blocked by AMSI at runtime in ~3.8 s (script-content scanning).",
    "  Events 1116 + 1117; the atomic itself failed with 'Access is denied'.",
    "T1562.001 — disable Defender (Impair Defenses)",
    "  Blocked by Tamper Protection, Defender's self-defence layer.",
    "  Scored by direct RTP-state check (reset.ps1 5013 noise confounds the event window).",
    "  Verified: RTP never dropped; the block landed at trigger time."],
    "callout":["Neither win is a signature catch — both are behaviour / self-defence: AMSI (script content) and Tamper Protection (config integrity)."],
    "notes":"The two wins come from genuinely different layers. T1059.001: AMSI caught the Mimikatz script at execution time, ~3.8 s, logging events 1116 and 1117, and the atomic died with access-denied — runtime script-content scanning, not a file signature. T1562.001, the attempt to disable Defender: Tamper Protection blocked it. We scored this one by directly verifying the RTP state rather than through the event-window pipeline, because our own reset script toggles RTP and emits 5013 events inside the collection window, which would confound event scoring. Direct verification showed RTP never dropped, the 5013 block landed at the trigger time, and no 5007/5001 config-change events fired. Both wins are behavioural/self-defence, not signature."},

 17: {"n":17,"title":"The 9 gaps span the kill chain","kicker":"Results · Axis B","layout":"killchain","body":[
    "Discovery - T1082, T1057: host and process recon runs unseen, scoping later stages.",
    "Execution / LOLBin - T1218.010 Regsvr32, T1059.003 cmd: signed binaries ride on trust.",
    "Persistence - T1547.001 Run Key, T1053.005 Scheduled Task: footholds survive reboot undetected.",
    "Credential Access - T1003.001 LSASS, T1555 password stores: secrets harvested silently.",
    "Defense Evasion - T1140 Deobfuscate/Decode: payloads unpacked with no alarm raised."],
    "notes":"The nine gaps cover the full behavioural spectrum, which is what makes them concerning. Discovery: both system and process enumeration ran with no detection. Execution via signed LOLBins: Regsvr32 and cmd both passed, because the binaries are trusted. Persistence: the Run Key and the Scheduled Task both installed cleanly, so a foothold survives reboot. Credential access: LSASS dumping and password-store theft both went unseen — and even the dedicated LSASS ASR rule missed it in our spot-check. Deobfuscation, T1140, unpacked with no alarm. Each maps to a supplementary Sigma or YARA rule, except T1555 and T1140 which remain future work."},

 18: {"n":18,"title":"The gaps are real","kicker":"Validity","layout":"table","body":[
    "Objection tested: are the 9 misses just a cloud-OFF or ASR-OFF artefact?",
    "One variable changed per spot-check; Defender build pinned (AMEngine 1.1.26100.4, sig 1.463.490.0)."],
    "table_headers":["Technique","Baseline","Cloud-ON (run 9)","ASR Block (run 10)"],
    "table_rows":[["T1003.001 LSASS dump","not_detected","not_detected","not_detected (no 1121)"],
                  ["T1547.001 Run Key","not_detected","not_detected","not tested"],
                  ["T1218.010 Regsvr32","not_detected","not_detected","not tested"],
                  ["T1059.001 (control)","DETECTED","DETECTED (+2010 x3)","not tested"]],
    "callout":["Cloud-ON delta: 0 / 3 flipped","Control fired 2010 x3 → cloud genuinely live","ASR Block still missed LSASS (no 1121)","Gaps = a product property, not a config artefact"],
    "notes":"The committee's first question will be whether we rigged the baseline by leaving cloud off. We answer directly: in run 9 we toggled only cloud protection and re-measured three gaps plus a control. The delta was zero of three, and the control T1059.001 stayed detected and fired three event-2010 cloud lookups, proving the cloud path was active. Run 10 then enabled only the LSASS ASR rule in Block mode, and LSASS dumping still went undetected with no 1121 event. The gaps survive the strongest cheap attempts to explain them away."},

 19: {"n":19,"title":"Three bugs found on real data","kicker":"Rigor","layout":"content","body":[
    "Running on real telemetry — not just reasoning — surfaced three scoring defects, each fixed:",
    "  Layer-by-axis: a behaviour-axis catch is a runtime/AMSI detection, never a static file scan.",
    "  Block = detection: a Defender block with in-window events scores detected; detections outrank the gates.",
    "  No false 'ran': a missing atomic made Invoke-AtomicTest exit 0 while printing an error on stdout.",
    "  Fix: the runner now requires the 'Executing test' marker and rejects 'does not exist'.",
    "Install-check: 10/11 atomics installed; only T1562.001 was missing (its run_id 11 is now corrected).",
    "Every other measurement used an installed atomic and stands; 61 unit tests pass."],
    "callout":["Net effect","A non-run now scores inconclusive / error — never a false not_detected."],
    "notes":"This slide is about measurement integrity. Three bugs only showed up once we scored real telemetry. The most consequential was the false-ran bug: the T1562.001 atomic was never installed, Invoke-AtomicTest exited zero while printing that the file did not exist, and the old runner counted that as a real not_detected. Requiring the Executing-test marker fixed it, and an install-check across all eleven IDs confirmed only that one run was invalid, so every other verdict holds. The hardened tool passes all 61 unit tests."},

 21: {"n":21,"title":"YARA closes the payload gaps","kicker":"Rule set","layout":"yara","body":[
    "Two rules — one per Axis A gap the signature engine missed",
    "  KTLD_Encoded_Sample_On_Disk → the v1 encoded sample (XOR 0x5A + Base64 blob)",
    "  KTLD_Payload_Loader_Binary → the loader/dropper; catches fileless v3 by its on-disk loader",
    "  Rules embed only the obfuscated blob + ordinary .NET loader strings",
    "  No plaintext signature → repo + build outputs stay AV-clean"],
    "callout":["Live validation (rules/fp_scan.py)","5 / 5 true positives (1 encoded sample + 4 loaders)","0 false positives / 12,450 goodware files","corpus: System32 + SysWOW64 + .NET Framework","precision = recall = 1.0"],
    "notes":"Defender caught the raw sample on disk but missed the two payload forms that matter: trivial obfuscation and fileless loading. We wrote exactly two YARA rules, one per measured gap, following a minimalism principle — a supplementary rule only where Defender was shown to fail. The fileless v3 is caught by its on-disk loader, which is the pragmatic hook. The rule files embed only the already-obfuscated blob so the repository never trips an AV scan. These are our strongest-validated rules: five of five true positives and zero false positives over 12,450 real goodware files."},

 22: {"n":22,"title":"Sigma closes the behaviour gaps","kicker":"Rule set","layout":"two-panel","body":[
    "Seven Sigma rules — one per not_detected technique amenable to a generic rule",
    "  T1082, T1057 discovery (process creation)",
    "  T1218.010 Regsvr32, T1059.003 cmd (process creation)",
    "  T1547.001 Run Key (registry), T1053.005 Scheduled Task",
    "  T1003.001 LSASS → Sysmon EID 10, the primary gap-filler (RTP+cloud+ASR all missed it)",
    "  Each rule cites the run_id that evidenced its gap"],
    "callout":["7 / 7 logic-validated","fire on crafted positive events, silent on benign (sigma_validate.py)","Honest caveat: live-telemetry FP study BLOCKED","Sysmon unavailable (image-level bug)","deployed Sigma FP rate remains an open item"],
    "notes":"For the behavioural gaps we wrote seven Sigma rules, each traceable to the run_id that documented the gap. The LSASS rule is the headline one: because RTP, cloud, and the dedicated ASR rule all missed T1003.001, a Sysmon-EID-10 process-access rule is the only remaining control in this configuration. We are deliberately honest: all seven pass logical validation, firing on crafted positive events and staying silent on benign ones, but we could not run a live false-positive study because Sysmon would not load on the VM. Unlike the YARA rules, the Sigma rules carry no field false-positive figure yet, and we flag that as open."},

 23: {"n":23,"title":"Technique → layer → fix","kicker":"Mitigation","layout":"table","body":[
    "Two confirmed wins across two layers; most gaps map to a concrete supplementary control."],
    "table_headers":["Technique","Verdict","Defender layer","Fix / supplementary rule"],
    "table_rows":[["T1059.001 PowerShell (Mimikatz)","detected","AMSI (~3.8 s)","Covered — keep AMSI on"],
                  ["T1562.001 Impair Defenses","detected","Tamper Protection","Covered — keep Tamper on"],
                  ["T1003.001 LSASS dump","not_detected","none (ASR missed)","LSASS Sigma (EID 10) + ASR defence-in-depth"],
                  ["T1547.001 / T1053.005 persistence","not_detected","none","Sigma + registry / task auditing"],
                  ["T1218.010 / T1059.003 LOLBins","not_detected","none","Sigma + WDAC / AppLocker"],
                  ["Axis A v1 / v3 payloads","not_detected","none (signature)","2 YARA rules (encoded + loader)"],
                  ["T1555 / T1140 (stores, deobfuscation)","not_detected","none","Future work — cred-vault + deobfuscation auditing"]],
    "callout":["Minimalism: a rule only where Defender was measured to fail","2 YARA + 7 Sigma, each tied to a run_id gap","T1555 + T1140: no rule yet — flagged as future work"],
    "notes":"The actionable synthesis: for each measured technique, which Defender layer stopped it, and if none did, what we recommend. The two wins come from two different layers — AMSI on the script buffer and Tamper Protection on Defender's own config — and the advice is to keep them on. For LSASS we pair the Sigma rule with the ASR rule as defence-in-depth. Persistence and LOLBin gaps need native auditing and application control. The two payload gaps are closed by the YARA rules. Two gaps — T1555 and T1140 — have no rule yet and are honestly marked as future work. Every row traces to a measured verdict."},

 24: {"n":24,"title":"Read the results within these bounds","kicker":"Limitations","layout":"content","body":[
    "Atomic test #1 only: a miss means this variant evaded Defender, not every variant of the technique.",
    "Default-ish consumer config: enterprise EDR, tuned ASR, and WDAC would likely catch more.",
    "Fidelity proves execution, not effect: the atomic ran and Defender could react — not that the effect landed.",
    "Sysmon unavailable (image-level bug): no live-telemetry false-positive figure for the EID-10 Sigma rules.",
    "EICAR is a benign proxy: measures the signature / fileless path, not real-malware heuristics or reputation."],
    "callout":["Note","The ASR spot-check illustrates #1:","another LSASS atomic might well trip 1121."],
    "notes":"We want the committee to see exactly how far these claims reach. Five caveats bound them. We ran only the first atomic per technique, so a miss is scoped to that implementation — the ASR result shows how much variant choice matters. The target is a near-default consumer box, not hardened enterprise. Fidelity confirms the stimulus was delivered, not that the full malicious effect landed. Sysmon never loaded, so the Sysmon-keyed Sigma rules have no live false-positive number. And the payload is EICAR, a faithful proxy for signature behaviour but not for heuristic or cloud-reputation responses. Within those bounds, the gaps are real."},

 25: {"n":25,"title":"Conclusion & recommendations","kicker":"Conclusion","layout":"content","body":[
    "Defender defends what it knows: raw on-disk files (signature), script buffers (AMSI), its own config (Tamper).",
    "It is largely blind to attacker behaviour: 2/11 stopped (18.2%); obfuscated v1 and fileless v3 both missed.",
    "Cloud-ON (0/3) and the LSASS ASR rule did not close the gaps — real coverage limits, not config artefacts.",
    "The rules close the measured gaps: 2 YARA (0 FP / 12,450) + 7 Sigma; T1555 and T1140 remain future work.",
    "Recommend: deploy the rule set; keep AMSI and Tamper Protection enabled.",
    "Recommend: enable the LSASS ASR rule + the LSASS Sigma (EID 10) as defence-in-depth.",
    "Recommend: turn on command-line, registry and scheduled-task auditing for the persistence/discovery gaps.",
    "Recommend: constrain Regsvr32 and cmd LOLBins with WDAC / AppLocker."],
    "callout":["Future work","Run every atomic per technique;","repair Sysmon for a live Sigma FP study;","write rules for T1555 + T1140;","test beyond the EICAR proxy."],
    "notes":"To close: within a reproducible, automated framework, Defender defends content it already knows but is largely blind to behaviour. It stopped two of eleven techniques and caught only the two payload variants that wrote plaintext to disk, and our spot-checks prove neither cloud nor ASR rescues the rest. The contribution is a validated, low-false-positive rule set that covers the worst blind spots. The recommendations are concrete and ordered by impact: deploy the rules, keep the two working layers on, add LSASS defence-in-depth, enable the auditing the Sigma rules need, and constrain LOLBins. Future work repairs Sysmon, broadens the atomic matrix, and closes the two remaining gaps."},
}

RENDER = {
    "list": render_list, "cards": render_cards, "two-panel": render_panels,
    "content": render_content, "table": render_table, "architecture": render_architecture,
    "stat": render_stat, "killchain": render_killchain,
    "axisa": render_axisa_table, "twowins": render_twowins, "yara": render_yara,
}

# ===================== assemble in order =====================
import sys

def emit(n):
    try:
        RENDER[S[n]["layout"]](S[n])
    except Exception as e:
        sys.stderr.write("FAIL slide %d (%s): %s\n" % (n, S[n]["layout"], e))
        raise

build_title()                                                        # 1
for n in (2, 3, 4, 5):
    emit(n)
build_divider("Part I", "Methodology & System Design",
              "Two axes, four scoring states, a fidelity gate, and the measurement loop.")  # 6
for n in (7, 8, 9, 10, 11):
    emit(n)
build_divider("Part II", "Measurement Results & Validity",
              "What Defender caught on each axis — and the proof the gaps are real.")     # 12
for n in (13, 14, 15, 16, 17, 18, 19):
    emit(n)
build_divider("Part III", "Supplementary Rules & Mitigation",
              "YARA and Sigma for the measured gaps, the mitigation map, and conclusions.")  # 20
for n in (21, 22, 23, 24, 25):
    emit(n)

prs.save("report/KTLD_Slides.pptx")
print("saved report/KTLD_Slides.pptx with", len(prs.slides._sldIdLst), "slides")
