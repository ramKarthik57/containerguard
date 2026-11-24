import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # --- Color Palette ---
    C_NAVY_DARK = RGBColor(15, 23, 42)      # #0F172A (Slate 900)
    C_NAVY_LIGHT = RGBColor(30, 41, 59)     # #1E293B (Slate 800)
    C_BLUE_BRAND = RGBColor(30, 58, 138)    # #1E3A8A (Blue 900)
    C_BLUE_ACCENT = RGBColor(2, 132, 199)   # #0284C7 (Sky 600)
    C_TEAL = RGBColor(13, 148, 136)         # #0D9488 (Teal 600)
    C_GREEN = RGBColor(6, 95, 70)           # #065F46 (Emerald 800)
    C_GREEN_BG = RGBColor(236, 253, 245)    # #ECFDF5 (Emerald 50)
    C_RED = RGBColor(153, 27, 27)           # #991B1B (Red 800)
    C_RED_BG = RGBColor(254, 242, 242)      # #FEF2F2 (Red 50)
    C_AMBER = RGBColor(180, 83, 9)          # #B45309 (Amber 700)
    C_AMBER_BG = RGBColor(255, 251, 235)    # #FFFBEB (Amber 50)
    C_BG_LIGHT = RGBColor(248, 250, 252)    # #F8FAFC (Slate 50)
    C_WHITE = RGBColor(255, 255, 255)
    C_TEXT_DARK = RGBColor(15, 23, 42)      # Slate 900
    C_TEXT_MUTED = RGBColor(100, 116, 139)  # Slate 500
    C_BORDER_LIGHT = RGBColor(203, 213, 225)# Slate 300

    assets_dir = "/home/ram/ebpf-smoke-test/docs/ppt_assets"

    def add_header(slide, tracker, title, subtitle=None):
        # Top banner category
        tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.35))
        tf = tb.text_frame
        tf.word_wrap = True
        tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.text = tracker.upper()
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = C_BLUE_ACCENT

        # Slide Main Title
        tb2 = slide.shapes.add_textbox(Inches(0.8), Inches(0.72), Inches(11.7), Inches(0.6))
        tf2 = tb2.text_frame
        tf2.word_wrap = True
        tf2.margin_left = tf2.margin_top = tf2.margin_right = tf2.margin_bottom = 0
        p2 = tf2.paragraphs[0]
        p2.text = title
        p2.font.size = Pt(22)
        p2.font.bold = True
        p2.font.color.rgb = C_NAVY_DARK

        # Subtitle if present
        if subtitle:
            tb3 = slide.shapes.add_textbox(Inches(0.8), Inches(1.28), Inches(11.7), Inches(0.35))
            tf3 = tb3.text_frame
            tf3.word_wrap = True
            tf3.margin_left = tf3.margin_top = tf3.margin_right = tf3.margin_bottom = 0
            p3 = tf3.paragraphs[0]
            p3.text = subtitle
            p3.font.size = Pt(11)
            p3.font.color.rgb = C_TEXT_MUTED

    def add_card(slide, left, top, width, height, bg_color=C_WHITE, border_color=C_BORDER_LIGHT):
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        shape.fill.solid()
        shape.fill.fore_color.rgb = bg_color
        if border_color:
            shape.line.color.rgb = border_color
            shape.line.width = Pt(1.2)
        else:
            shape.line.fill.background()
        return shape

    # =========================================================================
    # SLIDE 1: TITLE SLIDE (Dark Navy Premium Theme)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    bg1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg1.fill.solid()
    bg1.fill.fore_color.rgb = C_NAVY_DARK
    bg1.line.fill.background()

    # Title Banner Accent Line
    acc1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.0), Inches(1.1), Inches(1.2), Inches(0.08))
    acc1.fill.solid()
    acc1.fill.fore_color.rgb = C_BLUE_ACCENT
    acc1.line.fill.background()

    # Main Project Title
    t_box1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.3), Inches(11.3), Inches(1.2))
    tf1 = t_box1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "ContainerGuard"
    p.font.size = Pt(46)
    p.font.bold = True
    p.font.color.rgb = C_WHITE

    # Subtitle
    sub_box1 = s1.shapes.add_textbox(Inches(1.0), Inches(2.4), Inches(11.3), Inches(0.8))
    tf_sub = sub_box1.text_frame
    tf_sub.word_wrap = True
    p = tf_sub.paragraphs[0]
    p.text = "In-Kernel eBPF Telemetry & Deterministic Container Runtime Security"
    p.font.size = Pt(20)
    p.font.bold = True
    p.font.color.rgb = RGBColor(56, 189, 248) # Sky 400

    # Review Badge
    desc_box = s1.shapes.add_textbox(Inches(1.0), Inches(3.2), Inches(11.3), Inches(0.6))
    tf_desc = desc_box.text_frame
    p = tf_desc.paragraphs[0]
    p.text = "Zeroth Review Project Presentation — Capstone Engineering Defense & Technical Specification"
    p.font.size = Pt(13)
    p.font.color.rgb = RGBColor(148, 163, 184)

    # 3 Badges
    badges = [
        ("✓ Phase I Milestone: 100% Verified", RGBColor(16, 185, 129), RGBColor(6, 78, 59)),
        ("Linux 6.18+ Kernel eBPF (CO-RE)", RGBColor(56, 189, 248), RGBColor(30, 58, 138)),
        ("Zero Telemetry Loss Invariant", RGBColor(248, 113, 113), RGBColor(127, 29, 29))
    ]
    bx = Inches(1.0)
    for text, border_c, bg_c in badges:
        b_shp = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, bx, Inches(4.0), Inches(3.5), Inches(0.5))
        b_shp.fill.solid()
        b_shp.fill.fore_color.rgb = bg_c
        b_shp.line.color.rgb = border_c
        b_shp.line.width = Pt(1.5)
        btf = b_shp.text_frame
        p = btf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        p.text = text
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = border_c
        bx += Inches(3.7)

    # Metadata Card at Bottom
    meta_card = add_card(s1, Inches(1.0), Inches(4.85), Inches(11.333), Inches(1.85), RGBColor(30, 41, 59), RGBColor(51, 65, 85))
    mtf = meta_card.text_frame
    mtf.word_wrap = True
    mtf.margin_left = Inches(0.3)
    mtf.margin_top = Inches(0.2)

    p = mtf.paragraphs[0]
    p.text = "PROJECT METADATA & COMMITTEE REFERENCE"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = RGBColor(56, 189, 248)

    meta_items = [
        "Project Domain: Cloud Native Systems Security, Linux Kernel Subsystems & Applied eBPF",
        "Target Platform: Linux 6.18+ (Native x86_64 / WSL2 cgroup v2) | Docker Engine v27+",
        "Repository & Codebase: https://github.com/ramKarthik57/containerguard (master branch)",
        "Audit Status: 100% Phase I Empirical Acceptance (125/125 events, 14/14 test assertions passed)"
    ]
    for item in meta_items:
        p = mtf.add_paragraph()
        p.text = "• " + item
        p.font.size = Pt(10)
        p.font.color.rgb = RGBColor(226, 232, 240)

    # =========================================================================
    # SLIDE 2: EXECUTIVE SUMMARY & NOVELTY
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_header(s2, "Executive Overview", "Project Executive Summary & Core Novelty", "Solving high-frequency container runtime observability blind spots with sub-microsecond eBPF telemetry")

    card_w = Inches(3.64)
    card_h = Inches(5.0)

    # Card 1: Problem
    add_card(s2, Inches(0.8), Inches(1.8), card_w, card_h, C_RED_BG, RGBColor(248, 113, 113))
    tb = s2.shapes.add_textbox(Inches(1.0), Inches(2.0), card_w - Inches(0.4), card_h - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "THE PROBLEM"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_RED

    p = tf.add_paragraph()
    p.text = "Traditional Runtime Blindness"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    points1 = [
        "Modern cloud workloads launch thousands of ephemeral containers daily (<50ms lifecycles).",
        "Traditional tools (/proc pollers, auditd, ptrace) introduce 15-30% syscall latency or miss short-lived executions entirely.",
        "Operating system PID wrapping causes process ancestry trees to collide and report false lineage.",
        "Silent ring buffer drops during execution bursts blind security analysts to coordinated attacks."
    ]
    for pt in points1:
        p = tf.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = C_NAVY_LIGHT

    # Card 2: Solution
    add_card(s2, Inches(4.84), Inches(1.8), card_w, card_h, RGBColor(240, 249, 255), RGBColor(186, 230, 253))
    tb = s2.shapes.add_textbox(Inches(5.04), Inches(2.0), card_w - Inches(0.4), card_h - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "THE INNOVATION"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    p = tf.add_paragraph()
    p.text = "In-Kernel eBPF Telemetry"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    points2 = [
        "5 Coordinated Kernel Tracepoints: Intercepts exec entry, binary commit, and errno exits.",
        "Immutable Identity: Decoupled ProcessInstanceKey(TGID, StartTimeNS) immune to PID reuse.",
        "Cgroup v2 Inode Grounding: Tombstone cache eliminates races for killed containers.",
        "Mathematical Conservation: Atomic hardware counters prove zero untracked dropped events."
    ]
    for pt in points2:
        p = tf.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = C_NAVY_LIGHT

    # Card 3: Results
    add_card(s2, Inches(8.88), Inches(1.8), card_w, card_h, C_GREEN_BG, RGBColor(167, 243, 208))
    tb = s2.shapes.add_textbox(Inches(9.08), Inches(2.0), card_w - Inches(0.4), card_h - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "VERIFIED OUTCOMES"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_GREEN

    p = tf.add_paragraph()
    p.text = "Phase I 50% Milestone"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    points3 = [
        "100% Empirical Pass: 14/14 test assertions verified across all Linux execution pathways.",
        "Zero Lost Telemetry: 125/125 events delivered with perfect monotonic sequence continuity.",
        "Minimal Host Overhead: +3.46% execution time (+7.77 microseconds per syscall).",
        "Ultra-Light Footprint: 6.02 MiB RSS daemon memory usage on Linux 6.18+."
    ]
    for pt in points3:
        p = tf.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 3: PROBLEM DEFINITION & MOTIVATION
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_header(s3, "Problem Statement", "Motivation: The Container Runtime Observability Crisis", "Why microservice architectures break conventional Linux security instrumentation models")

    # Left Card: Container Dynamics
    w_half = Inches(5.6)
    add_card(s3, Inches(0.8), Inches(1.8), w_half, Inches(5.0), C_WHITE)
    tb = s3.shapes.add_textbox(Inches(1.0), Inches(2.0), w_half - Inches(0.4), Inches(4.6))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "THE CLOUD-NATIVE THREAT LANDSCAPE"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    challenges = [
        ("Ephemeral Container Lifecycles", "Serverless jobs, build containers, and admission hooks execute in <50ms. Traditional agents querying Docker socket or polling /proc fail to capture these processes before they terminate."),
        ("Namespace Masking & Root Concealment", "Containers run within isolated user and PID namespaces. An adversary executing as root inside a container sees PID 1, while on the host they execute as an unprivileged UID with a high recycled PID."),
        ("Fileless In-Memory Attack Vectors", "Modern malware allocates anonymous memory via memfd_create(2) and executes filelessly using execveat(AT_EMPTY_PATH). On-disk endpoint scanners detect nothing because no file touches disk.")
    ]
    for title, desc in challenges:
        p = tf.add_paragraph()
        p.text = title
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = C_NAVY_DARK
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(10.5)
        p.font.color.rgb = C_NAVY_LIGHT

    # Right Card: The Traditional Monitoring Dead End
    add_card(s3, Inches(6.8), Inches(1.8), w_half, Inches(5.0), C_WHITE)
    tb = s3.shapes.add_textbox(Inches(7.0), Inches(2.0), w_half - Inches(0.4), Inches(4.6))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "WHY TRADITIONAL TOOLS FAIL"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_RED

    failures = [
        ("Linux auditd: Kernel Netlink Bottleneck", "Synchronous logging creates massive CPU contention under heavy execve loads (15-30% overhead), forcing administrators to disable exec logging on production clusters."),
        ("Periodic /proc Pollers: Race Condition Prone", "Polling /proc on 1s or 5s intervals misses transient micro-processes completely, leaving massive forensic gaps during rapid payload execution."),
        ("Silent Drops: The Absence-of-Proof Fallacy", "When kernel-to-user queues overflow under burst pressure, standard tools drop records silently. Analysts mistake zero alerts for a secure cluster when an attack occurred.")
    ]
    for title, desc in failures:
        p = tf.add_paragraph()
        p.text = title
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = C_NAVY_DARK
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(10.5)
        p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 4: THE 5 RUNTIME BLIND SPOTS
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_header(s4, "Root Cause Analysis", "The 5 Runtime Blind Spots & ContainerGuard Defenses", "Direct 1-to-1 mapping between operating system failure modes and architectural countermeasures")

    # Embed Figure 1
    fig1_path = os.path.join(assets_dir, "fig1_blindspots.png")
    if os.path.exists(fig1_path):
        s4.shapes.add_picture(fig1_path, Inches(0.8), Inches(1.75), width=Inches(11.733))

    # Summary Callout Card underneath
    c_bot = add_card(s4, Inches(0.8), Inches(5.7), Inches(11.733), Inches(1.3), C_BG_LIGHT, C_BLUE_ACCENT)
    ctf = c_bot.text_frame
    ctf.word_wrap = True
    ctf.margin_left = Inches(0.25)
    ctf.margin_top = Inches(0.15)
    p = ctf.paragraphs[0]
    p.text = "KEY ARCHITECTURAL TAKEAWAY"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND
    p = ctf.add_paragraph()
    p.text = "ContainerGuard eliminates all five blind spots simultaneously: PID wrapping is solved via immutable nanosecond start-time keys; ephemeral races are captured via tombstone caching; cgroup migrations are tracked in-place; buffer drops are mathematically conserved; and fileless execution is intercepted at kernel tracepoint entry."
    p.font.size = Pt(10)
    p.font.color.rgb = C_NAVY_DARK

    # =========================================================================
    # SLIDE 5: LITERATURE SURVEY & COMPARATIVE ANALYSIS
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_header(s5, "Literature Survey", "Existing Systems vs. ContainerGuard Comparative Analysis", "Rigorous technical feature comparison against industry and open-source monitoring systems")

    # Comparison Table
    t_shp = s5.shapes.add_table(6, 5, Inches(0.8), Inches(1.8), Inches(11.733), Inches(5.0))
    table = t_shp.table
    table.columns[0].width = Inches(2.333)
    table.columns[1].width = Inches(2.2)
    table.columns[2].width = Inches(2.4)
    table.columns[3].width = Inches(2.4)
    table.columns[4].width = Inches(2.4)

    headers = ["Evaluation Dimension", "Linux auditd", "Sysdig / Falco", "Tetragon / Tracee", "ContainerGuard (Ours)"]
    for col_idx, h in enumerate(headers):
        cell = table.cell(0, col_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = C_NAVY_DARK
        p = cell.text_frame.paragraphs[0]
        p.text = h
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_WHITE

    rows = [
        ("Kernel Hook Mechanism", "Synchronous Netlink", "Kernel Module / eBPF", "eBPF kprobes / tracepoints", "5 Coordinated Tracepoints (CO-RE)"),
        ("Identity Key Anchor", "Integer PID (Wraps)", "PID / Comm String", "PID + Namespace", "Immutable (TGID, StartTimeNS)"),
        ("Container Inode Binding", "Path heuristic (/proc)", "Container socket poll", "Cgroup path string", "Cgroup v2 Inode + Tombstone Cache"),
        ("Loss Accounting Law", "Silent netlink drop", "Drop counters (sampling)", "Buffer overflow flags", "Strict Conservation Invariant (Hooks = Sub + Drop)"),
        ("Syscall Overhead (Exec)", "+15% to +30%", "+8% to +14%", "+5% to +9%", "+3.46% (7.77 us latency, 6 MiB RSS)")
    ]

    for row_idx, r_data in enumerate(rows):
        for col_idx, val in enumerate(r_data):
            cell = table.cell(row_idx + 1, col_idx)
            cell.fill.solid()
            if col_idx == 4:
                cell.fill.fore_color.rgb = C_GREEN_BG
            elif row_idx % 2 == 1:
                cell.fill.fore_color.rgb = C_BG_LIGHT
            else:
                cell.fill.fore_color.rgb = C_WHITE
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.size = Pt(10)
            if col_idx == 4:
                p.font.bold = True
                p.font.color.rgb = C_GREEN
            elif col_idx == 0:
                p.font.bold = True
                p.font.color.rgb = C_NAVY_DARK
            else:
                p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 6: PROPOSED SOLUTION & CORE CONTRIBUTIONS
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_header(s6, "Proposed Methodology", "Core Technical Innovations & Proposed Methodology", "An asynchronous, memory-mapped dual-plane architecture for zero-loss container intrusion detection")

    box_w = Inches(5.6)
    box_h = Inches(2.4)

    # Box 1
    add_card(s6, Inches(0.8), Inches(1.8), box_w, box_h, C_WHITE, C_BORDER_LIGHT)
    tb = s6.shapes.add_textbox(Inches(1.0), Inches(1.9), box_w - Inches(0.4), box_h - Inches(0.2))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "1. Multi-Tracepoint Execution Semantics"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND
    p = tf.add_paragraph()
    p.text = "Coordinates 5 kernel tracepoints across syscall initiation (sys_enter), binary activation (sched_process_exec), and failure exit (sys_exit). Differentiates execution attempts from committed binaries with exact errno accounting."
    p.font.size = Pt(10.5)
    p.font.color.rgb = C_NAVY_LIGHT

    # Box 2
    add_card(s6, Inches(6.8), Inches(1.8), box_w, box_h, C_WHITE, C_BORDER_LIGHT)
    tb = s6.shapes.add_textbox(Inches(7.0), Inches(1.9), box_w - Inches(0.4), box_h - Inches(0.2))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "2. Immutable Identity Decoupling"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND
    p = tf.add_paragraph()
    p.text = "Decouples mutable routing state (CgroupID) from immutable process identity (TGID, StartTimeNS). Resolves thread-group leader start times directly via BPF CO-RE, eliminating thread skew and PID reuse ambiguity."
    p.font.size = Pt(10.5)
    p.font.color.rgb = C_NAVY_LIGHT

    # Box 3
    add_card(s6, Inches(0.8), Inches(4.5), box_w, box_h, C_WHITE, C_BORDER_LIGHT)
    tb = s6.shapes.add_textbox(Inches(1.0), Inches(4.6), box_w - Inches(0.4), box_h - Inches(0.2))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "3. Mathematical Telemetry Conservation"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND
    p = tf.add_paragraph()
    p.text = "Proves telemetry integrity via in-kernel atomic array maps. Enforces the conservation law: Hook Calls = Submissions + Reservation Drops. Monotonic 64-bit sequence numbers guarantee zero user-space transport loss."
    p.font.size = Pt(10.5)
    p.font.color.rgb = C_NAVY_LIGHT

    # Box 4
    add_card(s6, Inches(6.8), Inches(4.5), box_w, box_h, C_WHITE, C_BORDER_LIGHT)
    tb = s6.shapes.add_textbox(Inches(7.0), Inches(4.6), box_w - Inches(0.4), box_h - Inches(0.2))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "4. Deterministic Triage & Ancestry Trees"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND
    p = tf.add_paragraph()
    p.text = "Evaluates 3 deterministic rules without statistical drift or false positives. Formats full process ancestry (shim -> runc -> entrypoint -> breakout) in real time and attaches historical cgroup migration tracking."
    p.font.size = Pt(10.5)
    p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 7: END-TO-END SYSTEM ARCHITECTURE
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    add_header(s7, "System Architecture", "End-to-End System Architecture: 7-Tier Pipeline", "The asynchronous, lockless data bridge between the Linux kernel and user space daemon")

    # Embed Figure 2
    fig2_path = os.path.join(assets_dir, "fig2_architecture.png")
    if os.path.exists(fig2_path):
        s7.shapes.add_picture(fig2_path, Inches(0.8), Inches(1.75), width=Inches(7.2))

    # Explanatory Cards on Right
    rw = Inches(4.3)
    rh = Inches(1.2)
    ry = Inches(1.75)

    tiers = [
        ("Kernel Telemetry Core", "5 tracepoints, 16k-entry LRU active attempts map, per-CPU scratchpad to stay within 512B eBPF stack limit."),
        ("16 MiB Ring Buffer", "Lockless mmap channel transferring 368B on-wire binary records with zero memory copy overhead."),
        ("Attribution Engine", "Resolves container context via cgroup v2 inodes; maintains 10k FIFO buffer & tombstone cache for dead pods."),
        ("Detection & Persistence", "Evaluates deterministic rules (CG-RULE-001/002/003) and appends to structured JSONL audit logs.")
    ]
    for t_name, t_desc in tiers:
        add_card(s7, Inches(8.2), ry, rw, rh, C_BG_LIGHT, C_BORDER_LIGHT)
        tb = s7.shapes.add_textbox(Inches(8.35), ry + Inches(0.1), rw - Inches(0.3), rh - Inches(0.2))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = t_name
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_BLUE_BRAND
        p = tf.add_paragraph()
        p.text = t_desc
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_NAVY_DARK
        ry += Inches(1.3)

    # =========================================================================
    # SLIDE 8: IN-KERNEL eBPF ENGINE INTERNALS
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    add_header(s8, "Kernel Mechanics", "eBPF Kernel Engine & Multi-Tracepoint Interception", "Zero-stack verifier compliance and exact 360-byte binary event layout")

    # Embed Figure 3
    fig3_path = os.path.join(assets_dir, "fig3_lifecycle.png")
    if os.path.exists(fig3_path):
        s8.shapes.add_picture(fig3_path, Inches(0.8), Inches(1.8), width=Inches(6.8))

    # Right Side: Deep Technical Cards
    rw = Inches(4.7)
    add_card(s8, Inches(7.8), Inches(1.8), rw, Inches(2.4), C_WHITE, C_BORDER_LIGHT)
    tb = s8.shapes.add_textbox(Inches(8.0), Inches(1.9), rw - Inches(0.4), Inches(2.2))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "512-Byte Stack Relief: Per-CPU Scratchpad"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    pts = [
        "eBPF verifier strictly limits runtime stack to 512 bytes.",
        "Allocating 360-byte struct directly on stack would consume 70% of stack frame and cause verifier rejection.",
        "ContainerGuard creates a dedicated single-entry per-CPU array map (attempt_scratch).",
        "Non-preemptible tracepoint context ensures zero concurrency hazards and <64 bytes stack frame usage."
    ]
    for pt in pts:
        p = tf.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_NAVY_DARK

    add_card(s8, Inches(7.8), Inches(4.4), rw, Inches(2.4), C_WHITE, C_BORDER_LIGHT)
    tb = s8.shapes.add_textbox(Inches(8.0), Inches(4.5), rw - Inches(0.4), Inches(2.2))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "Compact 360-Byte Binary Wire Format"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    pts2 = [
        "Offsets 0-24: Monotonic timestamp, cgroup_id, parent_cgroup_id, seq_num.",
        "Offsets 32-60: start_time_ns, pid, tgid, ppid, uid, gid, euid.",
        "Offsets 64-68: exit_code (errno), bitmask flags (COMMITTED, FAILED, SETUID).",
        "Offsets 72-344: comm[16], filename[256] (exec pathname or memfd spec)."
    ]
    for pt in pts2:
        p = tf.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_NAVY_DARK

    # =========================================================================
    # SLIDE 9: CONTAINER RESOLUTION & TOMBSTONING
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    add_header(s9, "Attribution Engine", "Container Identity Resolution & Tombstone Caching", "Eliminating lifecycle race conditions through immutable Linux cgroup v2 filesystem inodes")

    # Embed Figure 5
    fig5_path = os.path.join(assets_dir, "fig5_resolution.png")
    if os.path.exists(fig5_path):
        s9.shapes.add_picture(fig5_path, Inches(0.8), Inches(1.8), width=Inches(6.8))

    # Right side: Attribution Guarantees
    rw = Inches(4.7)
    add_card(s9, Inches(7.8), Inches(1.8), rw, Inches(5.0), C_WHITE, C_BORDER_LIGHT)
    tb = s9.shapes.add_textbox(Inches(8.0), Inches(2.0), rw - Inches(0.4), Inches(4.6))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "FOUR ATTRIBUTION SAFEGUARDS"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    safeguards = [
        ("Host Inode Seeding", "At startup, stats /sys/fs/cgroup to record host root cgroup inode. Any task in this inode is definitively categorized as host execution without API lookups."),
        ("Tombstone Caching (staleMappings)", "When a container terminates, its cgroup inode mapping is archived into a tombstone cache rather than dropped. Delayed in-flight ring buffer events are still mapped perfectly."),
        ("Bounded FIFO Attribution Queue", "Events arriving before Docker API events enter a 10,000-item FIFO queue with a 2-second timeout. Handled up to 25k event stress tests with 0 drops."),
        ("The Fail-Safe Principle", "If an inode cannot be resolved after 2 seconds, it is marked UNRESOLVED. ContainerGuard never blindly falls back to attributing unknown container activity to the host.")
    ]
    for title, desc in safeguards:
        p = tf.add_paragraph()
        p.text = title
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_NAVY_DARK
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 10: PROCESS LINEAGE & IDENTITY DECOUPLING
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    add_header(s10, "Lineage Tracking", "Process Lineage & Identity Decoupling", "Preserving execution parentage and historical attribution across dynamic cgroup migrations")

    card_w = Inches(3.64)
    card_h = Inches(5.0)

    # Key 1
    add_card(s10, Inches(0.8), Inches(1.8), card_w, card_h, C_WHITE)
    tb = s10.shapes.add_textbox(Inches(1.0), Inches(2.0), card_w - Inches(0.4), card_h - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "IMMUTABLE IDENTITY"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND
    p = tf.add_paragraph()
    p.text = "ProcessInstanceKey"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    p = tf.add_paragraph()
    p.text = "Constituent Fields:\n• uint32 TGID\n• uint64 StartTimeNS\n\nProperties:\n• Fixed for the absolute lifetime of the executing task.\n• Decoupled from ephemeral integer PIDs.\n• Nanosecond granularity eliminates PID wrap collision risks."
    p.font.size = Pt(10.5)
    p.font.color.rgb = C_NAVY_LIGHT

    # Key 2
    add_card(s10, Inches(4.84), Inches(1.8), card_w, card_h, C_WHITE)
    tb = s10.shapes.add_textbox(Inches(5.04), Inches(2.0), card_w - Inches(0.4), card_h - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "DYNAMIC ROUTING"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND
    p = tf.add_paragraph()
    p.text = "ProcessKey"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    p = tf.add_paragraph()
    p.text = "Constituent Fields:\n• uint64 CgroupID (Inode)\n• uint32 TGID\n• uint64 StartTimeNS\n\nProperties:\n• Serves as active table lookup key in userspace.\n• Changes dynamically during cgroup re-parenting without breaking the underlying ProcessInstanceKey."
    p.font.size = Pt(10.5)
    p.font.color.rgb = C_NAVY_LIGHT

    # Key 3
    add_card(s10, Inches(8.88), Inches(1.8), card_w, card_h, C_WHITE)
    tb = s10.shapes.add_textbox(Inches(9.08), Inches(2.0), card_w - Inches(0.4), card_h - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "LINEAGE PRESERVATION"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p = tf.add_paragraph()
    p.text = "CgroupHistory Array"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    p = tf.add_paragraph()
    p.text = "Migration Handling:\n1. Process looked up via ProcessInstanceKey.\n2. When new CgroupID differs from existing, prior cgroup appended to CgroupHistory.\n3. Sets cgroup_migrated = true.\n4. Ancestry tree intact: container parentage is never lost."
    p.font.size = Pt(10.5)
    p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 11: DETERMINISTIC DETECTION ENGINE
    # =========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    add_header(s11, "Detection Engine", "Deterministic Security Rule Triage", "Zero-drift, reproducible detection without false positives or heuristic training overhead")

    # Embed Figure 6
    fig6_path = os.path.join(assets_dir, "fig6_detection.png")
    if os.path.exists(fig6_path):
        s11.shapes.add_picture(fig6_path, Inches(0.8), Inches(1.8), width=Inches(6.8))

    # Right side: Rule Specs
    rw = Inches(4.7)
    add_card(s11, Inches(7.8), Inches(1.8), rw, Inches(5.0), C_WHITE, C_BORDER_LIGHT)
    tb = s11.shapes.add_textbox(Inches(8.0), Inches(2.0), rw - Inches(0.4), Inches(4.6))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "DETERMINISTIC RULE SPECIFICATIONS"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    rules = [
        ("CG-RULE-001: Privileged Breakout (CRITICAL)", "Trigger: Execution of container breakout utilities (nsenter, unshare, chroot, modprobe).\nEnrichment: Formats and attaches full ancestor lineage tree (shim -> runc -> entrypoint -> nsenter)."),
        ("CG-RULE-002: Writable Mount Execution (HIGH)", "Trigger: Launching executables from temporary or memory filesystems (/tmp/, /dev/shm/, /var/tmp/).\nThreat Model: Exploits dropping stagers in writable container paths."),
        ("CG-RULE-003: Container Shell Spawning (MEDIUM)", "Trigger: Spawning interactive shell binaries (/bin/sh, /bin/bash, zsh) inside production containers.\nThreat Model: Detects container ingress or remote command execution.")
    ]
    for r_title, r_desc in rules:
        p = tf.add_paragraph()
        p.text = r_title
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_NAVY_DARK
        p = tf.add_paragraph()
        p.text = r_desc
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 12: MATHEMATICAL LOSS ACCOUNTING
    # =========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    add_header(s12, "Telemetry Integrity", "Telemetry Integrity & Mathematical Loss Accounting", "Observability as a formally verifiable conservation law across kernel and user space")

    # Top Formula Card
    f_card = add_card(s12, Inches(0.8), Inches(1.8), Inches(11.733), Inches(1.4), C_AMBER_BG, C_AMBER)
    ftf = f_card.text_frame
    ftf.word_wrap = True
    ftf.margin_left = Inches(0.3)
    ftf.margin_top = Inches(0.2)
    p = ftf.paragraphs[0]
    p.text = "THE CONSERVATION LAW OF KERNEL TELEMETRY"
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_AMBER
    p = ftf.add_paragraph()
    p.text = "CG_METRIC_HOOK_CALLS = CG_METRIC_RB_SUBMITTED + CG_METRIC_RB_RESERVE_DROPS"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK
    p = ftf.add_paragraph()
    p.text = "Every kernel tracepoint invocation is accounted for via atomic array map counters. Telemetry loss is never silent."
    p.font.size = Pt(10)
    p.font.color.rgb = C_NAVY_LIGHT

    # Dual Column Below
    w_half = Inches(5.6)
    add_card(s12, Inches(0.8), Inches(3.4), w_half, Inches(3.4), C_WHITE)
    tb = s12.shapes.add_textbox(Inches(1.0), Inches(3.5), w_half - Inches(0.4), Inches(3.1))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "KERNEL RESERVATION DROPS"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_RED

    k_points = [
        "Occur exclusively when the 16 MiB BPF ring buffer is completely saturated under reader backpressure.",
        "bpf_ringbuf_reserve() returns NULL and kernel atomically increments telemetry_counters[1].",
        "Empirical proof (Phase H.2): Deliberate 4-second reader pause dropped exactly 1,874 events, satisfying the conservation equation with 100.00% precision."
    ]
    for pt in k_points:
        p = tf.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(10)
        p.font.color.rgb = C_NAVY_LIGHT

    add_card(s12, Inches(6.8), Inches(3.4), w_half, Inches(3.4), C_WHITE)
    tb = s12.shapes.add_textbox(Inches(7.0), Inches(3.5), w_half - Inches(0.4), Inches(3.1))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "USER-SPACE SEQUENCE GAPS"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    u_points = [
        "Monitored via the monotonic 64-bit seq_num counter embedded in every 360-byte binary header.",
        "In-kernel sequence increments atomically via __sync_fetch_and_add(&event_seq, 1).",
        "A sequence gap (Δseq > 1) signals data corruption or drops inside the transport layer.",
        "Empirical proof: Across all benchmark suites (41k+ events), sequence gaps remained strictly ZERO."
    ]
    for pt in u_points:
        p = tf.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(10)
        p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 13: SPECIFICATIONS & DEVELOPMENT ENVIRONMENT
    # =========================================================================
    s13 = prs.slides.add_slide(blank_layout)
    add_header(s13, "Technical Stack", "Hardware & Software Technical Specifications", "Reproducible production-grade stack deployed across Linux kernel and userspace")

    # 4 Cards Layout
    w_card = Inches(2.7)
    h_card = Inches(5.0)
    specs = [
        ("OPERATING SYSTEM", C_BLUE_BRAND, [
            ("Kernel Version", "Linux 6.18.33.1 WSL2 / Native Linux x86_64"),
            ("Cgroup Architecture", "cgroup v2 unified hierarchy (/sys/fs/cgroup)"),
            ("BTF Support", "Kernel built with CONFIG_DEBUG_INFO_BTF=y"),
            ("eBPF Subsystem", "BPF Ring Buffer & BPF CO-RE enabled")
        ]),
        ("KERNEL TOOLCHAIN", C_TEAL, [
            ("Compiler", "Clang / LLVM 18.1.3"),
            ("Target Architecture", "bpf / BPF CO-RE (Compile Once, Run Everywhere)"),
            ("Kernel Headers", "vmlinux.h generated via bpftool btf dump"),
            ("Object File", "bpf/execve_events.o (Frozen SUT binary)")
        ]),
        ("USERSPACE DAEMON", C_BLUE_ACCENT, [
            ("Language / Runtime", "Go 1.22+ (Linux amd64)"),
            ("eBPF Loader", "github.com/cilium/ebpf (Pure Go)"),
            ("Container SDK", "Moby Docker Engine Client SDK (v27+)"),
            ("Concurrency Model", "Goroutines with lockless channel ingestion")
        ]),
        ("TEST HARNESS", C_GREEN, [
            ("Automation Suite", "scripts/execution_path_test.sh"),
            ("Supervisor", "cmd/test_supervisor (PID tracking)"),
            ("Target Testbeds", "cg-test-a, cg-test-b Docker containers"),
            ("Output Logs", "events.jsonl & alerts.jsonl (Strict JSONL)")
        ])
    ]

    bx = Inches(0.8)
    for title, col, items in specs:
        add_card(s13, bx, Inches(1.8), w_card, h_card, C_WHITE)
        tb = s13.shapes.add_textbox(bx + Inches(0.15), Inches(2.0), w_card - Inches(0.3), h_card - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = col

        for k, v in items:
            p = tf.add_paragraph()
            p.text = k
            p.font.size = Pt(10)
            p.font.bold = True
            p.font.color.rgb = C_NAVY_DARK
            p = tf.add_paragraph()
            p.text = v
            p.font.size = Pt(9)
            p.font.color.rgb = C_NAVY_LIGHT
        bx += Inches(2.95)

    # =========================================================================
    # SLIDE 14: PHASE I AUDIT RESULTS (50% MILESTONE)
    # =========================================================================
    s14 = prs.slides.add_slide(blank_layout)
    add_header(s14, "Empirical Validation", "Phase I Empirical Results (50% Milestone Passed)", "Cryptographically verifiable test assertions from live Linux 6.18 execution run")

    # Left: Scorecard Table
    t_shp = s14.shapes.add_table(8, 3, Inches(0.8), Inches(1.8), Inches(6.8), Inches(5.0))
    table = t_shp.table
    table.columns[0].width = Inches(0.6)
    table.columns[1].width = Inches(4.7)
    table.columns[2].width = Inches(1.5)

    headers = ["#", "Empirical Test Assertion", "Verdict"]
    for c_idx, h in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = C_NAVY_DARK
        p = cell.text_frame.paragraphs[0]
        p.text = h
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = C_WHITE

    assertions = [
        ("1", "Standard execve ELF & direct syscall bypass", "PASS (100%)"),
        ("2", "Relative execveat & anonymous memfd exec", "PASS (100%)"),
        ("3", "Symlink resolution & static ELF binary commit", "PASS (100%)"),
        ("4", "Setuid privilege transition (EUID != UID)", "PASS (100%)"),
        ("5", "Failed exec errno capture (-ENOENT, -EACCES)", "PASS (100%)"),
        ("6", "Transient container race (<50ms lifecycles)", "PASS (100%)"),
        ("7", "Strict loss conservation (125 = 125 + 0 drops)", "PASS (100%)")
    ]
    for r_idx, (num, name, verd) in enumerate(assertions):
        cell_n = table.cell(r_idx + 1, 0)
        cell_t = table.cell(r_idx + 1, 1)
        cell_v = table.cell(r_idx + 1, 2)
        cell_n.fill.solid()
        cell_t.fill.solid()
        cell_v.fill.solid()
        cell_n.fill.fore_color.rgb = C_BG_LIGHT
        cell_t.fill.fore_color.rgb = C_WHITE
        cell_v.fill.fore_color.rgb = C_GREEN_BG

        cell_n.text_frame.paragraphs[0].text = num
        cell_n.text_frame.paragraphs[0].font.size = Pt(9.5)
        cell_n.text_frame.paragraphs[0].font.bold = True

        cell_t.text_frame.paragraphs[0].text = name
        cell_t.text_frame.paragraphs[0].font.size = Pt(9.5)

        p = cell_v.text_frame.paragraphs[0]
        p.text = verd
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = C_GREEN

    # Right: Metric Highlights Cards
    rw = Inches(4.7)
    add_card(s14, Inches(7.8), Inches(1.8), rw, Inches(5.0), C_WHITE, C_BORDER_LIGHT)
    tb = s14.shapes.add_textbox(Inches(8.0), Inches(2.0), rw - Inches(0.4), Inches(4.6))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "KEY PERFORMANCE METRICS"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    metrics = [
        ("125 / 125 Events Delivered", "Zero sequence gaps; 100% monotonic sequence continuity across all tested execution pathways."),
        ("+3.46% Syscall Overhead", "Barely measurable 7.77 microsecond execution penalty per syscall under continuous monitoring."),
        ("6.02 MiB RSS Footprint", "Extremely lightweight userspace daemon memory footprint suitable for resource-constrained edge/k8s nodes."),
        ("Cryptographic Provenance", "Packaged in containerguard-phaseI-run.tar.gz with SHA-256 hash verified by independent review.")
    ]
    for m_title, m_desc in metrics:
        p = tf.add_paragraph()
        p.text = m_title
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_NAVY_DARK
        p = tf.add_paragraph()
        p.text = m_desc
        p.font.size = Pt(9.5)
        p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 15: TIMELINE & PHASE II ROADMAP
    # =========================================================================
    s15 = prs.slides.add_slide(blank_layout)
    add_header(s15, "Project Roadmap", "Project Timeline, Milestones & Phase II Roadmap", "Clear demarcation between completed Phase I telemetry and upcoming Phase II policy layers")

    w_half = Inches(5.6)
    h_card = Inches(5.0)

    # Phase I Card
    add_card(s15, Inches(0.8), Inches(1.8), w_half, h_card, C_GREEN_BG, RGBColor(16, 185, 129))
    tb = s15.shapes.add_textbox(Inches(1.0), Inches(2.0), w_half - Inches(0.4), h_card - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "PHASE I: 0% – 50% MILESTONE"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_GREEN

    p = tf.add_paragraph()
    p.text = "Core Telemetry & Detection (COMPLETED & FROZEN)"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    p1_items = [
        "[x] 5-Tracepoint eBPF Kernel Telemetry Engine (bpf/execve_events.c)",
        "[x] BPF CO-RE Relocations on Linux 6.18+ vmlinux.h",
        "[x] Zero-Copy 16 MiB Memory-Mapped BPF Ring Buffer Ingestion",
        "[x] Cgroup v2 Inode Grounding & Stale Mapping Tombstone Cache",
        "[x] Decoupled ProcessInstanceKey Lineage Tracker & CgroupHistory",
        "[x] Three Deterministic Detection Rules (CG-RULE-001/002/003)",
        "[x] Telemetry Conservation Law Invariant Verification",
        "[x] 14-Point Automated Verification Harness & Audit Dossier"
    ]
    for item in p1_items:
        p = tf.add_paragraph()
        p.text = item
        p.font.size = Pt(10)
        p.font.color.rgb = C_NAVY_LIGHT

    # Phase II Card
    add_card(s15, Inches(6.8), Inches(1.8), w_half, h_card, RGBColor(248, 250, 252), RGBColor(148, 163, 184))
    tb = s15.shapes.add_textbox(Inches(7.0), Inches(2.0), w_half - Inches(0.4), h_card - Inches(0.4))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "PHASE II: 50% – 100% MILESTONE"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_BLUE_BRAND

    p = tf.add_paragraph()
    p.text = "Policy Enforcement & Prevention (PLANNED)"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_NAVY_DARK

    p2_items = [
        "[ ] Inline LSM Syscall Prevention via bpf_lsm hooks (SIGKILL/EPERM)",
        "[ ] Dynamic Policy Configuration Engine (Hot-reloading YAML/JSON)",
        "[ ] Network Socket-to-Process Correlation (Connect/Accept tracking)",
        "[ ] Distributed Telemetry Exporters (gRPC stream / Apache Kafka)",
        "[ ] Kubernetes Admission Controller & DaemonSet Deployment",
        "[ ] Automated Incident Remediation (Cgroup container freezing)",
        "[ ] MITRE ATT&CK Cloud Matrix Automated Mapping",
        "[ ] Production Cluster Stress Benchmarking (100k+ events/sec)"
    ]
    for item in p2_items:
        p = tf.add_paragraph()
        p.text = item
        p.font.size = Pt(10)
        p.font.color.rgb = C_NAVY_LIGHT

    # =========================================================================
    # SLIDE 16: CONCLUSION & DEFENSE Q&A
    # =========================================================================
    s16 = prs.slides.add_slide(blank_layout)
    bg16 = s16.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg16.fill.solid()
    bg16.fill.fore_color.rgb = C_NAVY_DARK
    bg16.line.fill.background()

    # Title Banner Accent Line
    acc16 = s16.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.0), Inches(1.0), Inches(1.2), Inches(0.08))
    acc16.fill.solid()
    acc16.fill.fore_color.rgb = C_BLUE_ACCENT
    acc16.line.fill.background()

    # Main Project Title
    t_box16 = s16.shapes.add_textbox(Inches(1.0), Inches(1.2), Inches(11.3), Inches(1.0))
    tf16 = t_box16.text_frame
    p = tf16.paragraphs[0]
    p.text = "ContainerGuard: Proven Runtime Integrity"
    p.font.size = Pt(36)
    p.font.bold = True
    p.font.color.rgb = C_WHITE

    # Key Takeaways Cards
    tw_w = Inches(3.64)
    tw_h = Inches(2.6)

    tws = [
        ("Unbypassable Visibility", "Captures all execution pathways directly inside the Linux kernel via 5 tracepoints, neutralizing PID recycling, ephemeral races, and fileless memory concealment."),
        ("Provable Telemetry Conservation", "Treats telemetry loss as a verifiable conservation equation (Hooks = Submits + Drops), eliminating the dangerous absence-of-proof fallacy in container monitoring."),
        ("Zero-Drift Determinism", "Evaluates deterministic security rules with rich contextual ancestry trees while introducing only +3.46% syscall overhead and 6 MiB memory footprint.")
    ]

    tx = Inches(1.0)
    for title, desc in tws:
        c = add_card(s16, tx, Inches(2.3), tw_w, tw_h, RGBColor(30, 41, 59), RGBColor(51, 65, 85))
        tb = s16.shapes.add_textbox(tx + Inches(0.2), Inches(2.45), tw_w - Inches(0.4), tw_h - Inches(0.3))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = RGBColor(56, 189, 248)
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(10.5)
        p.font.color.rgb = RGBColor(226, 232, 240)
        tx += Inches(3.84)

    # Bottom Contact & Q&A Box
    q_card = add_card(s16, Inches(1.0), Inches(5.2), Inches(11.333), Inches(1.6), RGBColor(15, 23, 42), RGBColor(56, 189, 248))
    qtf = q_card.text_frame
    qtf.word_wrap = True
    qtf.margin_left = Inches(0.3)
    qtf.margin_top = Inches(0.15)
    p = qtf.paragraphs[0]
    p.text = "ZEROTH REVIEW EVALUATION COMMITTEE DEFENSE — THANK YOU"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = RGBColor(56, 189, 248)

    p = qtf.add_paragraph()
    p.text = "• Open Source Repository: https://github.com/ramKarthik57/containerguard\n• Documentation & Audit Evidence: docs/ContainerGuard_Comprehensive_Project_Guide.pdf\n• Questions, Guidance, and Evaluation Feedback are warmly invited."
    p.font.size = Pt(11)
    p.font.color.rgb = C_WHITE

    # Save Presentation
    pptx_path = "/home/ram/ebpf-smoke-test/ContainerGuard_Zeroth_Review.pptx"
    docs_pptx_path = "/home/ram/ebpf-smoke-test/docs/ContainerGuard_Zeroth_Review.pptx"
    brain_pptx_path = "/home/ram/.gemini/antigravity/brain/767a3dd4-c78f-4862-9a58-ee68df4b3630/ContainerGuard_Zeroth_Review.pptx"

    prs.save(pptx_path)
    prs.save(docs_pptx_path)
    prs.save(brain_pptx_path)
    print(f"PowerPoint successfully created at:")
    print(f"  - {pptx_path}")
    print(f"  - {docs_pptx_path}")
    print(f"  - {brain_pptx_path}")

if __name__ == "__main__":
    create_deck()
