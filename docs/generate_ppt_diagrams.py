import subprocess
import os

assets_dir = "/home/ram/ebpf-smoke-test/docs/ppt_assets"
os.makedirs(assets_dir, exist_ok=True)

preamble = r"""\documentclass[tikz,border=10pt]{standalone}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{amsmath,amssymb}
\usepackage{tikz}
\usetikzlibrary{shapes.geometric, arrows.meta, positioning, calc, fit, backgrounds}

\definecolor{primary}{HTML}{0F172A}
\definecolor{primaryblue}{HTML}{1E3A8A}
\definecolor{accentblue}{HTML}{0284C7}
\definecolor{tealaccent}{HTML}{0D9488}
\definecolor{darkgreen}{HTML}{065F46}
\definecolor{lightgreen}{HTML}{ECFDF5}
\definecolor{crimson}{HTML}{991B1B}
\definecolor{lightred}{HTML}{FEF2F2}
\definecolor{amber}{HTML}{B45309}
\definecolor{lightamber}{HTML}{FFFBEB}
\definecolor{boxbg}{HTML}{F8FAFC}

\begin{document}
"""

diagrams = {
    "fig1_blindspots": r"""
\begin{tikzpicture}[
    challenge/.style={rectangle, draw=crimson, fill=lightred, text=crimson, rounded corners=3pt, minimum width=6.0cm, minimum height=0.85cm, align=left, font=\scriptsize\bfseries},
    defense/.style={rectangle, draw=darkgreen, fill=lightgreen, text=darkgreen, rounded corners=3pt, minimum width=6.2cm, minimum height=0.85cm, align=left, font=\scriptsize\bfseries},
    conn/.style={-{Stealth[scale=1.1]}, very thick, draw=primaryblue}
]
    \node[challenge] (c1) at (0, 4.0) {1. PID Recycling Collisions\\ \tiny\textnormal{PIDs wrap rapidly under high throughput}};
    \node[challenge] (c2) at (0, 3.0) {2. Transient Lifecycle Races\\ \tiny\textnormal{Short-lived containers exit in $<50$ms}};
    \node[challenge] (c3) at (0, 2.0) {3. Cgroup Migrations\\ \tiny\textnormal{Dynamic moves sever process lineage}};
    \node[challenge] (c4) at (0, 1.0) {4. Silent Buffer Saturation\\ \tiny\textnormal{High-frequency exec bursts drop events}};
    \node[challenge] (c5) at (0, 0.0) {5. Execution Camouflage\\ \tiny\textnormal{\texttt{execveat} fileless in-memory execution}};

    \node[defense] (d1) at (9.8, 4.0) {Immutable \texttt{ProcessInstanceKey}\\ \tiny\textnormal{Key: (Kernel TGID, Process StartTimeNS)}};
    \node[defense] (d2) at (9.8, 3.0) {Cgroup v2 Inode Binding + Tombstones\\ \tiny\textnormal{Attribution Buffer holds events until mapped}};
    \node[defense] (d3) at (9.8, 2.0) {\texttt{CgroupHistory} Lineage Array\\ \tiny\textnormal{In-place key update with migration flag}};
    \node[defense] (d4) at (9.8, 1.0) {Atomic Kernel Telemetry Counters\\ \tiny\textnormal{Invariant: $\text{Hooks} = \text{Submissions} + \text{Drops}$}};
    \node[defense] (d5) at (9.8, 0.0) {5 Multi-Tracepoint Kernel Hooks\\ \tiny\textnormal{Captures entry, image commit, and errno exit}};

    \draw[conn] (c1.east) -- node[above, font=\tiny\bfseries\color{primaryblue}, inner sep=2pt]{Decouple Identity} (d1.west);
    \draw[conn] (c2.east) -- node[above, font=\tiny\bfseries\color{primaryblue}, inner sep=2pt]{Attribution Buffer} (d2.west);
    \draw[conn] (c3.east) -- node[above, font=\tiny\bfseries\color{primaryblue}, inner sep=2pt]{Preserve Lineage} (d3.west);
    \draw[conn] (c4.east) -- node[above, font=\tiny\bfseries\color{primaryblue}, inner sep=2pt]{Loss Accounting} (d4.west);
    \draw[conn] (c5.east) -- node[above, font=\tiny\bfseries\color{primaryblue}, inner sep=2pt]{Syscall Visibility} (d5.west);
\end{tikzpicture}
""",

    "fig2_architecture": r"""
\begin{tikzpicture}[
    tierbox/.style={rectangle, draw=primaryblue, fill=primaryblue!10, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=6pt, minimum width=13.5cm, minimum height=0.9cm},
    userbox/.style={rectangle, draw=tealaccent, fill=tealaccent!10, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=6pt, minimum width=13.5cm, minimum height=0.9cm},
    storebox/.style={rectangle, draw=amber, fill=amber!10, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=6pt, minimum width=13.5cm, minimum height=0.9cm},
    arrow/.style={-{Stealth[scale=1.2]}, thick, draw=primaryblue},
    thickflow/.style={-{Stealth[scale=1.3]}, line width=2pt, draw=accentblue}
]
    \node[tierbox] (t1) at (0, 7.5) {1. Kernel Tracepoint Probes\\ \scriptsize\textnormal{\texttt{sys\_enter\_execve/at} (Syscall Entry) $\bullet$ \texttt{sched\_process\_exec} (Commit) $\bullet$ \texttt{sys\_exit\_execve/at} (Errno Exit)}};
    \node[tierbox, fill=primaryblue!5] (t2) at (0, 5.8) {2. In-Flight State Tracking \& Stack Relief\\ \scriptsize\textnormal{\texttt{active\_exec\_attempts} (16,384-entry LRU Map) $\bullet$ \texttt{attempt\_scratch} (Per-CPU Scratchpad) $\bullet$ \texttt{telemetry\_counters}}};
    \node[tierbox, draw=accentblue, fill=accentblue!15] (t3) at (0, 4.1) {3. In-Kernel Ring Buffer Data Channel\\ \scriptsize\textnormal{\texttt{events} (16 MiB Lockless BPF Ring Buffer) $\bullet$ Atomic Monotonic \texttt{seq\_num} Counter}};

    \node[userbox] (t4) at (0, 2.2) {4. Userspace Ingestion Pipeline\\ \scriptsize\textnormal{Zero-Copy Memory-Mapped Reader (\texttt{internal/collector}) $\bullet$ Monotonic Sequence Gap Verification (\texttt{internal/pipeline})}};
    \node[userbox, fill=tealaccent!5] (t5) at (0, 0.5) {5. Container Identity Resolution \& Attribution Buffer\\ \scriptsize\textnormal{Cgroup v2 Inode Binding $\bullet$ Docker Event Stream Reconciler $\bullet$ Bounded FIFO Queue (10k items, 2s TTL) $\bullet$ Tombstone Cache}};
    \node[userbox, fill=tealaccent!15] (t6) at (0, -1.2) {6. Process Identity Lineage \& Deterministic Rule Engine\\ \scriptsize\textnormal{Decoupled \texttt{ProcessInstanceKey\{TGID, StartTimeNS\}} $\bullet$ \texttt{CgroupHistory} Migration Tracker $\bullet$ Rules 001, 002, 003}};

    \node[storebox] (t7) at (0, -2.9) {7. Local Persistence Subsystem\\ \scriptsize\textnormal{\texttt{exec\_paths\_events.jsonl} (Attributed Telemetry) $\bullet$ \texttt{exec\_paths\_alerts.jsonl} (Security Alerts)}};

    \draw[arrow] (t1) -- node[right, font=\tiny\bfseries]{In-Flight Attempt} (t2);
    \draw[arrow] (t2) -- node[right, font=\tiny\bfseries]{Commit / Exit Record} (t3);
    \draw[thickflow] (t3) -- node[right, font=\scriptsize\bfseries\color{accentblue}]{368B On-Wire Records (\texttt{mmap} Stream)} (t4);
    \draw[arrow] (t4) -- node[right, font=\tiny\bfseries]{Verified Raw Events} (t5);
    \draw[arrow] (t5) -- node[right, font=\tiny\bfseries]{Attributed Security Events} (t6);
    \draw[arrow] (t6) -- node[right, font=\tiny\bfseries]{Events \& Enriched Alerts} (t7);
\end{tikzpicture}
""",

    "fig3_lifecycle": r"""
\begin{tikzpicture}[
    box/.style={rectangle, draw=primaryblue, fill=boxbg, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=6pt},
    decision/.style={rectangle, draw=amber, fill=lightamber, rounded corners=4pt, font=\small\bfseries, align=center, inner sep=5pt},
    arrow/.style={-{Stealth[scale=1.2]}, thick, draw=primaryblue}
]
    \node[box, minimum width=6cm] (app) at (0, 6.2) {User Process: \texttt{execve(pathname, argv, envp)}};
    \node[box, fill=primaryblue!15, minimum width=8cm] (enter) at (0, 4.8) {\texttt{sys\_enter\_execve(at)}\\ \scriptsize CO-RE cgroup inode capture \& active\_exec\_attempts LRU store};
    \node[decision] (loader) at (0, 3.0) {Kernel Binary Loader\\ \scriptsize\textnormal{\texttt{search\_binary\_handler}}};

    \node[box, fill=darkgreen!15, draw=darkgreen, minimum width=5.2cm] (sched) at (-4.2, 0.8) {\texttt{sched\_process\_exec}\\ \scriptsize Loader committed image\\ \textbf{\textcolor{darkgreen}{CG\_FLAG\_COMMITTED\_EXEC}}};
    \node[box, fill=crimson!15, draw=crimson, minimum width=5.2cm] (exit) at (4.2, 0.8) {\texttt{sys\_exit\_execve(at)}\\ \scriptsize Loader failed with errno\\ \textbf{\textcolor{crimson}{CG\_FLAG\_EXEC\_FAILED}}};

    \node[box, fill=accentblue!15, draw=accentblue, minimum width=11cm] (rb) at (0, -1.6) {eBPF Ring Buffer Submission (\texttt{bpf\_ringbuf\_submit})\\ \scriptsize 360-Byte Binary Event + Monotonic Sequence Number};

    \draw[arrow] (app) -- (enter);
    \draw[arrow] (enter) -- (loader);
    \draw[arrow] (loader) -| node[above left, font=\footnotesize\bfseries\color{darkgreen}]{Success (ret = 0)} (sched.north);
    \draw[arrow] (loader) -| node[above right, font=\footnotesize\bfseries\color{crimson}]{Failure (ret < 0)} (exit.north);
    \draw[arrow] (sched.south) -- ++(0,-0.5) -| node[pos=0.25, below, font=\tiny\bfseries]{Submit Event} (rb.155);
    \draw[arrow] (exit.south) -- ++(0,-0.5) -| node[pos=0.25, below, font=\tiny\bfseries]{Submit Failure} (rb.25);
\end{tikzpicture}
""",

    "fig5_resolution": r"""
\begin{tikzpicture}[
    check/.style={rectangle, draw=primaryblue, fill=boxbg, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=6pt, minimum width=5.8cm},
    resolved/.style={rectangle, draw=darkgreen, fill=lightgreen, text=darkgreen, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=5pt, minimum width=4.5cm},
    pending/.style={rectangle, draw=amber, fill=lightamber, text=amber, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=5pt, minimum width=5.8cm},
    failed/.style={rectangle, draw=crimson, fill=lightred, text=crimson, rounded corners=3pt, font=\small\bfseries, align=center, inner sep=5pt, minimum width=5.8cm},
    arrow/.style={-{Stealth[scale=1.2]}, thick, draw=primaryblue}
]
    \node[check, fill=primaryblue!15] (start) at (0, 5.0) {Kernel Emits Event with CgroupID (Inode)};
    \node[check] (checkhost) at (0, 3.6) {CgroupID == HostRootInode?};
    \node[resolved] (host) at (6.2, 3.6) {AttributionHost\\ \scriptsize Attached Host Context};

    \node[check] (active) at (0, 2.2) {Inode in Active \texttt{byCgroup} Map?};
    \node[resolved] (container) at (6.2, 2.2) {AttributionResolved\\ \scriptsize Attached Container Context};

    \node[check] (tomb) at (0, 0.8) {Inode in \texttt{staleMappings} Tombstones?};
    \node[resolved] (stale) at (6.2, 0.8) {AttributionResolved\\ \scriptsize Attached Tombstone Context};

    \node[pending] (queue) at (0, -0.8) {Attribution Buffer Queue\\ \scriptsize FIFO Queue (Capacity: 10,000, TTL: 2s)};
    \node[failed] (unresolved) at (0, -2.4) {AttributionUnresolved\\ \scriptsize Fail-Safe: Tagged UNRESOLVED (Never Host!)};

    \draw[arrow] (start) -- (checkhost);
    \draw[arrow] (checkhost) -- node[above, font=\footnotesize\bfseries\color{darkgreen}]{Yes} (host);
    \draw[arrow] (checkhost) -- node[right, font=\footnotesize\bfseries]{No} (active);
    \draw[arrow] (active) -- node[above, font=\footnotesize\bfseries\color{darkgreen}]{Yes} (container);
    \draw[arrow] (active) -- node[right, font=\footnotesize\bfseries]{No} (tomb);
    \draw[arrow] (tomb) -- node[above, font=\footnotesize\bfseries\color{darkgreen}]{Yes} (stale);
    \draw[arrow] (tomb) -- node[right, font=\footnotesize\bfseries]{No} (queue);
    \draw[arrow] (queue) -- node[right, font=\footnotesize\bfseries\color{crimson}]{TTL Expired} (unresolved);
    \draw[arrow] (queue.east) -- (8.8, -0.8) |- node[pos=0.25, right, font=\footnotesize\bfseries\color{darkgreen}]{Docker Start Arrives} (container.east);
\end{tikzpicture}
""",

    "fig6_detection": r"""
\begin{tikzpicture}[
    event/.style={rectangle, draw=primaryblue, fill=primaryblue!10, rounded corners=3pt, font=\small\bfseries, align=center, minimum width=6cm, minimum height=0.85cm},
    rule/.style={rectangle, draw=primary, fill=boxbg, rounded corners=3pt, font=\small\bfseries, align=center, minimum width=4.6cm, minimum height=1.3cm},
    crit/.style={rectangle, draw=crimson, fill=lightred, text=crimson, rounded corners=3pt, font=\small\bfseries, align=center, text width=3.4cm, minimum height=1.1cm},
    high/.style={rectangle, draw=amber, fill=lightamber, text=amber, rounded corners=3pt, font=\small\bfseries, align=center, text width=3.4cm, minimum height=1.1cm},
    med/.style={rectangle, draw=tealaccent, fill=tealaccent!10, text=tealaccent, rounded corners=3pt, font=\small\bfseries, align=center, text width=3.4cm, minimum height=1.1cm},
    pass/.style={rectangle, draw=darkgreen, fill=lightgreen, text=darkgreen, rounded corners=3pt, font=\small\bfseries, align=center, minimum width=10cm, minimum height=1.0cm},
    arrow/.style={-{Stealth[scale=1.2]}, thick, draw=primaryblue}
]
    \node[event] (ev) at (0, 3.5) {Attributed Security Event\\ \scriptsize Container Context + Process Lineage Attached};

    \node[rule] (r1) at (-5.2, 1.4) {\textbf{CG-RULE-001}\\ Privileged Breakout\\ \scriptsize\texttt{nsenter, unshare, chroot}};
    \node[rule] (r2) at (0.0, 1.4) {\textbf{CG-RULE-002}\\ Volatile Mount Exec\\ \scriptsize\texttt{/tmp/, /dev/shm/, /var/tmp/}};
    \node[rule] (r3) at (5.2, 1.4) {\textbf{CG-RULE-003}\\ Container Shell Exec\\ \scriptsize\texttt{/bin/sh, /bin/bash, zsh}};

    \node[crit] (a1) at (-5.2, -0.8) {\textbf{CRITICAL ALERT}\\ \scriptsize Formatted Lineage Attached};
    \node[high] (a2) at (0.0, -0.8) {\textbf{HIGH ALERT}\\ \scriptsize Writable Mount Exec};
    \node[med] (a3) at (5.2, -0.8) {\textbf{MEDIUM ALERT}\\ \scriptsize Shell Ingress};

    \node[pass] (sink) at (0, -2.8) {\textbf{Telemetry Sink (\texttt{exec\_paths\_events.jsonl})}\\ \scriptsize All Events Logged for Forensic Audit};

    \draw[arrow] (ev) -| (r1);
    \draw[arrow] (ev) -- (r2);
    \draw[arrow] (ev) -| (r3);

    \draw[arrow] (r1) -- node[right, font=\tiny\bfseries]{Match} (a1);
    \draw[arrow] (r2) -- node[right, font=\tiny\bfseries]{Match} (a2);
    \draw[arrow] (r3) -- node[right, font=\tiny\bfseries]{Match} (a3);

    \draw[arrow] (a1) |- (sink);
    \draw[arrow] (a2) -- (sink);
    \draw[arrow] (a3) |- (sink);
\end{tikzpicture}
"""
}

for name, body in diagrams.items():
    tex_file = os.path.join(assets_dir, f"{name}.tex")
    pdf_file = os.path.join(assets_dir, f"{name}.pdf")
    png_prefix = os.path.join(assets_dir, f"{name}")
    
    with open(tex_file, "w") as f:
        f.write(preamble + body + "\n\\end{document}\n")
    
    print(f"Compiling {name}...")
    res = subprocess.run(["pdflatex", "-interaction=nonstopmode", f"{name}.tex"], cwd=assets_dir, capture_output=True)
    if res.returncode != 0:
        print(f"Error compiling {name}: {res.stderr.decode('utf-8', errors='replace')}")
    else:
        # Convert to PNG at 220 DPI for crisp presentation display
        subprocess.run(["pdftoppm", "-png", "-r", "220", f"{name}.pdf", png_prefix], cwd=assets_dir)
        # Move/rename the generated file to name.png
        generated_png = f"{png_prefix}-1.png"
        target_png = f"{png_prefix}.png"
        if os.path.exists(generated_png):
            os.rename(generated_png, target_png)
            print(f"Rendered {target_png}")

print("All PPT assets successfully generated!")
