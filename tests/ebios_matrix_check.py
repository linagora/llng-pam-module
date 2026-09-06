#!/usr/bin/env python3
"""
Check that every EBIOS risk matrix in doc/security/ agrees with the risk sheets
it summarises (#213, #214).

Why this exists: the matrices were maintained by hand, next to the sheets they
summarise, and drifted from them in at least thirteen places -- a risk shown one
column to the left, a residual impact that no sheet states, a consolidated table
missing eleven analysed risks and carrying two that had no sheet at all. An
evaluator reads the matrix, not the sheets, so a matrix that disagrees with its
own study is worse than no matrix.

The rule enforced here is simple: a matrix cell is not a claim of its own. Every
placement must be derivable from the (Probabilite, Impact) written in the
corresponding sheet, and every analysed risk must appear exactly once.

Run:  python3 tests/ebios_matrix_check.py
"""

import re
import sys
from pathlib import Path

DOC = Path(__file__).resolve().parent.parent / "doc" / "security"

ENROLLMENT = DOC / "01-enrollment.md"
SSH = DOC / "02-ssh-connection.md"
CONSOLIDATED = DOC / "99-risk-reduce.md"

RISK_ID = r"R-?S?A?\d+"
HEADING = re.compile(rf"^#{{3,4}}\s+({RISK_ID})\s*[-–—]\s", re.M)
ANY_HEADING = re.compile(r"^#{1,6}\s", re.M)

# A score table row: "| **Probabilite** | 1 (because ...) |"
PROB_ROW = re.compile(r"^\|\s*\*\*Probabilit[ée]\*\*\s*\|\s*([0-9])", re.M)
IMPACT_ROW = re.compile(r"^\|\s*\*\*Impact\*\*\s*\|\s*([0-9])", re.M)


def sheets(path):
    """Return {risk_id: {"initial": (P, I), "residual": (P, I), "level": n, "line": n}}.

    A sheet runs from its own heading to the next heading of the same or a
    higher level: stopping only at the next *risk* heading would make the last
    sheet in a file swallow the matrices that follow it.
    """
    lines = path.read_text(encoding="utf-8").split("\n")

    # Heading levels per line, with fenced code blocks blanked out: a shell
    # comment inside a ``` block ("# FORTEMENT RECOMMANDE ...") is not a
    # Markdown heading, and treating it as one truncates the sheet before its
    # residual-score table.
    level_of = [0] * len(lines)
    fenced = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        h = re.match(r"^(#{1,6})\s", line)
        if h:
            level_of[i] = len(h.group(1))

    starts = []
    for i, line in enumerate(lines):
        if not 3 <= level_of[i] <= 4:
            continue
        m = re.match(rf"^#+\s+({RISK_ID})\s*[-\u2013\u2014]\s", line)
        if m:
            starts.append((i, level_of[i], m.group(1)))

    found = {}
    for n, (i, level, rid) in enumerate(starts):
        end = len(lines)
        for j in range(i + 1, len(lines)):
            if level_of[j] and level_of[j] <= level:
                end = j
                break
        body = "\n".join(lines[i:end])
        probs = PROB_ROW.findall(body)
        impacts = IMPACT_ROW.findall(body)
        if len(probs) < 2 or len(impacts) < 2:
            continue  # not a scored sheet (or an unscored backlog heading)
        found[rid] = {
            "initial": (int(probs[0]), int(impacts[0])),
            "residual": (int(probs[-1]), int(impacts[-1])),
            "level": level,
            "line": i + 1,
        }
    return found


def matrix(path, after_heading):
    """Parse the 4x4 matrix that follows `after_heading`.

    Returns {risk_id: (P, I)} and the line the matrix starts on.
    """
    text = path.read_text(encoding="utf-8")
    start = text.index(after_heading) + len(after_heading)
    table = text[start:]
    placed = {}
    line0 = text[:start].count("\n") + 1
    for row in table.split("\n"):
        row = row.strip()
        if not row.startswith("|"):
            if placed:
                break  # table finished
            continue
        m = re.match(r"^\|\s*\*\*([0-9])\s*-", row)
        if not m:
            continue
        impact = int(m.group(1))
        cells = [c.strip() for c in row.strip("|").split("|")][1:]
        for col, cell in enumerate(cells, start=1):
            for rid in re.findall(rf"\b{RISK_ID}\b", cell):
                placed[rid] = (col, impact)
    return placed, line0


def compare(label, expected, placed, kind, errors):
    """`expected` is {rid: (P, I)}; `placed` is what the matrix says."""
    for rid, want in sorted(expected.items()):
        got = placed.get(rid)
        if got is None:
            errors.append(f"{label}: {rid} is analysed ({kind} P={want[0]}, I={want[1]}) "
                          f"but absent from the matrix")
        elif got != want:
            errors.append(f"{label}: {rid} placed at P={got[0]}, I={got[1]} "
                          f"but its sheet says P={want[0]}, I={want[1]}")
    for rid in sorted(placed):
        if rid not in expected:
            errors.append(f"{label}: {rid} appears in the matrix but has no scored sheet")


def main():
    errors = []

    enrol = sheets(ENROLLMENT)
    ssh = sheets(SSH)

    if len(enrol) < 14:
        errors.append(f"01-enrollment.md: only {len(enrol)} scored sheets parsed, expected 14")
    if len(ssh) < 23:
        errors.append(f"02-ssh-connection.md: only {len(ssh)} scored sheets parsed, expected 23+")

    checks = [
        ("01-enrollment avant", ENROLLMENT, "## 3. Matrice des Risques\n\n### Avant remédiation\n",
         {k: v["initial"] for k, v in enrol.items()}, "initial"),
        ("01-enrollment après", ENROLLMENT, "### Après remédiation\n",
         {k: v["residual"] for k, v in enrol.items()}, "residual"),
        ("02-ssh avant", SSH, "## 4. Matrice des Risques\n\n### Avant remédiation\n",
         {k: v["initial"] for k, v in ssh.items()}, "initial"),
        ("02-ssh après", SSH, "### Après remédiation complète\n",
         {k: v["residual"] for k, v in ssh.items()}, "residual"),
    ]

    for label, path, heading, expected, kind in checks:
        try:
            placed, _ = matrix(path, heading)
        except ValueError:
            errors.append(f"{label}: matrix heading not found ({heading.strip()!r})")
            continue
        compare(label, expected, placed, kind, errors)

    # The consolidated matrix must cover EVERY analysed risk from both studies.
    all_residual = {}
    all_residual.update({k: v["residual"] for k, v in enrol.items()})
    all_residual.update({k: v["residual"] for k, v in ssh.items()})
    try:
        placed, _ = matrix(CONSOLIDATED, "## Matrice des Risques Résiduels (Mode E)\n")
    except ValueError:
        placed = None
        errors.append("99-risk-reduce.md: consolidated matrix heading not found")
    if placed is not None:
        compare("99-risk-reduce consolidée", all_residual, placed, "residual", errors)

    # 99-risk-reduce.md repeats each score in its own section headings
    # ("### R5 _(P=1, I=4)_ - ..."). Those must agree with the sheets too: the
    # file used to state three different values for R-S18 on three lines.
    text = CONSOLIDATED.read_text(encoding="utf-8")
    for m in re.finditer(rf"^#{{2,4}}\s+({RISK_ID})\s+_\(P=([0-9]+)[^)]*?I=([0-9]+)", text, re.M):
        rid, p, i = m.group(1), int(m.group(2)), int(m.group(3))
        want = all_residual.get(rid)
        if want is None:
            errors.append(f"99-risk-reduce heading: {rid} has no scored sheet")
        elif (p, i) != want:
            line = text[:m.start()].count("\n") + 1
            errors.append(f"99-risk-reduce heading (line {line}): {rid} says P={p}, I={i} "
                          f"but its sheet says P={want[0]}, I={want[1]}")

    if errors:
        print(f"{len(errors)} matrix/sheet disagreement(s):\n")
        for e in errors:
            print(f"  - {e}")
        return 1

    total = len(all_residual)
    print(f"OK: {total} risk sheets, every matrix cell derivable from its sheet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
