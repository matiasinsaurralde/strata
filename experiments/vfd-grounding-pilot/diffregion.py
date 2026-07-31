"""Reconstruct pre-fix (before) and post-fix (after) code regions for a given
target file from a unified git diff. Deterministic, uses the exact diff bytes.

before = context lines + removed('-') lines (added lines dropped)
after  = context lines + added('+') lines   (removed lines dropped)
The enclosing function from each @@ hunk header is kept as a marker line.
"""
import re

def regions_for_file(diff_text, target_path):
    lines = diff_text.splitlines()
    # find the 'diff --git a/... b/target' block
    starts = [i for i, l in enumerate(lines) if l.startswith("diff --git ")]
    starts.append(len(lines))
    block = None
    for k in range(len(starts) - 1):
        header = lines[starts[k]]
        if target_path in header:
            block = lines[starts[k]:starts[k + 1]]
            break
    if block is None:
        raise ValueError(f"target {target_path} not found in diff")
    before, after = [], []
    for l in block:
        if l.startswith("@@"):
            m = re.search(r"@@.*@@\s?(.*)", l)
            ctx = m.group(1) if m else ""
            marker = f"\n// ---- {ctx.strip()} ----" if ctx.strip() else "\n// ----"
            before.append(marker); after.append(marker)
            continue
        if l.startswith(("diff --git", "index ", "--- ", "+++ ", "new file", "deleted file",
                         "similarity", "rename", "old mode", "new mode", "Binary files")):
            continue
        if l.startswith("+"):
            after.append(l[1:])
        elif l.startswith("-"):
            before.append(l[1:])
        else:
            # context line (leading space, or blank line that lost its space)
            c = l[1:] if l.startswith(" ") else l
            before.append(c); after.append(c)
    return "\n".join(before).strip(), "\n".join(after).strip()
