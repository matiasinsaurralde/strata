"""Aggregate all exp2 result files into a master grounding table."""
import json, glob, os
BASE = os.path.dirname(os.path.abspath(__file__))
from contexts import CASES
rows = []
for fp in glob.glob(os.path.join(BASE, "runs", "exp2_*.jsonl")):
    for l in open(fp):
        rows.append(json.loads(l))
conds = ["blind", "relevant", "irrelevant", "leading"]
configs = sorted({(r["model"], r["effort"]) for r in rows if not r.get("error")},
                 key=lambda x: (x[0], {"none":0,"low":1,"medium":2,"high":3}.get(x[1],9)))
ncases = len(CASES)
print(f"GROUNDING master table  ({ncases} cases: {', '.join(CASES)})")
print(f"{'config':<22}{'metric':<26}" + "".join(f"{c:<12}" for c in conds))
for (m, eff) in configs:
    rs = [r for r in rows if r["model"]==m and r["effort"]==eff and not r.get("error")]
    # vuln detection
    line = f"{m+':'+eff:<22}{'VULN detect (recall)':<26}"
    for c in conds:
        cells=[r for r in rs if r["version"]=="before" and r["cond"]==c]
        hit=sum(1 for r in cells if r["target_hit"])
        line += f"{f'{hit}/{len(cells)}':<12}"
    print(line)
    # patched target-class hits (alert volume / potential FP)
    line = f"{'':<22}{'PATCHED same-class hit':<26}"
    for c in conds:
        cells=[r for r in rs if r["version"]=="after" and r["cond"]==c]
        hit=sum(1 for r in cells if r["target_hit"])
        line += f"{f'{hit}/{len(cells)}':<12}"
    print(line)
    # avg findings on patched (volume)
    line = f"{'':<22}{'PATCHED avg #findings':<26}"
    for c in conds:
        cells=[r for r in rs if r["version"]=="after" and r["cond"]==c]
        avg=sum(r["n_findings"] for r in cells)/max(len(cells),1)
        line += f"{avg:<12.2f}"
    print(line)
    print()
