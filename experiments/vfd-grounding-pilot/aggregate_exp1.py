"""Aggregate all exp1 result files into clean tables for the writeup."""
import json, glob, os
BASE = os.path.dirname(os.path.abspath(__file__))
MAN = json.load(open(os.path.join(BASE, "manifest.json")))
POS = {e["id"]: e for e in MAN["positives"]}
NEG = {e["id"]: e for e in MAN["negatives"]}

rows = []
for fp in glob.glob(os.path.join(BASE, "runs", "exp1_gpt*.jsonl")):
    for l in open(fp):
        rows.append(json.loads(l))

configs = sorted({(r["model"], r["effort"]) for r in rows if not r.get("error")},
                 key=lambda x: (x[0], {"none":0,"low":1,"medium":2,"high":3}.get(x[1],9)))

print("CONTENT-LADDER: recall (positives) / specificity (negatives) by config and level")
print(f"{'model:effort':<20}{'lvl':<4}{'recall':<9}{'quiet_rec':<11}{'neg_FP':<8}{'cwe_hit':<9}")
for (m, eff) in configs:
    rs = [r for r in rows if r["model"]==m and r["effort"]==eff and not r.get("error")]
    for lvl in ("L0","L1","L2"):
        pos=[r for r in rs if r["kind"]=="positives" and r["level"]==lvl]
        neg=[r for r in rs if r["kind"]=="negatives" and r["level"]==lvl]
        if not pos and not neg: continue
        rec=sum(1 for r in pos if r["security_fix"] is True)
        q=[r for r in pos if r.get("stratum","").startswith("quiet")]
        qr=sum(1 for r in q if r["security_fix"] is True)
        cwe=sum(1 for r in pos if r.get("cwe_hit"))
        fp=sum(1 for r in neg if r["security_fix"] is True)
        print(f"{m+':'+eff:<20}{lvl:<4}{f'{rec}/{len(pos)}':<9}{f'{qr}/{len(q)}':<11}{f'{fp}/{len(neg)}':<8}{f'{cwe}/{len(pos)}':<9}")
    print()

# neutral prompt file
npf = os.path.join(BASE,"runs","exp1_neutralprompt.jsonl")
if os.path.exists(npf):
    nrows=[json.loads(l) for l in open(npf)]
    print("NEUTRAL-PROMPT ablation (L0 diff-only, no 'not a dep bump' hint):")
    for m in sorted({r["model"] for r in nrows}):
        rs=[r for r in nrows if r["model"]==m and not r.get("error")]
        pos=[r for r in rs if r["kind"]=="positives"]; neg=[r for r in rs if r["kind"]=="negatives"]
        rec=sum(1 for r in pos if r["security_fix"] is True); fp=sum(1 for r in neg if r["security_fix"] is True)
        print(f"  {m:<16} recall={rec}/{len(pos)}  neg_FP={fp}/{len(neg)}")
