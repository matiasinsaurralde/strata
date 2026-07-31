"""Experiment 1 - content-ladder triage.

For each commit and each content level (L0 diff-only, L1 +commit msg, L2 +PR),
ask the model: does this commit fix a security vulnerability? Measure recall on
positives, specificity/FPR on negatives, and CWE accuracy - and how added
context shifts the decision.

Usage:  python exp1.py "gpt-5.4:none" ["gpt-5.4:medium" ...]
"""
import json, os, sys, concurrent.futures as cf
import common as C

BASE = C.BASE
MAN = json.load(open(os.path.join(BASE, "manifest.json")))

def levels_for(entry):
    lv = ["L0", "L1"]
    if C.load_pr(entry):  # non-empty PR body
        lv.append("L2")
    return lv

def build_tasks(specs):
    tasks = []
    for kind in ("positives", "negatives"):
        for e in MAN[kind]:
            text = open(os.path.join(BASE, e["patch"]), encoding="utf-8").read()
            subj, body, diff = C.parse_patch(text)
            pr = C.load_pr(e)
            for lvl in levels_for(e):
                prompt = C.build_prompt(lvl, subj, body, diff, pr)
                for spec in specs:
                    model, effort = spec.split(":")
                    tasks.append({"kind": kind, "id": e["id"], "level": lvl,
                                  "model": model, "effort": effort,
                                  "prompt": prompt, "entry": e})
    return tasks

def run_one(t, meter):
    model, effort = t["model"], t["effort"]
    msgs = [{"role": "system", "content": C.SYS},
            {"role": "user", "content": t["prompt"]}]
    kw = {}
    if model.startswith("gpt-5") and "chat" not in model:
        kw["reasoning_effort"] = effort
    else:
        kw["temperature"] = 0
    r = C.chat(model, msgs, **kw)
    out = {"kind": t["kind"], "id": t["id"], "level": t["level"],
           "model": model, "effort": effort}
    if "error" in r:
        out["error"] = r["error"]; return out
    content = r["choices"][0]["message"]["content"]
    meter.add(model, r.get("usage", {}))
    js = C.extract_json(content)
    out["raw"] = content
    out["parsed"] = js
    out["security_fix"] = (js or {}).get("security_fix")
    out["confidence"] = (js or {}).get("confidence")
    out["cwe"] = (js or {}).get("cwe")
    out["why"] = (js or {}).get("why")
    e = t["entry"]
    if t["kind"] == "positives":
        out["cwe_hit"] = C.cwe_hit(out["cwe"], e["cwe_truth"], e["cwe_keywords"])
        out["stratum"] = e["stratum"]
    else:
        out["hardness"] = e["hardness"]; out["neg_kind"] = e["kind"]
    return out

def main():
    specs = sys.argv[1:] or ["gpt-5.4:none"]
    tasks = build_tasks(specs)
    meter = C.Meter()
    print(f"specs={specs}  tasks={len(tasks)}")
    results = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(run_one, t, meter) for t in tasks]
        for i, f in enumerate(cf.as_completed(futs), 1):
            results.append(f.result())
            if i % 10 == 0:
                print(f"  {i}/{len(tasks)} done, ${meter.usd:.3f}")
    tag = "_".join(s.replace(":", "-") for s in specs)
    outpath = os.path.join(BASE, "runs", f"exp1_{tag}.jsonl")
    with open(outpath, "w") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")
    errs = [r for r in results if r.get("error")]
    print(f"\nwrote {outpath}  ({len(results)} rows, {len(errs)} errors)")
    print("METER:", json.dumps(meter.summary()))
    if errs:
        print("ERRORS (first 3):", [e["error"][:120] for e in errs[:3]])
    summarize(results, specs)

def summarize(results, specs):
    for spec in specs:
        model, effort = spec.split(":")
        rs = [r for r in results if r["model"] == model and r["effort"] == effort and not r.get("error")]
        print(f"\n===== {spec} =====")
        # per-commit YES/NO grid
        print(f"{'id':<28}{'kind':<5}{'strat/hard':<16}{'L0':<6}{'L1':<6}{'L2':<6}{'cwe(L0/L1)'}")
        ids = []
        for kind in ("positives", "negatives"):
            for e in MAN[kind]:
                ids.append((kind, e["id"]))
        for kind, cid in ids:
            row = {r["level"]: r for r in rs if r["id"] == cid}
            def cell(lvl):
                if lvl not in row: return "-"
                v = row[lvl].get("security_fix")
                return "YES" if v is True else ("no" if v is False else "?")
            meta = ""
            if kind == "positives":
                meta = next(r.get("stratum","") for r in rs if r["id"]==cid) if any(r["id"]==cid for r in rs) else ""
            else:
                meta = next((r.get("hardness","") for r in rs if r["id"]==cid), "")
            cwe0 = row.get("L0",{}).get("cwe_hit","")
            cwe1 = row.get("L1",{}).get("cwe_hit","")
            cwestr = f"{cwe0}/{cwe1}" if kind=="positives" else ""
            print(f"{cid:<28}{('pos' if kind=='positives' else 'neg'):<5}{meta:<16}{cell('L0'):<6}{cell('L1'):<6}{cell('L2'):<6}{cwestr}")
        # aggregate
        for lvl in ("L0", "L1", "L2"):
            pos = [r for r in rs if r["kind"]=="positives" and r["level"]==lvl]
            neg = [r for r in rs if r["kind"]=="negatives" and r["level"]==lvl]
            if pos:
                rec = sum(1 for r in pos if r["security_fix"] is True)
                qpos = [r for r in pos if r.get("stratum","").startswith("quiet")]
                qrec = sum(1 for r in qpos if r["security_fix"] is True)
                cwe = sum(1 for r in pos if r.get("cwe_hit"))
                s = f"  {lvl} recall={rec}/{len(pos)}"
                if qpos: s += f"  quiet_recall={qrec}/{len(qpos)}"
                s += f"  cwe_hit={cwe}/{len(pos)}"
            else:
                s = f"  {lvl} recall=-"
            if neg:
                fp = sum(1 for r in neg if r["security_fix"] is True)
                s += f"  |  neg FP={fp}/{len(neg)} (specificity={len(neg)-fp}/{len(neg)})"
            if pos or neg:
                print(s)

if __name__ == "__main__":
    main()
