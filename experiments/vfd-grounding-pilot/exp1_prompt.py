"""Prompt-sensitivity ablation for Experiment 1.

The main run's system prompt tells the model a fix is "not a mere bug, feature,
refactor, or routine dependency bump" - which primes rejection of dep bumps and
may be doing the FPR work. Here we re-run L0 (diff-only) with a NEUTRAL system
prompt that drops that exclusion clause, to see how much of the clean
specificity is prompt engineering vs model capability.

Usage: python exp1_prompt.py "gpt-4o:none" "gpt-5.2:none" "gpt-5.4:none"
"""
import json, os, sys, concurrent.futures as cf
import common as C

BASE = C.BASE
MAN = json.load(open(os.path.join(BASE, "manifest.json")))
NEUTRAL_SYS = ("You are a security engineer reviewing a single git commit to decide "
               "whether it fixes a security vulnerability.")

def main():
    specs = sys.argv[1:] or ["gpt-4o:none", "gpt-5.2:none", "gpt-5.4:none"]
    tasks = []
    for kind in ("positives", "negatives"):
        for e in MAN[kind]:
            text = open(os.path.join(BASE, e["patch"]), encoding="utf-8").read()
            subj, body, diff = C.parse_patch(text)
            prompt = C.build_prompt("L0", subj, body, diff, None)
            for spec in specs:
                model, effort = spec.split(":")
                tasks.append((kind, e, model, effort, prompt))
    meter = C.Meter()
    def run(t):
        kind, e, model, effort, prompt = t
        msgs = [{"role": "system", "content": NEUTRAL_SYS},
                {"role": "user", "content": prompt}]
        kw = {"reasoning_effort": effort} if (model.startswith("gpt-5") and "chat" not in model) else {"temperature": 0}
        r = C.chat(model, msgs, **kw)
        o = {"kind": kind, "id": e["id"], "model": model, "effort": effort}
        if "error" in r:
            o["error"] = r["error"]; return o
        meter.add(model, r.get("usage", {}))
        js = C.extract_json(r["choices"][0]["message"]["content"])
        o["security_fix"] = (js or {}).get("security_fix")
        o["why"] = (js or {}).get("why")
        if kind == "negatives":
            o["hardness"] = e["hardness"]
        return o
    res = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(run, tasks):
            res.append(r)
    with open(os.path.join(BASE, "runs", "exp1_neutralprompt.jsonl"), "w") as fh:
        for r in res: fh.write(json.dumps(r) + "\n")
    print("METER:", json.dumps(meter.summary()))
    for spec in specs:
        model, effort = spec.split(":")
        rs = [r for r in res if r["model"] == model and not r.get("error")]
        pos = [r for r in rs if r["kind"] == "positives"]
        neg = [r for r in rs if r["kind"] == "negatives"]
        rec = sum(1 for r in pos if r["security_fix"] is True)
        fp = sum(1 for r in neg if r["security_fix"] is True)
        print(f"\n[{spec}] NEUTRAL prompt, L0 diff-only:  recall={rec}/{len(pos)}  neg_FP={fp}/{len(neg)}")
        for r in neg:
            v = "YES(FP)" if r["security_fix"] is True else "no"
            print(f"    {r['id']:<28}{r.get('hardness',''):<6}{v:<8} {str(r.get('why'))[:80]}")

if __name__ == "__main__":
    main()
