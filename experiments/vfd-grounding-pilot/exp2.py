"""Experiment 2 - security-context grounding.

Does a security context generated from a repo's PAST vulnerabilities improve
the model's findings on NEW code, vs analyzing it blind for the first time?

For each case we review the FULL file in two versions (before=vulnerable,
after=patched) under four context conditions (blind / grounded-relevant /
grounded-irrelevant / leading). We measure:
  - detection of the HELD-OUT target vuln on the vulnerable file (recall)
  - false alarm for the target vuln on the PATCHED file (precision cost)
across conditions. Grounding "helps accuracy" iff relevant context raises
detection on vulnerable code WITHOUT raising false alarms on patched code, and
iff irrelevant context does NOT (ruling out mere yes-priming).

Usage: python exp2.py "gpt-5.4:none" ["gpt-5.4:medium"]
"""
import json, os, sys, concurrent.futures as cf
import common as C
from contexts import CASES

BASE = C.BASE
SYS = ("You are a senior application-security auditor performing a code review. "
       "Report only genuine, concrete security vulnerabilities in the code shown "
       "(not style, not hypothetical hardening). Be precise about location.")
INSTR = ('Respond with ONLY a JSON object: {"findings": [{"cwe": "<id or class>", '
         '"location": "<function/area>", "severity": "low|medium|high", '
         '"why": "<one sentence>"}]}. If you find no security vulnerability, return '
         '{"findings": []}. Do not invent issues to fill the list.')

def build_user(case, version_code, condition, ctx):
    header = f"Code under review from {case['repo']} - file {case['file']}:\n"
    blocks = []
    if condition == "blind":
        blocks.append(header)
    else:
        label = {"relevant": "PRIOR SECURITY CONTEXT for this repository (background from earlier analysis)",
                 "irrelevant": "PRIOR SECURITY CONTEXT for this repository (background from earlier analysis)",
                 "leading": "PRIOR FINDING to verify"}[condition]
        blocks.append(f"=== {label} ===\n{ctx}\n=== END CONTEXT ===\n")
        blocks.append("Use the context as background. Review the code on its own merits; "
                      "report a vulnerability only if it is actually present in the code.\n")
        blocks.append(header)
    blocks.append("```go\n" + version_code + "\n```\n")
    blocks.append(INSTR)
    return "\n".join(blocks)

def target_hit(findings, case):
    kws = case["target_keywords"]
    for f in findings or []:
        blob = " ".join(str(f.get(k, "")) for k in ("cwe", "location", "why")).lower()
        if any(kw in blob for kw in kws):
            return True
    return False

def main():
    specs = sys.argv[1:] or ["gpt-5.4:none"]
    conditions = ["blind", "relevant", "irrelevant", "leading"]
    tasks = []
    for cid, case in CASES.items():
        for version in ("before", "after"):
            code = open(os.path.join(BASE, "code", f"{cid}.{version}.go"), encoding="utf-8").read()
            for cond in conditions:
                ctx = None if cond == "blind" else case[cond]
                user = build_user(case, code, cond, ctx)
                for spec in specs:
                    model, effort = spec.split(":")
                    tasks.append({"case": cid, "version": version, "cond": cond,
                                  "model": model, "effort": effort, "user": user})
    meter = C.Meter()
    print(f"specs={specs}  tasks={len(tasks)}")

    def run(t):
        model, effort = t["model"], t["effort"]
        msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": t["user"]}]
        kw = {"reasoning_effort": effort} if (model.startswith("gpt-5") and "chat" not in model) else {"temperature": 0}
        r = C.chat(model, msgs, **kw)
        o = {k: t[k] for k in ("case", "version", "cond", "model", "effort")}
        if "error" in r:
            o["error"] = r["error"]; return o
        meter.add(model, r.get("usage", {}))
        js = C.extract_json(r["choices"][0]["message"]["content"])
        findings = (js or {}).get("findings", []) if isinstance(js, dict) else []
        o["n_findings"] = len(findings)
        o["target_hit"] = target_hit(findings, CASES[t["case"]])
        o["findings"] = findings
        return o

    results = []
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(run, t) for t in tasks]
        for i, f in enumerate(cf.as_completed(futs), 1):
            results.append(f.result())
            if i % 12 == 0:
                print(f"  {i}/{len(tasks)} done, ${meter.usd:.3f}")
    tag = "_".join(s.replace(":", "-") for s in specs)
    outpath = os.path.join(BASE, "runs", f"exp2_{tag}.jsonl")
    with open(outpath, "w") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")
    errs = [r for r in results if r.get("error")]
    print(f"\nwrote {outpath} ({len(results)} rows, {len(errs)} errors)")
    print("METER:", json.dumps(meter.summary()))
    summarize(results, specs, conditions)

def summarize(results, specs, conditions):
    for spec in specs:
        model, effort = spec.split(":")
        rs = [r for r in results if r["model"] == model and r["effort"] == effort and not r.get("error")]
        print(f"\n===== {spec} =====")
        # detection on vulnerable (before) and false-alarm on patched (after), per condition
        print(f"{'':<12}" + "".join(f"{c:<12}" for c in conditions))
        for version, lbl in (("before", "VULN detect (target found)"), ("after", "PATCHED false-alarm")):
            print(f"  {lbl}")
            line = f"{'    hit-rate':<12}"
            for cond in conditions:
                cells = [r for r in rs if r["version"] == version and r["cond"] == cond]
                hit = sum(1 for r in cells if r["target_hit"])
                line += f"{f'{hit}/{len(cells)}':<12}"
            print(line)
            nf = f"{'    avg#find':<12}"
            for cond in conditions:
                cells = [r for r in rs if r["version"] == version and r["cond"] == cond]
                avg = sum(r["n_findings"] for r in cells) / max(len(cells), 1)
                nf += f"{avg:<12.2f}"
            print(nf)
        # per-case detail on vulnerable file
        print("  per-case target-hit on VULNERABLE file (before):")
        for cid in CASES:
            row = f"    {cid:<10}"
            for cond in conditions:
                cell = next((r for r in rs if r["case"] == cid and r["version"] == "before" and r["cond"] == cond), None)
                row += f"{('YES' if cell and cell['target_hit'] else 'miss'):<12}"
            print(row)
        print("  per-case target-hit on PATCHED file (after) [YES = false alarm]:")
        for cid in CASES:
            row = f"    {cid:<10}"
            for cond in conditions:
                cell = next((r for r in rs if r["case"] == cid and r["version"] == "after" and r["cond"] == cond), None)
                row += f"{('YES' if cell and cell['target_hit'] else '-'):<12}"
            print(row)

if __name__ == "__main__":
    main()
