"""Shared helpers: OpenAI calls, cost metering, patch parsing, scoring."""
import json, os, re, time, urllib.request, urllib.error, threading

BASE = os.path.dirname(os.path.abspath(__file__))
API_URL = "https://api.openai.com/v1/chat/completions"
PROXY = os.environ.get("HTTPS_PROXY")

# Pricing per 1M tokens: (input, cached_input, output).  output includes reasoning tokens.
# gpt-5.x values from repo's ModelPricing(1.25, 10.0, 0.125). gpt-4o from OpenAI public.
PRICING = {
    "gpt-5.4":        (1.25, 0.125, 10.0),
    "gpt-5.4-mini":   (0.25, 0.025, 2.0),
    "gpt-5.2":        (1.25, 0.125, 10.0),
    "gpt-5.5":        (1.25, 0.125, 10.0),
    "gpt-5.6-luna":   (1.25, 0.125, 10.0),
    "gpt-5.6-sol":    (1.25, 0.125, 10.0),
    "gpt-5.6-terra":  (1.25, 0.125, 10.0),
    "gpt-5":          (1.25, 0.125, 10.0),
    "gpt-4o":         (2.50, 1.25, 10.0),
    "gpt-4.1":        (2.00, 0.50, 8.0),
}
_DEFAULT_PRICE = (1.25, 0.125, 10.0)  # proxy for unknown models (flagged in reports)

class Meter:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = 0
        self.prompt = 0
        self.cached = 0
        self.completion = 0
        self.reasoning = 0
        self.usd = 0.0
    def add(self, model, usage):
        pin, pcached, pout = PRICING.get(model, _DEFAULT_PRICE)
        pt = usage.get("prompt_tokens", 0)
        ct = usage.get("completion_tokens", 0)
        cached = usage.get("prompt_tokens_details", {}).get("cached_tokens", 0)
        rt = usage.get("completion_tokens_details", {}).get("reasoning_tokens", 0)
        uncached = max(pt - cached, 0)
        cost = (uncached * pin + cached * pcached + ct * pout) / 1_000_000
        with self.lock:
            self.calls += 1
            self.prompt += pt
            self.cached += cached
            self.completion += ct
            self.reasoning += rt
            self.usd += cost
        return cost
    def summary(self):
        return {"calls": self.calls, "prompt_tokens": self.prompt, "cached_tokens": self.cached,
                "completion_tokens": self.completion, "reasoning_tokens": self.reasoning,
                "usd": round(self.usd, 4)}

def _opener():
    if PROXY:
        return urllib.request.build_opener(urllib.request.ProxyHandler({"https": PROXY, "http": PROXY}))
    return urllib.request.build_opener()

def chat(model, messages, reasoning_effort=None, temperature=None, max_retries=4, timeout=180):
    body = {"model": model, "messages": messages}
    if reasoning_effort is not None:
        body["reasoning_effort"] = reasoning_effort
    if temperature is not None:
        body["temperature"] = temperature
    data = json.dumps(body).encode()
    last = None
    for attempt in range(max_retries):
        req = urllib.request.Request(API_URL, data=data,
            headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
                     "Content-Type": "application/json"})
        try:
            with _opener().open(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}: {e.read().decode()[:300]}"
            if e.code in (429, 500, 502, 503, 529):
                time.sleep(2 ** attempt); continue
            return {"error": last}
        except Exception as e:  # noqa
            last = str(e); time.sleep(2 ** attempt); continue
    return {"error": last}

# ---- patch parsing -------------------------------------------------------
def parse_patch(text):
    """Return (subject, message, diff) from a git format-patch blob."""
    lines = text.splitlines()
    # subject: starts at 'Subject:' possibly wrapped over continuation lines (leading ws)
    subj_idx = next((i for i, l in enumerate(lines) if l.startswith("Subject:")), None)
    subject, body_start = "", 0
    if subj_idx is not None:
        subject = lines[subj_idx][len("Subject:"):].strip()
        j = subj_idx + 1
        while j < len(lines) and lines[j].startswith((" ", "\t")) and lines[j].strip():
            subject += " " + lines[j].strip(); j += 1
        body_start = j
    subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", subject)
    # find diffstat separator line that is exactly '---'
    sep = next((i for i in range(body_start, len(lines)) if lines[i].strip() == "---"), None)
    diff_idx = next((i for i, l in enumerate(lines) if l.startswith("diff --git ")), None)
    body_lines = lines[body_start:sep] if sep is not None else []
    body = "\n".join(body_lines).strip()
    diff = "\n".join(lines[diff_idx:]) if diff_idx is not None else ""
    return subject, body, diff

def load_pr(entry):
    pr = entry.get("pr")
    if not pr or pr == "EMPTY":
        return None
    path = os.path.join(BASE, pr)
    if os.path.exists(path):
        t = open(path, encoding="utf-8").read().strip()
        return t or None
    return None

# ---- prompt building -----------------------------------------------------
SYS = ("You are a security engineer triaging a single git commit. "
       "Decide whether the commit fixes a security vulnerability (not a mere bug, "
       "feature, refactor, or routine dependency bump).")

INSTR = ('Answer with ONLY a JSON object: '
         '{"security_fix": true|false, "confidence": <0.0-1.0>, '
         '"cwe": "<CWE id or short class name, or unknown>", '
         '"why": "<one short sentence>"}. Output the JSON and nothing else.')

def build_prompt(level, subject, body, diff, pr_body):
    """level in {L0,L1,L2}. Returns user message string."""
    parts = []
    if level == "L0":
        parts.append("Below is the commit diff and NOTHING else — no message, no description, "
                     "no PR. Judge only from the code change.")
        parts.append("\n=== DIFF ===\n" + diff + "\n=== END DIFF ===")
    elif level == "L1":
        msg = subject + (("\n\n" + body) if body else "")
        parts.append("Below is the commit message (title + body) and the diff.")
        parts.append("\n=== COMMIT MESSAGE ===\n" + msg + "\n=== END COMMIT MESSAGE ===")
        parts.append("\n=== DIFF ===\n" + diff + "\n=== END DIFF ===")
    elif level == "L2":
        msg = subject + (("\n\n" + body) if body else "")
        parts.append("Below is the commit message (title + body), the associated pull "
                     "request description, and the diff.")
        parts.append("\n=== COMMIT MESSAGE ===\n" + msg + "\n=== END COMMIT MESSAGE ===")
        parts.append("\n=== PULL REQUEST DESCRIPTION ===\n" + (pr_body or "") +
                     "\n=== END PULL REQUEST DESCRIPTION ===")
        parts.append("\n=== DIFF ===\n" + diff + "\n=== END DIFF ===")
    parts.append("\n" + INSTR)
    return "\n".join(parts)

def extract_json(content):
    if content is None:
        return None
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        # try to salvage trailing-comma / code fences
        s = m.group(0)
        s = re.sub(r",\s*}", "}", s)
        try:
            return json.loads(s)
        except Exception:
            return None

def cwe_hit(pred_cwe, cwe_truth, cwe_keywords):
    if not pred_cwe:
        return False
    p = str(pred_cwe).lower()
    for c in cwe_truth:
        if c.lower() in p:
            return True
    for k in cwe_keywords:
        if k.lower() in p:
            return True
    return False
