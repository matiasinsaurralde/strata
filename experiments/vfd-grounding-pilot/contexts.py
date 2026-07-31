"""Security-context definitions for Experiment 2 (grounding).

Per case we define:
  relevant   - aggregate, securitycontext.dev-style context for the SAME repo,
               matching the held-out vuln's CWE family, WITHOUT naming the exact
               function/line (realistic prior-history grounding).
  irrelevant - same repo, a DIFFERENT plausible vuln class (priming control:
               if this raises detection of the target, the model is just being
               made yes-happy, not genuinely grounded).
  leading    - states the specific finding directly ("these are the findings").
               Applied to BOTH vulnerable and PATCHED code to measure priming /
               false-alarm inflation - the naive/too-obvious approach.

  target_keywords - used to score whether a model finding matches the held-out
               vuln (checked against the finding's cwe/why/location).
"""

CASES = {
  "sliver": {
    "repo": "BishopFox/sliver",
    "file": "server/db/models/website.go",
    "target_cwe": "CWE-22 (Path Traversal)",
    "target_keywords": ["path travers", "travers", "filepath.join", "readfile",
                         "webcontent.path", ".path", "arbitrary file", "directory",
                         "toprotobuf", "path construction", "outside"],
    "relevant": (
      "Security context for BishopFox/sliver (compiled from prior fixes).\n"
      "- Total prior security fixes: 9;  peak severity: HIGH.\n"
      "- RECURRING PATTERN - Path Traversal (CWE-22): several past fixes involved "
      "stored or client-controlled string values being used to build filesystem "
      "paths (filepath.Join / os.ReadFile / os.Open) in the website/content-hosting "
      "subsystem, allowing reads outside the intended directory.\n"
      "- Most-fixed area: server-side content serving (server/db/models, server/website).\n"
      "- Guidance: scrutinize any place a stored/DB or client-supplied field is used "
      "to construct a filesystem path."
    ),
    "irrelevant": (
      "Security context for BishopFox/sliver (compiled from prior fixes).\n"
      "- RECURRING PATTERN - Insecure Deserialization (CWE-502): gob/JSON decoding of "
      "attacker-controlled implant messages has been mishandled.\n"
      "- RECURRING PATTERN - Use of hardcoded / weak default credentials (CWE-798) in "
      "mTLS setup.\n"
      "- Guidance: scrutinize gob.Decode of network input and default cert/key material."
    ),
    "leading": (
      "Prior review of this file reported a Path Traversal (CWE-22): a stored, "
      "potentially attacker-controlled value (webcontent.Path) is passed to "
      "filepath.Join/os.ReadFile in Website.ToProtobuf, allowing reads outside "
      "webContentDir. Confirm whether this vulnerability is present."
    ),
  },

  "istio": {
    "repo": "istio/istio",
    "file": "pilot/pkg/security/authz/model/generator.go",
    "target_cwe": "CWE-185/CWE-863 (regex injection -> authorization bypass)",
    "target_keywords": ["regex", "regular expression", "metachar", "quotemeta",
                         "escap", "authorization bypass", "authz bypass", "bypass",
                         "serviceaccount", "principal", "spiffe", "injection", "sa/"],
    "relevant": (
      "Security context for istio/istio (compiled from prior fixes).\n"
      "- Total prior security fixes: 23;  CVEs: 14;  peak severity: CRITICAL.\n"
      "- RECURRING PATTERN - Authorization bypass via matcher construction "
      "(CWE-863 / CWE-185): AuthorizationPolicy principals and paths are compiled "
      "into regular expressions; past fixes addressed unintended matches when "
      "user-supplied identifiers (namespaces, service accounts, paths) were "
      "interpolated into a regex/matcher WITHOUT escaping.\n"
      "- Most-fixed component: pilot authz model / RBAC (pilot/pkg/security/authz).\n"
      "- Guidance: scrutinize any regex/matcher built from configuration strings in "
      "the authz code paths."
    ),
    "irrelevant": (
      "Security context for istio/istio (compiled from prior fixes).\n"
      "- RECURRING PATTERN - Denial of Service via unbounded resource consumption "
      "(CWE-400): large or malformed xDS / HTTP-2 payloads have caused excessive "
      "memory/CPU.\n"
      "- Guidance: scrutinize parsing of untrusted control-plane payloads for missing "
      "size limits and goroutine leaks."
    ),
    "leading": (
      "Prior review of this file reported an Authorization Bypass (CWE-185/CWE-863): "
      "serviceAccountRegex interpolates the namespace and service-account values into "
      "a regex without escaping metacharacters, so a crafted name can broaden the "
      "match. Confirm whether this vulnerability is present."
    ),
  },

  "aws-efs": {
    "repo": "kubernetes-sigs/aws-efs-csi-driver",
    "file": "pkg/driver/node.go",
    "target_cwe": "CWE-88/CWE-77 (mount option / argument injection)",
    "target_keywords": ["injection", "mount option", "option inject", "argument inject",
                         "mounttargetip", "unsanit", "unvalidat", "validat",
                         "volumecontext", "volume context", "command inject", "append"],
    "relevant": (
      "Security context for kubernetes-sigs/aws-efs-csi-driver (compiled from prior fixes).\n"
      "- RECURRING PATTERN - Argument / Mount-option Injection (CWE-88 / CWE-77): "
      "values taken from the CSI volume context (volume attributes) have been "
      "concatenated into mount option strings or command arguments without validation, "
      "letting a caller inject additional options.\n"
      "- Most-affected area: NodePublishVolume mount-option assembly (pkg/driver/node.go).\n"
      "- Guidance: scrutinize any volumeContext value appended to mountOptions or passed "
      "toward mount/exec without strict validation/sanitization."
    ),
    "irrelevant": (
      "Security context for kubernetes-sigs/aws-efs-csi-driver (compiled from prior fixes).\n"
      "- RECURRING PATTERN - Incorrect privilege / IAM credential handling (CWE-269): "
      "cross-account and IAM role assumption logic has mishandled credentials.\n"
      "- Guidance: scrutinize crossAccount and awsProfile handling for privilege errors."
    ),
    "leading": (
      "Prior review of this file reported a Mount-option Injection (CWE-88): the "
      "MountTargetIp value from the volume context is appended to mount options without "
      "validation in NodePublishVolume, allowing option injection. Confirm whether this "
      "vulnerability is present."
    ),
  },

  "go-tuf": {
    "repo": "theupdateframework/go-tuf",
    "file": "metadata/metadata.go",
    "target_cwe": "CWE-617/CWE-754/CWE-248 (reachable panic / unchecked type assertion -> DoS)",
    "target_keywords": ["panic", "type assertion", "assertion", "nil deref", "nil",
                         "uncaught", "denial of service", "dos", "crash", "checktype",
                         "unchecked", "malformed", "runtime error"],
    "relevant": (
      "Security context for theupdateframework/go-tuf (compiled from prior fixes).\n"
      "- RECURRING PATTERN - Client Denial of Service via malformed server responses "
      "(CWE-617 / CWE-754): parsing of untrusted, attacker-controlled TUF metadata has "
      "repeatedly hit reachable panics - unchecked type assertions, nil dereferences, "
      "unhandled error paths - turning a malformed response into a client crash.\n"
      "- Guidance: scrutinize any unchecked type assertion or map access performed on "
      "freshly unmarshaled/untrusted metadata."
    ),
    "irrelevant": (
      "Security context for theupdateframework/go-tuf (compiled from prior fixes).\n"
      "- RECURRING PATTERN - Signature/threshold verification bypass (CWE-347): "
      "delegation and threshold checks have had logic errors letting metadata be trusted "
      "without sufficient valid signatures.\n"
      "- Guidance: scrutinize VerifyDelegate threshold accounting and key-id handling."
    ),
    "leading": (
      "Prior review of this file reported a reachable panic / Denial of Service "
      "(CWE-617): checkType performs an unchecked chained type assertion "
      "(m[\"signed\"].(map[string]any)[\"_type\"].(string)) on unmarshaled metadata, so "
      "malformed input panics. Confirm whether this vulnerability is present."
    ),
  },
}
