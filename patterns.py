import re, math
from collections import Counter

PATTERNS = [
    (r"sk-proj-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Project"),
    (r"sk-svcacct-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Service Account"),
    (r"sk-admin-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Admin"),
    (r"sk-[A-Za-z0-9]{20,42}T3BlbkFJ[A-Za-z0-9]{20,42}", "OpenAI Legacy"),
    (r"sk-ant-api03-[A-Za-z0-9_-]{70,110}", "Anthropic"),
    (r"AIzaSy[A-Za-z0-9_-]{33}", "Google Gemini"),
    (r"xai-[A-Za-z0-9]{30,70}", "xAI Grok"),
    (r"sk-[a-f0-9]{32,64}", "DeepSeek"),
    (r"sk-or-v1-[A-Za-z0-9_-]{40,100}", "OpenRouter"),
    (r"gsk_[a-zA-Z0-9]{45,60}", "Groq"),
    (r"hf_[A-Za-z0-9]{30,60}", "HuggingFace"),
    (r"r8_[A-Za-z0-9]{30,50}", "Replicate"),
    (r"mist_[A-Za-z0-9]{25,60}", "Mistral"),
    (r"pplx-[A-Za-z0-9_-]{30,80}", "Perplexity"),
    (r"together_[A-Za-z0-9]{30,60}", "Together AI"),
    (r"fw_[A-Za-z0-9]{30,50}", "Fireworks"),
    (r"ghp_[A-Za-z0-9]{36,40}", "GitHub PAT"),
    (r"github_pat_[A-Za-z0-9_]{60,90}", "GitHub PAT (fine-grained)"),
    (r"glpat-[A-Za-z0-9_-]{20,40}", "GitLab PAT"),
    (r"xox[baprs]-[A-Za-z0-9-]{20,80}", "Slack Token"),
    (r"sk_live_[A-Za-z0-9]{20,40}", "Stripe Live Secret"),
    (r"pk_live_[A-Za-z0-9]{20,40}", "Stripe Live Publishable"),
    (r"rk_live_[A-Za-z0-9]{20,40}", "Stripe Live Restricted"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,100}", "Azure Connection String"),
]

PLACEHOLDER_PATTERNS = [
    r"(?i)your[-_]?(key|api|secret|token)",
    r"(?i)(changeme|change_me|replace|placeholder|example|demo|test|dummy|sample)",
    r"sk-[a-zA-Z0-9]{20,30}$",
    r"sk-proj-[a-zA-Z0-9_-]{10,30}$",
    r"^\$[A-Z_]+$",
    r"^\$\{[A-Z_]+\}$",
    r"your-api-key-goes-here",
]

# Known test/example keys (corpus for false positive filtering)
KNOWN_TEST_KEYS = {
    "sk-proj-example123456789012345678901234567890",
    "sk-thisisatestkey12345678901234567890123",
    "your_openai_api_key_here",
    "REPLACE_ME_WITH_REAL_KEY",
    "test_api_key_do_not_use",
    "example_key_for_demo_only",
    "sk-dummykeyfordocumentationpurposes",
}

def is_test_key(key):
    k = key.strip()
    if k in KNOWN_TEST_KEYS:
        return True
    # Also check for repeated patterns
    if len(set(k)) < 8:  # Low unique char count (e.g., "aaaaaaaa...")
        return True
    return False

ALLOWED_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sh", ".env", ".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".toml", ".md", ".txt", ".cfg", ".properties"}

_re_entire_pat = None

def get_combined_pattern():
    global _re_entire_pat
    if _re_entire_pat is None:
        fragments = [p for p, _ in PATTERNS]
        _re_entire_pat = re.compile("|".join(fragments))
    return _re_entire_pat

def is_placeholder(key):
    return any(re.match(p, key) for p in PLACEHOLDER_PATTERNS)

def entropy(s):
    if len(s) < 20: return 0.0
    c = Counter(s); p = [v/len(s) for v in c.values()]
    return -sum(v * math.log2(v) for v in p if v > 0)

def extract_keys(text, min_entropy=3.6):
    if not text: return []
    found = []
    seen = set()
    for pat, service in PATTERNS:
        for m in re.finditer(pat, text):
            k = m.group(0)
            if k in seen: continue
            seen.add(k)
            if len(k) < 32: continue
            if re.match(r"^[0-9a-fA-F]{40,}$", k): continue
            if is_placeholder(k): continue
            if is_test_key(k): continue
            e = entropy(k)
            if e < min_entropy: continue
            found.append({"service": service, "key": k, "entropy": e})
    return found

VALIDATORS = {}

def register_validator(service, fn):
    VALIDATORS[service] = fn

def validate_key(service, key):
    for prefix, fn in VALIDATORS.items():
        if service.startswith(prefix):
            return fn(key)
    return "unknown"
