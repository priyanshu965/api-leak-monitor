import os, re, time, json, tempfile, subprocess, tarfile, io, gzip, fnmatch, urllib.parse
import requests
from db import is_event_seen, mark_event_seen, is_key_seen, save_finding
from patterns import extract_keys, ALLOWED_EXTS, PATTERNS, get_combined_pattern, entropy

SHODAN_KEY = os.getenv("SHODAN_KEY", "")
CENSYS_SECRET = os.getenv("CENSYS_SECRET", "")
PASTEBIN_KEY = os.getenv("PASTEBIN_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GOOGLE_CX = os.getenv("GOOGLE_CX", "")
SCAN_PAGES = int(os.getenv("SCAN_PAGES", "10"))
HEADERS = {"User-Agent": "API-Leak-Scanner/2.0"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

_logged_this_run = set()

def log_result(service, key, source, repo="", file_path="", context="", entropy_val=0):
    if key in _logged_this_run: return
    _logged_this_run.add(key)
    if is_key_seen(key): return
    save_finding(service, key, source, repo, file_path, context, entropy_val)
    print(f"  [{source}] {service} | {key[:40]}... | {repo[:50]}")

# ── 1. GitHub Events ──

def scan_events():
    print("\n[GitHub Events]")
    seen = set(); events = []
    for p in range(1, SCAN_PAGES + 1):
        try:
            r = requests.get("https://api.github.com/events", params={"per_page": 100, "page": p}, headers=HEADERS, timeout=15)
            if r.status_code != 200: break
            batch = r.json()
            if not batch: break
            events.extend(batch)
        except: break
    print(f"  Fetched {len(events)} events")
    count = 0
    for ev in reversed(events):
        eid = str(ev.get("id", ""))
        if not eid or is_event_seen(eid, "events"): continue
        mark_event_seen(eid, "events")
        if ev.get("type") != "PushEvent": continue
        payload = ev.get("payload", {})
        if "head" not in payload or "before" not in payload: continue
        repo = ev["repo"]["name"]
        try:
            r = requests.get(f"https://api.github.com/repos/{repo}/compare/{payload['before']}...{payload['head']}", headers=HEADERS, timeout=10)
            if r.status_code != 200: continue
        except: continue
        for f in r.json().get("files", []):
            patch = f.get("patch", "")
            fn = f["filename"]
            if not any(fn.lower().endswith(e) for e in ALLOWED_EXTS): continue
            for line in patch.splitlines():
                if not line.startswith("+"): continue
                for k in extract_keys(line[1:].strip()):
                    log_result(k["service"], k["key"], "events", repo, fn, f"https://github.com/{repo}/pull/new", k["entropy"])
        count += 1
    print(f"  Scanned {count} pushes")

# ── 2. Sourcegraph ──

def scan_sourcegraph():
    print("\n[Sourcegraph]")
    seen = set(); queries = ["T3BlbkFJ lang:dotenv", "sk-proj- lang:dotenv", "OPENAI_API_KEY lang:dotenv"]
    for q in queries:
        try:
            r = requests.post("https://sourcegraph.com/.api/graphql", json={
                "query": f'{{ search(query: "{q} patternType:standard") {{ results {{ matchCount results {{ ... on FileMatch {{ file {{ path repository {{ name }} }} }} }} }} }} }}'
            }, timeout=15)
            if r.status_code != 200: continue
            for res in r.json().get("data", {}).get("search", {}).get("results", {}).get("results", []):
                repo = res.get("file", {}).get("repository", {}).get("name", "").replace("github.com/", "")
                path = res.get("file", {}).get("path", "")
                key = f"{repo}/{path}"
                if key in seen: continue
                seen.add(key)
                for branch in ["main", "master"]:
                    try:
                        c = requests.get(f"https://raw.githubusercontent.com/{repo}/{branch}/{path}", timeout=10).text
                        for k in extract_keys(c):
                            log_result(k["service"], k["key"], "sourcegraph", repo, path, f"https://github.com/{repo}/blob/{branch}/{path}", k["entropy"])
                        break
                    except: continue
        except: pass
    print(f"  Checked {len(seen)} files")

# ── 3. GitHub Gists ──

def scan_gists():
    print("\n[GitHub Gists]")
    for q in ["OPENAI_API_KEY", "sk-proj", "T3BlbkFJ"]:
        try:
            r = requests.get(f"https://api.github.com/search/code?q={q}+extension:env+gist&sort=indexed&order=desc&per_page=30", headers=HEADERS, timeout=10)
            if r.status_code != 200: continue
            for item in r.json().get("items", []):
                repo = item.get("repository", {}).get("full_name", "gist")
                fn = item.get("name", "")
                html = item.get("html_url", "")
                gu = item.get("git_url", "")
                if not gu: continue
                try:
                    c = requests.get(gu.replace("git://", "https://").replace(".git", "") + "?raw=true", timeout=10).text
                    for k in extract_keys(c):
                        log_result(k["service"], k["key"], "gists", repo, fn, html, k["entropy"])
                except: pass
        except: pass

# ── 4. Gitleaks (trending repos) ──

def scan_gitleaks():
    print("\n[Gitleaks Trending]")
    if not subprocess.run(["which", "gitleaks"], capture_output=True).returncode == 0:
        return print("  gitleaks not installed")
    try:
        r = requests.get("https://api.github.com/search/repositories?q=created:>2024-01-01+language:python&sort=stars&order=desc&per_page=5", headers=HEADERS, timeout=10)
        if r.status_code != 200: return
        for repo in r.json().get("items", [])[:5]:
            name = repo["full_name"]; clone = repo["clone_url"]
            print(f"  Scanning {name}...")
            tmp = tempfile.mkdtemp()
            try:
                subprocess.run(["git", "clone", "--depth", "1", "--quiet", clone, tmp], capture_output=True, timeout=30)
                result = subprocess.run(["gitleaks", "detect", "--source", tmp, "--no-git", "--report-format", "json", "--report-path", "/dev/stdout"], capture_output=True, text=True, timeout=30)
                for line in result.stdout.strip().split("\n"):
                    if not line: continue
                    try:
                        f = json.loads(line); s = f.get("Secret", "")
                        if s and len(s) > 10:
                            for k in extract_keys(s):
                                log_result(k["service"], k["key"], "gitleaks", name, f.get("File",""), f"gitleaks: {f.get('Description','')}", k["entropy"])
                    except: pass
            except: pass
            finally:
                subprocess.run(["rm", "-rf", tmp])
    except: pass

# ── 5. Shodan ──

def scan_shodan():
    print("\n[Shodan]")
    if not SHODAN_KEY: return print("  No API key")
    for q in [".env", "OPENAI_API_KEY", "filetype:env"]:
        try:
            r = requests.get(f"https://api.shodan.io/shodan/query?query={requests.utils.quote(q)}&key={SHODAN_KEY}", timeout=15)
            if r.status_code != 200: continue
            for match in r.json().get("matches", [])[:30]:
                ip = match.get("ip_str", "?"); port = match.get("port", "?"); data = match.get("data", "")
                for k in extract_keys(data):
                    log_result(k["service"], k["key"], "shodan", f"{ip}:{port}", "", f"shodan://{ip}:{port}", k["entropy"])
        except Exception as e:
            print(f"  Error: {e}")

# ── 6. Censys ──

def scan_censys():
    print("\n[Censys]")
    if not CENSYS_SECRET: return print("  No API key")
    try:
        # Try Bearer token with full censys_xxx token
        r = requests.get("https://search.censys.io/api/v2/hosts/search?q=.env+AND+services.service_name%3DHTTP&per_page=30",
            headers={"Accept": "application/json", "Authorization": f"Bearer {CENSYS_SECRET}"}, timeout=15)
        if r.status_code == 401:
            # Try Basic auth with parsed API ID and Secret
            import base64
            parts = CENSYS_SECRET.split("_")
            if len(parts) >= 3:
                api_id, secret = parts[1], parts[2]
                auth_b64 = base64.b64encode(f"{api_id}:{secret}".encode()).decode()
                r = requests.get("https://search.censys.io/api/v2/hosts/search?q=.env&per_page=30",
                    headers={"Accept": "application/json", "Authorization": f"Basic {auth_b64}"}, timeout=15)
        if r.status_code != 200: return print(f"  API error: {r.status_code}")
        for hit in r.json().get("result", {}).get("hits", [])[:30]:
            ip = hit.get("ip", "?"); services = hit.get("services", [])
            for svc in services:
                data = str(svc)
                for k in extract_keys(data):
                    log_result(k["service"], k["key"], "censys", str(ip), "", f"censys://{ip}:{svc.get('port','?')}", k["entropy"])
    except Exception as e:
        print(f"  Error: {e}")

# ── 7. Pastebin ──

def scan_pastebin():
    print("\n[Pastebin]")
    try:
        r = requests.get("https://scrape.pastebin.com/api_scraping.php?limit=50", timeout=10)
        if r.status_code != 200: return print(f"  API error: {r.status_code}")
        pastes = r.json() if isinstance(r.json(), list) else []
        if not pastes:
            r2 = requests.get("https://pastebin.com/archive", timeout=10)
            pastes = [{"key": m} for m in re.findall(r'/raw/([a-zA-Z0-9]{8})', r2.text)][:30]
        for paste in pastes[:30]:
            key = paste.get("key", "") if isinstance(paste, dict) else paste
            if not key: continue
            try:
                c = requests.get(f"https://pastebin.com/raw/{key}", timeout=10).text
                for k in extract_keys(c):
                    log_result(k["service"], k["key"], "pastebin", "", "", f"https://pastebin.com/raw/{key}", k["entropy"])
            except: pass
    except Exception as e:
        print(f"  Error: {e}")

# ── 8. npm ──

def scan_npm():
    print("\n[npm]")
    try:
        r = requests.get("https://registry.npmjs.org/-/v1/search?text=openai+api&size=25&sort=updated", timeout=15)
        if r.status_code != 200: return
        for pkg in r.json().get("objects", []):
            pkg_name = pkg["package"]["name"]
            version = pkg["package"].get("version", "latest")
            try:
                tgz = requests.get(f"https://registry.npmjs.org/{pkg_name}/-/{pkg_name.split('/')[-1]}-{version}.tgz", timeout=15)
                if tgz.status_code != 200: continue
                tf = tarfile.open(fileobj=io.BytesIO(tgz.content))
                for member in tf.getmembers():
                    if any(member.name.endswith(e) for e in [".env", ".env.example", ".env.local"]):
                        try:
                            c = tf.extractfile(member).read().decode("utf-8", errors="ignore") if member.isfile() else ""
                            for k in extract_keys(c):
                                log_result(k["service"], k["key"], "npm", pkg_name, member.name, f"npm://{pkg_name}@{version}", k["entropy"])
                        except: pass
                tf.close()
            except: pass
    except Exception as e:
        print(f"  Error: {e}")

# ── 9. PyPI ──

def scan_pypi():
    print("\n[PyPI]")
    try:
        r = requests.get("https://pypi.org/search/?q=openai&o=&c=Programming+Language+%3A%3A+Python", timeout=10)
        if r.status_code != 200: return
        names = re.findall(r'/project/([^/]+)/', r.text)[:20]
        for pkg_name in set(names):
            try:
                r2 = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=10)
                if r2.status_code != 200: continue
                data = r2.json()
                for url_info in data.get("urls", []):
                    if url_info.get("packagetype") in ("sdist", "bdist_wheel"):
                        tgz = requests.get(url_info["url"], timeout=30)
                        if tgz.status_code != 200: continue
                        try:
                            tf = tarfile.open(fileobj=io.BytesIO(tgz.content))
                            for member in tf.getmembers():
                                if any(member.name.endswith(e) for e in [".env", ".env.example"]):
                                    c = tf.extractfile(member).read().decode("utf-8", errors="ignore") if member.isfile() else ""
                                    for k in extract_keys(c):
                                        log_result(k["service"], k["key"], "pypi", pkg_name, member.name, f"pypi://{pkg_name}", k["entropy"])
                            tf.close()
                        except: pass
            except: pass
    except Exception as e:
        print(f"  Error: {e}")

def scan_s3():
    print("\n[S3 Buckets]")
    common = ["admin", "backup", "data", "uploads", "static", "media", "assets", "files", "private", "config"]
    for name in common:
        for ext in ["", "-data", "-backup", "-uploads"]:
            url = f"https://{name}{ext}.s3.amazonaws.com/.env"
            try:
                r = requests.get(url, timeout=7)
                if r.status_code == 200 and "KEY" in r.text:
                    for k in extract_keys(r.text):
                        log_result(k["service"], k["key"], "s3", url, "", f"s3://{name}{ext}", k["entropy"])
            except: pass

def scan_gcs():
    print("\n[GCS Buckets]")
    common = ["admin", "backup", "data", "uploads", "static"]
    for name in common:
        url = f"https://storage.googleapis.com/{name}/.env"
        try:
            r = requests.get(url, timeout=7)
            if r.status_code == 200 and "KEY" in r.text:
                for k in extract_keys(r.text):
                    log_result(k["service"], k["key"], "gcs", url, "", f"gcs://{name}", k["entropy"])
        except: pass

# ── 11. Vercel (via Google dorking) ──

VERCEL_DORKS = [
    'site:vercel.app "OPENAI_API_KEY"',
    'site:vercel.app "sk-proj-"',
    'site:vercel.app filetype:env',
    'site:vercel.app "AIzaSy"',
    'site:*.vercel.app ".env" "API"',
]

def scan_vercel():
    print("\n[Vercel Dorking]")
    if not GOOGLE_API_KEY or not GOOGLE_CX:
        return print("  No Google API key (set GOOGLE_API_KEY + GOOGLE_CX)")
    for dork in VERCEL_DORKS:
        try:
            r = requests.get("https://www.googleapis.com/customsearch/v1", params={
                "key": GOOGLE_API_KEY, "cx": GOOGLE_CX, "q": dork, "num": 10
            }, timeout=15)
            if r.status_code != 200: continue
            for item in r.json().get("items", []):
                link = item.get("link", "")
                title = item.get("title", "")
                snippet = item.get("snippet", "")
                text = f"{title} {snippet}"
                try:
                    page = requests.get(link, timeout=10, headers=HEADERS).text
                    text += " " + page
                except: pass
                for k in extract_keys(text):
                    log_result(k["service"], k["key"], "vercel", link, "", f"vercel dork: {dork}", k["entropy"])
        except Exception as e:
            print(f"  Error: {e}")

# ── 12. Google Dorking ──

GOOGLE_DORKS = [
    # API keys in env files
    '"OPENAI_API_KEY" filetype:env',
    '"sk-proj-" filetype:env',
    '"ANTHROPIC_API_KEY" filetype:env',
    '"AWS_ACCESS_KEY_ID" filetype:env',
    '"-----BEGIN OPENSSH PRIVATE KEY-----"',
    '"AIzaSy" filetype:json',
    'inurl:passwords.txt "API"',
    'inurl:.env.example "sk-"',
    '"HF_TOKEN" filetype:env',
    '"DATABASE_URL" filetype:env "password"',
    # Cloud storage
    'site:s3.amazonaws.com .env',
    'site:storage.googleapis.com .env',
    'site:blob.core.windows.net .env',
    'intitle:"index of" .env',
    # Config files
    'filetype:json "api_key"',
    'filetype:yaml "apiKey"',
    'filetype:toml "api-key"',
    'inurl:config.json "secret"',
    'inurl:.env.production',
    # Database connection strings
    '"mongodb://" filetype:env',
    '"mysql://" filetype:env',
    '"postgresql://" filetype:env',
    # Cloud provider keys
    '"aws_secret_access_key"',
    '"google_application_credentials"',
    '"private_key_id" filetype:json',
    # Payment/subscription
    '"sk_live_" filetype:env',
    '"stripe" filetype:env',
    '"braintree" "merchant_id"',
    # Social media APIs
    '"facebook_api" filetype:env',
    '"twitter_api" filetype:env',
    '"instagram_access_token"',
    # Misc
    '"xoxb-" filetype:env',
    '"glpat-" filetype:env',
    'inurl:wp-config.php "API"',
    'filetype:log "api_key"',
    'inurl:phpinfo.php "OPENAI"',
    # Backup files
    '"backup" "OPENAI_API_KEY"',
    'filetype:sql "api_key"',
    'filetype:csv "api_key"',
    # Cloud platforms
    'site:vercel.app ".env"',
    'site:netlify.app ".env"',
    'site:herokuapp.com ".env"',
    'site:render.com ".env"',
    # Kubernetes/Docker
    '"KUBERNETES_SERVICE_HOST" filetype:env',
    'filetype:dockerfile "ENV"',
    # New patterns
    '"sk-or-v1-" filetype:env',
    '"gsk_" filetype:env',
    '"pplx-" filetype:env',
    'inurl:.env.local',
    'filetype:ini "api_key"',
    'inurl:configuration.php "OPENAI"',
]

def scan_googledork():
    print("\n[Google Dorking]")
    if not GOOGLE_API_KEY or not GOOGLE_CX:
        return print("  No Google API key (set GOOGLE_API_KEY + GOOGLE_CX)")
    for dork in GOOGLE_DORKS:
        try:
            r = requests.get("https://www.googleapis.com/customsearch/v1", params={
                "key": GOOGLE_API_KEY, "cx": GOOGLE_CX, "q": dork, "num": 10
            }, timeout=15)
            if r.status_code != 200: continue
            for item in r.json().get("items", []):
                link = item.get("link", "")
                snippet = item.get("snippet", "")
                try:
                    page = requests.get(link, timeout=10, headers=HEADERS).text
                    for k in extract_keys(page):
                        log_result(k["service"], k["key"], "googledork", link, "", f"dork: {dork}", k["entropy"])
                except: pass
                for k in extract_keys(snippet):
                    log_result(k["service"], k["key"], "googledork", link, "", f"dork: {dork}", k["entropy"])
        except Exception as e:
            print(f"  Error: {e}")

# ── 10. Docker Hub ──

def scan_dockerhub():
    print("\n[Docker Hub]")
    search_terms = ["openai", "gpt", "langchain"]
    seen_images = set()
    for term in search_terms:
        try:
            r = requests.get(f"https://hub.docker.com/v2/repositories/?search={term}&page_size=10", timeout=15)
            if r.status_code != 200: continue
            for repo_data in r.json().get("results", []):
                name = repo_data["repo_name"]
                if name in seen_images: continue
                seen_images.add(name)
                try:
                    tags_r = requests.get(f"https://hub.docker.com/v2/repositories/{name}/tags?page_size=3", timeout=10)
                    if tags_r.status_code != 200: continue
                    for tag_data in tags_r.json().get("results", []):
                        tag = tag_data["name"]
                        for image_data in tag_data.get("images", []):
                            layers = image_data.get("layers", [])
                            for layer in layers[:3]:
                                try:
                                    lr = requests.get(layer["url"] if "url" in layer else f"https://registry-1.docker.io/v2/{name}/blobs/{layer['digest']}", timeout=10)
                                    if lr.status_code != 200: continue
                                    try:
                                        decompressed = gzip.decompress(lr.content)
                                        text = decompressed.decode("utf-8", errors="ignore")
                                        for k in extract_keys(text):
                                            log_result(k["service"], k["key"], "dockerhub", name, f"tag:{tag}", f"docker://{name}:{tag}", k["entropy"])
                                    except: pass
                                except: pass
                except: pass
        except: pass
