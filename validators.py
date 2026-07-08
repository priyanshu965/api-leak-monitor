import requests
from patterns import register_validator

def _openai(k):
    try: return requests.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _anthropic(k):
    try: return requests.get("https://api.anthropic.com/v1/models", headers={"x-api-key": k, "anthropic-version": "2023-06-01"}, timeout=7).status_code == 200
    except: return "error"

def _google(k):
    try: return requests.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={k}", timeout=7).status_code == 200
    except: return "error"

def _xai(k):
    try: return requests.get("https://api.x.ai/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _openrouter(k):
    try: return requests.get("https://openrouter.ai/api/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _groq(k):
    try: return requests.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _deepseek(k):
    try: return requests.get("https://api.deepseek.com/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _huggingface(k):
    try: return requests.get("https://huggingface.co/api/models?limit=1", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _replicate(k):
    try: return requests.get("https://api.replicate.com/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _mistral(k):
    try: return requests.get("https://api.mistral.ai/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _github(k):
    try: return requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _stripe(k):
    try: return requests.get("https://api.stripe.com/v1/balance", auth=(k, ""), timeout=7).status_code == 200
    except: return "error"

def _slack(k):
    try: return requests.get("https://slack.com/api/auth.test", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _gitlab(k):
    try: return requests.get("https://gitlab.com/api/v4/user", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _perplexity(k):
    try: return requests.get("https://api.perplexity.ai/chat/completions", headers={"Authorization": f"Bearer {k}"}, json={"model":"pplx-70b-online","messages":[{"role":"user","content":"hi"}]}, timeout=7).status_code in (200, 400)
    except: return "error"

def _together(k):
    try: return requests.get("https://api.together.xyz/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _fireworks(k):
    try: return requests.get("https://api.fireworks.ai/v1/models", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _discord(k):
    try:
        wid, wsec = k.split("/") if "/" in k else (k, "")
        r = requests.get(f"https://discord.com/api/webhooks/{wid}/{wsec}", timeout=7)
        return r.status_code in (200, 401)
    except: return "error"

def _sendgrid(k):
    try: return requests.get("https://api.sendgrid.com/v3/user/profile", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _twilio(k):
    try:
        sid = k.split(":")[0] if ":" in k else k
        r = requests.get(f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json", auth=(sid, k.split(":")[1] if ":" in k else ""), timeout=7)
        return r.status_code == 200
    except: return "error"

def _cloudflare(k):
    try: return requests.get("https://api.cloudflare.com/client/v4/user/tokens/verify", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _vercel(k):
    try: return requests.get("https://api.vercel.com/v2/user", headers={"Authorization": f"Bearer {k}"}, timeout=7).status_code == 200
    except: return "error"

def _aws(k):
    # Can't validate access key without secret; accept format only
    return len(k) == 20 and k.startswith("AKIA")

def _azure(k):
    # Can't validate connection string without parsing; accept format only
    return "AccountKey=" in k and "AccountName=" in k

register_validator("OpenAI", _openai)
register_validator("Anthropic", _anthropic)
register_validator("Google", _google)
register_validator("xAI", _xai)
register_validator("OpenRouter", _openrouter)
register_validator("Groq", _groq)
register_validator("DeepSeek", _deepseek)
register_validator("HuggingFace", _huggingface)
register_validator("Replicate", _replicate)
register_validator("Mistral", _mistral)
register_validator("GitHub", _github)
register_validator("Stripe", _stripe)
register_validator("Slack", _slack)
register_validator("GitLab", _gitlab)
register_validator("Perplexity", _perplexity)
register_validator("Together", _together)
register_validator("Fireworks", _fireworks)
register_validator("Discord", _discord)
register_validator("SendGrid", _sendgrid)
register_validator("Twilio", _twilio)
register_validator("Cloudflare", _cloudflare)
register_validator("Vercel", _vercel)
register_validator("AWS", _aws)
register_validator("Azure", _azure)
