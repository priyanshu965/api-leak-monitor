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
