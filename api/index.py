"""
GuardMail AI backend (Flask).

Single-file Flask app deployed on Vercel that:
  - Handles Google OAuth login and stores Gmail credentials in the session cookie
    (there is no database for user accounts - the session *is* the account).
  - Fetches the user's inbox via the Gmail API and scores each message for
    phishing/spam/spoofing risk, using keyword heuristics plus an optional
    Groq (Llama 3.1) categorizer.
  - Generates an educational threat report and a quiz for a given email via Groq,
    falling back to canned responses if Groq is unavailable or fails.
  - Serves /api/analyze-ext for the Chrome extension, which scores emails scraped
    directly off the Gmail web UI (no Gmail API access, so no Groq categorization
    there - just the keyword fallback).
  - Optionally persists "reported to SOC" cases to Supabase for the /cases history
    page; without Supabase configured it falls back to an in-memory set that's
    lost on every serverless cold start (see README "Known limitations").

Rough layout, top to bottom:
  1. App / session / CORS / rate-limiter setup
  2. Supabase helpers (reported-case persistence)
  3. Google OAuth config + scam/spam/dangerous-link keyword lists
  4. Scoring & classification helpers: spoofing detection, risk scoring, link
     sandboxing, the local keyword fallback categorizer, and the Groq-backed
     categorizer/report/quiz calls
  5. Gmail fetch (fetch_gmail_emails) - pulls one page of messages, batches the
     per-message Gmail API calls, categorizes them concurrently via Groq
  6. Routes: /, /demo, /login, /callback, /logout, /api/feed-state, /api/report-soc,
     /api/analyze-ext, /analyze, /api/quiz, /how-it-works, /settings, /cases,
     /privacy, plus branded 404/500 error pages

Demo mode: /demo sets session['demo'] and serves a canned, deterministic inbox
(DEMO_INBOX) through the same scoring pipeline - no Google account or Groq
quota needed. Reported demo cases live in the session.
"""
import os
import json
import re
import hashlib
from concurrent.futures import ThreadPoolExecutor
import httpx
from flask import Flask, render_template, request, jsonify, redirect, session, copy_current_request_context
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from groq import Groq
from dotenv import load_dotenv

# google_auth_oauthlib / googleapiclient are NOT imported here - they're the
# heaviest imports in this file (large discovery/reflection machinery under
# the hood) and on a serverless cold start, a module-level import means every
# request pays that cost even for routes that never touch Gmail (the landing
# page, /demo, /how-it-works, /settings, /cases...). They're imported lazily
# inside the specific functions that need them (fetch_gmail_emails, /login,
# /callback) instead, so only an actual OAuth/Gmail request pays for them.

load_dotenv()

# Local dev only: allow the OAuth dance over plain HTTP and enable Flask's debugger.
# Both default OFF so a misconfigured deploy never accidentally ships with them on.
DEBUG_MODE = os.getenv("FLASK_DEBUG", "0") == "1"
if DEBUG_MODE:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__, template_folder='../templates', static_folder='../static', static_url_path='/static')

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set (it signs session "
        "cookies, which carry OAuth credentials)."
    )
app.secret_key = FLASK_SECRET_KEY

# Session cookies carry Gmail OAuth credentials, so lock them down: no JS access,
# not sent cross-site, and HTTPS-only outside of local debugging. Note the
# failure mode if DEBUG_MODE is off while testing over plain http://localhost:
# browsers/HTTP clients silently refuse to send a Secure-flagged cookie back
# over an insecure connection, so the session never round-trips at all - not
# just OAuth, but login, demo mode, and reported cases all silently stop
# persisting across requests. Set FLASK_DEBUG=1 for any local HTTP testing.
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = not DEBUG_MODE

# Only the extension's content script needs cross-origin access; everything else
# is same-origin, session-cookie-authenticated and shouldn't accept foreign origins.
CORS(app, resources={r"/api/analyze-ext": {"origins": "*", "methods": ["POST"]}})

limiter = Limiter(get_remote_address, app=app, default_limits=[])

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
MAX_PROMPT_CHARS = 4000

# Reported-case history is optional: without these set, /cases just shows an
# empty state instead of failing, so GuardMail still works without a database.
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
SUPABASE_CONFIGURED = bool(SUPABASE_URL and SUPABASE_SERVICE_KEY)


def _supabase_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
    }


def save_reported_case(user_email: str, email_id: str, sender: str, subject: str, risk_score: int) -> None:
    """Persists a reported case to Supabase. Silently no-ops if Supabase isn't configured or the request fails."""
    if not SUPABASE_CONFIGURED:
        return
    try:
        httpx.post(
            f"{SUPABASE_URL}/rest/v1/reported_cases",
            headers=_supabase_headers(),
            json={
                "user_email": user_email,
                "email_id": email_id,
                "sender": sender,
                "subject": subject,
                "risk_score": risk_score,
            },
            timeout=5,
        )
    except Exception:
        pass


def get_reported_case_ids(user_email: str) -> set:
    """Returns the email_ids this user has already reported. Empty set if Supabase isn't configured or the request fails."""
    if not SUPABASE_CONFIGURED or not user_email:
        return set()
    try:
        resp = httpx.get(
            f"{SUPABASE_URL}/rest/v1/reported_cases",
            headers=_supabase_headers(),
            params={"user_email": f"eq.{user_email}", "select": "email_id"},
            timeout=5,
        )
        resp.raise_for_status()
        return {row["email_id"] for row in resp.json()}
    except Exception:
        return set()


def list_reported_cases(user_email: str) -> list:
    """Returns this user's reported cases, newest first. Empty list if Supabase isn't configured or the request fails."""
    if not SUPABASE_CONFIGURED or not user_email:
        return []
    try:
        resp = httpx.get(
            f"{SUPABASE_URL}/rest/v1/reported_cases",
            headers=_supabase_headers(),
            params={"user_email": f"eq.{user_email}", "select": "*", "order": "reported_at.desc"},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return []

# Google OAuth client config (see google_auth_oauthlib's expected "web" app format)
CLIENT_CONFIG = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:3000/callback")]
    }
}
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# In-memory fallback set of reported email ids, used when Supabase isn't
# configured. Not persisted - resets on every serverless cold start.
REPORTED_SOC_IDS = set()

# Scam detection requires BOTH a money/credential hook AND an urgency/pressure
# hook. Single-keyword matching flagged every legitimate PayPal receipt and bank
# statement as a scam; real phishing almost always combines "something valuable"
# with "act fast". "password" deliberately excluded from the money list - genuine
# password-reset emails pair it with urgency words like "expires".
SCAM_MONEY_KEYWORDS = [
    "wire", "transfer", "gift card", "gift cards", "bitcoin", "crypto",
    "bank", "paypal", "credentials", "prize", "winner", "inheritance",
    "bonus", "payment", "refund", "invoice",
]
SCAM_URGENCY_KEYWORDS = [
    "urgent", "urgently", "immediately", "suspended", "locked", "verify",
    "act now", "final notice", "last chance", "unusual activity",
    "24 hours", "48 hours", "expires", "limited time",
]
# Spam requires two distinct hits - one stray "free" or "sale" in a normal
# email shouldn't reclassify it.
SPAM_KEYWORDS = ["buy", "discount", "free", "marketing", "promotion", "sale", "deals", "unsubscribe", "coupon", "offer"]

# Keywords that make an unknown *registered domain* look like a phishing
# lookalike (paypal-secure-verify.com). Deliberately not applied to subdomains
# or paths on their own - login.salesforce.com and example.com/login are how
# real services work; registering "secure-login-verify.net" is how phishing works.
DANGEROUS_URL_KEYWORDS = [
    "verify", "secure", "login", "signin", "signon", "account",
    "update", "banking", "verification", "credentials", "wallet", "webscr",
]

# Domains whose links are treated as safe outright. The keyword heuristics
# exist to catch lookalike URLs; the real login/verify pages of major
# providers were all false-positiving on them.
TRUSTED_LINK_DOMAINS = (
    "google.com", "gmail.com", "youtube.com", "apple.com", "icloud.com",
    "microsoft.com", "live.com", "office.com", "outlook.com", "amazon.com",
    "paypal.com", "github.com", "gitlab.com", "linkedin.com", "facebook.com",
    "instagram.com", "netflix.com", "dropbox.com", "docusign.net", "docusign.com",
    "chase.com", "wellsfargo.com", "zoom.us", "slack.com", "x.com",
    "twitter.com", "spotify.com", "stripe.com", "shopify.com", "wikipedia.org",
)

# URL shorteners hide their destination - worth a caution label, but not an
# automatic "dangerous" since legitimate newsletters use them heavily.
SHORTENER_DOMAINS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "rb.gy")

# Commonly impersonated brands mapped to the domains they legitimately send
# from. A sender is only called spoofed when it claims a brand it doesn't
# match - "bank" was removed as a pseudo-brand because chase.com, bofa.com etc.
# don't contain the word "bank" and every real bank was getting flagged.
BRAND_DOMAINS = {
    "paypal": ("paypal.com", "paypal.co.uk", "paypal.me"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com"),
    "meta": ("meta.com", "facebook.com", "facebookmail.com", "instagram.com"),
    "facebook": ("facebook.com", "facebookmail.com", "meta.com"),
    "instagram": ("instagram.com", "facebookmail.com"),
    "netflix": ("netflix.com",),
    "amazon": ("amazon.com", "amazonaws.com", "amazonses.com", "amazon.co.uk", "amazon.ca", "amazon.de"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "microsoft": ("microsoft.com", "outlook.com", "live.com", "office.com", "microsoftonline.com"),
    "chase": ("chase.com", "jpmchase.com", "jpmorgan.com"),
    "wells fargo": ("wellsfargo.com",),
    "venmo": ("venmo.com",),
    "coinbase": ("coinbase.com",),
    "docusign": ("docusign.net", "docusign.com"),
    "dropbox": ("dropbox.com", "dropboxmail.com"),
    "linkedin": ("linkedin.com",),
    "spotify": ("spotify.com", "spotifymail.com"),
    "usps": ("usps.com",),
    "fedex": ("fedex.com",),
    "irs": ("irs.gov",),
}


def _contains_whole_word(text: str, keywords: list) -> bool:
    """Whole-word match so e.g. 'secure' doesn't false-positive match inside 'security'."""
    return any(re.search(rf'\b{re.escape(k)}\b', text) for k in keywords)


def _domain_is_or_under(domain: str, official_domains: tuple) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in official_domains)


def detect_spoofing(sender_str: str) -> bool:
    """Flags a sender that claims a well-known brand it doesn't belong to.

    A brand is "claimed" when it appears as a whole word in the display name /
    local part, or embedded in the sending domain itself (paypal.account-check.net).
    The claim only counts as spoofing when the actual sending domain is not one
    of - or a subdomain of - that brand's real domains.
    """
    sender_lower = sender_str.lower()
    email_match = re.search(r'<([^>]+)>', sender_str)
    if email_match:
        display_part = sender_lower.split('<')[0]
        domain = email_match.group(1).lower().split('@')[-1].strip()
    elif "@" in sender_lower:
        display_part, domain = sender_lower.split("@", 1)
        domain = domain.strip()
    else:
        return False

    for brand, official_domains in BRAND_DOMAINS.items():
        brand_word = brand.replace(" ", "")
        claimed_in_name = re.search(rf'\b{re.escape(brand)}\b', display_part)
        # \b treats dots and hyphens as boundaries, so this matches "paypal.evil.com"
        # and "paypal-alerts.net" but not "startups.com" for brand "ups".
        claimed_in_domain = re.search(rf'\b{re.escape(brand_word)}\b', domain)
        if (claimed_in_name or claimed_in_domain) and not _domain_is_or_under(domain, official_domains):
            return True
    return False


def build_risk_factors(category: str, spoofed: bool, links: list) -> list:
    """Explains a risk score as a list of {label, points} factors.

    This is the single source of truth for scoring - calculate_risk_index just
    sums it - so the "why this score" breakdown shown in the UI can never drift
    from the actual number.
    """
    factors = [{"label": "Every message starts at a baseline", "points": 10}]
    if category == "Scam Alert":
        factors.append({"label": "Content looks like a scam or phishing attempt", "points": 45})
    elif category == "Spam":
        factors.append({"label": "Content looks like bulk or promotional mail", "points": 20})
    if spoofed:
        factors.append({"label": "Sender claims a brand it doesn't match", "points": 25})
    dangerous_links = sum(1 for l in links if "Dangerous" in l["safety_status"])
    if dangerous_links:
        plural = "s" if dangerous_links > 1 else ""
        factors.append({"label": f"{dangerous_links} suspicious link{plural} in the message", "points": dangerous_links * 15})
    return factors


def calculate_risk_index(category: str, spoofed: bool, links: list) -> int:
    """Combines category/spoofing/link signals into a 0-100 risk score.

    Base 10, +45 for 'Scam Alert' / +20 for 'Spam', +25 if the sender looks
    spoofed, +15 per link flagged dangerous by parse_and_sandbox_links. Capped
    at 100.
    """
    return min(sum(f["points"] for f in build_risk_factors(category, spoofed, links)), 100)


def calculate_analytics(emails):
    """Rolls up a list of scored emails (from fetch_gmail_emails) into the
    dashboard's stat-bar counts: scams, spams, spoofed, SOC-reported, total,
    and scam percentage."""
    total = len(emails)
    counts = {
        "scams": sum(1 for e in emails if e.get("initial_category") == "Scam Alert"),
        "spams": sum(1 for e in emails if e.get("initial_category") == "Spam"),
        "spoofed": sum(1 for e in emails if e.get("spoofing_detected")),
        "soc_cases": sum(1 for e in emails if e.get("soc_reported"))
    }
    counts["total"] = total
    counts["percentage"] = round((counts["scams"] / total) * 100) if total > 0 else 0
    return counts


def classify_link(url: str) -> str:
    """Classifies a single URL by how trustworthy its destination looks.

    Order matters: a known-good domain short-circuits everything (real sites
    link to their own /login pages constantly, which is why keyword checks
    used to false-positive on nearly every legitimate service email). Beyond
    that, only host-level signals mark a link dangerous; path keywords alone
    need two distinct hits, since one '/login' in a path is normal.
    """
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url.lower())
        host = parts.hostname or ""
    except ValueError:
        return "Dangerous / Malformed address"

    if _domain_is_or_under(host, TRUSTED_LINK_DOMAINS):
        return "Trusted domain"
    if _domain_is_or_under(host, SHORTENER_DOMAINS):
        return "Shortened link / Destination hidden"
    if "@" in parts.netloc:
        return "Dangerous / Disguised destination"
    if re.fullmatch(r'[0-9.]+|\[[0-9a-f:]+\]', host):
        return "Dangerous / Raw IP address"
    if host.startswith("xn--") or ".xn--" in host:
        return "Dangerous / Lookalike characters"

    # A well-known brand name inside a domain that doesn't belong to that brand
    # (paypal.account-check.net) is the classic phishing-host shape.
    for brand, official_domains in BRAND_DOMAINS.items():
        brand_word = brand.replace(" ", "")
        if re.search(rf'\b{re.escape(brand_word)}\b', host) and not _domain_is_or_under(host, official_domains):
            return "Dangerous / Imitates a known brand"

    # Keyword hits in the registered domain itself ("verify-now.tk") are a strong
    # signal; hits spread across subdomain labels or the path only count when two
    # or more distinct keywords pile up.
    registrable = ".".join(host.split(".")[-2:])
    if _contains_whole_word(registrable, DANGEROUS_URL_KEYWORDS):
        return "Dangerous / Suspicious address"
    hits = {k for k in DANGEROUS_URL_KEYWORDS if re.search(rf'\b{re.escape(k)}\b', host + parts.path)}
    if len(hits) >= 2:
        return "Dangerous / Suspicious address"
    return "External link / Unverified"


def parse_and_sandbox_links(body_text):
    """Extracts URLs from the email body and classifies each one - see classify_link."""
    found_urls = re.findall(r'https?://[^\s<>"\')\]\n\r]+', body_text)
    return [
        {"url": url.rstrip(".,;:"), "safety_status": classify_link(url.rstrip(".,;:"))}
        for url in found_urls
    ]


def fallback_categorize(body: str) -> str:
    """Local keyword-based fallback categorizer, used when Groq is unavailable.

    Scam needs both a money/credential hook and an urgency hook; spam needs two
    distinct promotional keywords. One keyword alone never reclassifies a
    message - that's what made legitimate receipts get flagged as scams.
    """
    lower = body.lower()
    if _contains_whole_word(lower, SCAM_MONEY_KEYWORDS) and _contains_whole_word(lower, SCAM_URGENCY_KEYWORDS):
        return "Scam Alert"
    spam_hits = sum(1 for k in SPAM_KEYWORDS if re.search(rf'\b{re.escape(k)}\b', lower))
    if spam_hits >= 2:
        return "Spam"
    return "Important"


def truncate_for_prompt(text: str) -> str:
    """Caps text fed into a Groq prompt so cost/latency/token limits stay bounded."""
    return text[:MAX_PROMPT_CHARS]


# Categorization runs on every inbox load (up to 5 concurrent calls in the hot path),
# and only needs enough of the email to catch its opening ask/hook - a short prompt
# measured ~3x faster than the full MAX_PROMPT_CHARS without changing the result on
# real phishing/scam samples, unlike /analyze and /quiz which need full context for
# report/quiz quality and aren't in that hot path.
CATEGORIZE_PROMPT_CHARS = 500


def groq_categorize(body: str, sender: str = "", subject: str = "") -> str | None:
    """Calls Groq to categorize email. Returns None on failure.

    The prompt spells out that routine mail from real companies is NOT a scam -
    without that instruction the model over-flagged ordinary receipts and
    notifications, which was the biggest source of false Scam Alerts.
    """
    if not groq_client or not body:
        return None
    prompt = (
        "You classify emails for a phishing-awareness tool. Categories:\n"
        "- 'Scam Alert': deliberate deception - phishing, impersonation, fake invoices, credential theft, advance-fee fraud.\n"
        "- 'Spam': unsolicited but non-deceptive bulk mail - marketing, newsletters, promotions.\n"
        "- 'High Priority': time-sensitive legitimate mail - security codes, password resets, bills due, account notices from real services.\n"
        "- 'Important': all other normal legitimate mail.\n"
        "Routine receipts, order confirmations, and notifications from real companies are NOT scams. "
        "Only choose 'Scam Alert' when the message itself shows deception.\n"
        f"Sender: {sender[:200]}\nSubject: {subject[:200]}\n"
        f"Body: {body[:CATEGORIZE_PROMPT_CHARS]}\n"
        "Reply with exactly one category name and nothing else."
    )
    try:
        completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            max_tokens=10,
            temperature=0.0
        )
        decision = completion.choices[0].message.content.strip().strip("'\"")
        return decision if decision in ("High Priority", "Important", "Spam", "Scam Alert") else None
    except Exception:
        return None


def groq_json_call(prompt: str) -> dict | None:
    """Generic Groq call expecting a JSON response. Returns parsed dict or None."""
    if not groq_client:
        return None
    try:
        completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            max_tokens=512,
            temperature=0.0
        )
        raw = completion.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw).rstrip("`").strip()
        return json.loads(raw)
    except Exception:
        return None


def get_email_body(payload):
    """Extracts a text body from a Gmail message payload, which may be a
    nested multipart structure. Prefers a text/plain part; if none exists,
    falls back to the first text/html part with its tags stripped."""
    import base64
    if 'parts' in payload:
        # Step A: Attempt to prioritize clean raw plain text data packets
        for part in payload['parts']:
            if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                try:
                    return base64.urlsafe_b64decode(part['body']['data'].encode('ASCII')).decode('utf-8', errors='ignore')
                except Exception:
                    pass
        # Step B: Fall back onto text/html parsing matrices if plain text strings are empty
        for part in payload['parts']:
            if part.get('mimeType') == 'text/html' and 'data' in part.get('body', {}):
                try:
                    html_content = base64.urlsafe_b64decode(part['body']['data'].encode('ASCII')).decode('utf-8', errors='ignore')
                    return re.sub('<[^<]+?>', '', html_content)
                except Exception:
                    pass
            elif 'parts' in part:
                body = get_email_body(part)
                if body:
                    return body
    else:
        body_obj = payload.get('body', {})
        if 'data' in body_obj:
            try:
                content = base64.urlsafe_b64decode(body_obj['data'].encode('ASCII')).decode('utf-8', errors='ignore')
                if payload.get('mimeType') == 'text/html':
                    return re.sub('<[^<]+?>', '', content)
                return content
            except Exception:
                pass
    return ""


def score_email(meta: dict, category: str, soc_reported: bool = False) -> dict:
    """Runs one email (id/sender/subject/date/body) through the scoring pipeline
    and returns the full dict shape the dashboard consumes."""
    spoofed = detect_spoofing(meta["sender"])
    links = parse_and_sandbox_links(meta["body"])
    return {
        "id": meta["id"],
        "sender": meta["sender"],
        "subject": meta["subject"],
        "date": meta["date"],
        "body": meta["body"],  # un-truncated: the viewer pane shows the full text
        "initial_category": category,
        "spoofing_detected": spoofed,
        "risk_score": calculate_risk_index(category, spoofed, links),
        "risk_factors": build_risk_factors(category, spoofed, links),
        "soc_reported": soc_reported,
        "links": links,
    }


def fetch_gmail_emails(page_token=None, reported_ids=None):
    """Fetches and scores one page (5 messages) of the signed-in user's Gmail inbox.

    Rebuilds Google API credentials from the session, lists message ids for the
    requested page, fetches those messages in a single batched HTTP request, then
    scores each one (category, spoofing, links, risk_score) - see the per-email
    dict shape built below.

    Returns a 3-tuple: (emails_list, next_page_token, error_message). error_message is
    None on success, or a short human-readable string if the Gmail fetch failed, so
    callers can distinguish "empty inbox" from "fetch failed" instead of treating both
    the same way.
    """
    if reported_ids is None:
        reported_ids = REPORTED_SOC_IDS
    if 'credentials' not in session:
        return [], None, None
    from google.auth.exceptions import RefreshError
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    try:
        creds_dict = session['credentials']
        credentials = Credentials(
            token=creds_dict['token'],
            refresh_token=creds_dict.get('refresh_token'),
            token_uri=creds_dict['token_uri'],
            client_id=creds_dict['client_id'],
            client_secret=creds_dict['client_secret'],
            scopes=creds_dict['scopes']
        )
        service = build('gmail', 'v1', credentials=credentials)

        # Inject pageToken query parameter into the active request context map
        results = service.users().messages().list(userId='me', maxResults=5, pageToken=page_token).execute()
        messages = results.get('messages', [])
        next_page_token = results.get('nextPageToken', None)

        # Fetch the page's messages in a single batched HTTP request instead of
        # one round-trip per message - cuts inbox load latency substantially.
        message_data_by_id = {}

        def _collect(request_id, response, exception):
            if exception is None:
                message_data_by_id[request_id] = response

        if messages:
            batch = service.new_batch_http_request(callback=_collect)
            for msg in messages:
                batch.add(
                    service.users().messages().get(userId='me', id=msg['id'], format='full'),
                    request_id=msg['id']
                )
            batch.execute()

        emails_meta = []
        for msg in messages:
            msg_data = message_data_by_id.get(msg['id'])
            if not msg_data:
                continue
            payload = msg_data.get('payload', {})
            headers = payload.get('headers', [])

            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
            sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
            date_str = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'Unknown Date')

            body = get_email_body(payload)
            if not body or body.strip() == "":
                body = msg_data.get('snippet', '')

            emails_meta.append({"id": msg['id'], "sender": sender, "subject": subject, "date": date_str, "body": body})

        # Categorize concurrently (each is a Groq API round-trip) so a page of 10
        # messages doesn't serialize into 10x the latency.
        categories = []
        if emails_meta:
            with ThreadPoolExecutor(max_workers=len(emails_meta)) as executor:
                categories = list(executor.map(
                    lambda meta: groq_categorize(meta["body"], meta["sender"], meta["subject"]) or fallback_categorize(meta["body"]),
                    emails_meta
                ))

        emails_list = [
            score_email(meta, category, soc_reported=meta["id"] in reported_ids)
            for meta, category in zip(emails_meta, categories)
        ]
        return emails_list, next_page_token, None
    except RefreshError:
        # Refresh token expired/revoked - no amount of retrying will fix this from
        # here, so clear the dead session and let the user re-authenticate.
        session.clear()
        return [], None, "Your Gmail session expired. Please sign in again."
    except Exception as exc:
        return [], None, f"Couldn't reach Gmail: {exc.__class__.__name__}"


# The demo inbox: a canned mix of obvious phish, borderline spam, and clearly
# legitimate mail (including a real-looking PayPal receipt, which older scoring
# versions false-flagged). Scored at request time through the same pipeline as
# real mail so the demo always reflects current behavior.
DEMO_INBOX = [
    {
        "sender": "PayPal Support <service@paypal-alerts-center.com>",
        "subject": "Your account has been limited",
        "age_minutes": 35,
        "body": (
            "Dear Customer,\n\nWe noticed unusual activity on your PayPal account and it has been "
            "temporarily limited. Please verify your information within 24 hours to avoid permanent "
            "suspension:\n\nhttps://paypal.account-verification-center.com/secure\n\n"
            "Failure to verify will result in account closure.\n\nPayPal Security Team"
        ),
    },
    {
        "sender": "Chase Online Banking <alerts@chase-secure-update.net>",
        "subject": "Unusual activity detected on your account",
        "age_minutes": 130,
        "body": (
            "We detected unusual activity involving a wire transfer from your checking account. "
            "Sign in immediately to review this activity or your account will be locked:\n\n"
            "http://chase-secure-update.net/login/verify\n\nChase Fraud Prevention"
        ),
    },
    {
        "sender": "Prize Notification <winner-dept@rewardclaims-notify.xyz>",
        "subject": "Congratulations! Claim your $500 gift card",
        "age_minutes": 310,
        "body": (
            "Congratulations! You have been selected as this week's winner of a $500 gift card. "
            "Act now - this offer expires in 48 hours.\n\nClaim here: https://bit.ly/3xZ9qLm\n\n"
            "The Rewards Team"
        ),
    },
    {
        "sender": "USPS Redelivery <tracking@usps-package-alerts.info>",
        "subject": "Package on hold - schedule redelivery",
        "age_minutes": 900,
        "body": (
            "Your package could not be delivered due to an incomplete address. A redelivery payment "
            "of $1.99 is required. Complete it immediately or your parcel will be returned to sender:\n\n"
            "http://usps-package-alerts.info/track/redelivery\n\nUSPS Customer Service"
        ),
    },
    {
        "sender": "PayPal <service@paypal.com>",
        "subject": "Receipt for your payment to Spotify AB",
        "age_minutes": 1500,
        "body": (
            "You sent a payment of $12.99 USD to Spotify AB.\n\nView the details of this transaction "
            "in your account:\n\nhttps://www.paypal.com/myaccount/transactions\n\nThanks for using PayPal."
        ),
    },
    {
        "sender": "GitHub <noreply@github.com>",
        "subject": "[GitHub] Your personal access token is expiring",
        "age_minutes": 2100,
        "body": (
            "Your personal access token 'ci-deploy' will expire in 7 days.\n\nIf it's still needed, "
            "you can generate a new token:\n\nhttps://github.com/settings/tokens\n\n"
            "Thanks,\nThe GitHub Team"
        ),
    },
    {
        "sender": "ShopSphere <hello@shopsphere-mail.com>",
        "subject": "This weekend only: 40% off everything",
        "age_minutes": 3000,
        "body": (
            "This weekend only: 40% discount on all spring styles. Free shipping on orders over $50. "
            "Shop the sale before it ends Sunday night.\n\nhttps://shopsphere-mail.com/spring\n\n"
            "No longer want these emails? Unsubscribe: https://shopsphere-mail.com/preferences"
        ),
    },
    {
        "sender": "Maya Chen <maya.chen@gmail.com>",
        "subject": "Dinner on Saturday?",
        "age_minutes": 4200,
        "body": (
            "Hey!\n\nAre we still on for dinner Saturday? There's a new ramen place near the park "
            "I've been wanting to try.\n\nLet me know!\nMaya"
        ),
    },
]


def build_demo_emails():
    """Scores the canned demo inbox. Uses the keyword fallback categorizer only -
    demo traffic shouldn't spend Groq quota, and the fallback keeps it deterministic."""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    reported = set(session.get('reported_ids', []))
    emails = []
    for i, item in enumerate(DEMO_INBOX):
        meta = {
            "id": f"demo-{i + 1}",
            "sender": item["sender"],
            "subject": item["subject"],
            "date": (now - timedelta(minutes=item["age_minutes"])).isoformat(),
            "body": item["body"],
        }
        emails.append(score_email(meta, fallback_categorize(item["body"]), soc_reported=meta["id"] in reported))
    return emails


def _reported_ids_for_session():
    """Cached in the session so a Supabase round-trip only happens once per login,
    not on every inbox page load/refresh."""
    if 'reported_ids' in session:
        return set(session['reported_ids'])
    user_email = session.get('user_email')
    ids = get_reported_case_ids(user_email) if (SUPABASE_CONFIGURED and user_email) else set(REPORTED_SOC_IDS)
    session['reported_ids'] = list(ids)
    return ids


@app.context_processor
def inject_demo_flag():
    """Makes demo_mode available to every template (header shows a demo badge)."""
    return {"demo_mode": bool(session.get('demo'))}


@app.route('/demo')
def demo():
    """Sandbox mode: browse a canned inbox with no Google account. Lets visitors
    try the product before granting Gmail access."""
    session.clear()
    session['demo'] = True
    return redirect('/')


@app.route('/')
def index():
    """Dashboard shell. Renders logged-out or logged-in state only - the actual
    inbox contents load client-side afterwards via /api/feed-state."""
    if 'credentials' not in session and not session.get('demo'):
        return render_template('index.html', logged_in=False)
    # Emails are fetched client-side via /api/feed-state on page load instead of
    # blocking this response - Gmail + AI categorization can take a few seconds,
    # and that shouldn't delay showing the page shell.
    return render_template('index.html', logged_in=True, active_page='inbox')


@app.route('/login')
def login():
    """Starts the Google OAuth flow: builds the Google consent-screen URL,
    stashes a CSRF state token in the session, and redirects the browser there."""
    import google_auth_oauthlib.flow
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES
    )
    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:3000/callback")
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    """Google OAuth redirect target. Verifies the CSRF state param matches what
    /login stashed, exchanges the authorization code for credentials, stores
    those credentials in the session, and looks up the user's email address."""
    import google_auth_oauthlib.flow
    from googleapiclient.discovery import build
    state = session.get('state')
    incoming_state = request.args.get('state')
    
    # Checkpoint A: If the app restarted or session cookies dropped mid-flight, reset and bounce back to login
    if not state or state != incoming_state:
        session.clear()
        return redirect('/login')
        
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        state=state
    )
    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:3000/callback")
    
    authorization_response = request.url
    if authorization_response.startswith('http://') and not request.host.startswith('localhost'):
        authorization_response = authorization_response.replace('http://', 'https://')
        
    # Checkpoint B: Protect the token exchange from throwing raw exceptions during live debugging restarts
    try:
        flow.fetch_token(authorization_response=authorization_response)
    except Exception:
        session.clear()
        return redirect('/login')
        
    credentials = flow.credentials
    
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    try:
        profile = build('gmail', 'v1', credentials=credentials).users().getProfile(userId='me').execute()
        session['user_email'] = profile.get('emailAddress')
    except Exception:
        session['user_email'] = None

    return redirect('/')


@app.route('/logout')
def logout():
    """Logs the user out by clearing the session (drops the stored Gmail credentials)."""
    session.clear()
    return redirect('/')


@app.route('/api/feed-state', methods=['GET'])
def stream_feed_state():
    """Returns one page of scored inbox emails plus running analytics, for the
    dashboard's infinite-scroll feed (index.html polls this on load and on
    scroll, passing back the previous next_token to page forward)."""
    if session.get('demo'):
        # Paged like the real inbox (5 per page) so the demo exercises the same
        # infinite-scroll path the Gmail feed uses.
        page_size = 5
        try:
            offset = int(request.args.get('pageToken') or 0)
        except ValueError:
            offset = 0
        emails = build_demo_emails()
        page = emails[offset:offset + page_size]
        next_token = str(offset + page_size) if offset + page_size < len(emails) else None
        return jsonify({"emails": page, "next_token": next_token, "analytics": calculate_analytics(page), "error": None})
    if 'credentials' not in session:
        return jsonify({"emails": [], "next_token": None, "analytics": {"total": 0, "spoofed": 0, "soc_cases": 0, "percentage": 0}, "error": None})

    requested_token = request.args.get('pageToken', None)

    # The reported-ids lookup (Supabase on a cache miss) and the Gmail/AI fetch are
    # independent, so run them concurrently instead of paying both latencies in
    # series - the emails come back with soc_reported unset and get patched below
    # once the reported-ids thread resolves.
    reported_ids_fn = copy_current_request_context(_reported_ids_for_session)
    with ThreadPoolExecutor(max_workers=1) as executor:
        reported_ids_future = executor.submit(reported_ids_fn)
        emails, next_token, fetch_error = fetch_gmail_emails(page_token=requested_token, reported_ids=set())
        reported_ids = reported_ids_future.result()

    for email in emails:
        email['soc_reported'] = email['id'] in reported_ids

    analytics = calculate_analytics(emails)
    return jsonify({"emails": emails, "next_token": next_token, "analytics": analytics, "error": fetch_error})


@app.route('/api/report-soc/<email_id>', methods=['POST'])
def report_to_soc(email_id):
    """Marks an email as reported. Adds it to the in-memory REPORTED_SOC_IDS
    set and the session's cached reported-ids list (both used to render the
    "reported" badge), and persists it to Supabase - if configured - so it
    shows up on the /cases history page."""
    REPORTED_SOC_IDS.add(email_id)

    cached_ids = session.get('reported_ids', [])
    if email_id not in cached_ids:
        cached_ids.append(email_id)
    session['reported_ids'] = cached_ids

    if session.get('demo'):
        # Demo cases live in the session so the /cases page works without Supabase.
        # Known limitation: this is a read-modify-write on the session cookie, so
        # two report requests that are truly concurrent (fired within the same
        # round-trip window, e.g. rapid double-clicks) can both read the same
        # stale cookie and the later response's Set-Cookie silently drops the
        # other's entry. Not a concern for real (non-demo) reports - those are
        # independent Supabase row inserts, not a session read-modify-write.
        # Acceptable for demo mode's ephemeral, no-account sandbox; fixing it
        # properly would mean server-side storage for demo state, which is the
        # exact external-infrastructure cost demo mode exists to avoid.
        from datetime import datetime, timezone
        data = request.json or {}
        demo_cases = session.get('demo_cases', [])
        if not any(c.get('email_id') == email_id for c in demo_cases):
            demo_cases.insert(0, {
                "email_id": email_id,
                "sender": str(data.get('sender', ''))[:500],
                "subject": str(data.get('subject', ''))[:500],
                "risk_score": data.get('risk_score', 0),
                "reported_at": datetime.now(timezone.utc).strftime("%b %d, %Y at %H:%M UTC"),
            })
        session['demo_cases'] = demo_cases
        return jsonify({"status": "success", "message": "Email reported."})

    user_email = session.get('user_email')
    if SUPABASE_CONFIGURED and user_email:
        data = request.json or {}
        try:
            risk_score = int(data.get('risk_score', 0))
        except (TypeError, ValueError):
            risk_score = 0
        save_reported_case(
            user_email=user_email,
            email_id=email_id,
            sender=str(data.get('sender', ''))[:500],
            subject=str(data.get('subject', ''))[:500],
            risk_score=risk_score,
        )

    return jsonify({"status": "success", "message": "Email reported."})


@app.route('/api/analyze-ext', methods=['POST'])
@limiter.limit("20 per minute")
def analyze_from_extension():
    """Scores an email scraped directly from the Gmail page by the browser extension."""
    data = request.json or {}
    sender = str(data.get('sender', ''))
    subject = str(data.get('subject', ''))
    body = str(data.get('body', ''))

    category = fallback_categorize(body)
    spoofed = detect_spoofing(sender)
    links = parse_and_sandbox_links(body)
    risk_score = calculate_risk_index(category, spoofed, links)
    email_id = hashlib.sha1(f"{sender}|{subject}|{body}".encode('utf-8')).hexdigest()[:16]

    return jsonify({
        "id": email_id,
        "assigned_category": category,
        "spoofing_detected": spoofed,
        "risk_score": risk_score,
        "links": links
    })


@app.route('/analyze/<email_id>', methods=['POST'])
@limiter.limit("20 per minute")
def analyze_email(email_id):
    """Generates a threat report for an email."""
    data = request.json or {}
    sender = str(data.get('sender', ''))
    subject = str(data.get('subject', ''))
    body = str(data.get('body', ''))

    lower = body.lower()
    if "paypal" in lower or "bank" in lower or "wire" in lower:
        fallback = {
            "threat_type": "Possible Payment Scam",
            "educational_report": (
                "This message pushes you to act on a payment or account problem. Real companies "
                "don't ask for account details or payments over email - if you're unsure, go to "
                "the company's website yourself instead of using any link in the message."
            ),
            "indicators": ["Asks you to act on a payment or account issue", "Pressure to respond quickly"]
        }
    elif "login" in lower or "verify" in lower or "portal" in lower:
        fallback = {
            "threat_type": "Possible Phishing Link",
            "educational_report": (
                "This message steers you toward a sign-in or verification link. Scammers use "
                "lookalike web addresses to steal passwords - check the address carefully, and "
                "when in doubt, type the site's address into your browser yourself."
            ),
            "indicators": ["Contains a sign-in or verification link", "May imitate a real website"]
        }
    else:
        fallback = {
            "threat_type": "Suspicious Message",
            "educational_report": (
                "Something about this message looks off. Don't share passwords, codes, or personal "
                "details, and confirm the request with the sender through another channel before acting."
            ),
            "indicators": ["Unexpected or unusual request", "Sender you may not recognize"]
        }

    prompt = f"""
You are an elite cybersecurity educator analyzing a suspicious email threat.
Sender: {sender}
Subject: {subject}
Body: {truncate_for_prompt(body)}

Provide a JSON response with exactly three keys:
1. "threat_type": One of: 'Phishing Link Attack', 'Financial Wire Scam', 'Brand Impersonation', 'Malicious Attachment Trap'.
2. "educational_report": 2-3 sentences explaining indicators of compromise and how to protect oneself.
3. "indicators": A JSON list of 2-3 brief warning point strings.

Return ONLY raw valid JSON. No markdown.
"""
    report = groq_json_call(prompt) or fallback
    return jsonify({"status": "success", "report": report})


@app.route('/api/quiz/<email_id>', methods=['POST'])
@limiter.limit("20 per minute")
def generate_quiz(email_id):
    """Generates a multiple-choice quiz question from email content."""
    data = request.json or {}
    body = str(data.get('body', ''))

    fallback = {
        "question": "What's the biggest warning sign in an email like this one?",
        "options": [
            "An urgent tone pushing you to act before you can think",
            "Links that don't lead where they claim to",
            "A generic greeting from a sender you don't recognize",
            "All of the above"
        ],
        "correct_index": 3,
        "explanation": (
            "Scam emails usually stack several tricks at once - urgency, misleading links, "
            "and vague greetings - to pressure you into clicking."
        )
    }

    prompt = f"""
Based on this suspicious email, generate a multiple choice question to test a student's ability to spot this type of cybersecurity scam.
Body: {truncate_for_prompt(body)}

Provide a JSON response with exactly four keys:
1. "question": A clear educational multiple choice question focused on red flags in this email.
2. "options": An array of exactly 4 distinct answer strings.
3. "correct_index": Zero-based integer index of the correct answer.
4. "explanation": One sentence explaining why that answer is correct.

Return ONLY raw valid JSON. No markdown.
"""
    quiz = groq_json_call(prompt) or fallback
    return jsonify({"status": "success", "quiz": quiz})


def _is_signed_in() -> bool:
    """True for a real Gmail session or demo mode - drives which header/nav renders."""
    return 'credentials' in session or bool(session.get('demo'))


@app.route('/how-it-works')
def how_it_works():
    """Static explainer page - no auth required."""
    return render_template('how_it_works.html', logged_in=_is_signed_in(), active_page='how-it-works')


@app.route('/privacy')
def privacy():
    """Static privacy policy page - no auth required."""
    return render_template('privacy.html', logged_in=_is_signed_in())


@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Not found"}), 404
    return render_template(
        'error.html',
        logged_in=_is_signed_in(),
        code=404,
        heading="Page not found",
        message="The page you're looking for doesn't exist or may have moved.",
    ), 404


@app.errorhandler(500)
def internal_error(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Something went wrong on our end"}), 500
    return render_template(
        'error.html',
        logged_in=_is_signed_in(),
        code=500,
        heading="Something went wrong",
        message="An unexpected error occurred on our end. Please try again in a moment.",
    ), 500


@app.route('/settings')
def settings():
    """Settings page. Requires login (or demo mode)."""
    if 'credentials' not in session and not session.get('demo'):
        return redirect('/')
    return render_template('settings.html', logged_in=True, active_page='settings', user_email=session.get('user_email'))


@app.route('/cases')
def cases():
    """Lists this user's previously reported cases - from the session in demo
    mode, from Supabase otherwise (empty if Supabase isn't configured).
    Requires login (or demo mode)."""
    if session.get('demo'):
        return render_template(
            'cases.html',
            logged_in=True,
            active_page='cases',
            cases=session.get('demo_cases', []),
            supabase_configured=True,
        )
    if 'credentials' not in session:
        return redirect('/')
    user_email = session.get('user_email')
    return render_template(
        'cases.html',
        logged_in=True,
        active_page='cases',
        cases=list_reported_cases(user_email),
        supabase_configured=SUPABASE_CONFIGURED,
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=DEBUG_MODE)
