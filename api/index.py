import os
import json
import re
import hashlib
from concurrent.futures import ThreadPoolExecutor
import httpx
import google_auth_oauthlib.flow
from flask import Flask, render_template, request, jsonify, redirect, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from groq import Groq
from dotenv import load_dotenv
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

load_dotenv()

# Local dev only: allow the OAuth dance over plain HTTP and enable Flask's debugger.
# Both default OFF so a misconfigured deploy never accidentally ships with them on.
DEBUG_MODE = os.getenv("FLASK_DEBUG", "0") == "1"
if DEBUG_MODE:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__, template_folder='../templates')

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set (it signs session "
        "cookies, which carry OAuth credentials)."
    )
app.secret_key = FLASK_SECRET_KEY

# Session cookies carry Gmail OAuth credentials, so lock them down: no JS access,
# not sent cross-site, and HTTPS-only outside of local debugging.
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

# Google OAuth Configuration Matrix
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

# Global tracking framework for reported cases (persisted runtime fallback)
REPORTED_SOC_IDS = set()

SCAM_KEYWORDS = ["paypal", "verify", "bank", "wire", "transfer", "login", "credentials", "bonus"]
SPAM_KEYWORDS = ["buy", "discount", "free", "marketing", "promotion", "sale", "deals"]
DANGEROUS_URL_KEYWORDS = [
    "verify", "login", "secure", "bonus", "claim", "portal",
    "update", "paypal", "bank", "signin", "verification", "credentials"
]

AVATAR_COLORS = ["bg-blue-500", "bg-purple-500", "bg-emerald-500", "bg-amber-500",
                  "bg-rose-500", "bg-cyan-500", "bg-indigo-500", "bg-teal-500"]


def get_initials(sender: str) -> str:
    """Returns a single uppercase initial for a sender's display name (or email if none)."""
    name = sender.split('<')[0].strip()
    if not name:
        match = re.search(r'<([^>]+)>', sender)
        name = match.group(1) if match else sender
    return (name[:1] or '?').upper()


def get_avatar_color(sender: str) -> str:
    """Deterministically maps a sender string to a Tailwind background color class."""
    return AVATAR_COLORS[sum(ord(c) for c in sender) % len(AVATAR_COLORS)]


app.jinja_env.filters['initials'] = get_initials
app.jinja_env.filters['avatar_color'] = get_avatar_color


def detect_spoofing(sender_str: str) -> bool:
    """Detects if a popular brand name is being impersonated in the sender display string."""
    sender_lower = sender_str.lower()
    monitored_brands = ["paypal", "meta", "google", "netflix", "amazon", "apple", "bank", "security"]
    
    email_match = re.search(r'<([^>]+)>', sender_str)
    if email_match:
        display_part = sender_lower.split('<')[0]
        actual_email_domain = email_match.group(1).lower().split('@')[-1]
        for brand in monitored_brands:
            if brand in display_part and brand not in actual_email_domain:
                return True
    else:
        if "@" in sender_lower:
            local_part, domain_part = sender_lower.split("@", 1)
            for brand in monitored_brands:
                if brand in local_part and brand not in domain_part:
                    return True
    return False


def calculate_risk_index(category: str, spoofed: bool, links: list) -> int:
    """Calculates a comprehensive threat matrix risk score between 0 and 100."""
    score = 10
    if category == "Scam Alert":
        score += 45
    elif category == "Spam":
        score += 20
        
    if spoofed:
        score += 25
        
    dangerous_links = sum(1 for l in links if "Dangerous" in l["safety_status"])
    score += (dangerous_links * 15)
    
    return min(score, 100)


def calculate_analytics(emails):
    """Computes operational security metrics across real active inbox parameters."""
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


def parse_and_sandbox_links(body_text):
    """Extracts URLs from email content and flags them based on threat signatures."""
    found_urls = re.findall(r'https?://[^\s<>"\')\]\n\r]+', body_text)
    return [
        {
            "url": url.rstrip(".,;:"),
            "safety_status": (
                "Dangerous / Blacklisted Match"
                if any(k in url.lower() for k in DANGEROUS_URL_KEYWORDS)
                else "External Link / Unverified Clear"
            )
        }
        for url in found_urls
    ]


def fallback_categorize(body: str) -> str:
    """Local keyword-based fallback categorizer."""
    lower = body.lower()
    if any(k in lower for k in SCAM_KEYWORDS):
        return "Scam Alert"
    if any(k in lower for k in SPAM_KEYWORDS):
        return "Spam"
    return "Important"


def truncate_for_prompt(text: str) -> str:
    """Caps text fed into a Groq prompt so cost/latency/token limits stay bounded."""
    return text[:MAX_PROMPT_CHARS]


def groq_categorize(body: str) -> str | None:
    """Calls Groq to categorize email. Returns None on failure."""
    if not groq_client or not body:
        return None
    prompt = (
        "Categorize this email content into exactly one category: "
        "'High Priority', 'Important', 'Spam', or 'Scam Alert'. "
        f"Content: {truncate_for_prompt(body)}. Return ONLY the classification name, no punctuation."
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
    """Recursively processes multi-part structures to extract safe plain text segments, with HTML fallback tracking."""
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


def fetch_gmail_emails(page_token=None, reported_ids=None):
    """Builds access credentials and queries live Gmail message matrices seamlessly supporting token pagination.

    Returns a 3-tuple: (emails_list, next_page_token, error_message). error_message is
    None on success, or a short human-readable string if the Gmail fetch failed, so
    callers can distinguish "empty inbox" from "fetch failed" instead of treating both
    the same way.
    """
    if reported_ids is None:
        reported_ids = REPORTED_SOC_IDS
    if 'credentials' not in session:
        return [], None, None
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
        results = service.users().messages().list(userId='me', maxResults=10, pageToken=page_token).execute()
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
                    lambda meta: groq_categorize(meta["body"]) or fallback_categorize(meta["body"]),
                    emails_meta
                ))

        emails_list = []
        for meta, category in zip(emails_meta, categories):
            spoofed = detect_spoofing(meta["sender"])
            links = parse_and_sandbox_links(meta["body"])
            risk_score = calculate_risk_index(category, spoofed, links)
            soc_reported = meta["id"] in reported_ids

            emails_list.append({
                "id": meta["id"],
                "sender": meta["sender"],
                "subject": meta["subject"],
                "date": meta["date"],
                "body": meta["body"],  # Preserving un-truncated content lengths for deep internal viewing
                "initial_category": category,
                "spoofing_detected": spoofed,
                "risk_score": risk_score,
                "soc_reported": soc_reported,
                "links": links
            })
        return emails_list, next_page_token, None
    except RefreshError:
        # Refresh token expired/revoked - no amount of retrying will fix this from
        # here, so clear the dead session and let the user re-authenticate.
        session.clear()
        return [], None, "Your Gmail session expired. Please sign in again."
    except Exception as exc:
        return [], None, f"Couldn't reach Gmail: {exc.__class__.__name__}"


def _reported_ids_for_session():
    user_email = session.get('user_email')
    if SUPABASE_CONFIGURED and user_email:
        return get_reported_case_ids(user_email)
    return REPORTED_SOC_IDS


@app.route('/')
def index():
    if 'credentials' not in session:
        return render_template('index.html', logged_in=False, emails=[], next_token=None, analytics={"total": 0, "spoofed": 0, "soc_cases": 0, "percentage": 0}, fetch_error=None)

    current_token = request.args.get('pageToken', None)
    emails, next_token, fetch_error = fetch_gmail_emails(page_token=current_token, reported_ids=_reported_ids_for_session())
    analytics = calculate_analytics(emails)
    return render_template('index.html', logged_in=True, active_page='inbox', emails=emails, next_token=next_token, analytics=analytics, fetch_error=fetch_error)


@app.route('/login')
def login():
    """Initializes Google OAuth pipeline variables and options."""
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
    """Transforms verification properties into runtime auth tokens securely while mitigating state-mismatch panics."""
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
    """Clears localized cookie metrics configuration parameters safely."""
    session.clear()
    return redirect('/')


@app.route('/api/feed-state', methods=['GET'])
def stream_feed_state():
    if 'credentials' not in session:
        return jsonify({"emails": [], "next_token": None, "analytics": {"total": 0, "spoofed": 0, "soc_cases": 0, "percentage": 0}, "error": None})
    
    requested_token = request.args.get('pageToken', None)
    emails, next_token, fetch_error = fetch_gmail_emails(page_token=requested_token, reported_ids=_reported_ids_for_session())
    analytics = calculate_analytics(emails)
    return jsonify({"emails": emails, "next_token": next_token, "analytics": analytics, "error": fetch_error})


@app.route('/api/report-soc/<email_id>', methods=['POST'])
def report_to_soc(email_id):
    """Documents incident and escalates telemetry properties to the Enterprise SOC layer."""
    REPORTED_SOC_IDS.add(email_id)

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

    return jsonify({"status": "success", "message": f"Payload {email_id} successfully dispatched to SOC."})


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
            "threat_type": "Financial Wire Scam",
            "educational_report": (
                "The request demands immediate financial verification or wire parameters. "
                "Legitimate payment vendors will never ask for credentials via direct text paths."
            ),
            "indicators": ["Financial coercion hook", "Impersonated payment vendor gateway"]
        }
    elif "login" in lower or "verify" in lower or "portal" in lower:
        fallback = {
            "threat_type": "Phishing Link Attack",
            "educational_report": (
                "This payload utilizes artificial redirect URLs to harvest credentials. "
                "Inspect link structures carefully to confirm mismatch anomalies before clicking."
            ),
            "indicators": ["Deceptive link redirection setup", "Psychological action-inducing threat"]
        }
    else:
        fallback = {
            "threat_type": "Suspicious Threat Signature",
            "educational_report": (
                "This message possesses active psychological hooks. Avoid sharing security credentials, "
                "private identity details, or authorization profiles."
            ),
            "indicators": ["Urgent actionable demands", "Generic unrecognized email domain routing"]
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
        "question": "What is the primary indicator of compromise present within this email?",
        "options": [
            "The urgent warning tone demanding quick, unverified action",
            "The presence of external, blacklisted redirect hyperlinks",
            "The generic greeting and unmatched email domain",
            "All of the above"
        ],
        "correct_index": 3,
        "explanation": (
            "Scam campaigns typically integrate multiple psychological and structural warning flags "
            "simultaneously to maximize impact."
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


@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html', logged_in='credentials' in session, active_page='how-it-works')


@app.route('/settings')
def settings():
    if 'credentials' not in session:
        return redirect('/')
    return render_template('settings.html', logged_in=True, active_page='settings', user_email=session.get('user_email'))


@app.route('/cases')
def cases():
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
