# GuardMail AI

A Gmail security-awareness tool. It scans your inbox for phishing, spam, and
spoofed senders, scores each message's risk, and uses Groq (Llama 3.1) to
generate a plain-English threat report and a quick quiz so you learn to spot
the warning signs yourself. A companion Chrome extension lets you run the
same scan on an open Gmail thread without leaving your inbox.

## How it works

- **Backend** (`api/index.py`): Flask app. Logs in via Google OAuth
  (read-only Gmail scope), pulls your inbox, and for each message computes:
  - a category (`Important`, `High Priority`, `Spam`, `Scam Alert`) via Groq,
    with a conservative keyword fallback that requires both a money/credential
    hook *and* an urgency hook before calling anything a scam
  - a spoofed-sender check: a message is flagged only when it claims a
    well-known brand (in the display name or a lookalike domain) but wasn't
    sent from that brand's real domains (`BRAND_DOMAINS`)
  - a per-link classification: trusted domains pass (including their real
    login pages); lookalike hosts, keyword-registered domains, raw-IP links,
    and disguised destinations are dangerous; shorteners get a caution label
  - a risk score (0-100) plus a `risk_factors` breakdown explaining it,
    surfaced in the UI as "Why this score?"
  - on demand, an AI-generated threat report and quiz question (`Groq`)
- **Frontend** (`templates/index.html`): dashboard with inbox
  search/sort/filter chips, keyboard navigation (`j`/`k`/`/`/`Esc`), a message
  viewer with score breakdown, link sandbox, AI analysis pane with copy-report,
  quizzes with browser-local score tracking, mark-sender-as-safe (trusted
  senders, browser-local), reported-cases CSV export, and toasts.
- **Demo mode** (`/demo`): a canned sample inbox served through the same
  scoring pipeline — no Google account or Groq quota needed. Great for trying
  the product (or developing the UI) without OAuth.
- **Extension** (`extension/`): a Manifest V3 Chrome extension that injects a
  "scan" button into Gmail and posts the open email to the backend for the
  same scoring, independent of the dashboard's own inbox fetch.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # add -r requirements-dev.txt instead to also get pytest
```

Create a `.env` file in the project root:

```
GROQ_API_KEY=...            # from console.groq.com - omit to fall back to keyword-only categorization
FLASK_SECRET_KEY=...        # required; signs session cookies (which carry OAuth tokens)
GOOGLE_CLIENT_ID=...        # from Google Cloud Console OAuth client
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=http://localhost:3000/callback
FLASK_DEBUG=1                # optional, local dev only - enables Flask debug mode and allows OAuth over plain HTTP
```

Run it:

```bash
python3 api/index.py
```

Visit `http://localhost:3000` and sign in with Google.

## Extension (local install)

1. Open `chrome://extensions`, enable Developer Mode.
2. "Load unpacked" and select the `extension/` folder.
3. Open an email in Gmail and click the floating "Audit with GuardMail AI" button.
4. If your backend isn't running on `http://127.0.0.1:3000`, open the
   extension's options page (right-click its icon → Options) and point it at
   your deployed URL.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/
```

Covers the pure scoring/classification helpers (`detect_spoofing`,
`calculate_risk_index`, `build_risk_factors`, `classify_link`,
`parse_and_sandbox_links`, `fallback_categorize`), with regression tests for
the false-positive cases (real banks, providers' own login pages, receipts
that merely mention money).

## Deployment

Configured for Vercel (`vercel.json` routes everything through
`api/index.py`). Set the same environment variables in the Vercel project
settings, with `FLASK_DEBUG` unset (or `0`) and `GOOGLE_REDIRECT_URI` pointing
at your production callback URL.

## Known limitations

- **"Reported to SOC" status is in-memory only.** It's tracked in a plain
  Python set on the server process, not a database. On Vercel's serverless
  runtime this resets on cold starts, so reported status isn't guaranteed to
  persist across requests in production. Fine for a demo/single-instance
  deployment; would need an external store (e.g. Redis, Postgres) to be
  durable at scale.
- **Session cookies carry OAuth credentials.** Flask's default session is a
  signed (not encrypted) client-side cookie; it's locked down with
  `HttpOnly`/`Secure`/`SameSite` flags, but moving to server-side session
  storage would be a stronger guarantee if this ever handles real user data
  at scale.
- **Rate limiting is per-process and in-memory** (`Flask-Limiter` with no
  external backend), so it resets on restarts/cold starts too — it's a
  best-effort guard against runaway Groq usage, not a hard cap.
