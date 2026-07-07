# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

---

## Project: GuardMail AI

A Flask + Gmail OAuth dashboard (deployed on Vercel) plus a Chrome extension.
It scans a user's inbox for phishing/spam/spoofed senders, scores each
message's risk, and uses Groq (Llama 3.1) to generate a threat report and a
quiz so users learn to spot scams themselves.

**Layout:**
- `api/index.py` — Flask backend: OAuth login, Gmail fetch/scoring, Groq calls, all routes.
- `templates/index.html` — single-page dashboard (Tailwind + vanilla JS), server-rendered on load then JS-driven (search/sort, AI/quiz panes).
- `extension/` — Manifest V3 Chrome extension; injects a scan button into Gmail, posts to `/api/analyze-ext`, backend URL configurable via `extension/options.html`.
- `tests/` — pytest coverage for the pure scoring/classification helpers in `api/index.py`.

Full setup, env vars, and architecture are in `README.md` — read that first for
onboarding context rather than re-deriving it from the code.

**History:** this was originally a half-broken prototype (a corrupted,
duplicated `templates/index.html`, and the extension calling a backend route
that didn't exist). Both were fixed, then a broader production-readiness pass
followed: wired up the previously-dead Groq categorizer, removed an insecure
hardcoded secret-key fallback, locked down session cookies and CORS, handled
expired Gmail sessions gracefully, batched Gmail API calls, added per-IP rate
limiting on the Groq-backed routes, added inbox search/sort and client-side
AI/quiz result caching, made the extension's backend URL configurable, added
unit tests, and wrote the README.

A later product pass (July 2026) overhauled scoring to kill false positives
(brand->official-domain spoof matching via BRAND_DOMAINS, trusted-domain link
allowlist, registrable-domain keyword checks, money+urgency requirement in the
fallback categorizer), added risk_factors ("Why this score?") to every scored
email, added /demo mode (canned inbox through the real pipeline - also the
easiest way to develop/verify the logged-in UI without OAuth), and grew the
frontend: trusted senders (localStorage), keyboard nav, toasts, skeletons,
quiz score tracking, cases CSV export, landing page with product mockup,
privacy policy, and branded error pages.

A follow-up polish pass fixed the infinite-scroll stall (IntersectionObserver
only fires on intersection *changes* - loadNextBatch now re-observes after
every batch, plus a manual "Load more" fallback; demo mode pages 5-at-a-time
to exercise this path), swapped the blue-tinted slate palette for neutral
zinc, and added a motion system in base.html (gm-fade-up/gm-pop keyframes,
.reveal scroll reveals, count-up stats, SVG risk-score ring). All motion is
disabled by html.no-anim, driven by the Settings "Interface animations"
toggle (localStorage guardmail_animations) and prefers-reduced-motion. Note:
don't use requestAnimationFrame for state that must eventually apply - it
never fires in hidden tabs (the risk ring uses setTimeout for this reason).

The dashboard now uses a Gmail-style shell: desktop sidebar (category filters
with live counts, "Inbox health" grade, shortcuts hint - mobile falls back to
filter chips), a rounded top search bar, slim list header, rows with
read/unread dimming (session-scoped viewedIds) and hover quick-actions
(report / trust toggle) that call dispatchSocReport/quickToggleSafe without
opening the message. Keyboard: j/k navigate, / search, r report, ? shortcuts
overlay, Esc closes. The landing has an asymmetric hero (copy left, mockup
right), a marquee ticker of scam subject lines, and an interactive
"spot the phish" two-card game (pickPhish in the logged-out scripts block).

**Known, deliberate limitations** (see README "Known limitations" for why):
SOC-report state and the rate limiter are in-memory only — they reset on
serverless cold starts. This was a conscious choice to avoid adding external
infrastructure (a DB/KV store), not an oversight — don't "fix" it without
checking with the user first, since it's a real architecture tradeoff with
cost/complexity implications.
