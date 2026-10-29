# 🤖 AI Code Review Bot

A FastAPI service that receives **GitHub webhooks** and automatically posts
an **AI-style review comment** on every pull request that adds code.
The analysis is a deterministic, rule-based reviewer focused on Python
(security red flags, exception handling, hardcoded secrets, style, and 
test coverage).

```
GitHub PR opened ──webhook──▶ FastAPI /webhook
                                 │ 1. validates the HMAC-SHA256 signature
                                 │ 2. answers GitHub quickly ("accepted")
                                 ▼
                     background task
                        1. GET /repos/{repo}/pulls/{n}/files  (changed files + diffs)
                        2. rule-based reviewer (app/reviewer.py)
                        3. POST the Markdown comment via the
                           pull-request reviews API  (COMMENT event)
```

## Features

- ✅ **Overview only**: one general review comment per PR (plus table of changed files).
- ✅ **Duplicate protection**: reopening a PR does not post the identical comment again.
- ✅ **Signature validation**: rejects deliveries that are not signed with your webhook secret (`403`).
- ✅ **Token via `.env`** using `python-dotenv` — secrets never printed or committed.
- ✅ **Rule-based Python review** (deterministic, no AI API needed):
  - 🔒 security: `eval`/`exec`, `shell=True`, SQL built with f-strings, hardcoded
    secrets / AWS keys, `pickle.load`
  - ⚠️ warnings: `os.system`, weak `hashlib.md5`, bare/`except Exception`,
    mutable default arguments
  - 💡 suggestions: `print` → logging, `== None` → `is None`, TODO/FIXME,
    long lines (>120), `assert` as runtime check, missing tests
- ✅ **Error handling & logging** for GitHub 401/403/404, network errors, and malformed payloads.

## Requirements

- Python **3.10+**
- A GitHub account and the repository this bot reviews
- [ngrok](https://ngrok.com/) (free) so GitHub can reach your local machine

---

## 1. Setup

```powershell
# inside the project folder
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

A **`.env`** file (git-ignored) must exist in the project root with:

```
GITHUB_TOKEN=ghp_replace_me_with_your_real_token
GITHUB_WEBHOOK_SECRET=replace_me_with_a_long_random_string
# optional
LOG_LEVEL=INFO
REVIEW_STRICT=false
```

Both values already have placeholders in `.env` — you only fill in the two
real values described in the next sections. A `.env.example` documents
every variable; never commit the real `.env`.

## 2. Create the GitHub token

The bot authenticates with a **Personal Access Token (PAT)** to read PR
files and post review comments.

1. Go to <https://github.com/settings/tokens>.
2. **Fine-grained token** (recommended): *Generate new token* →
   - Repository access: only the repository you want reviewed
   - Permissions: **Contents: Read-only**, **Pull requests: Read and write**
   *(A classic token with the `repo` scope also works, but grants much more.)*
3. Copy the token **once** — GitHub will not show it again.
4. Paste it into `.env` as `GITHUB_TOKEN=...`. Do not paste tokens into
   chats, screenshots, or code.

## 3. Run the bot locally

```powershell
.\venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
```

On startup it prints a **config check** like (never the values):

```
Config check: GITHUB_TOKEN set | GITHUB_WEBHOOK_SECRET set | REVIEW_STRICT off
```

Quick checks: <http://127.0.0.1:8000/> and <http://127.0.0.1:8000/health>.

## 4. Expose it with ngrok

GitHub must be able to call your machine; ngrok tunnels a public HTTPS
URL to `localhost:8000`.

```powershell
ngrok http 8000
```

Copy the line like `Forwarding https://xxxx-xxxx.ngrok-free.app -> http://localhost:8000`.
The **https://…ngrok-free.app** URL is your webhook URL. ⚠️ It changes every
time you restart free ngrok — update the GitHub webhook (section 5) if it does.

## 5. Configure the GitHub webhook

In your repository: **Settings → Webhooks → Add webhook**

| Field | Value |
|---|---|
| Payload URL | `https://xxxx.ngrok-free.app/webhook` |
| Content type | **`application/json`** |
| Secret | the **same value** as `GITHUB_WEBHOOK_SECRET` in `.env` |
| Events | **Pull requests** |

Press **Add webhook**. GitHub immediately sends a `ping` delivery — the bot
log shows `Ping received from GitHub — webhook connected correctly.` and the
delivery appears green (✓ 200) in *Settings → Webhooks → Recent Deliveries*.

> How the secret works: GitHub signs each delivery with HMAC-SHA256 using
> that secret (header `X-Hub-Signature-256`). The bot recomputes the HMAC on
> the raw bytes and compares in constant time. A wrong secret → logged
> `signature mismatch` and **403**.

## 6. Testing

### 6.1 Reviewer dry run (no GitHub needed)

```powershell
python scripts/dry_run.py
```

Prints the exact comment a fake PR would receive (see `scripts/dry_run.py`
for the fake files). Use this when tuning the rules.

### 6.2 Webhook + signature test (no GitHub needed)

With the bot running:

```powershell
python scripts/dry_run.py --webhook                 # expect 200 ok + 200 accepted
python scripts/dry_run.py --webhook --bad-signature # expect 403 on both
```

### 6.3 Full end-to-end (real GitHub)

1. Bot running + ngrok running + webhook configured (sections 2–5).
2. Create a branch and a PR containing **`examples/bad_code.py`**
   (a file of deliberately bad code included in this repo) — copy it into a
   test branch and push.
3. Within a few seconds the PR gets one comment starting with
   **“🤖 AI Code Review”**, containing the file table and findings grouped by
   🔒 / ⚠️ / 💡.
4. Push another commit → `synchronize` event → a **new** review for the new
   diff. Re-open without changes → **no duplicate** comment is posted.

### 6.4 Unknown-PR behavior (error handling)

```powershell
python scripts/dry_run.py --webhook --repo octocat/hello-world --pr 1
```

Accepted by the webhook, then the background job logs
`GitHub 404 — repo or PR not visible with this token` — no crash, no spam.

## What the bot reacts to

| Event | Action | Behavior |
|---|---|---|
| `ping` | — | greetings, no comment |
| `pull_request` | `opened` / `reopened` / `synchronize` | reviews the added code |
| `pull_request` | `closed`, `labeled`, … | ignored |
| anything else | — | ignored (`status: ignored`) |

Set `REVIEW_STRICT=true` to make the bot **request changes** (which blocks
merging) instead of just commenting, whenever 🔒 security findings exist.

## Troubleshooting

| Symptom (bot log) | Cause & fix |
|---|---|
| `GITHUB_TOKEN NOT set` at startup | `.env` missing or under another name — create it next to `README.md` |
| `GitHub 401 Unauthorized` | token invalid/expired, or pasted with spaces — regenerate and re-paste |
| `GitHub 403` when posting | token lacks **Pull requests: Read and write** (fine-grained) — or rate limit; retry later |
| `GitHub 404` | token has no access to that repository (fine-grained: select the repo) |
| `invalid signature` / HTTP 403 | webhook "Secret" ≠ `GITHUB_WEBHOOK_SECRET` — make them identical |
| No review although PR opened | check *Recent Deliveries*: green? then check bot console; red `308/…`? ngrok URL changed — update Payload URL |
| Emoji garbled in console | cosmetic only (Windows code page); on GitHub the comment is fine |

## Project layout

```
app/
  main.py           FastAPI app: webhook receiver, signature check, review pipeline
  config.py         .env loading (python-dotenv) + safe config logging
  github_client.py  async GitHub API calls (files, reviews) with httpx
  reviewer.py       rule-based Python reviewer → one Markdown comment
scripts/
  dry_run.py        local testing: reviewer preview + signed webhook sender
examples/
  bad_code.py       deliberately bad file to push for end-to-end testing
.env                YOUR secrets (git-ignored, never commit)
.env.example        template documenting every variable
requirements.txt    fastapi, uvicorn, httpx, python-dotenv, pydantic
```

## Roadmap ideas

- Inline (line-level) comments instead of one general comment
- More languages (JS/TS rules), flake8/mypy integration
- Real LLM ("actual AI") review via an AI API as a second pass
- Deploy on Render/Railway so ngrok is no longer needed
