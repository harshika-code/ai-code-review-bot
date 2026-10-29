"""FastAPI server for the AI code review bot.

Lifecycle of a review:

    GitHub  --webhook-->  POST /webhook
        (1) HMAC-SHA256 signature check (X-Hub-Signature-256)
        (2) quick response to GitHub ["accepted"]
        (3) background task: fetch PR files -> rule-based review -> post comment
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Literal

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from app import reviewer
from app.config import (
    get_github_token,
    get_github_webhook_secret,
    is_review_strict_enabled,
    log_config_status,
)
from app.github_client import GitHubClient, GitHubError

logger = logging.getLogger("ai_code_review_bot")


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
def _configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level_name, logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    # The HTTP client libraries are very chatty at INFO; request id + token
    # values can show up there, so reduce them unless DEBUG is asked for.
    if level_name != "DEBUG":
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


# --------------------------------------------------------------------------
# Startup / shutdown
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Create the GitHub client on startup, close it on shutdown."""
    _configure_logging()
    log_config_status()

    token = get_github_token()
    if token:
        app.state.github = GitHubClient(token)
    else:
        app.state.github = None
        logger.error(
            "GITHUB_TOKEN is not set. Webhooks will still be accepted, but no "
            "review comments can be posted. Put a token in .env (see README.md)."
        )

    try:
        yield
    finally:
        if app.state.github is not None:
            await app.state.github.close()
            app.state.github = None


app = FastAPI(title="AI Code Review Bot", version="1.0.0", lifespan=lifespan)


# --------------------------------------------------------------------------
# Webhook payload models (only the fields we actually use)
# --------------------------------------------------------------------------
class PullRequestInfo(BaseModel):
    number: int
    title: str = ""


class RepositoryInfo(BaseModel):
    full_name: str


class PullRequestEvent(BaseModel):
    action: str
    pull_request: PullRequestInfo
    repository: RepositoryInfo


# --------------------------------------------------------------------------
# Signature validation
# --------------------------------------------------------------------------
def verify_github_signature(body: bytes, signature_header: str | None) -> bool:
    """Validate GitHub's X-Hub-Signature-256 header.

    GitHub signs every webhook payload with HMAC-SHA256 using the shared
    secret you configure on both sides (GitHub repo settings + .env).
    Comparison is done with ``hmac.compare_digest`` so timing attacks
    cannot leak the secret byte by byte.
    """
    secret = get_github_webhook_secret()

    if not secret:
        logger.warning(
            "GITHUB_WEBHOOK_SECRET is not set — skipping signature validation. "
            "This is fine for local tests, NOT for a public URL."
        )
        return True

    if not signature_header or not signature_header.startswith("sha256="):
        logger.warning("Webhook rejected: no valid X-Hub-Signature-256 header.")
        return False

    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    provided = signature_header.removeprefix("sha256=").strip()
    if not hmac.compare_digest(expected, provided):
        logger.warning("Webhook rejected: signature mismatch (wrong secret?).")
        return False

    return True


# --------------------------------------------------------------------------
# Review pipeline (runs in the background so the webhook answers fast)
# --------------------------------------------------------------------------
def _log_github_http_error(exc: httpx.HTTPError, context: str) -> None:
    """Turn httpx errors into short, actionable log lines (no secrets)."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        try:
            detail = exc.response.json().get("message", "")
        except Exception:
            detail = exc.response.text[:120]

        if status == 401:
            logger.error(
                "%s: GitHub 401 Unauthorized — the GITHUB_TOKEN in .env is "
                "missing, invalid, or expired.",
                context,
            )
        elif status == 403:
            logger.error(
                "%s: GitHub 403 — the token lacks the needed permission or the "
                "rate limit was hit. (%s)",
                context,
                detail,
            )
        elif status == 404:
            logger.error(
                "%s: GitHub 404 — repo or PR not visible with this token. (%s)",
                context,
                detail,
            )
        else:
            logger.error("%s: GitHub returned HTTP %s. (%s)", context, status, detail)
    else:
        logger.error("%s: cannot reach GitHub: %r", context, exc)


async def review_and_post(repo_full_name: str, pr_number: int, pr_title: str) -> None:
    """Fetch the PR's files, review them, and post one comment."""
    client: GitHubClient | None = app.state.github
    if client is None:
        logger.error(
            "Cannot review %s#%s — GITHUB_TOKEN is not configured.", repo_full_name, pr_number
        )
        return

    logger.info("Reviewing %s PR #%s (%s)", repo_full_name, pr_number, pr_title)

    # 1) Data
    try:
        files = await client.get_pull_request_files(repo_full_name, pr_number)
        existing_bodies = await client.get_existing_review_bodies(repo_full_name, pr_number)
    except (GitHubError, httpx.HTTPError) as exc:
        _log_github_http_error(exc, f"Fetching PR data for {repo_full_name}#{pr_number}")
        return

    # 2) Analysis (pure CPU, no network)
    try:
        review = reviewer.review_pull_request(repo_full_name, pr_number, pr_title, files)
    except Exception:
        logger.exception(
            "Reviewer crashed for %s#%s — posting a placeholder comment instead.",
            repo_full_name,
            pr_number,
        )
        review = reviewer.fallback_review(repo_full_name, pr_number, pr_title)

    # 3) Avoid posting the exact same comment twice (e.g. on a re-open).
    if review.body in existing_bodies:
        logger.info(
            "An identical review already exists on %s#%s; skipping.", repo_full_name, pr_number
        )
        return

    if not files:
        logger.info("%s#%s has no changed files to review; skipping.", repo_full_name, pr_number)
        return

    # 4) Post
    gh_event: Literal["COMMENT", "REQUEST_CHANGES"] = "COMMENT"
    if is_review_strict_enabled() and review.security_count:
        gh_event = "REQUEST_CHANGES"

    try:
        url = await client.post_general_review(
            repo_full_name, pr_number, review.body, event=gh_event
        )
        logger.info(
            "Review posted on %s#%s (event=%s, %d security finding(s)): %s",
            repo_full_name,
            pr_number,
            gh_event,
            review.security_count,
            url or "(no URL returned)",
        )
    except (GitHubError, httpx.HTTPError) as exc:
        _log_github_http_error(exc, f"Posting review on {repo_full_name}#{pr_number}")


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
@app.get("/")
def home() -> dict[str, str]:
    return {"message": "AI Code Review Bot is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}


@app.post("/webhook", summary="GitHub webhook receiver")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
) -> JSONResponse:
    event_type = x_github_event or "unknown"
    body = await request.body()

    # 1) Signature check happens on the raw bytes, before decoding.
    if not verify_github_signature(body, x_hub_signature_256):
        return JSONResponse(
            status_code=403, content={"status": "error", "message": "invalid signature"}
        )

    # 2) Parse.
    payload: Any
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        logger.warning("Webhook body was not valid JSON.")
        raise HTTPException(status_code=400, detail="body is not valid JSON") from None

    # GitHub's very first delivery after webhook creation is a "ping".
    if event_type == "ping":
        logger.info("Ping received from GitHub — webhook connected correctly.")
        return JSONResponse({"status": "ok", "message": "GitHub webhook connected"})

    if event_type != "pull_request":
        logger.debug("Ignoring event %r.", event_type)
        return JSONResponse({"status": "ignored", "event": event_type})

    # 3) Validate the small part of the payload we care about.
    try:
        pr_event = PullRequestEvent.model_validate(payload)
    except ValidationError:
        logger.warning("Ignoring pull_request event with an unexpected payload shape.")
        return JSONResponse({"status": "ignored", "reason": "unexpected payload"})

    # Only actions where *new code* appeared trigger a review. "closed",
    # "labeled", "assigned", … are ignored.
    if pr_event.action not in {"opened", "reopened", "synchronize"}:
        logger.info(
            "Ignoring pull_request action %s for %s#%s.",
            pr_event.action,
            pr_event.repository.full_name,
            pr_event.pull_request.number,
        )
        return JSONResponse({"status": "ignored", "action": pr_event.action})

    # 4) Answer quickly and let the review run in the background, so
    #    GitHub never times out while we are talking to its API.
    background_tasks.add_task(
        review_and_post,
        pr_event.repository.full_name,
        pr_event.pull_request.number,
        pr_event.pull_request.title,
    )

    logger.info(
        "Accepted pull_request event (action=%s) for %s#%s; review queued.",
        pr_event.action,
        pr_event.repository.full_name,
        pr_event.pull_request.number,
    )
    return JSONResponse(
        {
            "status": "accepted",
            "event": event_type,
            "action": pr_event.action,
            "repository": pr_event.repository.full_name,
            "pull_request": pr_event.pull_request.number,
        }
    )
