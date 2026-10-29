"""Small async wrapper around the parts of the GitHub REST API we need.

Every request is authenticated with the personal access token loaded
from ``.env`` (see ``app/config.py``) and made with ``httpx.AsyncClient``.

Security notes:
- the Authorization header is never logged,
- API error bodies are truncated before logging.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

GITHUB_API_BASE = "https://api.github.com"
# A page holds up to 30 files; cap pagination so huge PRs can't loop us.
MAX_FILE_PAGES = 3

logger = logging.getLogger(__name__)


class GitHubError(RuntimeError):
    """Raised when GitHub answers in a way we handle explicitly."""


class GitHubClient:
    """Authenticated client for the few GitHub endpoints the bot uses."""

    def __init__(self, token: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=GITHUB_API_BASE,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                # GitHub rejects API calls without a User-Agent.
                "User-Agent": "ai-code-review-bot",
            },
            timeout=httpx.Timeout(30.0),
        )

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Changed files of a pull request
    # ------------------------------------------------------------------
    async def get_pull_request_files(
        self, repo_full_name: str, pr_number: int
    ) -> list[dict[str, Any]]:
        """Return the changed files of a PR, following pagination."""
        url: str | None = f"/repos/{repo_full_name}/pulls/{pr_number}/files"
        files: list[dict[str, Any]] = []

        for _ in range(MAX_FILE_PAGES):
            response = await self._client.get(url or "")
            if response.status_code == 404:
                raise GitHubError(
                    f"PR #{pr_number} not found in {repo_full_name} (or the token cannot see it)."
                )
            response.raise_for_status()
            files.extend(response.json())
            url = response.links.get("next", {}).get("url")
            if not url:
                return files

        logger.warning(
            "%s PR #%s has more than %d changed files; reviewing only the first %d.",
            repo_full_name,
            pr_number,
            MAX_FILE_PAGES * 30,
            len(files),
        )
        return files

    # ------------------------------------------------------------------
    # Existing reviews (used to avoid duplicate comments)
    # ------------------------------------------------------------------
    async def get_existing_review_bodies(
        self, repo_full_name: str, pr_number: int
    ) -> list[str]:
        """Return the bodies of reviews already posted on a PR."""
        response = await self._client.get(f"/repos/{repo_full_name}/pulls/{pr_number}/reviews")
        if response.status_code == 404:
            raise GitHubError(
                f"PR #{pr_number} not found in {repo_full_name} (or the token cannot see it)."
            )
        response.raise_for_status()
        return [review.get("body", "") for review in response.json()]

    # ------------------------------------------------------------------
    # Posting the review comment
    # ------------------------------------------------------------------
    async def post_general_review(
        self,
        repo_full_name: str,
        pr_number: int,
        body: str,
        event: str = "COMMENT",
    ) -> str:
        """Submit one pull-request review with a Markdown ``body``.

        ``event`` must be one of COMMENT, REQUEST_CHANGES or APPROVE
        (a plain submission without an event stays "pending" and is not
        visible on the PR).
        """
        response = await self._client.post(
            f"/repos/{repo_full_name}/pulls/{pr_number}/reviews",
            json={"body": body, "event": event},
        )

        if response.status_code == 422:
            try:
                detail = response.json().get("message", "invalid review")
            except Exception:  # pragma: no cover - defensive only
                detail = response.text[:120]
            raise GitHubError(
                f"GitHub refused the review for {repo_full_name} PR #{pr_number}: {detail}"
            )

        response.raise_for_status()
        html_url = response.json().get("html_url", "")
        return html_url
