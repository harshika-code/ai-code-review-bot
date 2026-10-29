"""Central place for reading configuration.

Values come from a ``.env`` file in the project root (loaded once with
python-dotenv) or from real environment variables, which always win.

Secrets are never printed: the helpers below only report whether a
value exists, so logs stay safe to share and commit.
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Read .env once at import time. Variables already present in the real
# environment are NOT overwritten by .env values.
load_dotenv()


def get_github_token() -> str:
    """Return the GitHub personal access token, or "" if not configured."""
    return os.getenv("GITHUB_TOKEN", "").strip()


def get_github_webhook_secret() -> str:
    """Return the shared webhook secret, or "" if not configured."""
    return os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()


def is_review_strict_enabled() -> bool:
    """When enabled, reviews that find security problems request changes.

    Off by default so the bot never blocks merging.
    """
    return os.getenv("REVIEW_STRICT", "").strip().lower() in {"1", "true", "yes", "on"}


def log_config_status() -> None:
    """Log which configuration values are present (never their contents)."""
    logger.info(
        "Config check: GITHUB_TOKEN %s | GITHUB_WEBHOOK_SECRET %s | REVIEW_STRICT %s",
        "set" if get_github_token() else "NOT set",
        "set" if get_github_webhook_secret() else "NOT set",
        "on" if is_review_strict_enabled() else "off",
    )
