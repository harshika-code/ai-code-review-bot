"""Local helper for testing the bot WITHOUT touching GitHub.

Safe modes (no GitHub token needed):

    python scripts/dry_run.py
        Builds the review comment for a *fake* PR and prints it.
        Lets you tune the reviewer rules and see the exact Markdown.

    python scripts/dry_run.py --webhook [--bad-signature] [--port 8000]
        Sends a signed ping and a signed pull_request event to a bot
        running on 127.0.0.1:<port>, so you can verify the webhook and
        the signature validation locally.

    Optional flag: --repo owner/name --pr NUMBER
        Used with --webhook to point the fake pull_request event at a
        real PR (useful once your real token is configured).

This script NEVER prints a secret — it only tells you whether one
exists. It never sends your secrets to any third party; the only
network target is your own local server.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)  # make sure .env in the project root is found

from dotenv import load_dotenv  # noqa: E402
import httpx  # noqa: E402

from app import reviewer  # noqa: E402

load_dotenv()

# Windows consoles default to a code page that cannot print emoji.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_REPO = "octocat/hello-world"


# --------------------------------------------------------------------------
# A fake PR that triggers almost every rule in app/reviewer.py
# --------------------------------------------------------------------------
FAKE_FILES = [
    {
        "filename": "app/payments/charge.py",
        "status": "modified",
        "additions": 14,
        "deletions": 2,
        "patch": "\n".join(
            [
                "@@ -1,4 +1,14 @@",
                "+def charge(amount, retries=[]):",
                "+    api_key = \"sk-live-1234567890abcdef\"",
                "-    old_code = 1",
                "+    if amount == None:",
                "+        raise ValueError(f\"invalid amount {amount}\")",
                "+    query = f\"SELECT * FROM users WHERE name = '{amount}'\"",
                "+    try:",
                "+        process(name.endswith(args))",
                "+    except Exception:",
                "+        print(\"charge failed silently\")",
                "+    eval(user_callback_text)  # flexible plugin loading!",
                "+    subprocess.run(cmd, shell=True)",
                "+    digest = hashlib.md5(data).hexdigest()",
                "+    # TODO: remove before shipping",
                "+    return retries",
            ]
        ),
    },
    {
        "filename": "app/payments/__init__.py",
        "status": "added",
        "additions": 1,
        "deletions": 0,
        "patch": "+from .charge import charge\n",
    },
    {
        "filename": "README.md",
        "status": "modified",
        "additions": 6,
        "deletions": 1,
        "patch": "+New payment feature documentation goes here.\n",
    },
]


def run_reviewer_demo() -> None:
    print("=" * 72)
    print("Dry-run: review comment that would be posted (no GitHub call).")
    print("=" * 72)
    review = reviewer.review_pull_request(
        repo_full_name="demo/repo",
        pr_number=42,
        pr_title="Add payment processing",
        files=FAKE_FILES,
    )
    print(review.body)
    print()
    print("-" * 72)
    print(f"security_count used for REQUEST_CHANGES mode: {review.security_count}")
    print()


# --------------------------------------------------------------------------
# Webhook testing against a locally running server
# --------------------------------------------------------------------------
def sign_payload(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def build_pr_event(repository: str, pr_number: int) -> dict[str, object]:
    return {
        "action": "opened",
        "pull_request": {
            "number": pr_number,
            "title": "Local signature test PR",
        },
        "repository": {"full_name": repository},
    }


async def send_event(port: int, event: str, body: bytes, signature: str | None) -> None:
    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": event,
    }
    if signature:
        headers["X-Hub-Signature-256"] = signature
    url = f"http://127.0.0.1:{port}/webhook"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(url, content=body, headers=headers)
    print(f"POST /webhook (event={event}) -> HTTP {response.status_code}")
    print("  Response:", response.text)


async def webhook_mode(args: argparse.Namespace) -> None:
    """Mimic GitHub deliveries against a locally running bot."""
    real_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()

    if args.bad_signature:
        # Deliberately sign with the wrong secret -> the bot should 403.
        signing_secret = "definitely-not-the-real-secret"
        print("[*] Sending requests signed with a WRONG secret (expect HTTP 403).")
    elif real_secret:
        signing_secret = real_secret
        print("[*] Signing requests with GITHUB_WEBHOOK_SECRET from .env (value not printed).")
    else:
        signing_secret = ""
        print("[!] No GITHUB_WEBHOOK_SECRET in .env — sending unsigned requests;")
        print("    the bot will skip validation and log a warning (dev mode).")

    ping_body = json.dumps({"zen": "Keep it simple.", "hook_id": 1}).encode()
    pr_body = json.dumps(build_pr_event(args.repo, args.pr)).encode()

    signature_for = lambda body: (  # noqa: E731  (tiny local helper)
        sign_payload(signing_secret, body) if signing_secret else None
    )

    await send_event(args.port, "ping", ping_body, signature_for(ping_body))
    await send_event(args.port, "pull_request", pr_body, signature_for(pr_body))


def main() -> None:
    parser = argparse.ArgumentParser(description="Local test helper for the AI review bot")
    parser.add_argument("--webhook", action="store_true", help="POST to a local server")
    parser.add_argument("--bad-signature", action="store_true", help="send an invalid signature")
    parser.add_argument("--port", type=int, default=8000, help="local bot port (default 8000)")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="repository full_name for the event")
    parser.add_argument("--pr", type=int, default=1, help="PR number for the event")
    args = parser.parse_args()

    if args.webhook:
        import asyncio

        asyncio.run(webhook_mode(args))
    else:
        run_reviewer_demo()


if __name__ == "__main__":
    main()
