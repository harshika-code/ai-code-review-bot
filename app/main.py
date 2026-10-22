from fastapi import FastAPI, Header
from pydantic import BaseModel

app = FastAPI()


class PullRequest(BaseModel):
    number: int
    title: str


class Repository(BaseModel):
    full_name: str


class WebhookPayload(BaseModel):
    action: str
    pull_request: PullRequest
    repository: Repository


@app.get("/")
def home():
    return {"message": "AI Code Review Bot is running"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/webhook")
async def github_webhook(
    payload: WebhookPayload,
    x_github_event: str | None = Header(default=None)
):
    event_type = x_github_event or "unknown"

    print("\n--- Webhook received ---")
    print("Event type:", event_type)
    print("Action:", payload.action)
    print("Repository:", payload.repository.full_name)
    print("PR title:", payload.pull_request.title)
    print("PR number:", payload.pull_request.number)

    return {
        "status": "received",
        "event_type": event_type,
        "action": payload.action
    }