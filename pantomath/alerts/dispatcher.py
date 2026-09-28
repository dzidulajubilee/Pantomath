"""
Delivers a webhook payload via a plain HTTP POST. Uses urllib in a thread
executor rather than adding an async HTTP client dependency — same
pattern as pantomath/intelligence/enrichment.py's icon fetching. Fine for
this volume (one POST per matching item per configured webhook, which is
inherently low-frequency).
"""
import asyncio
import json
import ssl
import time
import urllib.error
import urllib.request

from pantomath.alerts.matcher import matches_webhook

TIMEOUT = 8  # seconds — don't let a slow/dead webhook endpoint stall polling

# Reused across calls rather than rebuilt per-request — building an
# unverified context is cheap, but there's no reason not to share it.
_INSECURE_SSL_CONTEXT = ssl._create_unverified_context()


def build_payload(item: dict, webhook: dict) -> dict:
    """
    Generic JSON payload. Includes a top-level "text" summary so
    naively-compatible webhook consumers (Slack, Discord, Mattermost, and
    similar "post a message" style integrations) show something
    reasonable without any configuration — full native formatting for a
    specific service (Slack blocks, Discord embeds, etc.) would need a
    small transform in front of this, which is out of scope here.
    """
    text = f"[{item.get('severity', 'low').upper()}] {item.get('source_name', 'Unknown source')}: {item.get('title', '')}"
    return {
        "text": text,
        "pantomath": {
            "id": item.get("id"),
            "title": item.get("title"),
            "link": item.get("link"),
            "summary": item.get("summary"),
            "severity": item.get("severity"),
            "source_id": item.get("source_id"),
            "source_name": item.get("source_name"),
            "category": item.get("category"),
            "vendors": item.get("vendors", []),
            "actors": item.get("actors", []),
            "cves": item.get("cves", []),
            "matched_webhook": {
                "name": webhook.get("name"),
                "keyword": webhook.get("keyword") or None,
                "min_severity": webhook.get("min_severity") or None,
            },
        },
    }


def send_webhook_sync(url: str, payload: dict, allow_insecure_tls: bool = False) -> tuple[bool, str]:
    """Blocking. Call via loop.run_in_executor(). Returns (success, status_message).

    allow_insecure_tls=True skips certificate verification for https:// URLs
    (self-signed certs, internal CAs) — opt-in per webhook, since it's a
    meaningful security tradeoff (no protection against MITM on that
    connection) that the person should be choosing deliberately, not one
    we default to.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Pantomath/1.0"},
    )
    context = _INSECURE_SSL_CONTEXT if allow_insecure_tls else None
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=context) as resp:
            return True, f"ok ({resp.status})"
    except urllib.error.HTTPError as e:
        return False, f"error: HTTP {e.code}"
    except Exception as e:
        return False, f"error: {str(e)[:150]}"


async def dispatch_webhooks_for_items(db, items: list[dict]):
    """
    Checks every enabled webhook against every newly-stored item and
    fires matching ones. Called from the scheduler right after a poll
    produces new items — see pantomath/feeds/scheduler.py.
    """
    if not items:
        return

    cur = await db.execute("SELECT * FROM webhooks WHERE enabled = 1")
    webhooks = [dict(r) for r in await cur.fetchall()]
    if not webhooks:
        return

    loop = asyncio.get_event_loop()
    for webhook in webhooks:
        matched_items = [item for item in items if matches_webhook(webhook, item)]
        if not matched_items:
            continue

        last_status = "ok"
        for item in matched_items:
            payload = build_payload(item, webhook)
            _ok, status = await loop.run_in_executor(
                None, send_webhook_sync, webhook["url"], payload, bool(webhook.get("allow_insecure_tls"))
            )
            last_status = status

        await db.execute(
            "UPDATE webhooks SET last_triggered = ?, last_status = ? WHERE id = ?",
            (time.time(), last_status, webhook["id"]),
        )
    await db.commit()
