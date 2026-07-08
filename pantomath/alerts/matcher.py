"""
Matches a new item against a webhook rule's conditions. A rule can filter
on any combination of keyword, source, and minimum severity — an unset
condition is treated as "any" (matches everything for that dimension).
A rule with every condition unset matches every new item, which is a
legitimate use case ("send me everything").
"""

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def matches_webhook(webhook: dict, item: dict) -> bool:
    keyword_filter = (webhook.get("keyword") or "").strip()
    if keyword_filter:
        keywords = [k.strip().lower() for k in keyword_filter.split(",") if k.strip()]
        haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
        if not any(k in haystack for k in keywords):
            return False

    source_filter = (webhook.get("source_id") or "").strip()
    if source_filter and source_filter != item.get("source_id"):
        return False

    min_severity = (webhook.get("min_severity") or "").strip()
    if min_severity:
        item_rank = SEVERITY_RANK.get(item.get("severity", "low"), 0)
        required_rank = SEVERITY_RANK.get(min_severity, 0)
        if item_rank < required_rank:
            return False

    return True
