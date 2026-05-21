import logging
import time

import requests

log = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0


def resilient_get(url: str, **kwargs) -> requests.Response:
    """requests.get with automatic backoff retry on HTTP 429 Rate Limit."""
    for attempt in range(_MAX_RETRIES):
        r = requests.get(url, **kwargs)
        if r.status_code != 429:
            return r
        retry_after = r.headers.get("Retry-After", "")
        wait = float(retry_after) if retry_after.isdigit() else _BACKOFF_BASE * (2 ** attempt)
        log.debug("429 at %s — waiting %.1fs (attempt %d/%d)", url, wait, attempt + 1, _MAX_RETRIES)
        time.sleep(wait)
    return requests.get(url, **kwargs)
