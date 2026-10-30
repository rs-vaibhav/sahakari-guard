"""Keyed pseudonymisation.

A token lets analysts join records across feeds ("same account in switch log
and ledger") without ever seeing the account number. Tokens are an HMAC with a
secret that never leaves the bank, so they cannot be reversed by brute force
outside the bank.
"""

from __future__ import annotations

import hashlib
import hmac


class Tokenizer:
    def __init__(self, secret: str | bytes, cache_size: int = 50_000) -> None:
        if not secret:
            raise ValueError("token secret must not be empty")
        self._key = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._cache: dict[tuple[str, str], str] = {}
        self._cache_size = cache_size

    def token(self, value: str, kind: str = "acct") -> str:
        if not value:
            return ""
        cache_key = (kind, value)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        digest = hmac.new(self._key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        result = f"tok_{digest}"
        if len(self._cache) >= self._cache_size:
            self._cache.clear()
        self._cache[cache_key] = result
        return result
