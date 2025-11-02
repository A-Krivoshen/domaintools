import time
from threading import RLock

class TTLCache:
    """A very small in-memory TTL cache. Thread-safe for simple use-cases."""
    def __init__(self):
        self._store = {}
        self._lock = RLock()

    def get(self, key):
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            value, expires_at = item
            if expires_at is not None and expires_at < time.time():
                # expired
                del self._store[key]
                return None
            return value

    def set(self, key, value, ttl_seconds=None):
        with self._lock:
            expires_at = None if ttl_seconds is None else time.time() + ttl_seconds
            self._store[key] = (value, expires_at)

    def clear(self):
        with self._lock:
            self._store.clear()
