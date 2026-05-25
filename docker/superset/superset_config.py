import os

# ── Database ──────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://superset:superset@superset-db:5432/superset"
)
SQLALCHEMY_DATABASE_URI = DATABASE_URL

# ── Secret key ───────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SUPERSET_SECRET_KEY", "changeme-super-secret-key-32chars!!")

# ── Cache (Redis) ────────────────────────────────────────────────────────
CACHE_CONFIG = {
    "CACHE_TYPE":       "RedisCache",
    "CACHE_REDIS_HOST": "redis",
    "CACHE_REDIS_PORT": 6379,
    "CACHE_REDIS_DB":   0,
}

DATA_CACHE_CONFIG = CACHE_CONFIG

# ── Feature flags ────────────────────────────────────────────────────────
FEATURE_FLAGS = {
    "DASHBOARD_NATIVE_FILTERS":       True,
    "DASHBOARD_CROSS_FILTERS":        True,
    "ENABLE_TEMPLATE_PROCESSING":     True,
    "ALERT_REPORTS":                  True,
}

# ── Security ─────────────────────────────────────────────────────────────
WTF_CSRF_ENABLED = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False   # set True if behind HTTPS

# ── Row limit ────────────────────────────────────────────────────────────
ROW_LIMIT = 50000
SUPERSET_WEBSERVER_TIMEOUT = 120
