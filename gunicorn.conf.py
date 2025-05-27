# ===== 4. Configuration gunicorn.conf.py =====
import os

bind = f"0.0.0.0:{os.getenv('PORT', 8080)}"
workers = 1
worker_class = "eventlet"
worker_connections = 1000
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 100

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Worker settings
preload_app = True
reload = False