"""Rate limiter shared across the master API.

Defined in a separate module (not in daemon/main.py) to avoid circular
imports: routes import this, and daemon/main.py imports the routes.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

# 120/min default = comfortable for htmx polls (every 5s = 12/min)
# but blocks abuse. Endpoints needing more can use their own decorator.
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])
