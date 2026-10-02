import asyncio

from fastapi import APIRouter, Request, Header, Depends, HTTPException
from lattice.core.limiter import limiter
import logging



async def _check_token(authorization: str = Header(None)) -> None:
    """Verify the bearer token matches config.master.api_token.

    H2 fix: added token auth to the previously-unprotected LAN routes.
    Returns 401 if no token, 403 if wrong token, 503 if api_token not configured.
    """
    from lattice.core.config import load_config
    try:
        config = load_config()
        expected = config.master.api_token
    except Exception:
        raise HTTPException(status_code=503, detail="API not configured (config unavailable)")
    if not expected:
        raise HTTPException(status_code=503, detail="API not configured (api_token missing)")
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization scheme")
    if not hmac.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="Invalid bearer token")
logger = logging.getLogger(__name__)
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from lattice.core.db import get_async_db_connection
from lattice.core.events import get_active_alerts
from lattice.core.config import get_config_value
from lattice.core.service_status import (
    HEALTHY_SERVICE_STATUS_SQL,
    FAILED_SERVICE_STATUS_SQL,
)
from lattice.ip_change.pool import AddressPoolError, read_address_pool
import hmac
router = APIRouter(prefix="/api", tags=["dashboard"])

templates_dir = Path(__file__).parent.parent.parent / "web" / "templates"
env = Environment(
    loader=FileSystemLoader(str(templates_dir)),
    autoescape=select_autoescape(['html', 'xml']),
    cache_size=400  # T7: 0 disables; 400 = hot templates
)

def render_template(template_name: str, **context):
    template = env.get_template(template_name)
    html = template.render(**context)
    return HTMLResponse(content=html)

@router.get("/dashboard", response_class=HTMLResponse, dependencies=[Depends(_check_token)])
@limiter.limit("120/minute")  # F436: rate limit (htmx polls every 5s = 12/min baseline)
async def dashboard(request: Request):
    # Use one async database connection for the dashboard queries.
    conn = await get_async_db_connection()
    cursor = await conn.cursor()
    await cursor.execute(f"""
        SELECT w.hostname, w.status, w.ip, w.last_heartbeat_at,
               SUM(CASE WHEN s.status IN ({HEALTHY_SERVICE_STATUS_SQL}) THEN 1 ELSE 0 END),
               SUM(CASE WHEN s.status IN ({FAILED_SERVICE_STATUS_SQL}) THEN 1 ELSE 0 END)
        FROM workers w
        LEFT JOIN services s ON s.worker_id = w.id
        WHERE w.removed_at IS NULL
        GROUP BY w.id
        ORDER BY w.hostname COLLATE NOCASE
    """)
    workers = []
    for row in await cursor.fetchall():
        workers.append({
            "hostname": row[0],
            "status": row[1],
            "ip": row[2],
            "last_heartbeat": row[3],
            "services_ok": row[4] or 0,
            "services_fail": row[5] or 0,
        })
    # M14 fix: JOIN events with workers to avoid N+1 (1 query instead of 1+N)
    await cursor.execute("""
        SELECT e.timestamp, e.severity, e.message, e.worker_id, w.hostname
        FROM events e
        LEFT JOIN workers w ON w.id = e.worker_id
        ORDER BY e.timestamp DESC
        LIMIT 20
    """)
    events = []
    for row in await cursor.fetchall():
        events.append({
            "timestamp": row[0],
            "severity": row[1],
            "message": row[2],
            "worker": row[4] or "unknown",
        })
    # A short, plain-language record of Lattice's repair decisions. These are
    # separate from general activity so a person can immediately see whether a
    # repair was tried, verified, or stopped for safety.
    await cursor.execute("""
        SELECT e.timestamp, e.type, e.severity, e.message, w.hostname
        FROM events e
        LEFT JOIN workers w ON w.id = e.worker_id
        WHERE e.type LIKE 'autoheal.%'
        ORDER BY e.timestamp DESC
        LIMIT 8
    """)
    repairs = []
    for row in await cursor.fetchall():
        repairs.append({
            "timestamp": row[0],
            "type": row[1],
            "severity": row[2],
            "message": row[3],
            "worker": row[4] or "Master",
        })
    await conn.close()

    alerts = await asyncio.to_thread(
        get_active_alerts
    )
    needs_attention = [
        alert for alert in alerts
        if alert["severity"] in {"warn", "warning", "error", "critical"}
    ]
    try:
        pool = await asyncio.to_thread(
            read_address_pool
        )
        network_pool_status = "Ready" if pool else "Not set up yet"
    except AddressPoolError:
        # A broken saved pool needs attention, but the dashboard must still load.
        network_pool_status = "Needs attention"

    autoheal_mode = (
        await asyncio.to_thread(
            get_config_value,
            "autoheal.mode",
        )
        or "alert_only"
    )
    autoheal_label = "Alert-only" if autoheal_mode != "automatic" else "Automatic"
    worker_count = len(workers)
    healthy_workers = sum(1 for worker in workers if worker["status"] == "healthy")
    return render_template("partials/dashboard_partial.html",
        request=request,
        workers=workers,
        alerts=alerts,
        needs_attention=needs_attention,
        events=events,
        repairs=repairs,
        network_pool_status=network_pool_status,
        autoheal_label=autoheal_label,
        worker_count=worker_count,
        healthy_workers=healthy_workers,
    )
