
import asyncio

from fastapi import APIRouter, HTTPException, Header, Depends, Response, Request
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
from lattice.core.db import get_async_db_connection
from lattice.core.events import log_event
import hmac
router = APIRouter(prefix="/api/workers", tags=["workers"])

@router.get("/{hostname}/detail", dependencies=[Depends(_check_token)])
async def worker_detail(hostname: str):
    conn = await get_async_db_connection()
    cursor = await conn.cursor()
    await cursor.execute(
        "SELECT id, hostname, status, ip, last_heartbeat_at "
        "FROM workers "
        "WHERE hostname = ? AND removed_at IS NULL",
        (hostname,),
    )
    row = await cursor.fetchone()

    if not row:
        await conn.close()
        raise HTTPException(
            status_code=404,
            detail="Worker not found",
        )

    worker_id = row[0]

    await cursor.execute(
        """
        SELECT name, status, type
        FROM services
        WHERE worker_id = ?
        """,
        (worker_id,),
    )
    services = [
        {
            "name": service[0],
            "status": service[1],
            "type": service[2],
            "auto_heal": False,
        }
        for service in await cursor.fetchall()
    ]

    await cursor.execute(
        """
        SELECT timestamp, severity, message
        FROM events
        WHERE worker_id = ?
        ORDER BY timestamp DESC
        LIMIT 20
        """,
        (worker_id,),
    )
    events = [
        {
            "timestamp": event[0],
            "severity": event[1],
            "message": event[2],
        }
        for event in await cursor.fetchall()
    ]

    await conn.close()
    return {
        "hostname": row[1],
        "status": row[2],
        "ip": row[3],
        "last_heartbeat": row[4],
        "uptime": "unknown",
        "services": services,
        "events": events
    }

@router.get("/{hostname}/partial", dependencies=[Depends(_check_token)])
async def worker_detail_partial(request: Request, hostname: str):
    from lattice.web.app import render_template
    worker = await worker_detail(hostname)
    return render_template("partials/worker_detail_partial.html", request=request, worker=worker)


@router.post("/{hostname}/recheck", dependencies=[Depends(_check_token)])
async def recheck_worker(hostname: str):
    # This deliberately does not restart a service or change a machine. It
    # records the request so the normal health monitor picks it up safely.
    conn = await get_async_db_connection()
    try:
        cursor = await conn.execute(
            """
            SELECT id
            FROM workers
            WHERE hostname = ?
              AND removed_at IS NULL
            """,
            (hostname,),
        )
        row = await cursor.fetchone()
    finally:
        await conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Worker not found")
    from lattice.core.config import set_config_value

    await asyncio.to_thread(
        set_config_value,
        f"health.recheck.{row[0]}",
        "true",
    )
    await asyncio.to_thread(
        log_event,
        row[0],
        "recheck_triggered",
        "info",
        f"Manual recheck requested for {hostname}",
    )
    return Response(status_code=204, headers={"HX-Trigger": "dashboardRefresh"})
