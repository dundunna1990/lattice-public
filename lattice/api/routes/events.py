
from fastapi import APIRouter, Query, Header, Depends, HTTPException, Request
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
import hmac
router = APIRouter(prefix="/api/events", tags=["events"])

@router.get("/list", dependencies=[Depends(_check_token)])
async def list_events(limit: int = Query(50, ge=1, le=200)):
    conn = await get_async_db_connection()
    cursor = await conn.cursor()
    # M14: JOIN events with workers to avoid N+1 queries
    await cursor.execute("""
        SELECT e.timestamp, e.severity, e.message, e.worker_id, w.hostname
        FROM events e
        LEFT JOIN workers w ON w.id = e.worker_id
        ORDER BY e.timestamp DESC
        LIMIT ?
    """, (limit,))
    events = []
    for row in await cursor.fetchall():
        events.append({
            "timestamp": row[0],
            "severity": row[1],
            "message": row[2],
            "worker": row[4] or "unknown",
        })
    await conn.close()
    return {"events": events}
@router.get("/partial", dependencies=[Depends(_check_token)])
async def events_partial(request: Request, limit: int = Query(50, ge=1, le=200)):
    from lattice.web.app import render_template
    payload = await list_events(limit)
    return render_template("partials/events_partial.html", request=request, events=payload["events"])
