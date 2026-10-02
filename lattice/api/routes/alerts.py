
from fastapi import APIRouter, HTTPException, Header, Depends, Request
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
from lattice.core.db import get_db_connection
from lattice.core.events import acknowledge_alert, get_active_alerts
import hmac
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
router = APIRouter(prefix="/api/alerts", tags=["alerts"])

templates_dir = Path(__file__).parent.parent.parent / "web" / "templates"
env = Environment(
    loader=FileSystemLoader(str(templates_dir)),
    autoescape=select_autoescape(["html", "xml"]),
    cache_size=400,
)


def render_template(template_name: str, **context):
    return HTMLResponse(content=env.get_template(template_name).render(**context))

@router.get("/list", dependencies=[Depends(_check_token)])
async def list_alerts():
    alerts = get_active_alerts()
    return {"alerts": alerts}


@router.get("/partial", response_class=HTMLResponse, dependencies=[Depends(_check_token)])
async def alerts_partial(request: Request):
    """HTML used by the browser dashboard; keep /list as the JSON API."""
    return render_template("partials/alerts_partial.html", request=request, alerts=get_active_alerts())

@router.post("/{alert_id}/ack", dependencies=[Depends(_check_token)])
async def ack_alert(alert_id: int):
    if acknowledge_alert(alert_id):
        return JSONResponse(
            {"status": "ok", "message": f"Alert {alert_id} acknowledged"},
            headers={"HX-Trigger": "dashboardRefresh,alertsRefresh"},
        )
    raise HTTPException(status_code=404, detail="Alert not found or already resolved")
