from fastapi import FastAPI, Request
import logging

logger = logging.getLogger(__name__)
from fastapi.responses import HTMLResponse, FileResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
app = FastAPI(title="Lattice Web UI")

templates_dir = Path(__file__).parent / "templates"
env = Environment(
    loader=FileSystemLoader(str(templates_dir)),
    autoescape=select_autoescape(['html', 'xml']),
    cache_size=400  # T7: 0 disables; 400 = hot templates
)
assets_dir = Path(__file__).parent / "assets"

def render_template(template_name: str, **context):
    template = env.get_template(template_name)
    html = template.render(**context)
    return HTMLResponse(content=html)

@app.get("/test")
async def test(request: Request):
    return {"status": "web UI is mounted"}


@app.get("/assets/{asset_name}", include_in_schema=False)
async def asset(asset_name: str):
    if asset_name not in {"lattice.css", "lattice.js"}:
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    return FileResponse(assets_dir / asset_name)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return render_template("dashboard.html", request=request)

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    return render_template("alerts.html", request=request)

@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    return render_template("events.html", request=request)

@app.get("/worker/{hostname}", response_class=HTMLResponse)
async def worker_page(request: Request, hostname: str):
    return render_template("worker_detail.html", request=request, worker={"hostname": hostname})
