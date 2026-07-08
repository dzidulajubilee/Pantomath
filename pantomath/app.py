import pathlib
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from pantomath import __version__
from pantomath.api.routes import broadcast, make_poll_now_route, router
from pantomath.database.sqlite import init_db
from pantomath.feeds.scheduler import Scheduler

ROOT = pathlib.Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"

scheduler = Scheduler(broadcast)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await scheduler.start()
    yield
    scheduler.stop()


app = FastAPI(title="Pantomath", lifespan=lifespan)

app.include_router(router)
make_poll_now_route(scheduler)  # registers /api/sources/{id}/poll on the same router


@app.get("/")
async def dashboard():
    """
    Renders the page shell with a cache-busting query param on every
    CSS/JS reference, derived from the installed package version. Without
    this, a browser that cached pantomath.css or app.js from a previous
    release can keep serving that stale copy indefinitely after an
    upgrade — since the URL never changes, there's nothing to tell it a
    newer version exists. Tying the cache-busting token to the actual
    installed version means every release automatically forces a fresh
    fetch, with no per-release manual step to remember.
    """
    html = (FRONTEND / "pages" / "dashboard.html").read_text()
    html = html.replace("{{CACHEBUST}}", __version__)
    return HTMLResponse(html)


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
