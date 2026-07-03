import pathlib
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.database.sqlite import init_db
from backend.feeds.scheduler import Scheduler
from backend.api.routes import router, broadcast, make_poll_now_route

ROOT = pathlib.Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"

app = FastAPI(title="Pantomath")
scheduler = Scheduler(broadcast)

app.include_router(router)
make_poll_now_route(scheduler)  # registers /api/sources/{id}/poll on the same router


@app.on_event("startup")
async def startup():
    await init_db()
    await scheduler.start()


@app.get("/")
async def dashboard():
    return FileResponse(FRONTEND / "pages" / "dashboard.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
