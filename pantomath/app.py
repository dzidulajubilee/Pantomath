import pathlib
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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
    return FileResponse(FRONTEND / "pages" / "dashboard.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
