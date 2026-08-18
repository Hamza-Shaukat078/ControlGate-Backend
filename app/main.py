from dotenv import load_dotenv
from pathlib import Path

# Load .env from project root (one level above app/)
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.core.config import settings
from app.api.api_v1 import api_router
from app.db.init_db import init_models
from app.db.mongo_init import ensure_indexes, seed_admin
from app.db.seed_asvs import seed_asvs_controls


app = FastAPI(title=settings.PROJECT_NAME)

# The ASVS catalog, portfolio dashboard and scan summaries are large, highly
# repetitive JSON documents (~280 controls, per-control results, code
# snippets). Gzipping them cuts the transfer by roughly an order of magnitude,
# which is the single biggest win for how fast the dashboard paints on a
# non-local connection. Responses under 1 KB are left uncompressed — below
# that the header overhead costs more than it saves.
app.add_middleware(GZipMiddleware, minimum_size=1000)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[orig.strip() for orig in settings.BACKEND_CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.on_event("startup")
async def on_startup():
    await init_models()
    await ensure_indexes()
    await seed_admin()
    await seed_asvs_controls()


app.include_router(api_router, prefix=settings.API_V1_STR)
