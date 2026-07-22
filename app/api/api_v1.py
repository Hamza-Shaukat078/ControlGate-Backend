from fastapi import APIRouter
from app.api.routes import (
    auth, dashboard, repositories, scans, graphs, reports, notifications, scan, admin,
    asvs, attestations, export,
)


api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(repositories.router)
api_router.include_router(scans.router)
api_router.include_router(graphs.router)
api_router.include_router(reports.router)
api_router.include_router(notifications.router)
api_router.include_router(scan.router)
api_router.include_router(admin.router)
api_router.include_router(asvs.router)
api_router.include_router(attestations.router)
api_router.include_router(export.router)
