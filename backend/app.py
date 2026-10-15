import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.routes.auth import router as auth_router
from backend.routes.courses import router as courses_router
from backend.routes.invites import router as invites_router
from backend.routes.enrollments import router as enrollments_router
from backend.routes.ledger import router as ledger_router
from backend.routes.simulation import router as simulation_router
from backend.database import db

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-seed initial Block #1 on startup so blocks exist for explorer/tamper testing
    try:
        from backend.routes.simulation import auto_seed_enrollment
        if len(db.ledger.chain) == 1:
            auto_seed_enrollment()
    except Exception as e:
        print(f"Startup note: {e}")
    yield

app = FastAPI(
    title="Course Enrollment System & Cryptographic Ledger",
    description="Clean HCI course enrollment portal with an immutable blockchain ledger, untrusted-DB tamper resistance, and attack simulation lab.",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Endpoints
app.include_router(auth_router, prefix="/api")
app.include_router(courses_router, prefix="/api")
app.include_router(invites_router, prefix="/api")
app.include_router(enrollments_router, prefix="/api")
app.include_router(ledger_router, prefix="/api")
app.include_router(simulation_router, prefix="/api")

# Static Assets & Multi-Page Routing
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # Main Portal (Clean UI - Zero crypto clutter)
    @app.get("/")
    async def serve_portal():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    # Security & Vulnerability Attack Lab
    @app.get("/attacks")
    async def serve_attacks():
        return FileResponse(os.path.join(STATIC_DIR, "attacks.html"))

    # Technical Blockchain Explorer
    @app.get("/explorer")
    async def serve_explorer():
        return FileResponse(os.path.join(STATIC_DIR, "explorer.html"))
