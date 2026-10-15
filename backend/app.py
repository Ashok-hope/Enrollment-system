import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.routes.courses import router as courses_router
from backend.routes.invites import router as invites_router
from backend.routes.enrollments import router as enrollments_router
from backend.routes.ledger import router as ledger_router
from backend.routes.simulation import router as simulation_router
from backend.database import db

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-seed Alice's enrollment on startup so the ledger starts with active Block #1
    try:
        from backend.routes.simulation import auto_seed_enrollment
        if len(db.ledger.chain) == 1: # only genesis exists
            auto_seed_enrollment()
    except Exception as e:
        print(f"Startup seeding notice: {e}")
    yield

app = FastAPI(
    title="Zero-Trust Cryptographic Course Enrollment & Ledger System",
    description="Tamper-evident blockchain ledger with asymmetric digital signatures, Merkle verification, and attack simulation.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for external hosting and client apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers under /api
app.include_router(courses_router, prefix="/api")
app.include_router(invites_router, prefix="/api")
app.include_router(enrollments_router, prefix="/api")
app.include_router(ledger_router, prefix="/api")
app.include_router(simulation_router, prefix="/api")

# Static files directory
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    async def serve_frontend():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))
