import logging
import os
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.api.health import router as health_router
from app.api.cases import router as cases_router
from app.api.entities import router as entities_router
from app.api.graph import router as graph_router
from app.api.transactions import router as transactions_router
from app.api.campaigns import router as campaigns_router
from app.api.investigations import router as investigations_router
from app.api.search import router as search_router
from app.api.stats import router as stats_router
from app.api.chat import router as chat_router
from app.api.auth import router as auth_router
from app.api.threat_map import router as threat_map_router
from app.models.case import Case
from app.models.user import User
from app.services.auth_service import hash_password, get_current_user
from app.services.graph_service import graph_service
from app.services.threat_map_service import ThreatMapService
from scripts.seed_demo import seed_database

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cyberscope")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing CYBERSCOPE database connection...")
    max_retries = 10
    connected = False
    for attempt in range(1, max_retries + 1):
        try:
            Base.metadata.create_all(bind=engine)
            connected = True
            logger.info("CYBERSCOPE database tables initialized.")
            break
        except Exception as e:
            logger.warning(f"Database not ready yet (attempt {attempt}/{max_retries}): {e}. Retrying in 2s...")
            time.sleep(2)

    if not connected:
        logger.error("Failed to initialize database tables after multiple retries.")

    # Check if database is empty and auto-seed demo data if needed
    try:
        db = SessionLocal()
        case_count = db.query(Case).count()
        if case_count == 0:
            logger.info("Database contains 0 cases. Auto-seeding demo data...")
            seed_database(db_session=db, drop_existing=False)
            logger.info("Auto-seeding complete.")
        else:
            logger.info(f"Database contains {case_count} cases. Synchronizing Fraud Graph...")
            graph_service.sync_from_db(db)
            logger.info("Fraud Graph synchronized successfully.")

        # Seed demo user ONLY in development if DEMO_USER_PASSWORD env var is explicitly provided
        demo_user_password = os.environ.get("DEMO_USER_PASSWORD")
        if settings.APP_ENV == "development" and demo_user_password:
            demo_user = db.query(User).filter(User.email == "investigator@cyberscope.io").first()
            if not demo_user:
                demo_user = User(
                    email="investigator@cyberscope.io",
                    password_hash=hash_password(demo_user_password),
                    name="Investigator Demo",
                    phone="+919876543210",
                    role="Investigator",
                    organization="TetraByte Cyber Defense",
                    is_verified_email=True,
                    is_verified_phone=True,
                    is_active=True
                )
                db.add(demo_user)
                db.commit()
                logger.info("Demo investigator user seeded.")

        # Ensure Threat Intelligence Map nodes are seeded
        ThreatMapService.ensure_seeded(db)
        logger.info("Threat Intelligence Map nodes verified and synchronized.")
        db.close()
    except Exception as e:
        logger.warning(f"Startup database check/seed error: {e}")

    yield
    logger.info("CYBERSCOPE backend shutting down.")


is_prod = settings.APP_ENV.lower() == "production"

app = FastAPI(
    title=settings.APP_NAME,
    description="Explainable Cyber-Fraud Intelligence & Investigation Platform",
    version="1.0.0",
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred while processing the investigation query.",
            "path": request.url.path
        }
    )


# Public routers
app.include_router(health_router, prefix="/api")
app.include_router(auth_router, prefix="/api")

# Data routers protected with mandatory authentication dependency
protected_dep = [Depends(get_current_user)]

app.include_router(stats_router, prefix="/api", dependencies=protected_dep)
app.include_router(cases_router, prefix="/api", dependencies=protected_dep)
app.include_router(entities_router, prefix="/api", dependencies=protected_dep)
app.include_router(graph_router, prefix="/api", dependencies=protected_dep)
app.include_router(transactions_router, prefix="/api", dependencies=protected_dep)
app.include_router(campaigns_router, prefix="/api", dependencies=protected_dep)
app.include_router(investigations_router, prefix="/api", dependencies=protected_dep)
app.include_router(search_router, prefix="/api", dependencies=protected_dep)
app.include_router(chat_router, prefix="/api", dependencies=protected_dep)
app.include_router(threat_map_router, prefix="/api", dependencies=protected_dep)


@app.get("/")
def root():
    return {
        "platform": "CYBERSCOPE",
        "description": "Explainable Cyber-Fraud Intelligence & Investigation Platform",
        "health_url": "/api/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
