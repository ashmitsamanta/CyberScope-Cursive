import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db

logger = logging.getLogger("cyberscope.health")
router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        logger.info("Health check DB status: healthy")
    except Exception as e:
        logger.error(f"Health check DB status: unhealthy ({e})")

    return {"status": "ok"}
