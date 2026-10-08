from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db
from app.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    db_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return {
        "status": "online",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database": db_status,
        "graph_backend": settings.GRAPH_BACKEND,
        "ai_provider": settings.AI_PROVIDER,
        "model": settings.PRIMARY_MODEL,
        "disclaimer": "CYBERSCOPE is a defensive research and hackathon prototype using synthetic data. Risk scores are investigative signals, not proof of criminal activity."
    }
