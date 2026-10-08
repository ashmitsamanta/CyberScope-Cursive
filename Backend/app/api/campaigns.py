from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database import get_db
from app.models.campaign import Campaign
from app.schemas.campaign import CampaignResponse, CampaignDetailResponse
from app.services.campaign_service import CampaignService

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


@router.get("", response_model=List[CampaignResponse])
def list_campaigns(db: Session = Depends(get_db)):
    campaigns = CampaignService.detect_and_sync_campaigns(db)
    return campaigns


@router.get("/{campaign_id_or_code}", response_model=CampaignDetailResponse)
def get_campaign(campaign_id_or_code: str, db: Session = Depends(get_db)):
    detail = CampaignService.get_campaign_detail(db, campaign_id_or_code)
    if not detail:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return detail
