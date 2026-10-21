from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/api/reports", tags=["ITDR Strategic Posture Reports"])


@router.get("/identity-resilience")
def get_identity_resilience(
    client_restriction: str = Query(default="ALL", description="ALL, Client Restricted, Unrestricted"),
    itdr_scope: str = Query(default="ITDR Scope Only", description="ALL, ITDR Scope Only, Non-ITDR"),
    view_mode: str = Query(default="ClientReq", description="ClientReq, MVP1, MVP2, MVP3"),
    db: Session = Depends(get_db),
):
    """
    Screen 1: Identity Resilience Dashboard.
    Provides coverage score ring, ATT&CK tactic exposure bars (covered vs exposed),
    resilience quadrant points, and critical blind spots.
    """
    service = DashboardService(db)
    return service.get_identity_resilience_overview(
        client_restriction=client_restriction,
        itdr_scope=itdr_scope,
        view_mode=view_mode,
    )


@router.get("/threat-exposure")
def get_threat_exposure(
    client_restriction: str = Query(default="ALL"),
    itdr_scope: str = Query(default="ITDR Scope Only"),
    db: Session = Depends(get_db),
):
    """
    Screen 3: Identity Threat Exposure.
    Returns sighted TTP metrics, attack phase groupings, and technique cards.
    """
    service = DashboardService(db)
    return service.get_threat_exposure_report(
        client_restriction=client_restriction,
        itdr_scope=itdr_scope,
    )


@router.get("/threat-scenarios")
def get_threat_scenarios(
    client_restriction: str = Query(default="ALL"),
    itdr_scope: str = Query(default="ITDR Scope Only"),
    db: Session = Depends(get_db),
):
    """
    Screen 4: Identity Threat Scenarios.
    Returns 2D resilience quadrant data (Detection % vs Mitigation %) and scenario list.
    """
    service = DashboardService(db)
    return service.get_threat_scenarios_report(
        client_restriction=client_restriction,
        itdr_scope=itdr_scope,
    )
