from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.coverage_service import CoverageService

router = APIRouter(tags=["Coverage Matrix"])


@router.get("/api/coverage-matrix")
def get_coverage_matrix(
    view_scope: str = Query(default="identity", description="identity or enterprise"),
    status: str = Query(default="all", description="all, covered, uncovered"),
    tools: Optional[List[str]] = Query(default=None, description="Active tool toggles"),
    client_restriction: str = Query(default="ALL"),
    itdr_scope: str = Query(default="ITDR Scope Only"),
    db: Session = Depends(get_db),
):
    """
    Screen 2: ITDR Coverage Matrix.
    Returns coverage KPIs, tool summary metrics, and columnar ATT&CK tactic matrix.
    """
    service = CoverageService(db)
    return service.get_coverage_matrix(
        view_scope=view_scope,
        status_filter=status.lower(),
        active_tools=tools,
        client_restriction=client_restriction,
        itdr_scope=itdr_scope,
    )


@router.get("/api/coverage-matrix/ttp-detail")
def get_ttp_detail(
    technique_id: str = Query(..., description="MITRE Technique ID e.g. T1078"),
    db: Session = Depends(get_db),
):
    """
    Screen 2: Technique Detail Drawer modal.
    Returns technique metadata, protecting rules, tools, and D3FEND defensive countermeasures.
    """
    service = CoverageService(db)
    detail = service.get_ttp_detail(technique_id)
    if "error" in detail:
        raise HTTPException(status_code=404, detail=detail["error"])
    return detail
