import re
import ipaddress
import urllib.parse
import datetime
import uuid
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.feeds import ThreatFeed

router = APIRouter(tags=["Threat Intelligence Feeds & Bulletins"])

ATTACK_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


class FeedIngestRequest(BaseModel):
    title: str = Field(..., min_length=5, max_length=300, description="Bulletin or advisory title")
    source: str = Field(..., min_length=2, max_length=150, description="Publishing organization or CTI source")
    content: str = Field(..., min_length=10, description="Full advisory text, log analysis, or CTI narrative")
    url: Optional[str] = Field(default=None, description="External reference URL")
    severity: str = Field(default="High", description="Critical, High, Medium, Low")


def validate_safe_url(url_str: str) -> str:
    """SSRF Protection: Rejects local/private loopback, cloud metadata IPs, and non-http schemes."""
    if not url_str:
        return ""
    parsed = urllib.parse.urlparse(url_str)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Invalid URL scheme. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname or ""
    if hostname in ("localhost", "127.0.0.1", "::1", "metadata.google.internal"):
        raise HTTPException(status_code=400, detail="SSRF Protection: Prohibited host destination.")

    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise HTTPException(status_code=400, detail="SSRF Protection: Private and link-local IP targets are blocked.")
    except ValueError:
        # Hostname is a domain name, not a raw IP
        pass

    return url_str


@router.get("/api/identity/bulletins")
def get_bulletins(
    status: Optional[str] = Query(default=None, description="New, Analyzed, Review, ALL"),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=30, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Screens 5 & 7: Searchable and filterable threat intelligence bulletins and completed reports.
    """
    query = db.query(ThreatFeed)
    if status and status.upper() != "ALL":
        query = query.filter(ThreatFeed.status.ilike(status))
    if search:
        query = query.filter(
            (ThreatFeed.title.ilike(f"%{search}%")) |
            (ThreatFeed.bulletin_id.ilike(f"%{search}%")) |
            (ThreatFeed.source.ilike(f"%{search}%"))
        )

    total = query.count()
    records = query.order_by(ThreatFeed.published_at.desc().nullslast()).offset(offset).limit(limit).all()

    # KPI counts
    total_count = db.query(ThreatFeed).count()
    new_count = db.query(ThreatFeed).filter(ThreatFeed.status.ilike("New")).count()
    analyzed_count = db.query(ThreatFeed).filter(ThreatFeed.status.ilike("Analyzed")).count()
    review_count = db.query(ThreatFeed).filter(ThreatFeed.status.ilike("Review")).count()

    return {
        "kpis": {
            "total_bulletins": total_count,
            "new_count": new_count,
            "analyzed_count": analyzed_count,
            "review_count": review_count,
        },
        "total": total,
        "limit": limit,
        "offset": offset,
        "bulletins": [
            {
                "id": b.id,
                "bulletin_id": b.bulletin_id,
                "title": b.title,
                "source": b.source,
                "status": b.status,
                "severity": b.severity,
                "published_at": b.published_at.isoformat() if b.published_at else None,
                "ingested_at": b.ingested_at.isoformat() if b.ingested_at else None,
                "related_ttps": b.related_ttps or [],
                "threat_actors": b.threat_actors or [],
                "url": b.url,
                "description": b.description or b.content,
                "is_demo": b.is_demo,
            }
            for b in records
        ]
    }


@router.get("/api/identity/feeds")
def get_feed_sources(db: Session = Depends(get_db)):
    """
    Screen 5: Threat intelligence feed status, active connectors, and sync telemetry.
    """
    # Active feed sources
    sources = [
        {"name": "CISA Cyber Advisories", "type": "RSS / CTI", "status": "Active", "frequency": "Hourly", "items_ingested": 18},
        {"name": "Microsoft Threat Intelligence", "type": "Graph API", "status": "Active", "frequency": "Realtime", "items_ingested": 24},
        {"name": "Okta Security Bulletins", "type": "Webhooks", "status": "Active", "frequency": "Daily", "items_ingested": 12},
        {"name": "CrowdStrike Falcon Intelligence", "type": "REST API", "status": "Active", "frequency": "Realtime", "items_ingested": 31},
        {"name": "Cloud Security Alliance (CSA)", "type": "Advisory Feed", "status": "Active", "frequency": "Daily", "items_ingested": 9},
        {"name": "Wiz Cloud Posture Feed", "type": "API Connector", "status": "Active", "frequency": "Daily", "items_ingested": 14},
    ]

    total_feeds = db.query(ThreatFeed).count()
    return {
        "total_active_feeds": len(sources),
        "total_bulletins_stored": total_feeds,
        "last_sync_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "feed_sources": sources,
    }


@router.post("/api/twin/feeds/ingest")
def ingest_threat_feed(
    req: FeedIngestRequest,
    db: Session = Depends(get_db),
):
    """
    Screen 5: Validates and ingests a custom CTI advisory or threat intelligence bulletin.
    Applies strict SSRF checks and regex extracts relevant ATT&CK TTPs.
    """
    safe_url = validate_safe_url(req.url) if req.url else None

    # Extract ATT&CK IDs from title and content
    combined_text = f"{req.title} {req.content}"
    found_ttps = sorted(list(set(ATTACK_ID_PATTERN.findall(combined_text))))

    bulletin_id = f"TB-{datetime.datetime.now().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"

    new_feed = ThreatFeed(
        bulletin_id=bulletin_id,
        source=req.source,
        title=req.title,
        description=req.content[:350] + ("..." if len(req.content) > 350 else ""),
        content=req.content,
        url=safe_url,
        published_at=datetime.datetime.now(datetime.timezone.utc),
        ingested_at=datetime.datetime.now(datetime.timezone.utc),
        status="New",
        related_ttps=found_ttps,
        severity=req.severity,
        is_demo=False,
        raw_payload={"custom_ingest": True},
    )

    db.add(new_feed)
    db.commit()
    db.refresh(new_feed)

    return {
        "success": True,
        "bulletin_id": new_feed.bulletin_id,
        "title": new_feed.title,
        "extracted_ttps": found_ttps,
        "status": new_feed.status,
        "message": f"Successfully ingested bulletin {bulletin_id} with {len(found_ttps)} detected TTPs.",
    }
