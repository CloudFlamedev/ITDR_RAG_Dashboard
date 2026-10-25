import pytest


def test_health_endpoints(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "online"
    assert "documentation" in r.json()

    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

    r = client.get("/api/system/status")
    assert r.status_code == 200
    data = r.json()
    assert "subsystems" in data
    assert data["subsystems"]["database"]["status"] == "Online"


def test_dashboard_endpoints(client):
    r = client.get("/api/reports/identity-resilience")
    assert r.status_code == 200
    res = r.json()
    assert "summary" in res
    assert "tactic_bars" in res
    assert "quadrant_points" in res

    r = client.get("/api/reports/threat-exposure")
    assert r.status_code == 200
    exp = r.json()
    assert "phase_columns" in exp

    r = client.get("/api/reports/threat-scenarios")
    assert r.status_code == 200
    scen = r.json()
    assert "scenarios" in scen


def test_coverage_endpoints(client):
    r = client.get("/api/coverage-matrix?view_scope=identity")
    assert r.status_code == 200
    matrix = r.json()
    assert "columns" in matrix
    assert "tools" in matrix

    r = client.get("/api/coverage-matrix/ttp-detail?technique_id=T1078")
    assert r.status_code == 200
    ttp = r.json()
    assert ttp["technique_id"].startswith("T1078")
    assert "mapped_rules" in ttp


def test_feed_ingest_and_ssrf_protection(client):
    # Prohibited loopback target
    r = client.post("/api/twin/feeds/ingest", json={
        "title": "Malicious SSRF Test",
        "source": "Attacker",
        "content": "Trying to query local loopback",
        "url": "http://127.0.0.1:8080/admin",
        "severity": "High"
    })
    assert r.status_code == 400
    assert "SSRF" in r.json()["detail"]

    # Prohibited scheme
    r = client.post("/api/twin/feeds/ingest", json={
        "title": "File Scheme Test",
        "source": "Attacker",
        "content": "Trying to read etc passwd",
        "url": "file:///etc/passwd",
        "severity": "High"
    })
    assert r.status_code == 400

    # Valid feed ingestion
    r = client.post("/api/twin/feeds/ingest", json={
        "title": "Valid External Advisory on T1078",
        "source": "CISA Advisory",
        "content": "Threat actors utilized compromised credentials (T1078) to pivot laterally.",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-999a",
        "severity": "High"
    })
    assert r.status_code == 200
    assert r.json()["success"] is True
    assert "T1078" in r.json()["extracted_ttps"]


def test_threat_modeling_api(client):
    # Samples
    r = client.get("/api/threats/samples")
    assert r.status_code == 200
    assert len(r.json()) > 0

    # Analyze
    r = client.post("/api/threats/analyze", json={
        "advisory_text": "Observed T1078.004 token abuse and LSASS memory dumping.",
        "sample_id": None,
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 5
    })
    assert r.status_code == 200
    res = r.json()
    assert res["status"] == "COMPLETED"
    assert "report" in res
    assert len(res["citations"]) > 0
    assert len(res["trace_steps"]) > 0

    # Report list and detail
    rep_id = res["report_id"]
    r = client.get("/api/threats/reports")
    assert r.status_code == 200
    assert r.json()["total"] > 0

    r = client.get(f"/api/threats/reports/{rep_id}")
    assert r.status_code == 200
    assert r.json()["report_id"] == rep_id


def test_rag_diagnostic_endpoints(client):
    r = client.get("/api/rag/health")
    assert r.status_code == 200
    assert "storage" in r.json()

    r = client.post("/api/rag/search", json={
        "query": "Kerberos ticket abuse and credential dumping",
        "top_k": 5,
        "include_d3fend": True
    })
    assert r.status_code == 200
    assert "candidates" in r.json()
    assert len(r.json()["candidates"]) > 0
