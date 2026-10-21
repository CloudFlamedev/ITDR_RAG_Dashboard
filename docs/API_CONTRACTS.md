# ITDR Platform API Contracts

## Overview
This document specifies the complete REST API interface for the ITDR Platform backend. All endpoints adhere to standard HTTP semantics, use JSON payloads, and return uniform error structures.

All endpoints specified in the **ITDR Functional Specification Document v2.0** are implemented verbatim.

---

## Global Filter Parameters
The following query parameters are accepted across reporting and coverage endpoints:

| Parameter | Type | Allowed Values | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `view_mode` | string | `ClientReq`, `MVP1`, `MVP2`, `MVP3` | `ClientReq` | Filters active rule visibility and maturity scope. |
| `client_restriction` | string | `ALL`, `Client Restricted`, `Unrestricted` | `ALL` | Filters detection rules and techniques based on tenant authorization. |
| `itdr_scope` | string | `ALL`, `ITDR Scope Only`, `Non-ITDR` | `ITDR Scope Only` | Restricts technique calculations to identity-relevant TTPs. |

---

## System Health & Diagnostics

### 1. Liveness Check
- **Path**: `GET /health`
- **Description**: Lightweight orchestrator probe verifying API process responsiveness.
- **Response**: `200 OK`
```json
{
  "status": "healthy",
  "service": "itdr-platform-api",
  "version": "2.0.0",
  "timestamp": "2026-10-22T00:00:00.000Z"
}
```

### 2. Multi-Subsystem Health & Telemetry
- **Path**: `GET /api/system/status`
- **Description**: Deep diagnostic check verifying PostgreSQL connectivity, Neon pgvector extension status, xAI Grok API key readiness, Hugging Face token readiness, and indexed knowledge-base volumes.
- **Response**: `200 OK`
```json
{
  "timestamp": "2026-10-22T00:00:00.000Z",
  "environment": "development",
  "demo_mode": true,
  "subsystems": {
    "database": {
      "status": "Online",
      "is_neon": false,
      "latency_ms": 1.45,
      "version": "PostgreSQL 16.10 ...",
      "error": null
    },
    "pgvector": {
      "status": "Fallback / Not Detected",
      "enabled": false,
      "embedding_dimensions": 384,
      "note": "Using resilient array fallback; enable extension in Neon via CREATE EXTENSION vector"
    },
    "xai_grok": {
      "status": "Online",
      "model": "grok-4.7",
      "base_url": "https://api.x.ai/v1",
      "configured": true
    },
    "huggingface": {
      "status": "Online",
      "model": "BAAI/bge-small-en-v1.5",
      "dimensions": 384,
      "configured": true
    },
    "knowledge_base": {
      "techniques_count": 867,
      "tactics_count": 15,
      "d3fend_count": 497,
      "rules_count": 25,
      "rag_indexed_chunks": 1679,
      "last_sync": "2026-10-22T00:15:00.000Z"
    }
  }
}
```

---

## Screen 1: Identity Resilience Dashboard

### 3. Identity Resilience Overview
- **Path**: `GET /api/reports/identity-resilience`
- **Query Parameters**:
  - `client_restriction` (optional, default: `ALL`)
  - `itdr_scope` (optional, default: `ITDR Scope Only`)
  - `view_mode` (optional, default: `ClientReq`)
- **Response**: `200 OK`
```json
{
  "summary": {
    "overall_coverage_pct": 58.4,
    "total_in_scope_techniques": 125,
    "covered_techniques": 73,
    "exposed_techniques": 52,
    "active_rules_count": 25,
    "is_demo_data": true
  },
  "tactic_exposure": [
    {
      "tactic_id": "TA0006",
      "tactic_name": "Credential Access",
      "covered": 18,
      "exposed": 7,
      "total": 25,
      "coverage_pct": 72.0
    },
    {
      "tactic_id": "TA0004",
      "tactic_name": "Privilege Escalation",
      "covered": 14,
      "exposed": 10,
      "total": 24,
      "coverage_pct": 58.3
    }
  ],
  "resilience_quadrant": [
    {
      "id": "SCEN-001",
      "name": "Cloud Credential Theft via Stolen Session Token",
      "impact": 8.5,
      "likelihood": 7.0,
      "resilience": 75.0,
      "status": "Resilient"
    }
  ],
  "critical_blind_spots": [
    {
      "technique_id": "T1621",
      "technique_name": "Multi-Factor Authentication Request Generation (MFA Fatigue)",
      "tactic": "Credential Access",
      "detection_difficulty": "High",
      "external_url": "https://attack.mitre.org/techniques/T1621/"
    }
  ]
}
```

---

## Screen 2: ITDR Coverage Matrix

### 4. Coverage Matrix Summary & Techniques
- **Path**: `GET /api/coverage-matrix`
- **Query Parameters**:
  - `view_scope`: `identity` (default) or `enterprise`
  - `status`: `all` (default), `covered`, `uncovered`
  - `tools`: Multi-value filter, e.g. `?tools=CrowdStrike&tools=Okta`
  - `client_restriction`, `itdr_scope`, `view_mode`
- **Response**: `200 OK`
```json
{
  "kpis": {
    "total_in_scope": 125,
    "covered_count": 73,
    "coverage_rate_pct": 58.4,
    "active_rules_count": 25,
    "gaps_count": 52
  },
  "active_tools": ["CrowdStrike", "Defender for Identity", "Okta", "Wiz", "In-House", "Third-Party"],
  "tactics": [
    {
      "id": "TA0006",
      "name": "Credential Access",
      "techniques": [
        {
          "id": "T1078.004",
          "name": "Valid Accounts: Cloud Accounts",
          "is_covered": true,
          "is_identity_relevant": true,
          "mapped_rules_count": 3,
          "tools": ["Okta", "Defender for Identity", "Wiz"]
        },
        {
          "id": "T1110.003",
          "name": "Brute Force: Password Spraying",
          "is_covered": false,
          "is_identity_relevant": true,
          "mapped_rules_count": 0,
          "tools": []
        }
      ]
    }
  ]
}
```

### 5. Technique & Rule Detail Drawer
- **Path**: `GET /api/coverage-matrix/ttp-detail?technique_id={id}`
- **Query Parameters**:
  - `technique_id` (required, string): e.g. `T1078.004`
- **Response**: `200 OK`
```json
{
  "technique": {
    "id": "T1078.004",
    "name": "Valid Accounts: Cloud Accounts",
    "description": "Adversaries may obtain and abuse credentials of cloud accounts...",
    "is_identity_relevant": true,
    "identity_domain": "Cloud IAM",
    "detection_difficulty": "Moderate",
    "external_url": "https://attack.mitre.org/techniques/T1078/004/",
    "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]
  },
  "coverage_status": "Covered",
  "mapped_rules": [
    {
      "rule_id": "c1f7a08e-5b12-4c6e-8219-4a9235e12810",
      "rule_name": "Okta Anomaly: Impossible Travel & MFA Bypass",
      "tool_source": "Okta",
      "rule_type": "Identity",
      "severity": "Critical",
      "coverage_depth": "Full",
      "confidence_score": 0.95,
      "query_logic": "eventType eq 'user.session.start' and debugContext.debugData.riskScore gt 80"
    }
  ],
  "d3fend_countermeasures": [
    {
      "id": "D3-MFA",
      "name": "Multi-factor Authentication",
      "tactic": "Credential Hardening",
      "relationship": "counters"
    }
  ]
}
```

---

## Screen 3: Threat Exposure & Screen 4: Scenarios

### 6. Threat Exposure Report
- **Path**: `GET /api/reports/threat-exposure`
- **Query Parameters**: `client_restriction`, `itdr_scope`, `view_mode`
- **Response**: `200 OK`
```json
{
  "kpis": {
    "total_sighted_ttps": 42,
    "sighted_with_coverage": 26,
    "sighted_uncovered": 16,
    "coverage_ratio_pct": 61.9
  },
  "attack_phases": [
    {
      "phase_name": "Credential Access & Theft",
      "total_ttps": 15,
      "covered_ttps": 10,
      "uncovered_ttps": 5,
      "techniques": [
        {
          "id": "T1003.001",
          "name": "OS Credential Dumping: LSASS Memory",
          "is_covered": true,
          "tools": ["CrowdStrike", "Defender for Identity"]
        }
      ]
    }
  ]
}
```

### 7. Threat Scenarios Report
- **Path**: `GET /api/reports/threat-scenarios`
- **Query Parameters**: `client_restriction`, `itdr_scope`, `view_mode`
- **Response**: `200 OK`
```json
{
  "scenarios": [
    {
      "id": "SCEN-001",
      "title": "Cloud Credential Theft via Stolen Session Token",
      "threat_actor": "Scattered Spider / UNC3944",
      "impact_score": 8.5,
      "likelihood_score": 7.0,
      "resilience_score": 75.0,
      "status": "Resilient",
      "involved_ttps": ["T1078.004", "T1556", "T1539"],
      "covered_ttps": 2,
      "uncovered_ttps": 1
    }
  ]
}
```

---

## Screen 5: Threat Intelligence Feeds

### 8. List Intelligence Bulletins
- **Path**: `GET /api/identity/bulletins`
- **Query Parameters**:
  - `status`: `New`, `Analyzed`, `Review`, `ALL` (optional)
  - `search`: Filter string against title and content (optional)
  - `limit`: Integer (1-100, default: 30)
  - `offset`: Integer (default: 0)
- **Response**: `200 OK`
```json
{
  "total": 7,
  "bulletins": [
    {
      "id": "e4b52b21-4475-47eb-ba05-7f1396a84c8a",
      "bulletin_id": "CTI-2026-001",
      "title": "CISA Advisory AA26-001A: Scattered Spider Cloud Identity Takeover",
      "source": "CISA Cybersecurity Advisory",
      "severity": "Critical",
      "status": "New",
      "external_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-001a",
      "created_at": "2026-10-22T00:00:00.000Z",
      "indicators": {
        "ttps": ["T1078.004", "T1621", "T1098.005"]
      }
    }
  ]
}
```

### 9. Synchronize Feeds
- **Path**: `POST /api/identity/feeds/sync`
- **Response**: `200 OK`
```json
{
  "status": "success",
  "message": "Feeds synchronized successfully",
  "synced_count": 7,
  "timestamp": "2026-10-22T00:00:00.000Z"
}
```

### 10. SSRF-Safe Feed Ingestion
- **Path**: `POST /api/twin/feeds/ingest`
- **Security**: Validates URL against SSRF attack vectors. Blocks `localhost`, `127.0.0.1`, RFC1918 private IPv4 subnets, link-local addresses, and cloud instance metadata addresses (`169.254.169.254`, `metadata.google.internal`).
- **Request Body**:
```json
{
  "title": "Adversary Campaign Targeting Azure AD Device Registration",
  "source": "Microsoft Security Threat Intelligence",
  "content": "Adversaries were observed executing T1098.005 to manipulate cloud device registration and bypass device-based conditional access policies.",
  "url": "https://www.microsoft.com/security/blog/2026/01/azure-ad-defense",
  "severity": "High"
}
```
- **Response**: `201 Created`
```json
{
  "id": "8f830a38-c649-41e9-a4b5-6809ec012891",
  "bulletin_id": "CTI-2026-008",
  "title": "Adversary Campaign Targeting Azure AD Device Registration",
  "status": "New",
  "extracted_ttps": ["T1098.005"],
  "rag_document_created": true
}
```
- **Error Responses**:
  - `400 Bad Request`: `{"detail": "SSRF Protection: Private and link-local IP targets are blocked."}`

---

## Screen 6: Threat Modeling Workspace

### 11. Curated Sample Threat Inputs
- **Path**: `GET /api/threats/samples`
- **Description**: Returns 4 pre-configured real-world identity attack advisories for 1-click loading in the Threat Modeling Workspace.
- **Response**: `200 OK`
```json
[
  {
    "id": "sample-01",
    "title": "Adversaries abused T1078.004 Cloud Token to Bypass MFA and Dump LSASS",
    "source": "CISA Advisory AA26-001A",
    "text": "A security analyst observed suspicious PowerShell execution originating from an Azure VM jump-box...",
    "related_ttps": ["T1078.004", "T1003.001", "T1003.006"]
  }
]
```

### 12. Run Stateful GenAI Threat Modeling Analysis
- **Path**: `POST /api/threats/analyze`
- **Description**: Triggers the 11-node LangGraph threat analysis workflow. Performs hybrid semantic and indicator-based retrieval from pgvector, calls Grok-4.7 via xAI, validates citations, calculates defensive gaps, and records observable trace steps.
- **Request Body**:
```json
{
  "threat_text": "An adversary compromised cloud admin session cookies (T1539) to authenticate to Entra ID (T1078.004). They proceeded to execute DCSync (T1003.006) to compromise all Active Directory domain password hashes.",
  "title": "Entra ID Cookie Hijack & DCSync Replication Attack",
  "model": "grok-4.7",
  "temperature": 0.1,
  "feed_id": null
}
```
- **Response**: `200 OK`
```json
{
  "report_id": "90e3dfbb-8822-48a0-9753-f75e2ba7d41a",
  "title": "Entra ID Cookie Hijack & DCSync Replication Attack",
  "threat_actor": "Unknown / Financially Motivated Actor",
  "overall_risk_score": "Critical",
  "confidence_score": 0.88,
  "executive_summary": "The advisory describes a multi-stage identity breach initiating with browser session hijacking and culminating in Active Directory domain replication...",
  "identified_ttps": [
    {
      "technique_id": "T1078.004",
      "technique_name": "Valid Accounts: Cloud Accounts",
      "tactic": "Initial Access",
      "coverage_status": "Covered",
      "tools": ["Okta", "Defender for Identity"],
      "confidence": 0.95,
      "rationale": "Directly matches adversary credential abuse vectors described in narrative."
    }
  ],
  "recommended_d3fend": [
    {
      "technique_id": "D3-MFA",
      "technique_name": "Multi-factor Authentication",
      "tactic": "Credential Hardening",
      "priority": "Immediate"
    }
  ],
  "immediate_actions": [
    "Revoke all Azure AD / Entra ID active session tokens using Revoke-AzureADUserAllRefreshToken",
    "Enable FIDO2 / Passkey phishing-resistant conditional access policies"
  ],
  "strategic_actions": [
    "Implement Directory Service Replication alerting on non-Domain Controller computer accounts"
  ],
  "citations": [
    {
      "source_id": "T1078.004",
      "source_type": "ATT&CK",
      "citation_text": "Valid Accounts: Cloud Accounts (Initial Access)",
      "relevance_score": 0.95
    }
  ],
  "trace": [
    {
      "step_index": 0,
      "node_name": "validate_input",
      "status": "success",
      "latency_ms": 0.42,
      "details": {"threat_text_length": 248}
    },
    {
      "step_index": 3,
      "node_name": "retrieve_attack_context",
      "status": "success",
      "latency_ms": 32.1,
      "details": {"retrieved_techniques": 8}
    },
    {
      "step_index": 7,
      "node_name": "generate_structured_report",
      "status": "success",
      "latency_ms": 1420.5,
      "details": {"model_invoked": "grok-4.7", "status": "Report generated and validated"}
    }
  ]
}
```

---

## Screen 7: Completed Intelligence Reports

### 13. Get Completed Report Detail
- **Path**: `GET /api/threats/reports/{report_id}`
- **Path Parameters**: `report_id` (UUID)
- **Response**: `200 OK` (Returns full structured report, mapped TTPs, citations, and trace steps).

---

## RAG Diagnostics & Vector Search

### 14. Hybrid RAG Search Diagnostic
- **Path**: `POST /api/rag/search`
- **Request Body**:
```json
{
  "query": "Kerberos ticket granting service attack and silver ticket generation",
  "top_k": 5,
  "include_d3fend": true,
  "source_kind": "attack"
}
```
- **Response**: `200 OK`
```json
{
  "query_summary": "Extracted 0 explicit technique IDs and 5 keywords",
  "explicit_indicators": {"ttps": []},
  "candidate_count": 5,
  "candidates": [
    {
      "source_id": "T1558.003",
      "title": "Steal or Forge Kerberos Tickets: Kerberoasting",
      "source_kind": "attack",
      "similarity_score": 0.884,
      "boosted": false
    }
  ]
}
```
