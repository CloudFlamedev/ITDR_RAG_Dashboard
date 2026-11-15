"""
Deterministic Retrieval Evaluation Metrics for the ITDR RAG Pipeline.
Computes Precision@K, Recall@K, missing/unexpected technique IDs,
and segmentations for explicit-ID vs no-ID query categories.
Does NOT require any external LLM calls.
"""
from typing import List, Dict, Any, Set, Optional


def normalize_id(identifier: Optional[str]) -> str:
    """Normalize MITRE ATT&CK or D3FEND identifier (strip whitespace, uppercase)."""
    if not identifier:
        return ""
    return str(identifier).strip().upper()


def _is_match(candidate_id: str, expected_id: str) -> bool:
    """
    Checks if a candidate technique matches an expected technique.
    Considers exact match (T1003.001 == T1003.001) or hierarchical subtechnique
    parent-child match (T1003 matching T1003.001 or vice-versa).
    """
    c = normalize_id(candidate_id)
    e = normalize_id(expected_id)
    if not c or not e:
        return False
    if c == e:
        return True
    # Subtechnique relationship match (e.g. T1078 matches T1078.004)
    if "." in c and c.split(".")[0] == e:
        return True
    if "." in e and e.split(".")[0] == c:
        return True
    return False


def compute_precision_at_k(
    retrieved_ids: List[str],
    expected_ids: List[str],
    k: int = 5,
) -> float:
    """
    Computes Precision@K:
    Proportion of top-K retrieved technique IDs that match expected IDs.
    
    Edge cases:
    - If expected_ids is empty (e.g., out-of-scope or insufficient evidence):
      - Returns 1.0 if retrieved_ids is also empty (correctly suppressed).
      - Returns 0.0 if any techniques were retrieved when none should be.
    - If retrieved_ids is empty and expected_ids is non-empty:
      - Returns 0.0.
    """
    norm_retrieved = [normalize_id(x) for x in retrieved_ids if normalize_id(x)][:k]
    norm_expected = [normalize_id(x) for x in expected_ids if normalize_id(x)]

    if not norm_expected:
        return 1.0 if not norm_retrieved else 0.0

    if not norm_retrieved:
        return 0.0

    matches = 0
    for r in norm_retrieved:
        if any(_is_match(r, e) for e in norm_expected):
            matches += 1

    return round(matches / len(norm_retrieved), 4)


def compute_recall_at_k(
    retrieved_ids: List[str],
    expected_ids: List[str],
    k: int = 5,
) -> float:
    """
    Computes Recall@K:
    Proportion of expected technique IDs that are retrieved within top-K.

    Edge cases:
    - If expected_ids is empty:
      - Returns 1.0 if retrieved_ids is also empty.
      - Returns 0.0 if techniques were hallucinated/retrieved.
    - If retrieved_ids is empty and expected_ids is non-empty:
      - Returns 0.0.
    """
    norm_retrieved = [normalize_id(x) for x in retrieved_ids if normalize_id(x)][:k]
    norm_expected = [normalize_id(x) for x in expected_ids if normalize_id(x)]

    if not norm_expected:
        return 1.0 if not norm_retrieved else 0.0

    if not norm_retrieved:
        return 0.0

    matches = 0
    for e in norm_expected:
        if any(_is_match(r, e) for r in norm_retrieved):
            matches += 1

    return round(matches / len(norm_expected), 4)


def find_missing_and_unexpected_ids(
    retrieved_ids: List[str],
    expected_ids: List[str],
    k: int = 5,
) -> Dict[str, List[str]]:
    """Identifies missing expected IDs and unexpected retrieved IDs."""
    norm_retrieved = [normalize_id(x) for x in retrieved_ids if normalize_id(x)][:k]
    norm_expected = [normalize_id(x) for x in expected_ids if normalize_id(x)]

    missing = []
    for e in norm_expected:
        if not any(_is_match(r, e) for r in norm_retrieved):
            missing.append(e)

    unexpected = []
    for r in norm_retrieved:
        if not any(_is_match(r, e) for e in norm_expected):
            unexpected.append(r)

    return {
        "missing": sorted(list(set(missing))),
        "unexpected": sorted(list(set(unexpected))),
    }


def evaluate_case_retrieval(
    retrieved_attack_ids: List[str],
    expected_attack_ids: List[str],
    retrieved_d3fend_ids: List[str],
    expected_d3fend_ids: List[str],
    k: int = 5,
) -> Dict[str, Any]:
    """Computes all deterministic retrieval metrics for an individual test case."""
    att_prec = compute_precision_at_k(retrieved_attack_ids, expected_attack_ids, k=k)
    att_rec = compute_recall_at_k(retrieved_attack_ids, expected_attack_ids, k=k)
    att_diff = find_missing_and_unexpected_ids(retrieved_attack_ids, expected_attack_ids, k=k)

    d3f_prec = compute_precision_at_k(retrieved_d3fend_ids, expected_d3fend_ids, k=k)
    d3f_rec = compute_recall_at_k(retrieved_d3fend_ids, expected_d3fend_ids, k=k)
    d3f_diff = find_missing_and_unexpected_ids(retrieved_d3fend_ids, expected_d3fend_ids, k=k)

    return {
        "k": k,
        "attack_precision_at_k": att_prec,
        "attack_recall_at_k": att_rec,
        "missing_attack_ids": att_diff["missing"],
        "unexpected_attack_ids": att_diff["unexpected"],
        "d3fend_precision_at_k": d3f_prec,
        "d3fend_recall_at_k": d3f_rec,
        "missing_d3fend_ids": d3f_diff["missing"],
        "unexpected_d3fend_ids": d3f_diff["unexpected"],
    }


def aggregate_retrieval_metrics(
    eval_cases_results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Aggregates retrieval metrics across all test cases.
    Separates results into:
    1. Explicit-ID queries (has_explicit_attack_id == True)
    2. No-ID queries (has_explicit_attack_id == False)
    3. Combined dataset
    And segments by case_type.
    """
    def _compute_group_summary(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not cases:
            return {
                "count": 0,
                "mean_attack_precision_at_k": 0.0,
                "mean_attack_recall_at_k": 0.0,
                "mean_d3fend_precision_at_k": 0.0,
                "mean_d3fend_recall_at_k": 0.0,
            }
        n = len(cases)
        return {
            "count": n,
            "mean_attack_precision_at_k": round(sum(c["attack_precision_at_k"] for c in cases) / n, 4),
            "mean_attack_recall_at_k": round(sum(c["attack_recall_at_k"] for c in cases) / n, 4),
            "mean_d3fend_precision_at_k": round(sum(c["d3fend_precision_at_k"] for c in cases) / n, 4),
            "mean_d3fend_recall_at_k": round(sum(c["d3fend_recall_at_k"] for c in cases) / n, 4),
        }

    explicit_cases = [c for c in eval_cases_results if c.get("has_explicit_attack_id", False)]
    no_id_cases = [c for c in eval_cases_results if not c.get("has_explicit_attack_id", False)]

    # Breakdown by case_type
    case_types = set(c.get("case_type", "unknown") for c in eval_cases_results)
    by_case_type = {}
    for ct in sorted(list(case_types)):
        ct_cases = [c for c in eval_cases_results if c.get("case_type") == ct]
        by_case_type[ct] = _compute_group_summary(ct_cases)

    return {
        "total_cases": len(eval_cases_results),
        "combined": _compute_group_summary(eval_cases_results),
        "explicit_id_queries": _compute_group_summary(explicit_cases),
        "no_id_queries": _compute_group_summary(no_id_cases),
        "by_case_type": by_case_type,
    }
