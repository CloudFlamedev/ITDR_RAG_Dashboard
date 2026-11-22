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
    Strictly enforces exact identifier matching (case-insensitive, whitespace-trimmed).
    Parent and sub-technique IDs (e.g., T1003 vs T1003.001) are strictly NOT treated as equivalent.
    """
    c = normalize_id(candidate_id)
    e = normalize_id(expected_id)
    if not c or not e:
        return False
    return c == e


def compute_precision_at_k(
    retrieved_ids: List[str],
    expected_ids: List[str],
    k: int = 5,
) -> float:
    """
    Computes Precision@K:
    Precision@K = Relevant results in top K / K.
    
    Missing results within the top K positions count as non-relevant.
    If fewer than K results are returned, the denominator remains strictly K.

    Edge cases:
    - If k <= 0: returns 0.0.
    - If expected_ids is empty:
      - Returns 1.0 if retrieved_ids is also empty (correctly suppressed).
      - Returns 0.0 if any techniques were retrieved when none should be.
    - If retrieved_ids is empty and expected_ids is non-empty:
      - Returns 0.0.
    """
    if k <= 0:
        return 0.0

    norm_retrieved = [normalize_id(x) for x in retrieved_ids if normalize_id(x)][:k]
    norm_expected = [normalize_id(x) for x in expected_ids if normalize_id(x)]

    if not norm_expected:
        return 1.0 if not norm_retrieved else 0.0

    if not norm_retrieved:
        return 0.0

    matches = 0
    matched_expected = set()
    for r in norm_retrieved:
        for e in norm_expected:
            if _is_match(r, e) and e not in matched_expected:
                matches += 1
                matched_expected.add(e)
                break

    return round(matches / k, 4)


def compute_recall_at_k(
    retrieved_ids: List[str],
    expected_ids: List[str],
    k: int = 5,
) -> float:
    """
    Computes Recall@K:
    Proportion of expected technique IDs that are retrieved within top-K.
    Enforces exact identifier matching.

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
    matched_expected = set()
    for e in norm_expected:
        if any(_is_match(r, e) for r in norm_retrieved) and e not in matched_expected:
            matches += 1
            matched_expected.add(e)

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


def compute_hit_rate_at_k(
    retrieved_ids: List[str],
    expected_ids: List[str],
    k: int = 5,
) -> float:
    """
    Computes Hit Rate@K:
    1.0 if at least one expected ID is in the top-K retrieved IDs, else 0.0.

    Edge cases:
    - If expected_ids is empty:
      - Returns 1.0 if retrieved_ids is also empty (correctly suppressed).
      - Returns 0.0 if any IDs were retrieved.
    - If retrieved_ids is empty and expected_ids is non-empty:
      - Returns 0.0.
    """
    norm_retrieved = [normalize_id(x) for x in retrieved_ids if normalize_id(x)][:k]
    norm_expected = [normalize_id(x) for x in expected_ids if normalize_id(x)]

    if not norm_expected:
        return 1.0 if not norm_retrieved else 0.0

    if not norm_retrieved:
        return 0.0

    for r in norm_retrieved:
        if any(_is_match(r, e) for e in norm_expected):
            return 1.0
    return 0.0


def compute_mrr(
    retrieved_ids: List[str],
    expected_ids: List[str],
    k: int = 5,
) -> float:
    """
    Computes Mean Reciprocal Rank (MRR / Reciprocal Rank@K):
    1 / rank of the FIRST matching expected ID within top-K retrieved IDs (1-based index).
    If no matching expected ID is within top-K, returns 0.0.

    Edge cases:
    - If expected_ids is empty:
      - Returns 1.0 if retrieved_ids is also empty.
      - Returns 0.0 if any IDs were retrieved.
    - If retrieved_ids is empty and expected_ids is non-empty:
      - Returns 0.0.
    """
    norm_retrieved = [normalize_id(x) for x in retrieved_ids if normalize_id(x)][:k]
    norm_expected = [normalize_id(x) for x in expected_ids if normalize_id(x)]

    if not norm_expected:
        return 1.0 if not norm_retrieved else 0.0

    if not norm_retrieved:
        return 0.0

    for idx, r in enumerate(norm_retrieved, start=1):
        if any(_is_match(r, e) for e in norm_expected):
            return round(1.0 / idx, 4)

    return 0.0


def evaluate_case_retrieval(
    retrieved_attack_ids: List[str],
    expected_attack_ids: List[str],
    retrieved_d3fend_ids: List[str],
    expected_d3fend_ids: List[str],
    k: int = 5,
    duration_ms: float = 0.0,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Computes all deterministic retrieval metrics for an individual test case."""
    is_negative = len(expected_attack_ids) == 0 and len(expected_d3fend_ids) == 0
    is_empty = len(retrieved_attack_ids) == 0 and len(retrieved_d3fend_ids) == 0
    has_error = error is not None

    is_false_positive = is_negative and not is_empty and not has_error
    is_correct_empty = is_negative and is_empty and not has_error

    att_prec = compute_precision_at_k(retrieved_attack_ids, expected_attack_ids, k=k)
    att_rec = compute_recall_at_k(retrieved_attack_ids, expected_attack_ids, k=k)
    att_hit = compute_hit_rate_at_k(retrieved_attack_ids, expected_attack_ids, k=k)
    att_mrr = compute_mrr(retrieved_attack_ids, expected_attack_ids, k=k)
    att_diff = find_missing_and_unexpected_ids(retrieved_attack_ids, expected_attack_ids, k=k)

    d3f_prec = compute_precision_at_k(retrieved_d3fend_ids, expected_d3fend_ids, k=k)
    d3f_rec = compute_recall_at_k(retrieved_d3fend_ids, expected_d3fend_ids, k=k)
    d3f_hit = compute_hit_rate_at_k(retrieved_d3fend_ids, expected_d3fend_ids, k=k)
    d3f_mrr = compute_mrr(retrieved_d3fend_ids, expected_d3fend_ids, k=k)
    d3f_diff = find_missing_and_unexpected_ids(retrieved_d3fend_ids, expected_d3fend_ids, k=k)

    return {
        "k": k,
        "is_negative": is_negative,
        "is_false_positive": is_false_positive,
        "is_correct_empty": is_correct_empty,
        "attack_precision_at_k": att_prec,
        "attack_recall_at_k": att_rec,
        "attack_hit_rate_at_k": att_hit,
        "attack_mrr": att_mrr,
        "missing_attack_ids": att_diff["missing"],
        "unexpected_attack_ids": att_diff["unexpected"],
        "d3fend_precision_at_k": d3f_prec,
        "d3fend_recall_at_k": d3f_rec,
        "d3fend_hit_rate_at_k": d3f_hit,
        "d3fend_mrr": d3f_mrr,
        "missing_d3fend_ids": d3f_diff["missing"],
        "unexpected_d3fend_ids": d3f_diff["unexpected"],
        "duration_ms": round(duration_ms, 2),
        "is_empty_retrieval": is_empty,
        "retrieval_error": error,
        "has_error": has_error,
    }


def aggregate_retrieval_metrics(
    eval_cases_results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Aggregates retrieval metrics across all test cases.
    Separates positive queries from negative queries:
    - Positive queries calculate: Recall@K, Precision@K, Hit Rate@K, MRR (ATT&CK and D3FEND).
    - Negative queries calculate: False Positive Rate, Correct Empty Retrieval Rate, Error Rate.
    Negative queries are strictly excluded from positive retrieval metric averages.
    """
    def _compute_positive_group_summary(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not cases:
            return {
                "count": 0,
                "mean_attack_recall_at_k": 0.0,
                "mean_attack_precision_at_k": 0.0,
                "mean_attack_hit_rate_at_k": 0.0,
                "mean_attack_mrr": 0.0,
                "mean_d3fend_recall_at_k": 0.0,
                "mean_d3fend_precision_at_k": 0.0,
                "mean_d3fend_hit_rate_at_k": 0.0,
                "mean_d3fend_mrr": 0.0,
                "empty_retrieval_count": 0,
                "empty_retrieval_rate": 0.0,
                "error_count": 0,
                "error_rate": 0.0,
                "mean_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
                "min_latency_ms": 0.0,
                "max_latency_ms": 0.0,
            }
        n = len(cases)
        latencies = sorted([float(c.get("duration_ms", 0.0)) for c in cases])
        p95_idx = max(0, int(len(latencies) * 0.95) - 1)
        p95_lat = latencies[p95_idx] if latencies else 0.0
        empty_count = sum(1 for c in cases if c.get("is_empty_retrieval", False))
        err_count = sum(1 for c in cases if c.get("has_error", False))

        return {
            "count": n,
            "mean_attack_recall_at_k": round(sum(c.get("attack_recall_at_k", 0.0) for c in cases) / n, 4),
            "mean_attack_precision_at_k": round(sum(c.get("attack_precision_at_k", 0.0) for c in cases) / n, 4),
            "mean_attack_hit_rate_at_k": round(sum(c.get("attack_hit_rate_at_k", 0.0) for c in cases) / n, 4),
            "mean_attack_mrr": round(sum(c.get("attack_mrr", 0.0) for c in cases) / n, 4),
            "mean_d3fend_recall_at_k": round(sum(c.get("d3fend_recall_at_k", 0.0) for c in cases) / n, 4),
            "mean_d3fend_precision_at_k": round(sum(c.get("d3fend_precision_at_k", 0.0) for c in cases) / n, 4),
            "mean_d3fend_hit_rate_at_k": round(sum(c.get("d3fend_hit_rate_at_k", 0.0) for c in cases) / n, 4),
            "mean_d3fend_mrr": round(sum(c.get("d3fend_mrr", 0.0) for c in cases) / n, 4),
            "empty_retrieval_count": empty_count,
            "empty_retrieval_rate": round(empty_count / n, 4),
            "error_count": err_count,
            "error_rate": round(err_count / n, 4),
            "mean_latency_ms": round(sum(latencies) / max(len(latencies), 1), 2),
            "p95_latency_ms": round(p95_lat, 2),
            "min_latency_ms": round(min(latencies), 2) if latencies else 0.0,
            "max_latency_ms": round(max(latencies), 2) if latencies else 0.0,
        }

    def _compute_negative_group_summary(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not cases:
            return {
                "count": 0,
                "false_positive_count": 0,
                "false_positive_rate": 0.0,
                "correct_empty_count": 0,
                "correct_empty_retrieval_rate": 0.0,
                "error_count": 0,
                "error_rate": 0.0,
                "mean_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
            }
        n = len(cases)
        err_count = sum(1 for c in cases if c.get("has_error", False))
        fp_count = sum(
            1 for c in cases
            if not c.get("has_error", False) and (
                len(c.get("retrieved_attack_ids", [])) > 0
                or len(c.get("retrieved_d3fend_ids", [])) > 0
                or not c.get("is_empty_retrieval", True)
            )
        )
        correct_empty = sum(
            1 for c in cases
            if not c.get("has_error", False) and c.get("is_empty_retrieval", False)
        )
        latencies = sorted([float(c.get("duration_ms", 0.0)) for c in cases])
        p95_idx = max(0, int(len(latencies) * 0.95) - 1)
        p95_lat = latencies[p95_idx] if latencies else 0.0

        return {
            "count": n,
            "false_positive_count": fp_count,
            "false_positive_rate": round(fp_count / n, 4),
            "correct_empty_count": correct_empty,
            "correct_empty_retrieval_rate": round(correct_empty / n, 4),
            "error_count": err_count,
            "error_rate": round(err_count / n, 4),
            "mean_latency_ms": round(sum(latencies) / max(len(latencies), 1), 2),
            "p95_latency_ms": round(p95_lat, 2),
        }

    def _is_negative(c: Dict[str, Any]) -> bool:
        if c.get("query_type") == "negative":
            return True
        if c.get("is_negative") is True:
            return True
        exp_att = c.get("expected_attack_ids")
        exp_d3f = c.get("expected_d3fend_ids")
        if (
            exp_att is not None
            and exp_d3f is not None
            and len(exp_att) == 0
            and len(exp_d3f) == 0
            and not c.get("has_explicit_attack_id", False)
        ):
            return True
        return False

    negative_cases = [c for c in eval_cases_results if _is_negative(c)]
    positive_cases = [c for c in eval_cases_results if not _is_negative(c)]

    explicit_cases = [
        c for c in positive_cases
        if c.get("query_type") == "explicit_id" or c.get("has_explicit_attack_id", False)
    ]
    semantic_cases = [
        c for c in positive_cases
        if c.get("query_type") == "semantic" or not c.get("has_explicit_attack_id", False)
    ]
    no_id_cases = [
        c for c in positive_cases
        if not c.get("has_explicit_attack_id", False)
    ]

    case_types = set(c.get("case_type", "unknown") for c in positive_cases)
    by_case_type = {}
    for ct in sorted(list(case_types)):
        ct_cases = [c for c in positive_cases if c.get("case_type") == ct]
        by_case_type[ct] = _compute_positive_group_summary(ct_cases)

    positive_summary = _compute_positive_group_summary(positive_cases)
    negative_summary = _compute_negative_group_summary(negative_cases)

    overall_err_count = sum(1 for c in eval_cases_results if c.get("has_error", False))
    overall_err_rate = round(overall_err_count / len(eval_cases_results), 4) if eval_cases_results else 0.0

    return {
        "total_cases": len(eval_cases_results),
        "positive_cases_count": len(positive_cases),
        "negative_cases_count": len(negative_cases),
        "overall_error_count": overall_err_count,
        "overall_error_rate": overall_err_rate,
        "combined": positive_summary,
        "positive_queries": positive_summary,
        "negative_queries": negative_summary,
        "explicit_id_queries": _compute_positive_group_summary(explicit_cases),
        "semantic_queries": _compute_positive_group_summary(semantic_cases),
        "no_id_queries": _compute_positive_group_summary(no_id_cases),
        "by_case_type": by_case_type,
    }


def print_retrieval_summary_table(
    metrics: Dict[str, Any],
    case_records: List[Dict[str, Any]],
    k: int = 5,
):
    """Prints a clean ASCII summary report table for live PostgreSQL/pgvector retrieval evaluation."""
    bar = "=" * 84
    sub_bar = "-" * 84

    print("\n" + bar)
    print(" ITDR LIVE POSTGRESQL / PGVECTOR RETRIEVAL EVALUATION REPORT")
    print(bar)
    pos = metrics.get("positive_queries") or metrics.get("combined", {})
    neg = metrics.get("negative_queries", {})
    total_count = metrics.get("total_cases", len(case_records))
    pos_count = metrics.get("positive_cases_count", pos.get("count", 0))
    neg_count = metrics.get("negative_cases_count", neg.get("count", 0))
    overall_err_rate = metrics.get("overall_error_rate", pos.get("error_rate", 0.0))

    print(f" Total Evaluation Queries : {total_count} (Positive: {pos_count}, Negative: {neg_count})")
    print(f" Top-K Cutoff             : K={k}")
    print(f" Mean Latency (Positive)  : {pos.get('mean_latency_ms', 0.0):.2f}ms (P95: {pos.get('p95_latency_ms', 0.0):.2f}ms)")
    print(f" Overall Error Rate       : {overall_err_rate * 100:.1f}% ({metrics.get('overall_error_count', 0)}/{total_count})")
    print(sub_bar)
    print(" 1. POSITIVE RETRIEVAL EFFECTIVENESS (Top-K)")
    print(sub_bar)
    print(f" ATT&CK Technique Recall@{k}      : {pos.get('mean_attack_recall_at_k', 0.0) * 100:.1f}%")
    print(f" ATT&CK Technique Precision@{k}   : {pos.get('mean_attack_precision_at_k', 0.0) * 100:.1f}%")
    print(f" ATT&CK Technique Hit Rate@{k}    : {pos.get('mean_attack_hit_rate_at_k', 0.0) * 100:.1f}%")
    print(f" ATT&CK Mean Reciprocal Rank (MRR): {pos.get('mean_attack_mrr', 0.0):.4f}")
    print(f" D3FEND Countermeasure Recall@{k} : {pos.get('mean_d3fend_recall_at_k', 0.0) * 100:.1f}%")
    print(f" D3FEND Precision@{k}             : {pos.get('mean_d3fend_precision_at_k', 0.0) * 100:.1f}%")
    print(f" D3FEND Hit Rate@{k}              : {pos.get('mean_d3fend_hit_rate_at_k', 0.0) * 100:.1f}%")
    print(f" D3FEND MRR                       : {pos.get('mean_d3fend_mrr', 0.0):.4f}")
    if neg_count > 0:
        print(sub_bar)
        print(" 2. NEGATIVE QUERY RETRIEVAL PERFORMANCE (Hallucination Suppression)")
        print(sub_bar)
        print(f" Negative Query Count             : {neg_count}")
        print(f" Correct Empty Retrieval Rate     : {neg.get('correct_empty_retrieval_rate', 0.0) * 100:.1f}% ({neg.get('correct_empty_count', 0)}/{neg_count}) [Desired: 100%]")
        print(f" False Positive Rate (FPR)        : {neg.get('false_positive_rate', 0.0) * 100:.1f}% ({neg.get('false_positive_count', 0)}/{neg_count}) [Must be 0.0%]")
        print(f" Negative Retrieval Error Rate    : {neg.get('error_rate', 0.0) * 100:.1f}% ({neg.get('error_count', 0)}/{neg_count})")
    print(sub_bar)
    print(" 3. QUERY CATEGORY SEGMENTATION")
    print(sub_bar)
    print(f" {'Category':<22} | {'Count':<6} | {'Recall@K':<10} | {'Prec@K':<10} | {'HitRate@K':<10} | {'MRR':<8} | {'Latency'}")
    print(f" {'-'*22} | {'-'*6} | {'-'*10} | {'-'*10} | {'-'*10} | {'-'*8} | {'-'*7}")
    for name, cat_data in [
        ("Explicit-ID Queries", metrics.get("explicit_id_queries", {})),
        ("Semantic Queries", metrics.get("semantic_queries", {})),
    ]:
        if cat_data.get("count", 0) > 0:
            print(
                f" {name:<22} | {cat_data['count']:<6} | "
                f"{cat_data['mean_attack_recall_at_k']*100:>7.1f}% | "
                f"{cat_data['mean_attack_precision_at_k']*100:>7.1f}% | "
                f"{cat_data['mean_attack_hit_rate_at_k']*100:>8.1f}% | "
                f"{cat_data['mean_attack_mrr']:>6.4f} | "
                f"{cat_data['mean_latency_ms']:>6.1f}ms"
            )
    print(sub_bar)
    print(" 4. PER-CASE RETRIEVAL SUMMARY")
    print(sub_bar)
    print(f" {'Sample ID':<16} | {'Type':<12} | {'ATT Rec':<8} | {'ATT Hit':<8} | {'ATT MRR':<8} | {'D3F Rec':<8} | {'Status/Latency'}")
    print(f" {'-'*16} | {'-'*12} | {'-'*8} | {'-'*8} | {'-'*8} | {'-'*8} | {'-'*14}")
    for c in case_records:
        sid = c.get("sample_id", "unknown")
        qtype = c.get("query_type", c.get("case_type", "unknown"))[:12]
        is_neg = c.get("is_negative", False) or qtype == "negative"
        if is_neg:
            att_rec = "N/A"
            att_hit = "N/A"
            att_mrr = "N/A"
            d3f_rec = "N/A"
            if c.get("has_error"):
                status_str = f"ERROR ({c.get('duration_ms', 0.0):.0f}ms)"
            elif c.get("is_false_positive"):
                status_str = f"LEAK ({c.get('duration_ms', 0.0):.0f}ms)"
            else:
                status_str = f"CLEAN ({c.get('duration_ms', 0.0):.0f}ms)"
        else:
            att_rec = f"{c.get('attack_recall_at_k', 0.0)*100:.0f}%"
            att_hit = "Yes" if c.get("attack_hit_rate_at_k", 0.0) >= 1.0 else "No"
            att_mrr = f"{c.get('attack_mrr', 0.0):.2f}"
            d3f_rec = f"{c.get('d3fend_recall_at_k', 0.0)*100:.0f}%"
            status_str = f"{c.get('duration_ms', 0.0):.1f}ms"
        print(f" {sid:<16} | {qtype:<12} | {att_rec:<8} | {att_hit:<8} | {att_mrr:<8} | {d3f_rec:<8} | {status_str}")
    print(bar + "\n")
