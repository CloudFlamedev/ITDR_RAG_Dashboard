"""
ITDR PostgreSQL / pgvector Hybrid Retrieval Evaluation Runner.
Executes the retrieval evaluation dataset (itdr_retrieval_eval.jsonl) directly against
the live PostgreSQL/pgvector database using authentic RetrievalService methods.

Computes:
1. Recall@K (ATT&CK and D3FEND)
2. Precision@K (ATT&CK and D3FEND)
3. Hit Rate@K (ATT&CK and D3FEND)
4. Mean Reciprocal Rank (MRR)
5. Empty retrieval rate and retrieval error rate
6. Per-query retrieval latency (mean, p95, min, max)
7. Query category segmentation (explicit-ID vs semantic vs negative)

CLI usage:
    python -m evaluation.run_retrieval_evaluation --dataset evaluation/datasets/itdr_retrieval_eval.jsonl
"""
import os
import sys
import csv
import json
import time
import argparse
import datetime
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.retrieval_service import RetrievalService
from evaluation.retrieval_metrics import (
    evaluate_case_retrieval,
    aggregate_retrieval_metrics,
    print_retrieval_summary_table,
)
from evaluation.run_security_evaluation import (
    validate_live_database_readiness,
    mask_sensitive_payloads,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("itdr-retrieval-evaluation-runner")
settings = get_settings()

RETRIEVAL_DATASET_VERSION = "1.0.0"
DEFAULT_RETRIEVAL_RESULTS_DIR = Path(__file__).parent / "results" / "retrieval"

DEFAULT_RETRIEVAL_THRESHOLDS = {
    "min_attack_recall": 0.80,
    "min_attack_hit_rate": 0.80,
    "min_d3fend_recall": 0.50,
    "min_d3fend_hit_rate": 0.60,
    "max_negative_fpr": 0.00,
    "max_error_rate": 0.00,
}


def verify_retrieval_acceptance(
    metrics: Dict[str, Any],
    thresholds: Optional[Dict[str, float]] = None,
    k: int = 5,
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Evaluates whether retrieval metrics meet configured acceptance criteria.
    Validates:
    1. ATT&CK Recall@K and Hit Rate@K
    2. D3FEND Recall@K and Hit Rate@K
    3. Negative query False Positive Rate (FPR)
    4. Overall Retrieval Error Rate
    Fails closed if any metric is missing (N/A) or below required threshold.
    Returns (success, failure_reasons, check_details).
    """
    th = {**DEFAULT_RETRIEVAL_THRESHOLDS, **(thresholds or {})}
    failures = []
    checks = {}

    pos = metrics.get("positive_queries") or metrics.get("combined") or {}
    pos_count = metrics.get("positive_cases_count", pos.get("count", 0))

    if pos_count == 0:
        failures.append("No positive test cases evaluated; positive retrieval metrics are missing (N/A).")
        checks["positive_count"] = {"actual": 0, "threshold": 1, "passed": False}
    else:
        checks["positive_count"] = {"actual": pos_count, "threshold": 1, "passed": True}
        # 1. ATT&CK Recall@K
        att_recall = pos.get("mean_attack_recall_at_k")
        if att_recall is None:
            failures.append(f"ATT&CK Recall@{k} is missing (N/A).")
            checks["attack_recall"] = {"actual": None, "threshold": th["min_attack_recall"], "passed": False}
        elif att_recall < th["min_attack_recall"]:
            failures.append(
                f"ATT&CK Recall@{k} ({att_recall * 100:.1f}%) fell below required threshold ({th['min_attack_recall'] * 100:.1f}%)."
            )
            checks["attack_recall"] = {"actual": att_recall, "threshold": th["min_attack_recall"], "passed": False}
        else:
            checks["attack_recall"] = {"actual": att_recall, "threshold": th["min_attack_recall"], "passed": True}

        # 2. ATT&CK Hit Rate@K
        att_hit = pos.get("mean_attack_hit_rate_at_k")
        if att_hit is None:
            failures.append(f"ATT&CK Hit Rate@{k} is missing (N/A).")
            checks["attack_hit_rate"] = {"actual": None, "threshold": th["min_attack_hit_rate"], "passed": False}
        elif att_hit < th["min_attack_hit_rate"]:
            failures.append(
                f"ATT&CK Hit Rate@{k} ({att_hit * 100:.1f}%) fell below required threshold ({th['min_attack_hit_rate'] * 100:.1f}%)."
            )
            checks["attack_hit_rate"] = {"actual": att_hit, "threshold": th["min_attack_hit_rate"], "passed": False}
        else:
            checks["attack_hit_rate"] = {"actual": att_hit, "threshold": th["min_attack_hit_rate"], "passed": True}

        # 3. D3FEND Recall@K
        d3f_recall = pos.get("mean_d3fend_recall_at_k")
        if d3f_recall is None:
            failures.append(f"D3FEND Recall@{k} is missing (N/A).")
            checks["d3fend_recall"] = {"actual": None, "threshold": th["min_d3fend_recall"], "passed": False}
        elif d3f_recall < th["min_d3fend_recall"]:
            failures.append(
                f"D3FEND Recall@{k} ({d3f_recall * 100:.1f}%) fell below required threshold ({th['min_d3fend_recall'] * 100:.1f}%)."
            )
            checks["d3fend_recall"] = {"actual": d3f_recall, "threshold": th["min_d3fend_recall"], "passed": False}
        else:
            checks["d3fend_recall"] = {"actual": d3f_recall, "threshold": th["min_d3fend_recall"], "passed": True}

        # 4. D3FEND Hit Rate@K
        d3f_hit = pos.get("mean_d3fend_hit_rate_at_k")
        if d3f_hit is None:
            failures.append(f"D3FEND Hit Rate@{k} is missing (N/A).")
            checks["d3fend_hit_rate"] = {"actual": None, "threshold": th["min_d3fend_hit_rate"], "passed": False}
        elif d3f_hit < th["min_d3fend_hit_rate"]:
            failures.append(
                f"D3FEND Hit Rate@{k} ({d3f_hit * 100:.1f}%) fell below required threshold ({th['min_d3fend_hit_rate'] * 100:.1f}%)."
            )
            checks["d3fend_hit_rate"] = {"actual": d3f_hit, "threshold": th["min_d3fend_hit_rate"], "passed": False}
        else:
            checks["d3fend_hit_rate"] = {"actual": d3f_hit, "threshold": th["min_d3fend_hit_rate"], "passed": True}

    # 5. Negative Query False Positive Rate
    neg = metrics.get("negative_queries") or {}
    neg_count = metrics.get("negative_cases_count", neg.get("count", 0))
    if neg_count > 0:
        neg_fpr = neg.get("false_positive_rate")
        if neg_fpr is None:
            failures.append("Negative Query False Positive Rate is missing (N/A).")
            checks["negative_fpr"] = {"actual": None, "threshold": th["max_negative_fpr"], "passed": False}
        elif neg_fpr > th["max_negative_fpr"]:
            failures.append(
                f"Negative Query False Positive Rate ({neg_fpr * 100:.1f}%) exceeded maximum allowed threshold ({th['max_negative_fpr'] * 100:.1f}%)."
            )
            checks["negative_fpr"] = {"actual": neg_fpr, "threshold": th["max_negative_fpr"], "passed": False}
        else:
            checks["negative_fpr"] = {"actual": neg_fpr, "threshold": th["max_negative_fpr"], "passed": True}
    else:
        checks["negative_fpr"] = {"actual": None, "threshold": th["max_negative_fpr"], "passed": True, "note": "No negative queries"}

    # 6. Overall Error Rate
    err_rate = metrics.get("overall_error_rate")
    if err_rate is None:
        err_rate = pos.get("error_rate")
    if err_rate is None:
        failures.append("Retrieval Error Rate is missing (N/A).")
        checks["error_rate"] = {"actual": None, "threshold": th["max_error_rate"], "passed": False}
    elif err_rate > th["max_error_rate"]:
        failures.append(
            f"Retrieval Error Rate ({err_rate * 100:.1f}%) exceeded maximum allowed threshold ({th['max_error_rate'] * 100:.1f}%)."
        )
        checks["error_rate"] = {"actual": err_rate, "threshold": th["max_error_rate"], "passed": False}
    else:
        checks["error_rate"] = {"actual": err_rate, "threshold": th["max_error_rate"], "passed": True}

    success = len(failures) == 0
    return success, failures, checks


def print_retrieval_acceptance_report(
    success: bool,
    failures: List[str],
    checks: Dict[str, Any],
    thresholds: Dict[str, float],
    k: int = 5,
):
    """Prints a clear, formatted acceptance verification report."""
    bar = "=" * 84
    sub = "-" * 84
    print("\n" + bar)
    print(" RETRIEVAL ACCEPTANCE CRITERIA VERIFICATION")
    print(bar)
    status_str = "PASSED" if success else "FAILED"
    print(f" Acceptance Status: {status_str}")
    print(sub)
    print(f" {'Metric / Acceptance Check':<40} | {'Actual':<12} | {'Threshold':<12} | {'Result'}")
    print(f" {'-'*40} | {'-'*12} | {'-'*12} | {'-'*8}")

    criteria = [
        (f"ATT&CK Technique Recall@{k}", "attack_recall", ">=", "min_attack_recall"),
        (f"ATT&CK Technique Hit Rate@{k}", "attack_hit_rate", ">=", "min_attack_hit_rate"),
        (f"D3FEND Countermeasure Recall@{k}", "d3fend_recall", ">=", "min_d3fend_recall"),
        (f"D3FEND Countermeasure Hit Rate@{k}", "d3fend_hit_rate", ">=", "min_d3fend_hit_rate"),
        ("Negative Query False Positive Rate", "negative_fpr", "<=", "max_negative_fpr"),
        ("Overall Retrieval Error Rate", "error_rate", "<=", "max_error_rate"),
    ]
    for name, key, op, th_key in criteria:
        c = checks.get(key, {})
        passed = c.get("passed", False)
        actual = c.get("actual")
        th_val = thresholds.get(th_key, 0.0)
        actual_str = f"{actual * 100:.1f}%" if actual is not None else "N/A"
        th_str = f"{op} {th_val * 100:.1f}%"
        res_str = "PASS" if passed else "FAIL"
        print(f" {name:<40} | {actual_str:<12} | {th_str:<12} | {res_str}")

    if failures:
        print(sub)
        print(" Specific Acceptance Failures:")
        for idx, f in enumerate(failures, start=1):
            print(f"   {idx}. {f}")
    print(bar + "\n")


def load_retrieval_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    """Loads and validates retrieval test cases from JSONL dataset."""
    if not dataset_path.exists():
        raise FileNotFoundError(f"Retrieval evaluation dataset not found at {dataset_path}")

    cases = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                record = json.loads(line)
                cases.append(record)
            except json.JSONDecodeError as exc:
                logger.warning(f"Skipping malformed JSON line {line_no} in {dataset_path}: {exc}")

    logger.info(f"Loaded {len(cases)} retrieval evaluation test cases from {dataset_path}")
    return cases


def export_retrieval_results(
    output_dir: Path,
    metrics: Dict[str, Any],
    case_records: List[Dict[str, Any]],
    k: int = 5,
    db_info: Optional[Dict[str, Any]] = None,
    acceptance_summary: Optional[Dict[str, Any]] = None,
):
    """Exports retrieval evaluation results to JSON and CSV reports."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. JSON Report
    json_path = output_dir / f"retrieval_evaluation_report_{timestamp}.json"
    payload = {
        "evaluation_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dataset_version": RETRIEVAL_DATASET_VERSION,
        "k_cutoff": k,
        "database_info": db_info or {},
        "acceptance_verification": acceptance_summary or {},
        "aggregate_retrieval_metrics": metrics,
        "detailed_case_results": mask_sensitive_payloads(case_records),
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    logger.info(f"Exported JSON retrieval evaluation report to {json_path}")

    # 2. CSV Report
    csv_path = output_dir / f"retrieval_evaluation_cases_{timestamp}.csv"
    fieldnames = [
        "sample_id",
        "query_type",
        "is_negative",
        "is_false_positive",
        "is_correct_empty",
        "query",
        "expected_attack_ids",
        "retrieved_attack_ids",
        "attack_recall_at_k",
        "attack_precision_at_k",
        "attack_hit_rate_at_k",
        "attack_mrr",
        "missing_attack_ids",
        "unexpected_attack_ids",
        "expected_d3fend_ids",
        "retrieved_d3fend_ids",
        "d3fend_recall_at_k",
        "d3fend_precision_at_k",
        "d3fend_hit_rate_at_k",
        "d3fend_mrr",
        "missing_d3fend_ids",
        "unexpected_d3fend_ids",
        "duration_ms",
        "is_empty_retrieval",
        "has_error",
        "retrieval_error",
        "ground_truth_rationale",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in case_records:
            row = dict(mask_sensitive_payloads(r))
            row["expected_attack_ids"] = ";".join(r.get("expected_attack_ids", []))
            row["retrieved_attack_ids"] = ";".join(r.get("retrieved_attack_ids", []))
            row["missing_attack_ids"] = ";".join(r.get("missing_attack_ids", []))
            row["unexpected_attack_ids"] = ";".join(r.get("unexpected_attack_ids", []))
            row["expected_d3fend_ids"] = ";".join(r.get("expected_d3fend_ids", []))
            row["retrieved_d3fend_ids"] = ";".join(r.get("retrieved_d3fend_ids", []))
            row["missing_d3fend_ids"] = ";".join(r.get("missing_d3fend_ids", []))
            row["unexpected_d3fend_ids"] = ";".join(r.get("unexpected_d3fend_ids", []))
            writer.writerow(row)
    logger.info(f"Exported CSV retrieval case results to {csv_path}")


def run_retrieval_evaluation(
    dataset_path: Path,
    output_dir: Optional[Path] = None,
    k: int = 5,
    max_candidates: int = 8,
    limit: Optional[int] = None,
    sample_ids: Optional[List[str]] = None,
    thresholds: Optional[Dict[str, float]] = None,
) -> bool:
    """
    Executes retrieval evaluation against the live PostgreSQL/pgvector database.
    Fails closed if the database is not ready or if configured acceptance criteria fail.
    """
    out_dir = output_dir or DEFAULT_RETRIEVAL_RESULTS_DIR
    logger.info("Verifying PostgreSQL/pgvector database readiness...")
    db_info = validate_live_database_readiness()

    cases = load_retrieval_dataset(dataset_path)

    if sample_ids:
        cases = [c for c in cases if c.get("sample_id") in sample_ids]
        logger.info(f"Filtered to {len(cases)} cases matching sample_ids={sample_ids}")

    if limit and limit > 0:
        cases = cases[:limit]
        logger.info(f"Limited execution to first {len(cases)} cases")

    if not cases:
        logger.error("No retrieval test cases to evaluate.")
        return False

    case_records: List[Dict[str, Any]] = []

    for idx, case in enumerate(cases, start=1):
        sid = case.get("sample_id", f"ret-{idx}")
        query = case.get("query", "")
        qtype = case.get("query_type", "unknown")
        expected_att = case.get("expected_attack_ids", [])
        expected_d3f = case.get("expected_d3fend_ids", [])
        rationale = case.get("ground_truth_rationale", "")

        logger.info(f"[{idx}/{len(cases)}] Evaluating {sid} ({qtype}): {query[:60]}...")

        start_time = time.perf_counter()
        db = SessionLocal()
        retrieval_error = None
        retrieved_att = []
        retrieved_d3f = []

        try:
            retriever = RetrievalService(db)
            res = retriever.retrieve(
                advisory_text=query,
                max_candidates=max_candidates,
                include_d3fend=True,
            )
            retrieved_att = [c["technique_id"] for c in res.get("candidates", [])]
            retrieved_d3f = [d["d3fend_id"] for d in res.get("defensive_countermeasures", [])]
        except Exception as exc:
            logger.error(f"  ✗ {sid} Retrieval exception: {exc}")
            retrieval_error = str(exc)
        finally:
            db.close()

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        eval_res = evaluate_case_retrieval(
            retrieved_attack_ids=retrieved_att,
            expected_attack_ids=expected_att,
            retrieved_d3fend_ids=retrieved_d3f,
            expected_d3fend_ids=expected_d3f,
            k=k,
            duration_ms=duration_ms,
            error=retrieval_error,
        )

        record = {
            "sample_id": sid,
            "query": query,
            "query_type": qtype,
            "expected_attack_ids": expected_att,
            "retrieved_attack_ids": retrieved_att,
            "expected_d3fend_ids": expected_d3f,
            "retrieved_d3fend_ids": retrieved_d3f,
            "ground_truth_rationale": rationale,
            **eval_res,
        }
        case_records.append(record)

        if eval_res.get("is_negative"):
            status_text = "Clean" if eval_res.get("is_correct_empty") else ("Error" if eval_res.get("has_error") else "FalsePositive")
            logger.info(f"  ✓ {sid} (Negative): Status={status_text}, Latency={duration_ms:.1f}ms")
        else:
            hit_str = "Hit" if eval_res["attack_hit_rate_at_k"] >= 1.0 else "Miss"
            logger.info(
                f"  ✓ {sid}: ATT Rec@{k}={eval_res['attack_recall_at_k']*100:.0f}%, "
                f"ATT Hit={hit_str}, ATT MRR={eval_res['attack_mrr']:.2f}, "
                f"D3F Rec@{k}={eval_res['d3fend_recall_at_k']*100:.0f}%, "
                f"Latency={duration_ms:.1f}ms"
            )

    # Aggregate metrics
    metrics = aggregate_retrieval_metrics(case_records)

    # Print ASCII summary report
    print_retrieval_summary_table(metrics, case_records, k=k)

    # Verify acceptance criteria
    eff_thresholds = {**DEFAULT_RETRIEVAL_THRESHOLDS, **(thresholds or {})}
    success, failures, check_details = verify_retrieval_acceptance(
        metrics=metrics,
        thresholds=eff_thresholds,
        k=k,
    )

    # Print acceptance report
    print_retrieval_acceptance_report(
        success=success,
        failures=failures,
        checks=check_details,
        thresholds=eff_thresholds,
        k=k,
    )

    # Export reports
    export_retrieval_results(
        out_dir,
        metrics,
        case_records,
        k=k,
        db_info=db_info,
        acceptance_summary={
            "success": success,
            "thresholds": eff_thresholds,
            "failures": failures,
            "checks": check_details,
        },
    )

    return success


def main():
    parser = argparse.ArgumentParser(description="ITDR Live PostgreSQL/pgvector Retrieval Evaluation Runner")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(Path(__file__).parent / "datasets" / "itdr_retrieval_eval.jsonl"),
        help="Path to retrieval evaluation dataset JSONL",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(DEFAULT_RETRIEVAL_RESULTS_DIR),
        help="Directory to save retrieval evaluation JSON and CSV reports",
    )
    parser.add_argument(
        "--k",
        type=int,
        default=5,
        help="Top-K evaluation cutoff (default: 5)",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=8,
        help="Max candidates retrieved per query (default: 8)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of test cases to run",
    )
    parser.add_argument(
        "--sample-ids",
        nargs="+",
        default=None,
        help="Filter to specific sample_ids (e.g. --sample-ids ret-001 ret-002)",
    )
    # Configurable Acceptance Thresholds
    parser.add_argument(
        "--min-attack-recall",
        type=float,
        default=DEFAULT_RETRIEVAL_THRESHOLDS["min_attack_recall"],
        help=f"Minimum ATT&CK Recall@K required to pass (default: {DEFAULT_RETRIEVAL_THRESHOLDS['min_attack_recall']})",
    )
    parser.add_argument(
        "--min-attack-hit-rate",
        type=float,
        default=DEFAULT_RETRIEVAL_THRESHOLDS["min_attack_hit_rate"],
        help=f"Minimum ATT&CK Hit Rate@K required to pass (default: {DEFAULT_RETRIEVAL_THRESHOLDS['min_attack_hit_rate']})",
    )
    parser.add_argument(
        "--min-d3fend-recall",
        type=float,
        default=DEFAULT_RETRIEVAL_THRESHOLDS["min_d3fend_recall"],
        help=f"Minimum D3FEND Recall@K required to pass (default: {DEFAULT_RETRIEVAL_THRESHOLDS['min_d3fend_recall']})",
    )
    parser.add_argument(
        "--min-d3fend-hit-rate",
        type=float,
        default=DEFAULT_RETRIEVAL_THRESHOLDS["min_d3fend_hit_rate"],
        help=f"Minimum D3FEND Hit Rate@K required to pass (default: {DEFAULT_RETRIEVAL_THRESHOLDS['min_d3fend_hit_rate']})",
    )
    parser.add_argument(
        "--max-negative-fpr",
        type=float,
        default=DEFAULT_RETRIEVAL_THRESHOLDS["max_negative_fpr"],
        help=f"Maximum allowed False Positive Rate for negative queries (default: {DEFAULT_RETRIEVAL_THRESHOLDS['max_negative_fpr']})",
    )
    parser.add_argument(
        "--max-error-rate",
        type=float,
        default=DEFAULT_RETRIEVAL_THRESHOLDS["max_error_rate"],
        help=f"Maximum allowed retrieval error rate (default: {DEFAULT_RETRIEVAL_THRESHOLDS['max_error_rate']})",
    )

    args = parser.parse_args()
    dataset_path = Path(args.dataset)
    output_dir = Path(args.output_dir)

    thresholds = {
        "min_attack_recall": args.min_attack_recall,
        "min_attack_hit_rate": args.min_attack_hit_rate,
        "min_d3fend_recall": args.min_d3fend_recall,
        "min_d3fend_hit_rate": args.min_d3fend_hit_rate,
        "max_negative_fpr": args.max_negative_fpr,
        "max_error_rate": args.max_error_rate,
    }

    success = run_retrieval_evaluation(
        dataset_path=dataset_path,
        output_dir=output_dir,
        k=args.k,
        max_candidates=args.max_candidates,
        limit=args.limit,
        sample_ids=args.sample_ids,
        thresholds=thresholds,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
