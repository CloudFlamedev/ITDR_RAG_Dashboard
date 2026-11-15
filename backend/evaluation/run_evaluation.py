"""
ITDR Pipeline Evaluation Runner.
Executes Golden Dataset against the LangGraph threat analysis workflow in safe evaluation mode.
Computes:
1. Deterministic Retrieval Metrics: Precision@K, Recall@K, missing/unexpected IDs.
2. Segmented Analysis: Explicit-ID vs No-ID query categories.
3. RAGAS Metrics: Context Precision, Context Recall, Faithfulness, Answer Relevancy, Factual Correctness.
4. Regression Monitoring against approved baseline.
Exports results to JSON and CSV.
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
from typing import List, Dict, Any, Optional

from app.core.config import get_settings
from app.ai.graph import threat_analysis_app
from evaluation.retrieval_metrics import (
    evaluate_case_retrieval,
    aggregate_retrieval_metrics,
)
from evaluation.ragas_evaluator import RagasEvaluator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("itdr-evaluation-runner")
settings = get_settings()

DATASET_VERSION = "2.0.0"


def load_golden_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    """Loads and validates test cases from JSONL dataset."""
    if not dataset_path.exists():
        raise FileNotFoundError(f"Evaluation dataset not found at {dataset_path}")

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

    logger.info(f"Loaded {len(cases)} evaluation test cases from {dataset_path}")
    return cases


def run_pipeline_for_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes the ITDR LangGraph pipeline in safe evaluation mode.
    Reuses retrieval, ranking, prompt building, and structured generation logic,
    while skipping production database persistence and quota checks.
    """
    sample_id = case.get("sample_id", "unknown")
    question = case["question"]

    initial_state = {
        "report_id": f"EVAL-{sample_id}-{int(time.time())}",
        "advisory_text": question,
        "sample_id": sample_id,
        "client_restriction": "ALL",
        "itdr_scope": "ITDR Scope Only",
        "view_mode": "ClientReq",
        "include_d3fend": True,
        "max_technique_candidates": 8,
        "created_by_user_id": None,
        "extracted_indicators": {},
        "retrieval_query": "",
        "candidate_techniques": [],
        "d3fend_countermeasures": [],
        "coverage_records": [],
        "highest_retrieval_confidence": 0.0,
        "highest_vector_similarity": 0.0,
        "highest_rerank_score": None,
        "rerank_applied": False,
        "insufficient_evidence": False,
        "prompt_messages": [],
        "raw_llm_response": None,
        "structured_report": None,
        "citations": [],
        "evaluation_contexts": [],
        "unsupported_attack_ids": [],
        "unsupported_d3fend_ids": [],
        "invalid_citations_count": 0,
        "trace_steps": [],
        "status": "INITIALIZING",
        "error": None,
        "evaluation_mode": True,  # SAFE EVALUATION MODE: No DB persistence or quota consumption
    }

    start = time.perf_counter()
    result = threat_analysis_app.invoke(initial_state)
    duration_sec = round(time.perf_counter() - start, 3)

    return {
        "result": result,
        "duration_sec": duration_sec,
    }


def compare_against_baseline(
    current_metrics: Dict[str, Any],
    baseline_path: Path,
    tolerance: float = 0.10,
) -> Dict[str, Any]:
    """
    Compares current evaluation metrics against approved baseline.
    Flags significant drops exceeding tolerance threshold.
    """
    if not baseline_path.exists():
        logger.info(f"No approved baseline file found at {baseline_path}. Regression check skipped.")
        return {
            "has_baseline": False,
            "passed": True,
            "regressions": [],
            "message": "First evaluation run: save as baseline for subsequent regression checks.",
        }

    with open(baseline_path, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    baseline_metrics = baseline.get("aggregate_metrics", {})
    regressions = []

    # Metrics to track for regression
    tracked_metrics = [
        ("combined_attack_precision_at_k", ("retrieval", "combined", "mean_attack_precision_at_k")),
        ("combined_attack_recall_at_k", ("retrieval", "combined", "mean_attack_recall_at_k")),
        ("no_id_attack_precision_at_k", ("retrieval", "no_id_queries", "mean_attack_precision_at_k")),
        ("no_id_attack_recall_at_k", ("retrieval", "no_id_queries", "mean_attack_recall_at_k")),
        ("context_precision", ("ragas", "mean_context_precision")),
        ("context_recall", ("ragas", "mean_context_recall")),
        ("faithfulness", ("ragas", "mean_faithfulness")),
        ("answer_relevancy", ("ragas", "mean_answer_relevancy")),
        ("factual_correctness", ("ragas", "mean_factual_correctness")),
    ]

    def _get_val(d: Dict[str, Any], keys: tuple) -> Optional[float]:
        curr = d
        for k in keys:
            if not isinstance(curr, dict) or k not in curr:
                return None
            curr = curr[k]
        return float(curr) if curr is not None else None

    for label, path_keys in tracked_metrics:
        base_val = _get_val(baseline_metrics, path_keys)
        curr_val = _get_val(current_metrics, path_keys)

        if base_val is not None and curr_val is not None:
            allowed_floor = round(base_val * (1.0 - tolerance), 4)
            if curr_val < allowed_floor:
                drop_pct = round(((base_val - curr_val) / base_val) * 100, 2)
                regressions.append({
                    "metric": label,
                    "baseline_score": base_val,
                    "current_score": curr_val,
                    "drop_percent": drop_pct,
                    "allowed_floor": allowed_floor,
                })

    passed = len(regressions) == 0
    return {
        "has_baseline": True,
        "passed": passed,
        "tolerance_used": tolerance,
        "regressions": regressions,
    }


def export_results(
    output_dir: Path,
    report_data: Dict[str, Any],
    case_results: List[Dict[str, Any]],
) -> Dict[str, Path]:
    """Exports evaluation results to structured JSON and CSV files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"evaluation_results_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    csv_path = output_dir / f"evaluation_results_{ts}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "sample_id",
            "case_type",
            "has_explicit_attack_id",
            "expected_attack_ids",
            "retrieved_attack_ids",
            "attack_precision_at_k",
            "attack_recall_at_k",
            "missing_attack_ids",
            "unexpected_attack_ids",
            "expected_d3fend_ids",
            "retrieved_d3fend_ids",
            "d3fend_precision_at_k",
            "d3fend_recall_at_k",
            "is_fallback_generation",
            "model_provider",
            "highest_vector_similarity",
            "highest_rerank_score",
            "context_precision",
            "context_recall",
            "faithfulness",
            "answer_relevancy",
            "factual_correctness",
            "duration_sec",
        ])

        for c in case_results:
            writer.writerow([
                c["sample_id"],
                c["case_type"],
                c["has_explicit_attack_id"],
                ";".join(c["expected_attack_ids"]),
                ";".join(c["retrieved_attack_ids"]),
                c["attack_precision_at_k"],
                c["attack_recall_at_k"],
                ";".join(c.get("missing_attack_ids", [])),
                ";".join(c.get("unexpected_attack_ids", [])),
                ";".join(c["expected_d3fend_ids"]),
                ";".join(c["retrieved_d3fend_ids"]),
                c["d3fend_precision_at_k"],
                c["d3fend_recall_at_k"],
                c.get("is_fallback_generation", False),
                c.get("model_provider", ""),
                c.get("highest_vector_similarity", 0.0),
                c.get("highest_rerank_score", ""),
                c.get("context_precision", ""),
                c.get("context_recall", ""),
                c.get("faithfulness", ""),
                c.get("answer_relevancy", ""),
                c.get("factual_correctness", ""),
                c.get("duration_sec", 0.0),
            ])

    logger.info(f"Exported evaluation JSON: {json_path}")
    logger.info(f"Exported evaluation CSV:  {csv_path}")

    return {"json": json_path, "csv": csv_path}


def print_summary_table(report: Dict[str, Any], regression_res: Dict[str, Any]):
    """Renders formatted ASCII summary table of evaluation results to terminal."""
    meta = report["metadata"]
    ret = report["retrieval_metrics"]
    ragas_res = report["ragas_metrics"]["aggregate_scores"]

    print("\n" + "=" * 80)
    print("           ITDR PIPELINE EVALUATION & BENCHMARK REPORT")
    print("=" * 80)
    print(f"Timestamp:         {meta['timestamp']}")
    print(f"Dataset:           {meta['dataset_path']} (v{meta['dataset_version']})")
    print(f"Total Cases:       {meta['total_cases_evaluated']}")
    print(f"Generation Model:  {meta['generation_model']} (Provider: {meta['generation_provider']})")
    print(f"Evaluator Model:   {meta['evaluator_model']}")
    print(f"Embedding Model:   {meta['embedding_model']}")
    print(f"Reranker Model:    {meta['reranker_model']}")
    print("-" * 80)
    print("1. DETERMINISTIC RETRIEVAL PERFORMANCE (Precision@5 & Recall@5)")
    print("-" * 80)
    print(f"{'Category':<28} | {'Count':<6} | {'ATT&CK Prec':<12} | {'ATT&CK Rec':<11} | {'D3FEND Prec':<11} | {'D3FEND Rec':<11}")
    print("-" * 80)

    comb = ret["combined"]
    exp = ret["explicit_id_queries"]
    no_id = ret["no_id_queries"]

    print(f"{'Combined Dataset':<28} | {comb['count']:<6} | {comb['mean_attack_precision_at_k']:<12.4f} | {comb['mean_attack_recall_at_k']:<11.4f} | {comb['mean_d3fend_precision_at_k']:<11.4f} | {comb['mean_d3fend_recall_at_k']:<11.4f}")
    print(f"{'Explicit ATT&CK IDs':<28} | {exp['count']:<6} | {exp['mean_attack_precision_at_k']:<12.4f} | {exp['mean_attack_recall_at_k']:<11.4f} | {exp['mean_d3fend_precision_at_k']:<11.4f} | {exp['mean_d3fend_recall_at_k']:<11.4f}")
    print(f"{'No-ID Queries (Semantic)':<28} | {no_id['count']:<6} | {no_id['mean_attack_precision_at_k']:<12.4f} | {no_id['mean_attack_recall_at_k']:<11.4f} | {no_id['mean_d3fend_precision_at_k']:<11.4f} | {no_id['mean_d3fend_recall_at_k']:<11.4f}")
    print("-" * 80)

    print("2. RAGAS AGENTIC RAG METRICS")
    print("-" * 80)
    def _fmt(v): return f"{v:.4f}" if v is not None else "N/A (Skipped)"
    print(f"Context Precision:     {_fmt(ragas_res.get('mean_context_precision'))}")
    print(f"Context Recall:        {_fmt(ragas_res.get('mean_context_recall'))}")
    print(f"Faithfulness:          {_fmt(ragas_res.get('mean_faithfulness'))}")
    print(f"Answer Relevancy:      {_fmt(ragas_res.get('mean_answer_relevancy'))}")
    print(f"Factual Correctness:   {_fmt(ragas_res.get('mean_factual_correctness'))}")
    print("-" * 80)

    print("3. REGRESSION MONITORING")
    print("-" * 80)
    if not regression_res.get("has_baseline"):
        print(f"Status: PASS ({regression_res.get('message')})")
    elif regression_res.get("passed"):
        print(f"Status: PASS (No regression detected against baseline, tolerance={regression_res.get('tolerance_used')*100:.0f}%)")
    else:
        print(f"Status: FAILED (Regressions detected exceeding {regression_res.get('tolerance_used')*100:.0f}% tolerance!):")
        for reg in regression_res.get("regressions", []):
            print(f"  - {reg['metric']}: dropped {reg['drop_percent']}% (Baseline: {reg['baseline_score']}, Current: {reg['current_score']}, Floor: {reg['allowed_floor']})")
    print("=" * 80 + "\n")


def run_evaluation(
    dataset_path: Path,
    limit: Optional[int] = None,
    sample_ids: Optional[List[str]] = None,
    skip_ragas: bool = False,
    output_dir: Optional[Path] = None,
    baseline_path: Optional[Path] = None,
    generate_baseline: bool = False,
    tolerance: float = 0.10,
) -> bool:
    """Main evaluation orchestrator function."""
    cases = load_golden_dataset(dataset_path)

    # Filter sample IDs if requested
    if sample_ids:
        target_ids = set(s.strip() for s in sample_ids)
        cases = [c for c in cases if c.get("sample_id") in target_ids]

    # Limit cases if requested
    if limit and limit > 0:
        cases = cases[:limit]

    logger.info(f"Starting evaluation on {len(cases)} test cases...")

    case_eval_records = []
    ragas_samples_input = []
    model_providers_seen = set()

    for idx, case in enumerate(cases, start=1):
        s_id = case.get("sample_id", f"case-{idx}")
        logger.info(f"[{idx}/{len(cases)}] Evaluating sample {s_id}: '{case['question'][:70]}...'")

        res_pack = run_pipeline_for_case(case)
        result = res_pack["result"]
        duration_sec = res_pack["duration_sec"]

        # 1. Deterministic Candidate IDs Extraction
        retrieved_candidates = result.get("candidate_techniques", [])
        retrieved_d3fend = result.get("d3fend_countermeasures", [])

        ret_attack_ids = [c["technique_id"] for c in retrieved_candidates]
        ret_d3fend_ids = [d["d3fend_id"] for d in retrieved_d3fend]

        exp_attack_ids = case.get("expected_attack_ids", [])
        exp_d3fend_ids = case.get("expected_d3fend_ids", [])

        # Evaluate individual retrieval metrics
        case_ret = evaluate_case_retrieval(
            retrieved_attack_ids=ret_attack_ids,
            expected_attack_ids=exp_attack_ids,
            retrieved_d3fend_ids=ret_d3fend_ids,
            expected_d3fend_ids=exp_d3fend_ids,
            k=5,
        )

        structured_rep = result.get("structured_report") or {}
        model_prov = structured_rep.get("model_provider") or "Deterministic Grounded Synthesis"
        model_providers_seen.add(model_prov)
        is_fallback = bool(result.get("is_fallback_generation", False))

        # Format generated answer text for RAGAS evaluation
        response_text = (
            structured_rep.get("executive_summary")
            or structured_rep.get("report_title")
            or result.get("raw_llm_response")
            or "No generated response."
        )

        record = {
            "sample_id": s_id,
            "question": case["question"],
            "case_type": case.get("case_type", "general"),
            "has_explicit_attack_id": bool(case.get("has_explicit_attack_id", False)),
            "expected_attack_ids": exp_attack_ids,
            "retrieved_attack_ids": ret_attack_ids,
            "expected_d3fend_ids": exp_d3fend_ids,
            "retrieved_d3fend_ids": ret_d3fend_ids,
            "attack_precision_at_k": case_ret["attack_precision_at_k"],
            "attack_recall_at_k": case_ret["attack_recall_at_k"],
            "missing_attack_ids": case_ret["missing_attack_ids"],
            "unexpected_attack_ids": case_ret["unexpected_attack_ids"],
            "d3fend_precision_at_k": case_ret["d3fend_precision_at_k"],
            "d3fend_recall_at_k": case_ret["d3fend_recall_at_k"],
            "missing_d3fend_ids": case_ret["missing_d3fend_ids"],
            "unexpected_d3fend_ids": case_ret["unexpected_d3fend_ids"],
            "is_fallback_generation": is_fallback,
            "model_provider": model_prov,
            "highest_vector_similarity": float(result.get("highest_vector_similarity", 0.0) or 0.0),
            "highest_rerank_score": result.get("highest_rerank_score"),
            "unsupported_attack_ids": result.get("unsupported_attack_ids", []),
            "unsupported_d3fend_ids": result.get("unsupported_d3fend_ids", []),
            "invalid_citations_count": result.get("invalid_citations_count", 0),
            "duration_sec": duration_sec,
        }
        case_eval_records.append(record)

        # Prepare payload for RAGAS
        ragas_samples_input.append({
            "sample_id": s_id,
            "question": case["question"],
            "contexts": result.get("evaluation_contexts", []),
            "response": response_text,
            "reference": case.get("reference_answer", ""),
            "is_fallback_generation": is_fallback,
        })

    # 2. Compute Aggregate Retrieval Metrics
    agg_retrieval = aggregate_retrieval_metrics(case_eval_records)

    # 3. Compute RAGAS Metrics
    if not skip_ragas:
        ragas_evaluator = RagasEvaluator()
        ragas_result = ragas_evaluator.evaluate_samples(ragas_samples_input)
    else:
        logger.info("RAGAS evaluation skipped via --skip-ragas flag.")
        ragas_result = {
            "status": "SKIPPED",
            "reason": "--skip-ragas flag specified",
            "per_sample_scores": [{"sample_id": c["sample_id"]} for c in case_eval_records],
            "aggregate_scores": {
                "mean_context_precision": None,
                "mean_context_recall": None,
                "mean_faithfulness": None,
                "mean_answer_relevancy": None,
                "mean_factual_correctness": None,
            },
        }

    # Merge RAGAS per-sample scores into case records
    ragas_by_id = {s["sample_id"]: s for s in ragas_result.get("per_sample_scores", [])}
    for c in case_eval_records:
        r_scores = ragas_by_id.get(c["sample_id"], {})
        c["context_precision"] = r_scores.get("context_precision")
        c["context_recall"] = r_scores.get("context_recall")
        c["faithfulness"] = r_scores.get("faithfulness")
        c["answer_relevancy"] = r_scores.get("answer_relevancy")
        c["factual_correctness"] = r_scores.get("factual_correctness")

    # 4. Assemble Final Report Object
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report_data = {
        "metadata": {
            "evaluation_id": f"EVAL-{int(time.time())}",
            "timestamp": now_iso,
            "dataset_version": DATASET_VERSION,
            "dataset_path": str(dataset_path),
            "total_cases_evaluated": len(cases),
            "generation_model": settings.effective_llm_model,
            "generation_provider": ", ".join(sorted(list(model_providers_seen))),
            "evaluator_model": os.environ.get("EVALUATOR_LLM_MODEL", "llama-3.3-70b-versatile"),
            "embedding_model": "BAAI/bge-m3 (384d)",
            "reranker_model": settings.effective_rerank_model,
        },
        "retrieval_metrics": agg_retrieval,
        "ragas_metrics": ragas_result,
        "case_details": case_eval_records,
    }

    # 5. Baseline Comparison & Regression Check
    base_file = baseline_path or (Path(__file__).parent / "baseline.json")
    regression_check = compare_against_baseline(
        current_metrics={
            "retrieval": agg_retrieval,
            "ragas": ragas_result.get("aggregate_scores", {}),
        },
        baseline_path=base_file,
        tolerance=tolerance,
    )
    report_data["regression_monitoring"] = regression_check

    # If requested or if no baseline exists, save baseline
    if generate_baseline or not base_file.exists():
        logger.info(f"Saving current evaluation results as approved baseline to {base_file}...")
        baseline_payload = {
            "baseline_generated_at": now_iso,
            "dataset_version": DATASET_VERSION,
            "aggregate_metrics": {
                "retrieval": agg_retrieval,
                "ragas": ragas_result.get("aggregate_scores", {}),
            },
        }
        with open(base_file, "w", encoding="utf-8") as f:
            json.dump(baseline_payload, f, indent=2)

    # 6. Export Results
    out_dir = output_dir or (Path(__file__).parent / "results")
    export_results(out_dir, report_data, case_eval_records)

    # 7. Print Summary
    print_summary_table(report_data, regression_check)

    return regression_check["passed"]


def main():
    parser = argparse.ArgumentParser(description="ITDR Pipeline Evaluation Runner")
    parser.add_argument("--dataset", type=str, default=None, help="Path to evaluation JSONL dataset")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of test cases to evaluate")
    parser.add_argument("--sample-ids", type=str, default=None, help="Comma-separated sample IDs to evaluate")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory to save JSON and CSV results")
    parser.add_argument("--skip-ragas", action="store_true", help="Skip RAGAS evaluation and run deterministic metrics only")
    parser.add_argument("--baseline", type=str, default=None, help="Path to approved baseline JSON")
    parser.add_argument("--generate-baseline", action="store_true", help="Generate or update baseline.json from this run")
    parser.add_argument("--tolerance", type=float, default=0.10, help="Allowed regression drop fraction (default: 0.10)")

    args = parser.parse_args()

    default_dataset = Path(__file__).parent / "datasets" / "itdr_eval.jsonl"
    dataset_path = Path(args.dataset) if args.dataset else default_dataset
    output_dir = Path(args.output_dir) if args.output_dir else (Path(__file__).parent / "results")
    baseline_path = Path(args.baseline) if args.baseline else None

    sample_ids = [s.strip() for s in args.sample_ids.split(",") if s.strip()] if args.sample_ids else None

    success = run_evaluation(
        dataset_path=dataset_path,
        limit=args.limit,
        sample_ids=sample_ids,
        skip_ragas=args.skip_ragas,
        output_dir=output_dir,
        baseline_path=baseline_path,
        generate_baseline=args.generate_baseline,
        tolerance=args.tolerance,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
