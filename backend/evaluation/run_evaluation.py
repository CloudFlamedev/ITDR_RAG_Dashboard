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
from evaluation.ragas_evaluator import RagasEvaluator, format_report_for_evaluation
from evaluation.run_security_evaluation import run_security_evaluation

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
        # Security Guardrail fields
        "input_security_status": "CLEAN",
        "input_security_risk": 0.0,
        "input_security_findings": [],
        "retrieved_context_security_status": "CLEAN",
        "retrieved_context_findings": [],
        "suspicious_document_ids": [],
        "quarantined_document_ids": [],
        "raw_retrieved_candidates": [],
        "raw_retrieved_d3fend": [],
        "trusted_candidate_techniques": [],
        "trusted_d3fend_countermeasures": [],
        "output_security_status": "CLEAN",
        "output_security_findings": [],
        "review_reasons": [],
        "guardrail_metadata": {},
        "validation_status": "PENDING",
        "is_schema_repaired": False,
        "is_fallback_generation": False,
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
            "status": "NOT_BASELINED",
            "passed": False,
            "regressions": [],
            "message": f"No approved baseline found at {baseline_path}. Run with --generate-baseline after review.",
        }

    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except Exception as exc:
        logger.error(f"Failed to read baseline file at {baseline_path}: {exc}")
        return {
            "has_baseline": True,
            "status": "EVALUATION_ERROR",
            "passed": False,
            "regressions": [],
            "message": f"Failed to load baseline from {baseline_path}: {exc}",
        }

    baseline_metrics = baseline.get("aggregate_metrics", {})
    if not baseline_metrics:
        return {
            "has_baseline": True,
            "status": "EVALUATION_ERROR",
            "passed": False,
            "regressions": [],
            "message": f"Baseline file at {baseline_path} missing aggregate_metrics.",
        }
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
        "status": "PASSED" if passed else "FAILED",
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
            "has_empty_context",
            "retrieval_context_status",
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
                c.get("has_empty_context", False),
                c.get("retrieval_context_status", "RETRIEVED"),
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
    def _fmt(v): return f"{v:.4f}" if v is not None else "N/A"
    print(f"Context Precision (All):           {_fmt(ragas_res.get('mean_context_precision'))}")
    print(f"Context Recall (All):              {_fmt(ragas_res.get('mean_context_recall'))}")
    print(f"Calculated Context Precision:      {_fmt(ragas_res.get('mean_calculated_context_precision'))} (excluding assigned empty failures)")
    print(f"Calculated Context Recall:         {_fmt(ragas_res.get('mean_calculated_context_recall'))} (excluding assigned empty failures)")
    print(f"Faithfulness:                      {_fmt(ragas_res.get('mean_faithfulness'))} (fallback generations excluded)")
    print(f"Answer Relevancy:                  {_fmt(ragas_res.get('mean_answer_relevancy'))} (fallback generations excluded)")
    print(f"Factual Correctness:               {_fmt(ragas_res.get('mean_factual_correctness'))} (fallback generations excluded)")
    print(f"Empty Retrieval Context Count:     {ragas_res.get('empty_context_count', 0)}")
    print(f"Retrieved Context Count:           {ragas_res.get('retrieved_context_count', 0)}")
    print(f"LLM Generation Count:              {ragas_res.get('llm_generation_count', 0)}")
    print(f"Fallback Generation Count:         {ragas_res.get('fallback_generation_count', 0)}")
    print("-" * 80)

    print("3. REGRESSION MONITORING")
    print("-" * 80)
    status = regression_res.get("status", "NOT_BASELINED")
    if status == "PASSED":
        print(f"Status: PASSED (No regression detected against baseline, tolerance={regression_res.get('tolerance_used', 0.1)*100:.0f}%)")
    elif status == "FAILED":
        print(f"Status: FAILED (Regressions detected exceeding {regression_res.get('tolerance_used', 0.1)*100:.0f}% tolerance!):")
        for reg in regression_res.get("regressions", []):
            print(f"  - {reg['metric']}: dropped {reg['drop_percent']}% (Baseline: {reg['baseline_score']}, Current: {reg['current_score']}, Floor: {reg['allowed_floor']})")
    elif status == "NOT_BASELINED":
        print(f"Status: NOT_BASELINED ({regression_res.get('message', 'No baseline found')})")
    elif status == "EVALUATION_ERROR":
        print(f"Status: EVALUATION_ERROR ({regression_res.get('message', 'Evaluation error occurred')})")
    else:
        print(f"Status: {status} ({regression_res.get('message', '')})")
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
    include_security: bool = False,
    security_dataset_path: Optional[Path] = None,
    retrieval_only: bool = False,
    ragas_only: bool = False,
) -> bool:
    """Main evaluation orchestrator function."""
    if retrieval_only:
        skip_ragas = True
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

        # Format complete structured report for RAGAS evaluation (evaluating complete report, excluding metadata)
        if isinstance(structured_rep, dict) and structured_rep:
            response_text = format_report_for_evaluation(structured_rep)
        else:
            response_text = result.get("raw_llm_response") or "No generated response."

        eval_contexts = result.get("evaluation_contexts", [])
        has_empty_ctx = not bool(eval_contexts)
        ret_status = "EMPTY_CONTEXT_ASSIGNED_FAILURE" if has_empty_ctx else "RETRIEVED"

        record = {
            "sample_id": s_id,
            "question": case["question"],
            "case_type": case.get("case_type", "general"),
            "has_explicit_attack_id": bool(case.get("has_explicit_attack_id", False)),
            "has_empty_context": has_empty_ctx,
            "retrieval_context_status": ret_status,
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
            "contexts": eval_contexts,
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
                "mean_calculated_context_precision": None,
                "mean_calculated_context_recall": None,
                "mean_faithfulness": None,
                "mean_answer_relevancy": None,
                "mean_factual_correctness": None,
                "evaluated_samples_count": len(case_eval_records),
                "empty_context_count": sum(1 for c in case_eval_records if c.get("has_empty_context")),
                "retrieved_context_count": sum(1 for c in case_eval_records if not c.get("has_empty_context")),
                "llm_generation_count": sum(1 for c in case_eval_records if not c.get("is_fallback_generation")),
                "fallback_generation_count": sum(1 for c in case_eval_records if c.get("is_fallback_generation")),
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
    empty_ctx_count = sum(1 for c in case_eval_records if c.get("has_empty_context"))
    report_data = {
        "metadata": {
            "evaluation_id": f"EVAL-{int(time.time())}",
            "timestamp": now_iso,
            "dataset_version": DATASET_VERSION,
            "dataset_path": str(dataset_path),
            "total_cases_evaluated": len(cases),
            "empty_context_samples_count": empty_ctx_count,
            "retrieved_context_samples_count": len(cases) - empty_ctx_count,
            "generation_model": settings.effective_llm_model,
            "generation_provider": ", ".join(sorted(list(model_providers_seen))),
            "evaluator_model": ragas_evaluator.model_name if not skip_ragas else "SKIPPED",
            "embedding_model": "BAAI/bge-m3 (384d)",
            "reranker_model": settings.effective_rerank_model,
        },
        "retrieval_metrics": agg_retrieval,
        "ragas_metrics": ragas_result,
        "case_details": case_eval_records,
    }

    # 5. Baseline Comparison & Regression Check
    base_file = baseline_path or (Path(__file__).parent / "baseline.json")
    if ragas_result.get("status") == "ERROR":
        regression_check = {
            "has_baseline": base_file.exists(),
            "status": "EVALUATION_ERROR",
            "passed": False,
            "tolerance_used": tolerance,
            "regressions": [],
            "message": f"RAGAS evaluation failed: {ragas_result.get('reason')}",
        }
    else:
        regression_check = compare_against_baseline(
            current_metrics={
                "retrieval": agg_retrieval,
                "ragas": ragas_result.get("aggregate_scores", {}),
            },
            baseline_path=base_file,
            tolerance=tolerance,
        )
    report_data["regression_monitoring"] = regression_check

    # Baseline generation guardrails: Require explicit generate_baseline flag, complete dataset, and non-null RAGAS scores
    if generate_baseline:
        ragas_scores = ragas_result.get("aggregate_scores", {})
        null_metrics = [
            m for m in [
                "mean_context_precision",
                "mean_context_recall",
                "mean_faithfulness",
                "mean_answer_relevancy",
                "mean_factual_correctness",
            ]
            if ragas_scores.get(m) is None
        ]
        if limit or sample_ids:
            logger.error(
                f"Cannot generate approved baseline on partial dataset run ({len(cases)} cases). "
                "Run the complete golden dataset to generate an approved baseline."
            )
            print("ERROR: Cannot save baseline on partial dataset run.")
        elif null_metrics:
            logger.error(
                f"Cannot generate approved baseline: RAGAS metrics contain null values: {null_metrics}. "
                "Ensure evaluator LLM and embeddings are configured and all metrics succeed."
            )
            print(f"ERROR: Cannot save baseline with null RAGAS metrics: {null_metrics}")
        else:
            logger.info(f"Saving current complete evaluation results as approved baseline to {base_file}...")
            baseline_payload = {
                "baseline_generated_at": now_iso,
                "dataset_version": DATASET_VERSION,
                "dataset_samples_count": len(cases),
                "aggregate_metrics": {
                    "retrieval": agg_retrieval,
                    "ragas": ragas_scores,
                },
            }
            with open(base_file, "w", encoding="utf-8") as f:
                json.dump(baseline_payload, f, indent=2)
            print(f"Approved baseline successfully generated and saved to {base_file}")
            regression_check["status"] = "PASSED"
            regression_check["passed"] = True

    # 6. Export Results
    out_dir = output_dir or (Path(__file__).parent / "results")
    export_results(out_dir, report_data, case_eval_records)

    # 7. Print Summary
    print_summary_table(report_data, regression_check)

    security_passed = True
    if include_security:
        sec_path = security_dataset_path or (Path(__file__).parent / "datasets" / "itdr_security_eval.jsonl")
        sec_out_dir = (output_dir / "security") if output_dir else (Path(__file__).parent / "results" / "security")
        logger.info(f"Running AI security guardrail evaluation from {sec_path}...")
        security_passed = run_security_evaluation(
            dataset_path=sec_path,
            output_dir=sec_out_dir,
            limit=limit,
            sample_ids=sample_ids,
        )

    return (regression_check["status"] == "PASSED") and security_passed


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
    parser.add_argument("--security", action="store_true", help="Run AI security guardrail evaluation")
    parser.add_argument("--security-dataset", type=str, default=None, help="Path to security evaluation JSONL dataset")
    parser.add_argument("--retrieval-only", action="store_true", help="Run retrieval evaluation only (skips RAGAS and security)")
    parser.add_argument("--ragas-only", action="store_true", help="Run RAGAS evaluation only")
    parser.add_argument("--full", action="store_true", help="Run full evaluation (retrieval + RAGAS + security)")

    args = parser.parse_args()

    default_dataset = Path(__file__).parent / "datasets" / "itdr_eval.jsonl"
    dataset_path = Path(args.dataset) if args.dataset else default_dataset
    output_dir = Path(args.output_dir) if args.output_dir else (Path(__file__).parent / "results")
    baseline_path = Path(args.baseline) if args.baseline else None

    sample_ids = [s.strip() for s in args.sample_ids.split(",") if s.strip()] if args.sample_ids else None

    # Handle security-only mode: --security passed without --full
    if args.security and not args.full:
        sec_dataset = Path(args.security_dataset) if args.security_dataset else (Path(__file__).parent / "datasets" / "itdr_security_eval.jsonl")
        sec_out_dir = output_dir / "security" if output_dir else (Path(__file__).parent / "results" / "security")
        success = run_security_evaluation(
            dataset_path=sec_dataset,
            output_dir=sec_out_dir,
            limit=args.limit,
            sample_ids=sample_ids,
        )
        sys.exit(0 if success else 1)

    # Full evaluation mode: retrieval + RAGAS + security
    if args.full:
        sec_dataset = Path(args.security_dataset) if args.security_dataset else (Path(__file__).parent / "datasets" / "itdr_security_eval.jsonl")
        success = run_evaluation(
            dataset_path=dataset_path,
            limit=args.limit,
            sample_ids=sample_ids,
            skip_ragas=args.skip_ragas,
            output_dir=output_dir,
            baseline_path=baseline_path,
            generate_baseline=args.generate_baseline,
            tolerance=args.tolerance,
            include_security=True,
            security_dataset_path=sec_dataset,
        )
        sys.exit(0 if success else 1)

    # Standard evaluation: retrieval-only, ragas-only, or default retrieval + ragas
    skip_ragas = args.skip_ragas or args.retrieval_only
    success = run_evaluation(
        dataset_path=dataset_path,
        limit=args.limit,
        sample_ids=sample_ids,
        skip_ragas=skip_ragas,
        output_dir=output_dir,
        baseline_path=baseline_path,
        generate_baseline=args.generate_baseline,
        tolerance=args.tolerance,
        retrieval_only=args.retrieval_only,
        ragas_only=args.ragas_only,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
