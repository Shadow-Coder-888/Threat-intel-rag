import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlflow
import time
from rag_engine import query_cve, retrieve_cves

TEST_DATASET = [
    {
        "question": "What are critical remote code execution CVEs?",
        "expected_keywords": ["remote", "execution", "critical", "code"],
    },
    {
        "question": "What is the mitigation for buffer overflow vulnerabilities?",
        "expected_keywords": ["buffer", "overflow", "patch", "update", "input"],
    },
    {
        "question": "What CVEs affect Windows with high severity?",
        "expected_keywords": ["windows", "high", "critical"],
    },
    {
        "question": "What are denial of service vulnerabilities?",
        "expected_keywords": ["denial", "service", "dos"],
    },
    {
        "question": "List CVEs with CVSS score above 9",
        "expected_keywords": ["critical", "9", "cvss", "score"],
    },
]


def compute_answer_relevancy(answer: str, question: str) -> float:
    question_words = set(question.lower().split())
    answer_words = set(answer.lower().split())
    overlap = question_words & answer_words
    return round(len(overlap) / len(question_words), 2)


def compute_keyword_recall(answer: str, expected_keywords: list) -> float:
    answer_lower = answer.lower()
    matched = sum(1 for kw in expected_keywords if kw.lower() in answer_lower)
    return round(matched / len(expected_keywords), 2)


def compute_context_relevancy(question: str, source_cves: list) -> float:
    if not source_cves:
        return 0.0
    question_words = set(question.lower().split())
    scores = []
    for cve in source_cves:
        desc_words = set(cve["description"].lower().split())
        overlap = question_words & desc_words
        scores.append(len(overlap) / len(question_words))
    return round(sum(scores) / len(scores), 2)


def evaluate():
    mlflow.set_experiment("threat-intel-rag-evaluation")

    all_relevancy = []
    all_recall = []
    all_context = []
    all_latency = []

    with mlflow.start_run(run_name="rag_evaluation"):
        mlflow.log_param("model", "llama-3.1-8b-instant")
        mlflow.log_param("embedding_model", "BAAI/bge-small-en-v1.5")
        mlflow.log_param("top_k", 5)
        mlflow.log_param("num_test_questions", len(TEST_DATASET))

        for i, test in enumerate(TEST_DATASET):
            print(f"\n[{i+1}/{len(TEST_DATASET)}] Evaluating: {test['question']}")

            start = time.time()
            result = query_cve(test["question"])
            latency = round(time.time() - start, 2)

            relevancy = compute_answer_relevancy(result["answer"], test["question"])
            recall = compute_keyword_recall(result["answer"], test["expected_keywords"])
            context = compute_context_relevancy(test["question"], result["source_cves"])

            all_relevancy.append(relevancy)
            all_recall.append(recall)
            all_context.append(context)
            all_latency.append(latency)

            mlflow.log_metric("answer_relevancy", relevancy, step=i)
            mlflow.log_metric("keyword_recall", recall, step=i)
            mlflow.log_metric("context_relevancy", context, step=i)
            mlflow.log_metric("latency_seconds", latency, step=i)

            print(f"  Answer Relevancy : {relevancy}")
            print(f"  Keyword Recall   : {recall}")
            print(f"  Context Relevancy: {context}")
            print(f"  Latency          : {latency}s")

        avg_relevancy = round(sum(all_relevancy) / len(all_relevancy), 2)
        avg_recall = round(sum(all_recall) / len(all_recall), 2)
        avg_context = round(sum(all_context) / len(all_context), 2)
        avg_latency = round(sum(all_latency) / len(all_latency), 2)

        mlflow.log_metric("avg_answer_relevancy", avg_relevancy)
        mlflow.log_metric("avg_keyword_recall", avg_recall)
        mlflow.log_metric("avg_context_relevancy", avg_context)
        mlflow.log_metric("avg_latency_seconds", avg_latency)

        print(f"\n{'='*50}")
        print(f"EVALUATION SUMMARY")
        print(f"{'='*50}")
        print(f"Avg Answer Relevancy : {avg_relevancy}")
        print(f"Avg Keyword Recall   : {avg_recall}")
        print(f"Avg Context Relevancy: {avg_context}")
        print(f"Avg Latency          : {avg_latency}s")
        print(f"{'='*50}")
        print(f"\n✅ Results logged to MLflow!")
        print(f"Run: mlflow ui")
        print(f"Open: http://localhost:5000")


if __name__ == "__main__":
    evaluate()