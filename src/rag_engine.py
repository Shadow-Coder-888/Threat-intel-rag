import os
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer
from groq import Groq

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY not found in .env file!")

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_API_KEY = os.getenv("QDRANT_API_KEY", None)
COLLECTION_NAME = "cves"
EMBED_MODEL_NAME = "BAAI/bge-small-en-v1.5"
GROQ_MODEL_NAME = "llama-3.1-8b-instant"
TOP_K = 5

embed_model = SentenceTransformer(EMBED_MODEL_NAME)
qdrant_client = QdrantClient(
    url=QDRANT_URL,
    api_key=QDRANT_API_KEY,
)
groq_client = Groq(api_key=GROQ_API_KEY)


def retrieve_cves(question: str) -> list:
    query_vector = embed_model.encode(question).tolist()
    results = qdrant_client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=TOP_K,
    ).points

    cves = []
    for r in results:
        cves.append({
            "cve_id": r.payload.get("cve_id", "Unknown"),
            "description": r.payload.get("description", ""),
            "severity": r.payload.get("severity", ""),
            "score": r.payload.get("score", ""),
            "relevance_score": round(r.score, 4),
        })
    return cves


def build_context(cves: list) -> str:
    context = ""
    for cve in cves:
        context += f"""
CVE ID: {cve['cve_id']}
Severity: {cve['severity']} (CVSS: {cve['score']})
Description: {cve['description']}
---"""
    return context.strip()


def query_cve(question: str) -> dict:
    print(f"\n🔍 Query: {question}")

    cves = retrieve_cves(question)
    context = build_context(cves)

    prompt = f"""You are a cybersecurity expert. Answer the question using only the CVE data provided below.
If the exact CVE is not in the data, say so and provide general guidance based on similar CVEs.

CVE DATA:
{context}

QUESTION: {question}

ANSWER:"""

    response = groq_client.chat.completions.create(
        model=GROQ_MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=512,
    )

    answer = response.choices[0].message.content

    return {
        "question": question,
        "answer": answer,
        "source_cves": cves,
    }


if __name__ == "__main__":
    test_questions = [
        "What are the most critical remote code execution CVEs?",
        "What are mitigations for buffer overflow vulnerabilities?",
        "What CVEs affect Microsoft Windows with high severity?",
    ]

    for question in test_questions:
        result = query_cve(question)
        print(f"\n{'='*60}")
        print(f"Q: {result['question']}")
        print(f"\nA: {result['answer']}")
        print(f"\n📄 Sources ({len(result['source_cves'])} CVEs):")
        for src in result['source_cves']:
            print(f"  - {src['cve_id']} | {src['severity']} | CVSS: {src['score']}")
        print(f"{'='*60}")