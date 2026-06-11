import json
from pathlib import Path
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer
from tqdm import tqdm


client = QdrantClient(host="localhost", port=6333)

model = SentenceTransformer("BAAI/bge-small-en-v1.5")

COLLECTION_NAME = "cves"

VECTOR_SIZE = 384


def create_collection():
    
    existing = [c.name for c in client.get_collections().collections]

    if COLLECTION_NAME in existing:
        print(f"Collection '{COLLECTION_NAME}' already exists — skipping.")
        return

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(
            size=VECTOR_SIZE,
            distance=Distance.COSINE  # Similarity measure
        )
    )
    print(f"Collection '{COLLECTION_NAME}' created.")


def load_cves() -> list[dict]:
    
    path = Path("data/cves.json")

    if not path.exists():
        raise FileNotFoundError("data/cves.json nahi mila — pehle fetch_cves.py run karo")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    print(f"Loaded {len(data)} CVEs from disk.")
    return data


def index_cves(cves: list[dict], batch_size: int = 50):
    
    print("Indexing CVEs into Qdrant...")

    
    total_batches = (len(cves) + batch_size - 1) // batch_size

    for i in tqdm(range(0, len(cves), batch_size), total=total_batches, desc="Batches"):
        batch = cves[i: i + batch_size]

        
        texts = [cve["description"] for cve in batch]

        
        vectors = model.encode(texts, normalize_embeddings=True).tolist()

        
        points = []
        for j, (cve, vector) in enumerate(zip(batch, vectors)):
            points.append(
                PointStruct(
                    id=i + j,          # Unique integer ID
                    vector=vector,     # 384-dim embedding
                    payload={          # Original data — filtering ke liye
                        "cve_id": cve["id"],
                        "description": cve["description"],
                        "severity": cve["severity"],
                        "score": cve["score"],
                        "published": cve["published"]
                    }
                )
            )

        
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=points
        )

    print(f"\nDone! {len(cves)} CVEs indexed in Qdrant.")


def verify_index():
  
    count = client.count(collection_name=COLLECTION_NAME).count
    print(f"\nTotal points in Qdrant: {count}")

    # Sample search
    print("\nSample search: 'buffer overflow vulnerability'")

    query_vector = model.encode(
        "buffer overflow vulnerability",
        normalize_embeddings=True
    ).tolist()

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=3
    ).points

    for i, result in enumerate(results):
        print(f"\n--- Result {i+1} ---")
        print(f"CVE ID   : {result.payload['cve_id']}")
        print(f"Severity : {result.payload['severity']} ({result.payload['score']})")
        print(f"Score    : {result.score:.3f}")  # Similarity score
        print(f"Desc     : {result.payload['description'][:120]}...")


if __name__ == "__main__":
    create_collection()
    cves = load_cves()
    index_cves(cves)
    verify_index()