import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from rag_engine import query_cve

load_dotenv()

app = FastAPI(
    title="Threat Intelligence RAG API",
    description="CVE-based cybersecurity Q&A using RAG",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class QueryRequest(BaseModel):
    question: str


class SourceCVE(BaseModel):
    cve_id: str
    relevance_score: float | None
    severity: str
    score: float | str


class QueryResponse(BaseModel):
    question: str
    answer: str
    source_cves: list[SourceCVE]


@app.get("/health")
def health_check():
    return {"status": "ok", "message": "Threat Intel RAG API is running"}


@app.post("/query", response_model=QueryResponse)
def query_endpoint(request: QueryRequest):
    if not request.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty")

    result = query_cve(request.question)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)