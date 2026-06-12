---
title: Threat Intel RAG
emoji: 🔐
colorFrom: red
colorTo: blue
sdk: docker
pinned: false
---

# 🔐 Threat Intelligence RAG Chatbot

A RAG-based cybersecurity chatbot that answers questions about CVE vulnerabilities using real NVD data.

## 🌐 Live Demo

👉 [Chat UI](https://threat-intel-rag.vercel.app/)
👉 [API Docs](https://shadow-coder-888-threat-intel-rag.hf.space/docs)

## 🚀 Features
- Search 500 real CVEs from NVD database
- Semantic vector search using Qdrant
- LLM-powered answers using Groq (LLaMA 3.1)
- REST API with FastAPI
- RAG evaluation with MLflow
- Fully containerized with Docker

## 🛠️ Tech Stack
| Component | Technology |
|---|---|
| Vector Database | Qdrant Cloud |
| Embedding Model | BAAI/bge-small-en-v1.5 |
| LLM | Groq (LLaMA 3.1 8B) |
| Backend | FastAPI |
| Deployment | Hugging Face Spaces + Docker |
| Evaluation | MLflow |

## 📡 API Endpoints
- `GET /health` — Server status
- `POST /query` — Ask a CVE question

## 💬 Example Questions
- "What are the most critical remote code execution CVEs?"
- "What is the mitigation for buffer overflow vulnerabilities?"
- "What CVEs affect Windows with high severity?"

## ⚙️ Local Setup
```bash
# Clone the repo
git clone https://github.com/Shadow-Coder-888/Threat-intel-rag.git
cd Threat-intel-rag

# Install dependencies
pip install -r requirements_docker.txt

# Set environment variables
# Add your GROQ_API_KEY, QDRANT_URL, QDRANT_API_KEY in .env file

# Run with Docker
docker compose up
```

## 📊 Architecture
```
User Question
     ↓
FastAPI (/query)
     ↓
BAAI/bge-small-en-v1.5 (Embedding)
     ↓
Qdrant Cloud (Vector Search - Top 5 CVEs)
     ↓
Groq LLaMA 3.1 (Answer Generation)
     ↓
Response + Source CVEs
```