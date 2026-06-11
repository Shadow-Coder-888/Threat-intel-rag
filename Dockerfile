FROM python:3.11-slim

WORKDIR /app

COPY requirements_docker.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements_docker.txt

COPY src/ ./src/

EXPOSE 7860

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860", "--app-dir", "/app/src"]