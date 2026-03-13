FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

EXPOSE ${PORT:-8000}

CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}
