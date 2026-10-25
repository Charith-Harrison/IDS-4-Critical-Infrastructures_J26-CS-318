FROM python:3.13-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY c3lab /app/c3lab
COPY tests /app/tests
CMD ["python", "-B", "-m", "c3lab", "run", "--output", "/output"]
