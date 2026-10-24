# Builder is checked against the exact qualified v0.3 image ID before use.
FROM c3-qualification:0.3.0
WORKDIR /main_collection
COPY runtime /main_collection/runtime
COPY engine /main_collection/engine
COPY frozen /main_collection/frozen
COPY tests /main_collection/tests
COPY tools /main_collection/tools
COPY collect-main.ps1 Dockerfile .dockerignore .gitignore /main_collection/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "-B", "-m", "runtime.identity"]
