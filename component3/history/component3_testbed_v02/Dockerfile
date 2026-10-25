# Reuse the locally verified Python/tcpdump image; no new package download.
# Host execution records its actual immutable image ID and the resulting ID.
FROM kaveesha-c3-pilot:0.1.0
WORKDIR /qualification
COPY c3qual /qualification/c3qual
COPY tests /qualification/tests
COPY design /qualification/design
COPY *.py *.ps1 *.yaml Dockerfile /qualification/
COPY .dockerignore .gitignore /qualification/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "-B", "-m", "c3qual", "check", "--planned-run", "Q01"]
