# Reuse the locally verified Python/tcpdump image; no new package download.
# Host execution records its actual immutable image ID and the resulting ID.
FROM c3-qualification:0.2.0
WORKDIR /qualification03
COPY c3qual /qualification03/c3qual
COPY tests /qualification03/tests
COPY design /qualification03/design
COPY *.py *.ps1 *.yaml Dockerfile /qualification03/
COPY .dockerignore .gitignore /qualification03/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "-B", "-m", "c3qual", "check", "--planned-run", "EQ01"]
