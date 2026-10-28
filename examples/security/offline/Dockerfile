ARG TRIVY_IMAGE
ARG PYTHON_IMAGE
FROM ${TRIVY_IMAGE} AS scanner
FROM ${PYTHON_IMAGE}
ARG SEMGREP_VERSION=1.174.0
RUN python -m pip install --no-cache-dir semgrep==${SEMGREP_VERSION}
COPY --from=scanner /usr/local/bin/trivy /usr/local/bin/trivy
COPY worker.py web_checks.py rules.yml manifest.json /opt/security/
COPY trivy-cache/db/ /opt/security/cache/db/
RUN chmod -R a+rX /opt/security
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["python3", "-B", "/opt/security/worker.py"]
