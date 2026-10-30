FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeynest ./honeynest
COPY config.example.yaml ./config.yaml

# O honeypot nunca roda como root dentro do container.
RUN useradd --create-home --uid 1000 honeynest && mkdir -p data logs && chown -R honeynest data logs
USER honeynest

EXPOSE 2222 2323 8080 2121 5000
CMD ["python", "-m", "honeynest", "-c", "config.yaml"]
