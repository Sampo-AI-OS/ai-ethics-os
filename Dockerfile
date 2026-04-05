FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if needed (e.g. for numpy/pandas compilation)
RUN apt-get update && apt-get install -y --no-install-recommends gcc python3-dev && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m appuser

# Copy requirements first for caching
COPY requirements.txt .
# Install dependencies inside the container - no whitelist needed here!
RUN pip install --no-cache-dir -r requirements.txt

# Install dev tools
RUN pip install --no-cache-dir ruff mypy pytest httpx

# Copy source code with correct ownership
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Basic Healthcheck to ensure application reliability
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

# Default command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]