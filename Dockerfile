# Multi-stage build for PCM-Ops Tools
FROM python:3.12-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry using pip (more secure than curl)
ENV POETRY_VERSION=2.1.3
RUN pip install --no-cache-dir poetry==$POETRY_VERSION

# Set work directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Production stage
FROM python:3.12-slim

# No additional runtime dependencies needed

# Create non-root user
RUN useradd -m -u 1000 appuser

# Set work directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=appuser:appuser backend/ ./backend/
COPY --chown=appuser:appuser data/ ./data/
COPY --chown=appuser:appuser setup.sh ./
COPY --chown=appuser:appuser start.sh ./
COPY --chown=appuser:appuser stop.sh ./

# Create necessary directories
RUN mkdir -p logs uploads data && \
    chown -R appuser:appuser logs uploads data && \
    chmod +x *.sh

# Switch to non-root user
USER appuser

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=8500
ENV HOST=0.0.0.0

# Expose port
EXPOSE 8500

# Health check using Python (no curl dependency)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8500/api/health')" || exit 1

# Run the application
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8500", "--workers", "4", "--log-level", "warning", "--access-log"]