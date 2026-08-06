# Use Python 3.12 slim image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies including C compiler for tree-sitter
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt requirements-cpg.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-cpg.txt

# Track C2 — Chromium + its OS-level deps for the headless-browser crawler/
# DOM-XSS probe. --with-deps pulls the (many) shared libraries Chromium
# needs that a slim base image doesn't have; playwright itself is already
# installed via requirements.txt above.
RUN playwright install --with-deps chromium

# Copy application code
COPY . .

# Clean any existing grammar repos and build fresh
RUN rm -rf tree-sitter-repos/tree-sitter-javascript && \
    python setup_grammars.py

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
