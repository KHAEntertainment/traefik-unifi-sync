FROM python:3.11-slim

# Set environment variables for unbuffered logging and non-root user
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Create a non-root user to run the application for better security
RUN useradd --create-home --shell /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy the dependency specification and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY sync.py ./

# Change ownership to the non-root user
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Default command to run the sync script
ENTRYPOINT ["python", "./sync.py"]