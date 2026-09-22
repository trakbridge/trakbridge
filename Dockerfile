#=============================================================================
# Flexible Multi-stage Dockerfile for TrakBridge
# =============================================================================

FROM python:3.12-slim AS builder

ARG SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${SETUPTOOLS_SCM_PRETEND_VERSION}

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    default-libmysqlclient-dev \
    libpq-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install build tools. Floors are explicit to close
# Trivy findings on the base-image pip/setuptools: GHSA-4xh5-x5gv-qwph,
# GHSA-qwm4-qh6w-59xr, GHSA-58qw-9mgm-455v, GHSA-jp4c-xjxw-mgf9,
# GHSA-wf93-45jw-7689, GHSA-6vgw-5pg2-w6jp (pip); CVE-2025-47273,
# CVE-2026-59890 (setuptools). Any version at or above these floors
# is accepted; the resolver may pick something newer at build time.
RUN pip install --no-cache-dir --upgrade \
    'pip>=26.2.0' \
    'setuptools>=83.0.0' \
    'wheel' \
    'setuptools-scm'

# Copy all files
COPY . /app
WORKDIR /app

# Configure git for setuptools-scm - ensure we have a valid git repo
RUN git config --global --add safe.directory /app || true

# Clean any cached build artifacts and install the package
RUN rm -rf build/ dist/ *.egg-info/ __pycache__ */__pycache__ \
    && find . -name "*.pyc" -delete \
    && pip cache purge \
    && pip install --no-cache-dir --force-reinstall .

# Production stage
FROM python:3.12-slim AS production

ARG SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${SETUPTOOLS_SCM_PRETEND_VERSION}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app" \
    FLASK_ENV=production

# Install runtime dependencies including gosu for user switching
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-mysql-client \
    postgresql-client \
    curl \
    gosu \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv

# Create app directories with broad permissions initially
WORKDIR /app

# Copy essential config files first
COPY hypercorn.toml /app/
COPY docker/entrypoint.sh /app/

# Copy all application source code and ensure it overwrites any installed package
COPY . /app/

# Copy the generated _version.py from builder
COPY --from=builder /app/_version.py /app/

# Install the application to ensure proper Python package resolution
RUN pip install --no-cache-dir --force-reinstall .

# Ensure proper permissions for runtime directories (after copy to avoid overwriting).
# external_config is per-deployment state written by the admin plugin manager;
# gitignored so may not exist in the build context. /app/backups is written
# lazily by ConfigLoader when a corrupted config file is quarantined.
RUN mkdir -p /app/logs /app/data /app/tmp /app/external_plugins /app/external_config /app/backups && \
    chmod 755 /app && \
    chmod 777 /app/logs /app/data /app/tmp && \
    chmod 755 /app/external_plugins /app/external_config /app/backups

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Create default non-root user for security
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -d /app -s /bin/bash appuser

# Set ownership and permissions for directories that appuser needs access to
RUN chown -R appuser:appuser /app/logs /app/data /app/tmp /app/external_config /app/backups /app/entrypoint.sh

# Ensure all users can read application files and appuser group has access
# Set group ownership and readable permissions for Python modules and static assets (exclude writable external_config)
RUN chown -R root:appuser /app/utils /app/plugins /app/services /app/models /app/routes /app/config /app/external_plugins /app/static /app/templates /app/migrations && \
    chmod -R 644 /app/utils /app/plugins /app/services /app/models /app/routes /app/config /app/external_plugins /app/static /app/templates /app/migrations && \
    find /app/utils /app/plugins /app/services /app/models /app/routes /app/config /app/external_plugins /app/static /app/templates /app/migrations -type d -exec chmod 755 {} \;

# Make core application files group-readable for dynamic users
RUN chown root:appuser /app/app.py /app/database.py /app/_version.py /app/pyproject.toml && \
    chmod 644 /app/app.py /app/database.py /app/_version.py /app/pyproject.toml

# Note: Container starts as root to allow dynamic user creation
# The /app/entrypoint.sh script will handle user switching based on USER_ID/GROUP_ID
# and default to appuser (1000:1000) if no dynamic user is requested

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-5000}/api/health || exit 1

EXPOSE 5000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD []

# Development stage
FROM production AS development

ENV FLASK_ENV=development

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install development dependencies
RUN pip install --no-cache-dir \
    flask-debugtoolbar \
    pytest \
    pytest-cov \
    pytest-xdist \
    black \
    flake8