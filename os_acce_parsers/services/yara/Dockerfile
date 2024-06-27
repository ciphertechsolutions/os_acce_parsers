FROM python:3.8
RUN python -m pip install -U pip && \
    pip wheel yara-python==4.3.1

FROM python:3.8-slim

RUN addgroup --system yara \
    && adduser --system --ingroup yara --home /home/yara yara

WORKDIR /opt/yara/service

COPY --from=0 yara_python*.whl .

ARG extra_deps

RUN python -m pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir yara_python*.whl && \
    pip install --no-cache-dir -U $extra_deps

COPY --chown=yara:yara ./os_acce_parsers/services/yara /opt/yara/service

# Add any other rules paths here

# !! [DO NOT MODIFY THE FOLLOWING LINE] !!
# %%rules%% COPY --chown=yara:yara $source_path /opt/yara/rules/$package_name

USER yara

ARG COMMIT_HASH
ENV COMMIT_HASH=${COMMIT_HASH:-N/A}

ENTRYPOINT ["gunicorn"]
CMD ["--workers=2", "-t", "600", "-k", "eventlet", "-b", "0.0.0.0:8080", "api:create_app()"]
