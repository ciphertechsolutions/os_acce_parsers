ARG python_version="3.9-slim"
ARG ida_image="ida:8.2.2"
FROM openjdk:17-jdk-slim AS java

ENV VERSION 11.0.1_PUBLIC
ENV GHIDRA_SHA a0bc9450aa3a231096b13a823c66311b9f84cb9cec4624393221cfed40ef6924
ENV GHIDRA_URL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip

RUN apt-get update && apt-get install -y fontconfig libxrender1 libxtst6 libxi6 wget unzip python3-requests --no-install-recommends \
    && wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_URL} \
    && echo "$GHIDRA_SHA /tmp/ghidra.zip" | sha256sum -c - \
    && unzip /tmp/ghidra.zip \
    && mv ghidra_${VERSION} /opt/ghidra \
    && chmod +x /opt/ghidra/ghidraRun \
    && echo "===> Clean up unnecessary files..." \
    && apt-get purge -y --auto-remove wget unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/* /opt/ghidra/docs /opt/ghidra/Extensions/Eclipse

FROM ${ida_image} AS ida
FROM python:${python_version}

COPY --from=java /opt/ghidra /opt/ghidra
COPY --from=java /usr/local/openjdk-17 /usr/local/openjdk-17
ENV PATH="/usr/local/openjdk-17/bin:${PATH}"
COPY --from=ida /opt/ida /opt/ida
COPY --from=ida /root/.idapro/ida.reg /root/.idapro/ida.reg
ENV IDA_DIR="/opt/ida" \
    GHIDRA_INSTALL_DIR="/opt/ghidra" \
    JAVA_HOME="/usr/local/openjdk-17" \
    KORDESII_LOG_CFG="/opt/acce-parsers/os_acce_parsers/services/parsers/kordesii_log_config.yml" \
    DRAGODIS_DISASSEMBLER="ghidra"

RUN addgroup --system acce \
    && adduser --system --ingroup acce acce

RUN find / -ignore_readdir_race -name 'libpython3.*.so.1.0' -type f -exec /opt/ida/idapyswitch --force-path '{}' \;

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y libgl1 libfontconfig1 libsecret-1-0 build-essential libssl-dev git && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Required as Docker does not support conditional copies, even if directory is empty
COPY --chown=acce:acce wheels /opt/acce-parsers/wheels
COPY --chown=acce:acce setup.py VERSION MANIFEST.in README.rst /opt/acce-parsers/

WORKDIR /opt/acce-parsers

ARG local_deps
ARG extra_deps
ARG index_url="https://acce.ciphertechsolutions.com/pypi/simple"

RUN python -m pip install --no-cache-dir -U pip && \
    if [ -z $local_deps ]; then :; else pip install --no-cache-dir --no-index --no-deps -f /opt/acce-parsers/wheels $local_deps; fi && \
    if [ -z $extra_deps ]; then :; else pip install --no-cache-dir -U $extra_deps; fi && \
    chown -R acce:acce /opt/acce-parsers

COPY --chown=acce:acce os_acce_parsers /opt/acce-parsers/os_acce_parsers

RUN pip install --index-url $index_url --no-cache-dir /opt/acce-parsers
# RUN acce_parsers init

# !! [DO NOT MODIFY THE FOLLOWING LINES] !!
# %%parser_files%% COPY --chown=acce:acce $source_path /opt/extra-parsers/$package_name
# %%parser_install%% RUN python -m pip install --no-cache-dir $extra_args /opt/extra-parsers/$package_name

ARG COMMIT_HASH
ENV COMMIT_HASH=${COMMIT_HASH:-N/A}

# ENTRYPOINT ["acce_parsers", "serve"]
# ENTRYPOINT [ "/bin/bash", "-c", "--" ]
CMD [ "/bin/bash", "-c", "--", "while true; do sleep 30; done;" ]