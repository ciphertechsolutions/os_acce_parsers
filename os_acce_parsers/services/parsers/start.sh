#!/bin/bash

# Copy ida.reg file from externally mounted directory
mkdir -p /root/.idapro/
[ -f /opt/ida-reg/ida.reg ] && cp /opt/ida-reg/ida.reg /root/.idapro/

# Configure Xvfb for IDA execution
export DISPLAY=":99"
nohup Xvfb :99 > /dev/null 2>&1 &

python os_acce_parsers/services/parsers/acce_api_runner.py
