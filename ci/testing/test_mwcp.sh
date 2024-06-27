#!/bin/bash

echo "Running MWCP tests..."


# Install including the tests directory. There is a bug in mwcp where 
# you can't specify a different location for the tests
sed -i 's/recursive-exclude/recursive-include/g' /opt/acce-parsers/MANIFEST.in

# Unsure why exactly this is required, may have to do with running with "bash".
pip install /opt/acce-parsers

result=0
failedTests=()

TEST_DIR=$(pwd)/mwcp_tests

mkdir "$TEST_DIR"

# Bug in the pytest call where you have to be in the mwcp directory
cd /usr/local/lib/python3.9/site-packages/mwcp || exit

DRAGODIS_DISASSEMBLER="ida"
QT_QPA_PLATFORM=offscreen pytest -o cache_dir=/cache --pyargs mwcp -m parsers --disable-pytest-warnings --durations 25 -vv -k "acce:" -n 32 --malware-repo /malrepo --junitxml="${TEST_DIR}/test_report.xml"
if [[ $? -ne 0 ]]; then
  result=1
fi
if [[ $result -ne 0 ]];then
  echo "==== Failed Tests ===="
fi

exit $result
