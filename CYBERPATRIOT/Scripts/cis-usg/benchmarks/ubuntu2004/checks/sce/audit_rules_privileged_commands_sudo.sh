#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

set -u

GROUP="privileged"

auditctl -l -k "$GROUP" |\
    grep -Eq '^-a always,exit.*-F path=/usr/bin/sudo.*-F auid>=1000.*-F auid!=(-1|unset)'\
    || exit ${XCCDF_RESULT_FAIL}

exit ${XCCDF_RESULT_PASS}
