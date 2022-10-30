#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

set -u

GROUP="modules"

# Check for static rules under /etc/audit/rules.d/*.rules
grep -q "^-w /bin/kmod -p [^-]*x -k $GROUP" /etc/audit/rules.d/*.rules || exit ${XCCDF_RESULT_FAIL}

# Check for loaded rules
auditctl -l -k "$GROUP" |\
    grep -Eq '^-w /bin/kmod -p [^-]*x' || exit ${XCCDF_RESULT_FAIL}

exit ${XCCDF_RESULT_PASS}
