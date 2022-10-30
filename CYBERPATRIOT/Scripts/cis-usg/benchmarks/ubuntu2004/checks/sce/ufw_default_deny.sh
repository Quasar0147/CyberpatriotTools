#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# 3.5.1.7 Ensure default deny firewall policy
rule_type="ufw"

# verify if rule type matches the current firewall being audited
if [ "${XCCDF_VALUE_fw_choice}" != "${rule_type}" ]; then
    exit ${XCCDF_RESULT_NOT_APPLICABLE}
fi

# if ufw is enabled, check for the default policy
ufw status verbose |\
    egrep -q "^Default:\s+deny\s+\(incoming\),\s+deny\s+\(outgoing\),\s+(disabled|deny)\s+\(routed\)"
if [ $? -ne 0 ]; then
    exit ${XCCDF_RESULT_FAIL}
fi

exit ${XCCDF_RESULT_PASS}
