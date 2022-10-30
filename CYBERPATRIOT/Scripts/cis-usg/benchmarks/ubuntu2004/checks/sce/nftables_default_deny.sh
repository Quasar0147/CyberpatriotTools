#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# 3.5.2.8 Ensure default deny firewall policy
rule_type="nftables"

# verify if rule type matches the current firewall being audited
if [ "${XCCDF_VALUE_fw_choice}" != "${rule_type}" ]; then
    exit ${XCCDF_RESULT_NOT_APPLICABLE}
fi

# Check if default policy is drop
nft list ruleset |& grep 'hook input' |& grep -w 'policy drop' &>/dev/null &&\
    nft list ruleset |& grep 'hook forward'|&  grep -w 'policy drop' &>/dev/null &&\
    nft list ruleset |& grep 'hook output' |& grep -w 'policy drop' &>/dev/null
if [ $? -ne 0 ]; then
    exit ${XCCDF_RESULT_FAIL}
fi

exit ${XCCDF_RESULT_PASS}
