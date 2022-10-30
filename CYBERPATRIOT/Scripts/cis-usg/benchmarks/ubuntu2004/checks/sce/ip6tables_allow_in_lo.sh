#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# 3.5.3.3.2 Ensure loopback traffic is configured: iptables_allow_in_lo
rule_type="iptables"

# verify if rule type matches the current firewall being audited
if [ "${XCCDF_VALUE_fw_choice}" != "${rule_type}" ]; then
    exit ${XCCDF_RESULT_NOT_APPLICABLE}
fi

# Pass rule if IPv6 is disabled on kernel

if [ ! -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ] || [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 1 ]; then
    exit $XCCDF_RESULT_PASS
fi

# Check chain INPUT for loopback related rules
ip6tables -L INPUT -v -n |\
    egrep -z "\s+[0-9]+\s+[0-9]+\s+ACCEPT\s+all\s+lo\s+\*\s+::/0\s+::/0[[:space:]]+[0-9]+\s+[0-9]+\s+DROP\s+all\s+\*\s+\*\s+::1\s+::/0"
if [ $? -ne 0 ]; then
    exit $XCCDF_RESULT_FAIL
fi

# Check chain OUTPUT for loopback related rules
ip6tables -L OUTPUT -v -n |\
    egrep "\s[0-9]+\s+[0-9]+\s+ACCEPT\s+all\s+\*\s+lo\s+::/0\s+::/0"
if [ $? -ne 0 ]; then
    exit $XCCDF_RESULT_FAIL
fi

exit $XCCDF_RESULT_PASS
