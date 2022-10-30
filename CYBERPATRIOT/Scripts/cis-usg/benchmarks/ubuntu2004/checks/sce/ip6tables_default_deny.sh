#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# 3.5.3.2.1 Ensure default deny firewall policy
rule_type="iptables"

# verify if rule type matches the current firewall being audited
if [ "${XCCDF_VALUE_fw_choice}" != "${rule_type}" ]; then
    exit ${XCCDF_RESULT_NOT_APPLICABLE}
fi

# Pass rule if IPv6 is disabled on kernel
if [ ! -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ] || [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 1 ]; then
    exit $XCCDF_RESULT_PASS
fi

output="$(ip6tables -L | grep Chain)"
if [ -z "${output}" ]; then
        exit $XCCDF_RESULT_FAIL
fi

while read line; do

	chain="$(echo $line | awk '{print $1, $2}')"
	policy="$(echo $line | awk '{print $4}' | tr -d ")")"
	if [ "$chain" = "Chain INPUT" ] || [ "$chain" = "Chain FORWARD" ] ||
	   [ "$chain" = "Chain OUTPUT" ]; then
		if [ "$policy" != "DROP" ] && [ "$policy" != "REJECT" ]; then
			exit $XCCDF_RESULT_FAIL
		fi
	fi

done <<< "$output"

exit $XCCDF_RESULT_PASS
