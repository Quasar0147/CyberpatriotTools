#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# 3.5.2.10 Ensure nftables rules are permanent
rule_type="nftables"

# verify if rule type matches the current firewall being audited
if [ "${XCCDF_VALUE_fw_choice}" != "${rule_type}" ]; then
    exit ${XCCDF_RESULT_NOT_APPLICABLE}
fi

# Check rules in input chain
filename="/etc/nftables.conf"

in_regexp="chain input {[^}]+}"
egrep -zo "${in_regexp}" ${filename} | egrep -zqw "policy drop" &&\
    egrep -zo "${in_regexp}" ${filename} | egrep -zqw "iif \"lo\" accept" &&\
    egrep -zo "${in_regexp}" ${filename} | egrep -zqw "ip saddr 127.0.0.0/8"
if [ $? -ne 0 ]; then
    exit ${XCCDF_RESULT_FAIL}
fi

# Only verify IPv6 rules if IPv6 support is enabled
if [ -e /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
    egrep -zo "${in_regexp}" ${filename} | egrep -zqw "ip6 saddr ::1"
    if [ $? -ne 0 ]; then
        exit ${XCCDF_RESULT_FAIL}
    fi
fi

out_regexp="chain output {[^}]+}"
egrep -zo "${out_regexp}" ${filename} | egrep -zqw "policy drop"
if [ $? -ne 0 ]; then
    exit ${XCCDF_RESULT_FAIL}
fi

fwd_regexp="chain forward {[^}]+}"
egrep -zo "${fwd_regexp}" ${filename} | egrep -zqw "policy drop"
if [ $? -ne 0 ]; then
    exit ${XCCDF_RESULT_FAIL}
fi

exit ${XCCDF_RESULT_PASS}
