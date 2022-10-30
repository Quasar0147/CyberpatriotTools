#!/bin/bash
#
#
# "Copyright 2021 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# 3.5.3.2.2 Ensure loopback traffic is configured: iptables_allow_in_lo
rule_type="iptables"

# verify if rule type matches the current firewall being audited
if [ "${XCCDF_VALUE_fw_choice}" != "${rule_type}" ]; then
    exit ${XCCDF_RESULT_NOT_APPLICABLE}
fi

rule_input_ACCEPT_satisfied=FALSE
rule_input_DROP_satisfied=FALSE

iptables_input="$(iptables -L INPUT -v -n)"
if [ -z "$iptables_input" ]; then
        exit $XCCDF_RESULT_FAIL
fi

while read line; do
	echo "$line" | grep -E '^.+ACCEPT\s+all\s+--\s+lo\s+\*\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0' 2>&1 >/dev/null
	result=$?
	if [ $result -eq 0 ]; then
		rule_input_ACCEPT_satisfied=TRUE
		continue
	fi

	echo "$line" | grep -E '^.+DROP\s+all\s+--\s+\*\s+\*\s+127\.0\.0\.0\/8\s+0\.0\.0\.0\/0' 2>&1 > /dev/null
	result=$?
	if [ $result -eq 0 ]; then
		if [ "$rule_input_ACCEPT_satisfied" = "FALSE" ]; then
		# rule_input_DROP found before rule_input_ACCEPT => failed
			exit $XCCDF_RESULT_FALSE
		fi

		# rule_input_ACCEPT & rule_input_DROP found in that
		# order => input; rules satisfied
		rule_input_DROP_satisfied=TRUE
		break
	fi
done <<< "$iptables_input"

# check output rules only if input rules have been satisfied

if [ "$rule_input_DROP_satisfied" = "TRUE" ]; then

	iptables_output="$(iptables -L OUTPUT -v -n)"
	if [ -z "$iptables_output" ]; then
		exit $XCCDF_RESULT_FAIL
	fi

	while read line; do
		echo "$line" | grep -E '^.+ACCEPT\s+all\s+--\s+\*\s+lo\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0' 2>&1 >/dev/null
		result=$?
		if [ $result -eq 0 ]; then
			# rule_output satisfied => both input and output
			# rules are  satisfied
			exit $XCCDF_RESULT_PASS
		fi
	done <<< "$iptables_output"
fi

exit $XCCDF_RESULT_FAIL
