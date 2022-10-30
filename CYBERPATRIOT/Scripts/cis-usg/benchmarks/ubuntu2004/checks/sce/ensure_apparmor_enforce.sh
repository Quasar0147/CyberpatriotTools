#!/bin/bash
#
#
# "Copyright 2020 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# If apparmor or apparmor-utils are not installed, then this test fails.
dpkg-query --show --showformat='${db:Status-Status}\n' "apparmor" 2>/dev/null | grep -q installed && dpkg-query --show --showformat='${db:Status-Status}\n' "apparmor-utils" 2>/dev/null | grep -q installed
if [ $? -ne 0 ]; then
        exit ${XCCDF_RESULT_FAIL}
fi

loaded_profiles=$(/usr/sbin/aa-status --profiled)
enforced_profiles=$(/usr/bin/aa-status --enforced)
if [ ${loaded_profiles} -ne ${enforced_profiles} ]; then
        exit $XCCDF_RESULT_FAIL
fi

complain=$(/usr/sbin/aa-status --complaining)
if [ $complain -ne 0 ]; then
        exit $XCCDF_RESULT_FAIL
fi

unconfined=$(/usr/sbin/aa-status | grep "processes are unconfined" | awk '{print $1;}')
if [ $unconfined -ne 0 ]; then
        exit $XCCDF_RESULT_FAIL
fi

exit $XCCDF_RESULT_PASS
