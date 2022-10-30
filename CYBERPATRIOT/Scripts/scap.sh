
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "aide" &> /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y "cron" &> /dev/null
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

/usr/sbin/aideinit
/bin/mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# AiDE usually adds its own cron jobs to /etc/cron.daily. If script is there, this rule is
# compliant. Otherwise, we copy the script to the /etc/cron.weekly
if ! egrep -q '^(/usr/bin/)?aide\.wrapper\s+' /etc/cron.*/*; then
    cp -f /usr/share/aide/config/cron.daily/aide /etc/cron.weekly/
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if test -e /etc/sysconfig/prelink -o -e /usr/sbin/prelink; then
    if grep -q ^PRELINKING /etc/sysconfig/prelink
    then
        sed -i 's/^PRELINKING[:blank:]*=[:blank:]*[:alpha:]*/PRELINKING=no/' /etc/sysconfig/prelink
    else
        printf '\n' >> /etc/sysconfig/prelink
        printf '%s\n' '# Set PRELINKING=no per security requirements' 'PRELINKING=no' >> /etc/sysconfig/prelink
    fi

    # Undo previous prelink changes to binaries if prelink is available.
    if test -x /usr/sbin/prelink; then
        /usr/sbin/prelink -ua
    fi
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" | grep -v 'distro\|ibus' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"

mkdir -p "${DBDIR}"

if [ "${#SETTINGSFILES[@]}" -eq 0 ]
then
    [ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
    printf '%s=%s\n' "disable-user-list" "true" >> ${DCONFFILE}
else
    escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
    if grep -q "^\\s*disable-user-list\\s*=" "${SETTINGSFILES[@]}"
    then

        sed -i "s/\\s*disable-user-list\\s*=\\s*.*/disable-user-list=${escaped_value}/g" "${SETTINGSFILES[@]}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\disable-user-list=${escaped_value}" "${SETTINGSFILES[@]}"
    fi
fi

dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/disable-user-list$" "/etc/dconf/db/" | grep -v 'distro\|ibus' | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"

mkdir -p "${LOCKSFOLDER}"

if [[ -z "${LOCKFILES}" ]]
then
    echo "/org/gnome/login-screen/disable-user-list" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
fi

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "sudo" &> /dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y "bash" &> /dev/null

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults.*\buse_pty\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option use_pty
        echo "Defaults use_pty" >> /etc/sudoers
    fi

    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi
var_sudo_logfile='/var/log/sudo.log'


if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults.*\blogfile=("(?:\\"|\\\\|[^"\\\n])*"\B|[^"](?:(?:\\,|\\"|\\ |\\\\|[^", \\\n])*)\b)\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option logfile
        echo "Defaults logfile=${var_sudo_logfile}" >> /etc/sudoers
    else
        # sudoers file defines Option logfile, remediate if appropriate value is not set
        if ! grep -P "^[\s]*Defaults.*\blogfile=${var_sudo_logfile}\b.*$" /etc/sudoers; then

            sed -Ei "s/(^[\s]*Defaults.*\blogfile=)[-]?\w+(\b.*$)/\1${var_sudo_logfile}\2/" /etc/sudoers
        fi
    fi

    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

login_banner_text='^Authorized[\s\n]+uses[\s\n]+only\.[\s\n]+All[\s\n]+activity[\s\n]+may[\s\n]+be[\s\n]+monitored[\s\n]+and[\s\n]+reported\.$'


# Multiple regexes transform the banner regex into a usable banner
# 0 - Remove anchors around the banner text
login_banner_text=$(echo "$login_banner_text" | sed 's/^\^\(.*\)\$$/\1/g')
# 1 - Keep only the first banners if there are multiple
#    (dod_banners contains the long and short banner)
login_banner_text=$(echo "$login_banner_text" | sed 's/^(\(.*\.\)|.*)$/\1/g')
# 2 - Add spaces ' '. (Transforms regex for "space or newline" into a " ")
login_banner_text=$(echo "$login_banner_text" | sed 's/\[\\s\\n\]+/ /g')
# 3 - Adds newline "tokens". (Transforms "(?:\[\\n\]+|(?:\\n)+)" into "(n)*")
login_banner_text=$(echo "$login_banner_text" | sed 's/(?:\[\\n\]+|(?:\\\\n)+)/(n)*/g')
# 4 - Remove any leftover backslash. (From any parethesis in the banner, for example).
login_banner_text=$(echo "$login_banner_text" | sed 's/\\//g')
# 5 - Removes the newline "token." (Transforms them into newline escape sequences "\n").
#    ( Needs to be done after 4, otherwise the escapce sequence will become just "n".
login_banner_text=$(echo "$login_banner_text" | sed 's/(n)\*/\\n/g')

# Will do both approach, since we plan to migrate to checks over dconf db. That way, future updates of the tool
# will pass the check even if we decide to check only for the dconf db path.
if [ -e "/etc/gdm3/greeter.dconf-defaults" ] ; then

    LC_ALL=C sed -i "/^\s*banner\-message\-text/Id" "/etc/gdm3/greeter.dconf-defaults"
else
    touch "/etc/gdm3/greeter.dconf-defaults"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/gdm3/greeter.dconf-defaults"

cp "/etc/gdm3/greeter.dconf-defaults" "/etc/gdm3/greeter.dconf-defaults.bak"
# Insert after the line matching the regex '\[org/gnome/login-screen\]'
line_number="$(LC_ALL=C grep -n "\[org/gnome/login-screen\]" "/etc/gdm3/greeter.dconf-defaults.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '\[org/gnome/login-screen\]', insert at
    # the end of the file.
    printf '%s\n' "banner-message-text='${login_banner_text}'" >> "/etc/gdm3/greeter.dconf-defaults"
else
    head -n "$(( line_number ))" "/etc/gdm3/greeter.dconf-defaults.bak" > "/etc/gdm3/greeter.dconf-defaults"
    printf '%s\n' "banner-message-text='${login_banner_text}'" >> "/etc/gdm3/greeter.dconf-defaults"
    tail -n "+$(( line_number + 1 ))" "/etc/gdm3/greeter.dconf-defaults.bak" >> "/etc/gdm3/greeter.dconf-defaults"
fi
# Clean up after ourselves.
rm "/etc/gdm3/greeter.dconf-defaults.bak"
# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" | grep -v 'distro\|ibus' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
DBDIR="/etc/dconf/db/gdm.d"

mkdir -p "${DBDIR}"

if [ "${#SETTINGSFILES[@]}" -eq 0 ]
then
    [ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
    printf '%s=%s\n' "banner-message-text" "'${login_banner_text}'" >> ${DCONFFILE}
else
    escaped_value="$(sed -e 's/\\/\\\\/g' <<< "'${login_banner_text}'")"
    if grep -q "^\\s*banner-message-text\\s*=" "${SETTINGSFILES[@]}"
    then

        sed -i "s/\\s*banner-message-text\\s*=\\s*.*/banner-message-text=${escaped_value}/g" "${SETTINGSFILES[@]}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-text=${escaped_value}" "${SETTINGSFILES[@]}"
    fi
fi

dconf update
# No need to use dconf update, since bash_dconf_settings does that already

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
touch /etc/motd
chgrp 0 /etc/issue
chgrp 0 /etc/motd
chown 0 /etc/issue
chown 0 /etc/motd
chmod u-xs,g-xws,o-xwt /etc/issue
chmod u-xs,g-xws,o-xwt /etc/motd
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

declare -a VALUES=()
declare -a VALUE_NAMES=()
declare -a ARGS=()
declare -a NEW_ARGS=()

var_password_pam_remember='5'

VALUES+=("$var_password_pam_remember")
VALUE_NAMES+=("remember")
ARGS+=("")
NEW_ARGS+=("")
VALUES+=("")
VALUE_NAMES+=("")
ARGS+=("use_authtok")
NEW_ARGS+=("use_authtok")

for idx in "${!VALUES[@]}"
do
    if [ -e "/etc/pam.d/common-password" ] ; then
        valueRegex="${VALUES[$idx]}" defaultValue="${VALUES[$idx]}"
        # non-empty values need to be preceded by an equals sign
        [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
        # add an equals sign to non-empty values
        [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"

        # fix the value for 'option' if one exists but does not match 'valueRegex'
        if grep -q -P "^\\s*password\\s+requisite\\s+pam_pwhistory.so(\\s.+)?\\s+${VALUE_NAMES[$idx]}(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-password" ; then
            sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+requisite\\s+pam_pwhistory.so(\\s.+)?\\s)${VALUE_NAMES[$idx]}=[^[:space:]]*/\\1${VALUE_NAMES[$idx]}${defaultValue}/" "/etc/pam.d/common-password"

        # add 'option=default' if option is not set
        elif grep -q -E "^\\s*password\\s+requisite\\s+pam_pwhistory.so" < "/etc/pam.d/common-password" &&
                grep    -E "^\\s*password\\s+requisite\\s+pam_pwhistory.so" < "/etc/pam.d/common-password" | grep -q -E -v "\\s${VALUE_NAMES[$idx]}(=|\\s|\$)" ; then

            sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+requisite\\s+pam_pwhistory.so[^\\n]*)/\\1 ${VALUE_NAMES[$idx]}${defaultValue}/" "/etc/pam.d/common-password"
        # add a new entry if none exists
        elif ! grep -q -P "^\\s*password\\s+requisite\\s+pam_pwhistory.so(\\s.+)?\\s+${VALUE_NAMES[$idx]}${valueRegex}(\\s|\$)" < "/etc/pam.d/common-password" ; then
            echo "password requisite pam_pwhistory.so ${VALUE_NAMES[$idx]}${defaultValue}" >> "/etc/pam.d/common-password"
        fi
    else
        echo "/etc/pam.d/common-password doesn't exist" >&2
    fi
done

for idx in "${!ARGS[@]}"
do
    if ! grep -q -P "^\s*password\s+requisite\s+pam_pwhistory.so.*\s+${ARGS[$idx]}\s*$" /etc/pam.d/common-password ; then
        sed --follow-symlinks -i -E -e "s/^\\s*password\\s+requisite\\s+pam_pwhistory.so.*\$/& ${NEW_ARGS[$idx]}/" /etc/pam.d/common-password
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
var_password_pam_tally2='3'

# Use a non-number regexp to force update of the value of the deny option
if [ -e "/etc/pam.d/common-auth" ] ; then
    valueRegex="°" defaultValue="${var_password_pam_tally2}"
    # non-empty values need to be preceded by an equals sign
    [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
    # add an equals sign to non-empty values
    [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"

    # fix 'type' if it's wrong
    if grep -q -P "^\\s*(?"'!'"auth\\s)[[:alnum:]]+\\s+[[:alnum:]]+\\s+pam_tally2.so" < "/etc/pam.d/common-auth" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*)[[:alnum:]]+(\\s+[[:alnum:]]+\\s+pam_tally2.so)/\\1auth\\2/" "/etc/pam.d/common-auth"
    fi

    # fix 'control' if it's wrong
    if grep -q -P "^\\s*auth\\s+(?"'!'"required)[[:alnum:]]+\\s+pam_tally2.so" < "/etc/pam.d/common-auth" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*auth\\s+)[[:alnum:]]+(\\s+pam_tally2.so)/\\1required\\2/" "/etc/pam.d/common-auth"
    fi

    # fix the value for 'option' if one exists but does not match 'valueRegex'
    if grep -q -P "^\\s*auth\\s+required\\s+pam_tally2.so(\\s.+)?\\s+deny(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-auth" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*auth\\s+required\\s+pam_tally2.so(\\s.+)?\\s)deny=[^[:space:]]*/\\1deny${defaultValue}/" "/etc/pam.d/common-auth"

    # add 'option=default' if option is not set
    elif grep -q -E "^\\s*auth\\s+required\\s+pam_tally2.so" < "/etc/pam.d/common-auth" &&
            grep    -E "^\\s*auth\\s+required\\s+pam_tally2.so" < "/etc/pam.d/common-auth" | grep -q -E -v "\\sdeny(=|\\s|\$)" ; then

        sed --follow-symlinks -i -E -e "s/^(\\s*auth\\s+required\\s+pam_tally2.so[^\\n]*)/\\1 deny${defaultValue}/" "/etc/pam.d/common-auth"
    # add a new entry if none exists
    elif ! grep -q -P "^\\s*auth\\s+required\\s+pam_tally2.so(\\s.+)?\\s+deny${valueRegex}(\\s|\$)" < "/etc/pam.d/common-auth" ; then
        echo "auth required pam_tally2.so deny${defaultValue}" >> "/etc/pam.d/common-auth"
    fi
else
    echo "/etc/pam.d/common-auth doesn't exist" >&2
fi
if [ -e "/etc/pam.d/common-auth" ] ; then
    valueRegex="(fail)" defaultValue="fail"
    # non-empty values need to be preceded by an equals sign
    [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
    # add an equals sign to non-empty values
    [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"

    # fix 'type' if it's wrong
    if grep -q -P "^\\s*(?"'!'"auth\\s)[[:alnum:]]+\\s+[[:alnum:]]+\\s+pam_tally2.so" < "/etc/pam.d/common-auth" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*)[[:alnum:]]+(\\s+[[:alnum:]]+\\s+pam_tally2.so)/\\1auth\\2/" "/etc/pam.d/common-auth"
    fi

    # fix 'control' if it's wrong
    if grep -q -P "^\\s*auth\\s+(?"'!'"required)[[:alnum:]]+\\s+pam_tally2.so" < "/etc/pam.d/common-auth" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*auth\\s+)[[:alnum:]]+(\\s+pam_tally2.so)/\\1required\\2/" "/etc/pam.d/common-auth"
    fi

    # fix the value for 'option' if one exists but does not match 'valueRegex'
    if grep -q -P "^\\s*auth\\s+required\\s+pam_tally2.so(\\s.+)?\\s+onerr(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-auth" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*auth\\s+required\\s+pam_tally2.so(\\s.+)?\\s)onerr=[^[:space:]]*/\\1onerr${defaultValue}/" "/etc/pam.d/common-auth"

    # add 'option=default' if option is not set
    elif grep -q -E "^\\s*auth\\s+required\\s+pam_tally2.so" < "/etc/pam.d/common-auth" &&
            grep    -E "^\\s*auth\\s+required\\s+pam_tally2.so" < "/etc/pam.d/common-auth" | grep -q -E -v "\\sonerr(=|\\s|\$)" ; then

        sed --follow-symlinks -i -E -e "s/^(\\s*auth\\s+required\\s+pam_tally2.so[^\\n]*)/\\1 onerr${defaultValue}/" "/etc/pam.d/common-auth"
    # add a new entry if none exists
    elif ! grep -q -P "^\\s*auth\\s+required\\s+pam_tally2.so(\\s.+)?\\s+onerr${valueRegex}(\\s|\$)" < "/etc/pam.d/common-auth" ; then
        echo "auth required pam_tally2.so onerr${defaultValue}" >> "/etc/pam.d/common-auth"
    fi
else
    echo "/etc/pam.d/common-auth doesn't exist" >&2
fi
if [ -e "/etc/pam.d/common-account" ] ; then
    valueRegex="" defaultValue=""
    # non-empty values need to be preceded by an equals sign
    [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
    # add an equals sign to non-empty values
    [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"

    # fix 'type' if it's wrong
    if grep -q -P "^\\s*(?"'!'"account\\s)[[:alnum:]]+\\s+[[:alnum:]]+\\s+pam_tally2.so" < "/etc/pam.d/common-account" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*)[[:alnum:]]+(\\s+[[:alnum:]]+\\s+pam_tally2.so)/\\1account\\2/" "/etc/pam.d/common-account"
    fi

    # fix 'control' if it's wrong
    if grep -q -P "^\\s*account\\s+(?"'!'"required)[[:alnum:]]+\\s+pam_tally2.so" < "/etc/pam.d/common-account" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*account\\s+)[[:alnum:]]+(\\s+pam_tally2.so)/\\1required\\2/" "/etc/pam.d/common-account"
    fi

    # fix the value for 'option' if one exists but does not match 'valueRegex'
    if grep -q -P "^\\s*account\\s+required\\s+pam_tally2.so(\\s.+)?\\s+(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-account" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*account\\s+required\\s+pam_tally2.so(\\s.+)?\\s)=[^[:space:]]*/\\1${defaultValue}/" "/etc/pam.d/common-account"

    # add 'option=default' if option is not set
    elif grep -q -E "^\\s*account\\s+required\\s+pam_tally2.so" < "/etc/pam.d/common-account" &&
            grep    -E "^\\s*account\\s+required\\s+pam_tally2.so" < "/etc/pam.d/common-account" | grep -q -E -v "\\s(=|\\s|\$)" ; then

        sed --follow-symlinks -i -E -e "s/^(\\s*account\\s+required\\s+pam_tally2.so[^\\n]*)/\\1 ${defaultValue}/" "/etc/pam.d/common-account"
    # add a new entry if none exists
    elif ! grep -q -P "^\\s*account\\s+required\\s+pam_tally2.so(\\s.+)?\\s+${valueRegex}(\\s|\$)" < "/etc/pam.d/common-account" ; then
        echo "account required pam_tally2.so ${defaultValue}" >> "/etc/pam.d/common-account"
    fi
else
    echo "/etc/pam.d/common-account doesn't exist" >&2
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_dcredit='-1'


# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/security/pwquality.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^dcredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_dcredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^dcredit\\>" "/etc/security/pwquality.conf"; then
    "${sed_command[@]}" "s/^dcredit\\>.*/$formatted_output/gi" "/etc/security/pwquality.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_lcredit='-1'


# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/security/pwquality.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^lcredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_lcredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^lcredit\\>" "/etc/security/pwquality.conf"; then
    "${sed_command[@]}" "s/^lcredit\\>.*/$formatted_output/gi" "/etc/security/pwquality.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_minclass='4'


# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/security/pwquality.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minclass")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minclass"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minclass\\>" "/etc/security/pwquality.conf"; then
    "${sed_command[@]}" "s/^minclass\\>.*/$formatted_output/gi" "/etc/security/pwquality.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_minlen='14'


# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/security/pwquality.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minlen")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minlen"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minlen\\>" "/etc/security/pwquality.conf"; then
    "${sed_command[@]}" "s/^minlen\\>.*/$formatted_output/gi" "/etc/security/pwquality.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_ocredit='-1'


# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/security/pwquality.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ocredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ocredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ocredit\\>" "/etc/security/pwquality.conf"; then
    "${sed_command[@]}" "s/^ocredit\\>.*/$formatted_output/gi" "/etc/security/pwquality.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_retry='3'


if [ -e "/etc/pam.d/common-password" ] ; then
    valueRegex="$var_password_pam_retry" defaultValue="$var_password_pam_retry"
    # non-empty values need to be preceded by an equals sign
    [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
    # add an equals sign to non-empty values
    [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"

    # fix 'type' if it's wrong
    if grep -q -P "^\\s*(?"'!'"password\\s)[[:alnum:]]+\\s+[[:alnum:]]+\\s+pam_pwquality.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*)[[:alnum:]]+(\\s+[[:alnum:]]+\\s+pam_pwquality.so)/\\1password\\2/" "/etc/pam.d/common-password"
    fi

    # fix 'control' if it's wrong
    if grep -q -P "^\\s*password\\s+(?"'!'"requisite)[[:alnum:]]+\\s+pam_pwquality.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+)[[:alnum:]]+(\\s+pam_pwquality.so)/\\1requisite\\2/" "/etc/pam.d/common-password"
    fi

    # fix the value for 'option' if one exists but does not match 'valueRegex'
    if grep -q -P "^\\s*password\\s+requisite\\s+pam_pwquality.so(\\s.+)?\\s+retry(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+requisite\\s+pam_pwquality.so(\\s.+)?\\s)retry=[^[:space:]]*/\\1retry${defaultValue}/" "/etc/pam.d/common-password"

    # add 'option=default' if option is not set
    elif grep -q -E "^\\s*password\\s+requisite\\s+pam_pwquality.so" < "/etc/pam.d/common-password" &&
            grep    -E "^\\s*password\\s+requisite\\s+pam_pwquality.so" < "/etc/pam.d/common-password" | grep -q -E -v "\\sretry(=|\\s|\$)" ; then

        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+requisite\\s+pam_pwquality.so[^\\n]*)/\\1 retry${defaultValue}/" "/etc/pam.d/common-password"
    # add a new entry if none exists
    elif ! grep -q -P "^\\s*password\\s+requisite\\s+pam_pwquality.so(\\s.+)?\\s+retry${valueRegex}(\\s|\$)" < "/etc/pam.d/common-password" ; then
        echo "password requisite pam_pwquality.so retry${defaultValue}" >> "/etc/pam.d/common-password"
    fi
else
    echo "/etc/pam.d/common-password doesn't exist" >&2
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_ucredit='-1'


# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/security/pwquality.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ucredit")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_ucredit"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ucredit\\>" "/etc/security/pwquality.conf"; then
    "${sed_command[@]}" "s/^ucredit\\>.*/$formatted_output/gi" "/etc/security/pwquality.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then

var_account_disable_post_pw_expiration='30'


# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/default/useradd"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^INACTIVE")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_account_disable_post_pw_expiration"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^INACTIVE\\>" "/etc/default/useradd"; then
    "${sed_command[@]}" "s/^INACTIVE\\>.*/$formatted_output/gi" "/etc/default/useradd"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/default/useradd"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then

var_accounts_maximum_age_login_defs='365'


grep -q ^PASS_MAX_DAYS /etc/login.defs && \
  sed -i "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS     $var_accounts_maximum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MAX_DAYS      $var_accounts_maximum_age_login_defs" >> /etc/login.defs
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then

var_accounts_minimum_age_login_defs='1'


grep -q ^PASS_MIN_DAYS /etc/login.defs && \
  sed -i "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS     $var_accounts_minimum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MIN_DAYS      $var_accounts_minimum_age_login_defs" >> /etc/login.defs
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then

var_accounts_password_warn_age_login_defs='7'


grep -q ^PASS_WARN_AGE /etc/login.defs && \
sed -i "s/PASS_WARN_AGE.*/PASS_WARN_AGE\t$var_accounts_password_warn_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]
then
  echo -e "PASS_WARN_AGE\t$var_accounts_password_warn_age_login_defs" >> /etc/login.defs
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
### Set Existing Passwords Maximum Age
### Set Existing Passwords Minimum Age
### Verify All Account Password Hashes are Shadowed with SHA512 (length check i assume)
### Prevent Login to Accounts With Empty Password
### Ensure that System Accounts Do Not Run a Shell Upon Login

find /home -name "*.netrc" -exec rm {} \;
awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | xargs --no-run-if-empty --max-lines=1 passwd -l
echo "auth             required        pam_wheel.so use_uid" >> /etc/pam.d/su
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /root/.bashrc
find /root -exec chmod g-wxt,o-wxt {} \;
var_accounts_user_umask='027'






grep -q umask /etc/bashrc && \
  sed -i "s/umask.*/umask $var_accounts_user_umask/g" /etc/bashrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> /etc/bashrc
fi
echo "umask $var_accounts_user_umask" >> /etc/csh.cshrc
echo "UMASK $var_accounts_user_umask" >> /etc/login.defs
echo "umask $var_accounts_user_umask" >> /etc/profile
while IFS= read -r dir; do
    while IFS= read -r -d '' file; do
        sed -i 's/^\([\s]*umask\s*\)/#\1/g' "$file"
    done <   <(find $dir -maxdepth 1 -type f -name ".*" -print0)
done <   <(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6}' /etc/passwd)
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_accounts_tmout='600'


# if 0, no occurence of tmout found, if 1, occurence found
tmout_found=0

for f in /etc/profile /etc/profile.d/*.sh; do
    if grep --silent '^\s*TMOUT' $f; then
        sed -i -E "s/^(\s*)TMOUT\s*=\s*(\w|\$)*(.*)$/\1TMOUT=$var_accounts_tmout\3/g" $f
        tmout_found=1
    fi
done

if [ $tmout_found -eq 0 ]; then
        echo -e "\n# Set TMOUT to $var_accounts_tmout per security requirements" >> /etc/profile.d/tmout.sh
        echo "TMOUT=$var_accounts_tmout" >> /etc/profile.d/tmout.sh
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chgrp -f " $3" "$6"/.[^\.]?*") }' /etc/passwd
awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chown -f " $3" "$6"/.[^\.]?*") }' /etc/passwd
for user in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $1}' /etc/passwd); do
    mkhomedir_helper $user 0077; ### Whats mkhomedir_helper
done
for home_dir in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6 }' /etc/passwd); do
    # Only update the permissions when necessary. This will avoid changing the inode timestamp when
    # the permission is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find "$home_dir" -maxdepth 0 -perm /7027 -exec chmod u-s,g-w-s,o=- {} \;
done
echo "ExecStartPost=-/sbin/augenrules --load" >> /usr/lib/systemd/system/auditd.service
echo "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S rmdir,unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S delete_module -F key=modules
-a always,exit -F arch=b64 -S init_module -F key=modules
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-w /sbin/rmmod -p x -k modules
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh-agent
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b32 -S stime -F key=audit_time_rules
-w /etc/localtime -p wa -k audit_time_rules
-e 2
-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
" >> /etc/audit/rules.d/0.rules
echo "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S rmdir,unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S delete_module -F key=modules
-a always,exit -F arch=b64 -S init_module -F key=modules
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-w /sbin/rmmod -p x -k modules
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh-agent
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b32 -S stime -F key=audit_time_rules
-w /etc/localtime -p wa -k audit_time_rules
-e 2
-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
" >> /etc/audit/rules.d/ZZZZZ.rules
echo "
-D
-b 8192
-f 1
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S rmdir,unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S delete_module -F key=modules
-a always,exit -F arch=b64 -S init_module -F key=modules
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-w /sbin/rmmod -p x -k modules
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh-agent
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
-a always,exit -F arch=b32 -S stime -F key=audit_time_rules
-w /etc/localtime -p wa -k audit_time_rules
-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
--backlog_wait_time 0
-a always,exit -F arch=b32 -S rename -S renameat -S unlink -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S delete_module -F key=modules
-a always,exit -F arch=b32 -S init_module -F key=modules
-e 2
" /etc/audit/rules.d/other.rules

chmod 644 /etc/audit/rules.d/ZZZZZ.rules
chmod 644 /etc/audit/rules.d/0.rules

sudo service auditd restart
# Remediation is applicable only in certain platforms

echo "
action_mail_acct = root
admin_space_left_action = single
max_log_file = 6
max_log_file_action = rotate
space_left_action = email
" >> /etc/audit/auditd.conf
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "auditd" &> /dev/null

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; }; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'auditd.service'
"$SYSTEMCTL_EXEC" start 'auditd.service'
"$SYSTEMCTL_EXEC" enable 'auditd.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed; }; then

# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*audit=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an audit= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)audit=[^[:space:]]\+\(.*\"\)/\1audit=1\2/"  '/etc/default/grub'
else
       # no audit=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit=1\"/"  '/etc/default/grub'
fi
update-grub

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed; }; then

# Correct the form of default kernel command line in GRUB
if grep -q '^GRUB_CMDLINE_LINUX=.*audit_backlog_limit=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an audit_backlog_limit= arg already exists
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)audit_backlog_limit=[^[:space:]]\+\(.*\"\)/\1audit_backlog_limit=8192\2/"  '/etc/default/grub'
else
       # no audit_backlog_limit=arg is present, append it
       sed -i "s/\(^GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit_backlog_limit=8192\"/"  '/etc/default/grub'
fi
update-grub

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

chown 0 /boot/grub/grub.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

chmod u-xs,g-xwrs,o-xwrt /boot/grub/grub.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
pwd="Baher13@costcoIsCool!"
echo "$pwd\n$pwd" | grub2-mkpasswd-pbkdf2
echo "
set superusers=\"boot\"
password_pbkdf2 boot grub.pbkdf2.sha512.VeryLongString
" >> /etc/grub.d/40_custom
update-grub
echo "*.* @@logcollector" >> /etc/rsyslog.conf
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "rsyslog" &> /dev/null

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'rsyslog.service'
"$SYSTEMCTL_EXEC" start 'rsyslog.service'
"$SYSTEMCTL_EXEC" enable 'rsyslog.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

DEBIAN_FRONTEND=noninteractive apt-get install -y "iptables" &> /dev/null
apt-get install -y iptables
apt-get install -y iptables-persistent
iptables -t nat -F
iptables -t mangle -F
iptables -t nat -X
iptables -t mangle -X
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -t nat -X
ip6tables -t mangle -X
ip6tables -F
ip6tables -X
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv6.conf.all.accept_ra from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_ra.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "net.ipv6.conf.all.accept_ra" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
sysctl_net_ipv6_conf_all_accept_ra_value='0'


#
# Set runtime for net.ipv6.conf.all.accept_ra
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_ra="$sysctl_net_ipv6_conf_all_accept_ra_value"

#
# If net.ipv6.conf.all.accept_ra present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_ra = value" to /etc/sysctl.conf
#
# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/sysctl.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_ra")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_ra_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_ra\\>" "/etc/sysctl.conf"; then
    "${sed_command[@]}" "s/^net.ipv6.conf.all.accept_ra\\>.*/$formatted_output/gi" "/etc/sysctl.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/sysctl.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv6.conf.all.accept_redirects from /etc/sysctl.d/*.conf files
for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf; do
  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "net.ipv6.conf.all.accept_redirects" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done
sysctl_net_ipv6_conf_all_accept_redirects_value='0'


#
# Set runtime for net.ipv6.conf.all.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_redirects="$sysctl_net_ipv6_conf_all_accept_redirects_value"

#
# If net.ipv6.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_redirects = value" to /etc/sysctl.conf
#
# Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
# Otherwise, regular sed command will do.
sed_command=('sed' '-i')
if test -L "/etc/sysctl.conf"; then
    sed_command+=('--follow-symlinks')
fi

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_redirects\\>" "/etc/sysctl.conf"; then
    "${sed_command[@]}" "s/^net.ipv6.conf.all.accept_redirects\\>.*/$formatted_output/gi" "/etc/sysctl.conf"
else
    # \n is precaution for case where file ends without trailing newline

    printf '%s\n' "$formatted_output" >> "/etc/sysctl.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.log_martians=1
sudo sysctl -w net.ipv4.conf.default.log_martians=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.conf.all.accept_ra=0
sudo sysctl -w net.ipv6.route.flush=1
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
sudo sysctl -w net.ipv6.route.flush=1
sudo sysctl -w kernel.randomize_va_space=2
sudo sysctl -w net.ipv6.conf.all.accept_source_route=0
sudo sysctl -w net.ipv6.conf.all.forwarding=0
sudo sysctl -w net.ipv6.conf.default.accept_ra=0
sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
sudo sysctl -w net.ipv6.conf.default.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w kernel.randomize_va_space=2
sudo sysctl -w net.ipv6.tcp_syncookies=1
sudo sysctl -w fs.protected_symlinks=1
sudo sysctl -w fs.protected_hardlinks=1
sudo sysctl -w kernel.kptr_restrict=2
sudo sysctl -w kernel.sysrq=0
echo "
net.ipv4.ip_forward=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.route.flush=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send redirects=0
net.ipv4.route.flush=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source route=0
net.ipv4.route.flush=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept redirects=0
net.ipv4.route.flush=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.route.flush=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.route.flush=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.route.flush=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.route.flush=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.route.flush=1
net.ipv4.route.flush=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.route.flush=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.route.flush=1
kernel.randomize_va_space=2
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.default.send_redirects=0
fs.suid_dumpable=0
kernel.randomize_va_space=2
net.ipv6.tcp_syncookies=1
fs.protected_symlinks=1
fs.protected_hardlinks=1
kernel.kptr_restrict=2
kernel.sysrq=0
" >> /etc/sysctl.d/0.rules
echo "
net.ipv4.ip_forward=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.route.flush=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send redirects=0
net.ipv4.route.flush=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source route=0
net.ipv4.route.flush=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept redirects=0
net.ipv4.route.flush=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.route.flush=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.route.flush=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.route.flush=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.route.flush=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.route.flush=1
net.ipv4.route.flush=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.route.flush=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.route.flush=1
kernel.randomize_va_space=2
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.default.send_redirects=0
fs.suid_dumpable=0
kernel.randomize_va_space=2
net.ipv4.tcp_syncookies=1
net.ipv6.tcp_syncookies=1
fs.protected_symlinks=1
fs.protected_hardlinks=1
kernel.kptr_restrict=2
kernel.sysrq=0
" >> /etc/sysctl.conf
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install dccp" /etc/modprobe.d/dccp.conf ; then

	sed -i 's#^install dccp.*#install dccp /bin/true#g' /etc/modprobe.d/dccp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/dccp.conf
	echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install rds" /etc/modprobe.d/rds.conf ; then

	sed -i 's#^install rds.*#install rds /bin/true#g' /etc/modprobe.d/rds.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/rds.conf
	echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install sctp" /etc/modprobe.d/sctp.conf ; then

	sed -i 's#^install sctp.*#install sctp /bin/true#g' /etc/modprobe.d/sctp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/sctp.conf
	echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install tipc" /etc/modprobe.d/tipc.conf ; then

	sed -i 's#^install tipc.*#install tipc /bin/true#g' /etc/modprobe.d/tipc.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/tipc.conf
	echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
sudo nmcli radio all off
sudo chgrp root /etc/group-
sudo chgrp shadow /etc/gshadow-
sudo chgrp root /etc/passwd-
sudo chgrp shadow /etc/shadow-
sudo chgrp root /etc/group
sudo chgrp shadow /etc/gshadow
sudo chgrp root /etc/passwd
sudo chgrp shadow /etc/shadow
sudo chown root /etc/group-
sudo chown root /etc/gshadow-
sudo chown root /etc/passwd-
sudo chown root /etc/shadow-
sudo chown root /etc/group
sudo chown root /etc/gshadow
sudo chown root /etc/passwd
sudo chown root /etc/shadow
sudo chmod 0644 /etc/group-
sudo chmod 0640 /etc/gshadow-
sudo chmod 0644 /etc/passwd-
sudo chmod 0640 /etc/shadow-
sudo chmod 0644 /etc/passwd
sudo chmod 0640 /etc/gshadow
sudo chmod 0644 /etc/passwd
sudo chmod 0640 /etc/shadow
### Ensure No World-Writable Files Exist
## Restrict Dynamic Mounting and Unmounting of Filesystems
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

function perform_remediation {



    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if [ "$(grep -c "$mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif [ "$(grep "$mount_point_match_regexp" /etc/fstab | grep -c "nodev")" -eq 0 ]; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        else
            mount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

function perform_remediation {



    mount_point_match_regexp="$(printf "[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if [ "$(grep -c "$mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif [ "$(grep "$mount_point_match_regexp" /etc/fstab | grep -c "noexec")" -eq 0 ]; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        else
            mount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
echo "*     hard   core    0" >> /etc/security/limits.conf
sudo sysctl -w fs.suid_dumpable=0
sudo systemctl mask --now avahi-daemon.service

## Restrict at and cron to Authorized Users if Necessary via allow not deny
sudo chgrp root /etc/at.allow
sudo chgrp root /etc/cron.allow
sudo chown root /etc/at.allow
sudo chown root /etc/cron.allow
sudo chmod 640 /etc/at.allow
sudo chmod 640 /etc/cron.allow
sudo chmod 640 /etc/cron.deny
sudo chmod 640 /etc/cron.allow
sudo systemctl enable cron.service
sudo chgrp root /etc/cron.d
sudo chgrp root /etc/cron.daily
sudo chgrp root /etc/cron.hourly
sudo chgrp root /etc/cron.weekly
sudo chgrp root /etc/cron.monthly
sudo chgrp root /etc/crontab
sudo chown root /etc/cron.d
sudo chown root /etc/cron.daily
sudo chown root /etc/cron.hourly
sudo chown root /etc/cron.weekly
sudo chown root /etc/cron.monthly
sudo chown root /etc/crontab
sudo chmod 0700 /etc/cron.d
sudo chmod 0700 /etc/cron.daily
sudo chmod 0700 /etc/cron.hourly
sudo chmod 0700 /etc/cron.weekly
sudo chmod 0700 /etc/cron.monthly
sudo chmod 0600 /etc/crontab
DEBIAN_FRONTEND=noninteractive apt-get install -y "ntp" &> /dev/null
DEBIAN_FRONTEND=noninteractive apt-get uninstall -y "chrony" &> /dev/null
sudo systemctl stop systemd-timesyncd
sudo systemctl disable systemd-timesyncd
sudo systemctl mask systemd-timesyncd
sudo timedatectl set-ntp on
sudo systemctl unmask ntpd
sudo systemctl enable ntpd
sudo systemctl start ntpd
DEBIAN_FRONTEND=noninteractive apt-get remove -y "xinetd" &> /dev/null
DEBIAN_FRONTEND=noninteractive apt-get remove -y "rsh-client" &> /dev/null
DEBIAN_FRONTEND=noninteractive apt-get remove -y "talk" &> /dev/null
DEBIAN_FRONTEND=noninteractive apt-get remove -y "telnet" &> /dev/null
SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'cups.service'
"$SYSTEMCTL_EXEC" disable 'cups.service'
"$SYSTEMCTL_EXEC" mask 'cups.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" list-unit-files | grep -q '^cups.socket'; then
    "$SYSTEMCTL_EXEC" stop 'cups.socket'
    "$SYSTEMCTL_EXEC" mask 'cups.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'cups.service' || true

opts="isc-dhcp-server nis bind vsftpd apache2 dovecot-core ldap-utils slapd squid samba snmp"
for x in $opts
do
    read -p "Remove $x [y/n]: " a
    if [ $a = y ]
    then
    DEBIAN_FRONTEND=noninteractive apt-get remove -y "$x" &> /dev/null
    echo "Removed!"
    fi
done

read -p "Install and configure openssh [y/n]: " a
if [ $a = y ]
then
    var_sshd_set_keepalive='3'
    if [ -e "/etc/ssh/sshd_config" ] ; then
        LC_ALL=C sed -i "/^\s*ClientAliveCountMax\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "ClientAliveCountMax $var_sshd_set_keepalive" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "ClientAliveCountMax $var_sshd_set_keepalive" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    sshd_idle_timeout_value='300'
    if [ -e "/etc/ssh/sshd_config" ] ; then

        LC_ALL=C sed -i "/^\s*ClientAliveInterval\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "ClientAliveInterval $sshd_idle_timeout_value" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "ClientAliveInterval $sshd_idle_timeout_value" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*HostbasedAuthentication\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "HostbasedAuthentication no" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "HostbasedAuthentication no" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*PermitEmptyPasswords\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "PermitEmptyPasswords no" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "PermitEmptyPasswords no" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*IgnoreRhosts\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "IgnoreRhosts yes" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "IgnoreRhosts yes" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "PermitRootLogin no" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "PermitRootLogin no" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*AllowTcpForwarding\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "AllowTcpForwarding no" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "AllowTcpForwarding no" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*X11Forwarding\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "X11Forwarding no" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "X11Forwarding no" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "PermitUserEnvironment no" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "PermitUserEnvironment no" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    if [ -e "/etc/ssh/sshd_config" ] ; then

    LC_ALL=C sed -i "/^\s*LogLevel\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "LogLevel INFO" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "LogLevel INFO" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    var_sshd_max_sessions='10'
    if [ -e "/etc/ssh/sshd_config" ] ; then

        LC_ALL=C sed -i "/^\s*MaxSessions\s\+/Id" "/etc/ssh/sshd_config"
    else
        touch "/etc/ssh/sshd_config"
    fi
    # make sure file has newline at the end
    sed -i -e '$a\' "/etc/ssh/sshd_config"

    cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
    # Insert before the line matching the regex '^Match'.
    line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
    if [ -z "$line_number" ]; then
        # There was no match of '^Match', insert at
        # the end of the file.
        printf '%s\n' "MaxSessions $var_sshd_max_sessions" >> "/etc/ssh/sshd_config"
    else
        head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
        printf '%s\n' "MaxSessions $var_sshd_max_sessions" >> "/etc/ssh/sshd_config"
        tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
    fi
    # Clean up after ourselves.
    rm "/etc/ssh/sshd_config.bak"
    echo "MaxAuthTries 4
    Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
    MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1" >> /etc/ssh/sshd_config
    sudo chgrp root /etc/ssh/sshd_config
    sudo chown root /etc/ssh/sshd_config
    sudo chmod 0600 /etc/ssh/sshd_config
    find -H /etc/ssh/ -maxdepth 1 -perm /u+xs,g+xwrs,o+xwrt -type f -regex '^.*_key$' -exec chmod u-xs,g-xwrs,o-xwrt {} \;
    find -H /etc/ssh/ -maxdepth 1 -perm /u+xs,g+xws,o+xwt -type f -regex '^.*.pub$' -exec chmod u-xs,g-xws,o-xwt {} \;
    sudo chmod 0644 /home/*/.ssh/*.pub
    sudo chmod 0600 /home/*/.ssh/*_key
fi
systemctl daemon-reload
