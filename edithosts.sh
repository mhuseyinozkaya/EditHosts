#!/usr/bin/env bash

# Check if the script was executed as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script must be run as root (use sudo)"
    exit 1
fi

ARGS=("$@")
ARG_COUNT="$#"
IP_ADDRESS=""
HOSTNAME=""
HOSTNAME_FILE="/etc/hosts"
EDIT_HOST_COMMENT="EditHosts declaration do not edit manually"

# Params: $IP_ADDRESS
ip_regex_check() {
    # IPv4 regex check
    if [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Params: $HOSTNAME
hostname_regex_check() {
    local hostname="$1"
    # Max 255 karakter kontrolü
    if [[ ${#hostname} -gt 255 ]]; then
        return 1
    fi
    # Label'lar için regex: 
    # Başında ve sonunda alfanümerik, içinde tire olabilir, 1-63 karakter arası
    local label_regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    
    local IFS='.'; read -ra labels <<< "$hostname"
    for label in "${labels[@]}"; do
        if ! [[ $label =~ $label_regex ]]; then
            return 1
        fi
    done
    return 0
}

# Find hostname of given IP address
# Params: find_hostname $IP_ADDRESS
find_hostname() {
    # Variable declaration
    local header_data
    local filtered
    header_data=$(curl -sI --connect-timeout 3 --max-time 5 "$1" | grep -i "Location")
    # If HTTP return data is not empty then parse header to get hostname
    if [ -n "$header_data" ]; then
        filtered=$(echo "$header_data" | awk '{print $2}')
        filtered="${filtered#*://}"; filtered="${filtered%%/*}"
        echo "$filtered"
        return 0
    fi
    return 1
}

# Params: edit_hosts_file $IP_ADDRESS $HOSTNAME
edit_hosts_file() {
    # Append comment line
    if ! grep -qF "$EDIT_HOST_COMMENT" "$HOSTNAME_FILE"; then
        echo "# $EDIT_HOST_COMMENT" >> $HOSTNAME_FILE
    fi
    # If hostname is already found in hosts file remove the old hostnames
    if grep -qF "$2" "$HOSTNAME_FILE"; then
        printf "[*] Hostname %s is already found, replacing with new ip address\n" "$2"
        sed -i "/$2/d" $HOSTNAME_FILE
    fi
    # Append new hostnames below the script comment
    sed -i "/# $EDIT_HOST_COMMENT/a $1 $2" $HOSTNAME_FILE
    echo "[+] Successfully written to hosts file"
}

#   Parameter parsing
if [[ "$ARG_COUNT" -eq 0 ]]; then
    echo "[!] Please enter an IP address"
    exit 2
elif [[ "$ARG_COUNT" -eq 1 ]] && ip_regex_check "${ARGS[0]}" ; then
    # If available find hostname from http header
    if HOSTNAME=$(find_hostname "${ARGS[0]}") && [ -n "$HOSTNAME" ] && hostname_regex_check "$HOSTNAME"; then
        printf "[+] Hostname %s found\n" "$HOSTNAME"
        IP_ADDRESS=${ARGS[0]}
    else
        echo "[!] Hostname not found, exiting..."
        exit 3
    fi
elif [[ "$ARG_COUNT" -eq 2 ]] && ip_regex_check "${ARGS[0]}" && hostname_regex_check "${ARGS[1]}"; then
    IP_ADDRESS=${ARGS[0]}
    HOSTNAME=${ARGS[1]}
else
    echo "[!] Please use the script correctly"
fi

#   Check if IP adress and hostname are empty
if [[ -n "$IP_ADDRESS" && -n "$HOSTNAME" && "$IP_ADDRESS" != "$HOSTNAME" ]]; then
    edit_hosts_file "$IP_ADDRESS" "$HOSTNAME"
else
    printf "[!] Nothing has changed in %s\n" "$HOSTNAME_FILE"
fi