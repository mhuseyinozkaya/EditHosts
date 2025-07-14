#!/usr/bin/env bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if the script was executed as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root (use sudo)${NC}"
    exit 1
fi

get_help() {
    cat << EOF
Usage: $0 [OPTIONS] [IP_ADDRESS] [HOSTNAME]

Options:
  -i                    Install the script system-wide by creating a symbolic link in /usr/local/bin.
  -h                    Show this help message.
  -tr, -rt              Test reachability of all hostnames in the hosts file and remove unreachable ones.
  IP_ADDRESS            Retrieve the hostname from HTTP headers of the given IP and add it to the hosts file.
  IP_ADDRESS HOSTNAME   Manually add or update the IP and hostname entry in the hosts file.

Examples:
  $0 -tr
  $0 -i
  $0 8.8.8.8
  $0 8.8.8.8 example.com

Notes:
  - This script must be run as root (use sudo).
  - IP addresses and hostnames are validated before processing.
  - The -i option installs the script to /usr/local/bin as 'edithosts',
    allowing you to run it globally from any directory.

EOF
}

IP_ADDRESS=""
HOSTNAME=""
HOSTS_FILE="/etc/hosts"
EDITHOSTS_BACKUP_FILE="/etc/hosts.EditHosts.bak"
EDITHOSTS_TOP_COMMENT="EditHosts declaration do not edit this comment and file manually"
EDITHOSTS_BOTTOM_COMMENT="End of EditHosts declaration do not edit comments"
REQUIRED_COMMANDS=("awk" "sed" "grep" "curl")

# Checks backup file for the security
if [[ -f "$EDITHOSTS_BACKUP_FILE" && -n "$EDITHOSTS_BACKUP_FILE" ]]; then
    printf "%s\n" \
    "[!] EditHosts backup file found" \
    "That means you terminated the script unsafely"
    read -rp "Press ENTER key to copy backup file..."
    cp "$EDITHOSTS_BACKUP_FILE" "$HOSTS_FILE"
    printf "${GREEN}[+] %s successfully copied to %s${NC}\n" "$EDITHOSTS_BACKUP_FILE" "$HOSTS_FILE"
fi

cp "$HOSTS_FILE" "$EDITHOSTS_BACKUP_FILE" # Copies hosts file to backup file

safeExit() {
    local arg="${1:-0}"
    if [[ -f "$EDITHOSTS_BACKUP_FILE" && -n "$EDITHOSTS_BACKUP_FILE" ]];then
        rm "$EDITHOSTS_BACKUP_FILE"
    fi
    # Exit codes
    case $arg in
        0)
            echo -e "${GREEN}[*] Program terminated safely and successfully${NC}";;
        2)
            echo -e "${RED}[!] Missing required dependencies for this script.${NC}";;
        3)  
            echo -e "${YELLOW}[!] EditHosts declarations are empty, no hostnames found${NC}";;
        4)
            echo -e "${RED}[!] Hostname not found${NC}";;
        5)
            echo -e "${GREEN}[+] Installation finished successfully. You can now run the script with: ${CYAN}edithosts${NC}";;
        *)
            echo -e "${RED}[!] Program exited with code $arg${NC}";;
    esac
    exit "$arg"
}

check_required_commands() {
    local isMissing=false
    for cmd in "$@"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            isMissing="true"
            printf "${RED}[!] %s not found${NC}\n" "$cmd"
        fi
    done
    "$isMissing" && safeExit 2
}

edit_comments() {
    # If top_comment not found in the file then append comment to end of file
    if ! grep -qF "$EDITHOSTS_TOP_COMMENT" "$HOSTS_FILE"; then
        echo "# $EDITHOSTS_TOP_COMMENT" >> $HOSTS_FILE
    fi
    # If bottom_comment not found then in the file append it after top_comment
    if ! grep -qF "$EDITHOSTS_BOTTOM_COMMENT" "$HOSTS_FILE"; then
        sed -i "/# $EDITHOSTS_TOP_COMMENT/a # $EDITHOSTS_BOTTOM_COMMENT" "$HOSTS_FILE"
    fi
}

# Arguments: $IP_ADDRESS
ip_regex_check() {
    # IPv4 regex check
    if [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Arguments: $HOSTNAME
hostname_regex_check() {
    local hostname="$1"
    # Hostame can be up to 255 characters
    if [[ ${#hostname} -gt 255 ]]; then
        return 1
    fi
    # Declaration regex template
    local label_regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'

    local IFS='.'; read -ra labels <<< "$hostname"
    for label in "${labels[@]}"; do
        if ! [[ $label =~ $label_regex ]]; then
            return 1
        fi
    done
    return 0
}

# Arguments: $IP_ADDRESS $HOSTNAME
edit_hosts_file() {
    # If hostname is already found in hosts file remove the old hostnames
    if grep -qF "$2" "$HOSTS_FILE"; then
        printf "${YELLOW}[*] Hostname %s is already found, replacing with new ip address${NC}\n" "$2"
        sed -i "/$2/d" $HOSTS_FILE
    fi
    # Append new IPs and hostnames between EditHosts comments
    sed -i "/# $EDITHOSTS_TOP_COMMENT/a $1 $2" "$HOSTS_FILE"
    echo -e "${GREEN}[+] Successfully written to hosts file${NC}"
}

# Find hostname of the given IP address
# Arguments: $IP_ADDRESS
find_hostname() {
    # Variable declaration
    local header_data
    local filtered url
    header_data=$(curl -sI --connect-timeout 3 --max-time 5 "$1" | grep -i "Location")
    # If HTTP return data is not empty then parse header to get hostname
    if [ -n "$header_data" ]; then
        url=$(echo "$header_data" | awk '{print $2}')
        url="${url#*://}" 
        filtered="${url%%/*}" 
        echo "$filtered"
        return 0
    fi
    return 1
}

# Gets hostnames between EditHosts comments
get_hosts() {
    local withinBlock=false
    while read -r line; do
        [[ "$line" == "# $EDITHOSTS_TOP_COMMENT" ]] && withinBlock=true && continue
        [[ "$line" == "# $EDITHOSTS_BOTTOM_COMMENT" ]] && withinBlock=false && continue
        $withinBlock && echo "$line"
    done < "$HOSTS_FILE"
}

# Checks host's reachability
# Arguments: $HOSTNAME
test_hosts() {
    local timeout=3
    echo -e "${YELLOW}[*] Checking reachability of host ${1} ...${NC}"
    ping -c3 -W "$timeout" "$1" > /dev/null 2>&1
}

# Arguments: $UNREACHABLE_HOSTNAMES
delete_hosts() {
    for hosts in "$@"; do
        sed -i "/$hosts/d" "$HOSTS_FILE"
        printf "${RED}[-] Host ${YELLOW}%s${RED} deleted${NC}\n" "$hosts"
    done
}

remove_unreachable_hosts() {
        mapfile -t hostnames < <(get_hosts | awk '{print $2}')
        if [[ "${#hostnames[@]}" -ne 0 ]]; then
            # Test hostnames
            local -a unreachableHosts=()
            for host in "${hostnames[@]}"; do
                if ! test_hosts "$host"; then
                    unreachableHosts+=("$host")
                fi
            done
            # Remove unreachables
            if [[ "${#unreachableHosts[@]}" -ne 0 ]]; then
                delete_hosts "${unreachableHosts[@]}" 
                echo -e "${GREEN}[*] Unreachable hosts successfully deleted${NC}"
            else
                echo -e "${CYAN}[*] Good news, all hostnames were reachable${NC}"
            fi
            return 0
        fi
        return 1
}

install_system_wide() {
        SCRIPT_NAME=$(basename "$0")
        SCRIPT_PATH=$(realpath "$0")
        INSTALLATION_DIR="/usr/local/lib/EditHosts"
        SYMBOLIC_LINK_DIR="/usr/local/bin"
    
        mkdir -p "$INSTALLATION_DIR"
        cp "$SCRIPT_PATH" "$INSTALLATION_DIR/$SCRIPT_NAME"
        # Eğer sembolik link varsa sil
        if [[ -L "$SYMBOLIC_LINK_DIR/edithosts" ]]; then
            rm "$SYMBOLIC_LINK_DIR/edithosts"
        fi

        ln -s "$INSTALLATION_DIR/$SCRIPT_NAME" "$SYMBOLIC_LINK_DIR/edithosts"
        return 0
}

parse_arguments() {

    local args arg_count
    args=("$@")
    arg_count="$#"

    if [[ "$arg_count" -eq 0 ]]; then
        echo -e "${RED}[!] Unknown usage, for help use ${NC}-h${RED} argument${NC}"
        return
    fi
    
    # Prints help message
    if [[ "$arg_count" -eq 1 && "${args[0]}" == "-h" ]]; then
        get_help
        return
    fi
    
    # Install script to system wide
    if [[ "$arg_count" -eq 1 && "${args[0]}" == "-i" ]]; then
        install_system_wide && safeExit 5
    fi

    # Test hostname reachability and remove the unreachables
    if [[ "$arg_count" -eq 1 && ( "${args[0]}" == "-tr" || "${args[0]}" == "-rt" ) ]]; then
        remove_unreachable_hosts || safeExit 3
        return
    fi

    #   If the only argument is IP address and valid then finds hostnames
    if [[ "$arg_count" -eq 1 ]] && ip_regex_check "${args[0]}"; then
        # If available find hostname from http header
        if HOSTNAME=$(find_hostname "${args[0]}") && \
            [ -n "$HOSTNAME" ] && hostname_regex_check "$HOSTNAME"; then
            printf "${GREEN}[+] Hostname ${CYAN}%s${GREEN} found${NC}\n" "$HOSTNAME"
            IP_ADDRESS=${args[0]}
        else
            safeExit 4
        fi
    #   Checks if IP and hostname are valid
    elif [[ "$arg_count" -eq 2 ]] && \
        ip_regex_check "${args[0]}" && hostname_regex_check "${args[1]}"; then
        IP_ADDRESS=${args[0]}
        HOSTNAME=${args[1]}
    fi

    #   Check if IP address and hostname are empty
    if [[ -n "$IP_ADDRESS" && -n "$HOSTNAME" && "$IP_ADDRESS" != "$HOSTNAME" ]]; then
        edit_hosts_file "$IP_ADDRESS" "$HOSTNAME"
    else
        printf "${YELLOW}[!] Nothing has changed in %s${NC}\n" "$HOSTS_FILE"
    fi
}

check_required_commands "${REQUIRED_COMMANDS[@]}"
edit_comments
parse_arguments "$@"
safeExit 0