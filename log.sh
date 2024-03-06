RED="\033[31m"
GREEN="\033[32m"
ORANGE="\033[33m"
CYAN="\033[96m"
RESET="\033[0m"

sanitize() {
    sanitized="${1//[^$'\n' -~]/}"
}

log() {
    local sev="$1" color="$2" fmt="$3"
    shift 3
    printf "$color$sev:$RESET $fmt\n" "$@" >&2
}

info()    { log info    "$CYAN"   "$@"; }
success() { log success "$GREEN"  "$@"; }
warning() { log warning "$ORANGE" "$@"; }
error()   { log error   "$RED"    "$@"; }
fatal() {
    log "fatal error" "$RED" "$@"
    exit 1
}
