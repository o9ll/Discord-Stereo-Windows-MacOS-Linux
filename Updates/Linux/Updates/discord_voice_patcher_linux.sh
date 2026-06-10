#!/usr/bin/env bash

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

set -euo pipefail

SCRIPT_VERSION="8.8"
SKIP_BACKUP=false
RESTORE_MODE=false

# region Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; DIM='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'
# endregion Colors

# region Config
SAMPLE_RATE=48000
BITRATE=248
BITRATE_BPS=$((BITRATE * 1000))

DETECT_HOME="${HOME:-}"
if [[ -n "${SUDO_USER:-}" ]] && [[ "$(id -u 2>/dev/null)" -eq 0 ]]; then
    _dh=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    [[ -n "${_dh:-}" ]] && DETECT_HOME="$_dh"
fi
[[ -z "${DETECT_HOME:-}" ]] && DETECT_HOME="${HOME:-}"

CACHE_DIR="$DETECT_HOME/.cache/DiscordVoicePatcher"
BACKUP_DIR="$CACHE_DIR/Backups"
LOG_FILE="$CACHE_DIR/patcher.log"
TEMP_DIR="$CACHE_DIR/build"
MAX_BACKUPS_PER_CLIENT="${MAX_BACKUPS_PER_CLIENT:-3}"
MAX_BACKUP_AGE_DAYS="${MAX_BACKUP_AGE_DAYS:-45}"
VOICE_BACKUP_DIR="${VOICE_BACKUP_DIR:-$CACHE_DIR/VoiceBackupLinux}"
VOICE_BACKUP_API="${VOICE_BACKUP_API:-https://api.github.com/repos/o9ll/Discord-Stereo-Windows-MacOS-Linux/contents/Updates%2FNodes%2FUnpatched%20Nodes%20%28For%20Patcher%29%2FLinux}"
# endregion Config

# region Offsets (PASTE HERE)

EXPECTED_MD5="fb6684a550a7b5c0fdfe65ec954649a9"
EXPECTED_SIZE=104160072

OFFSET_CommitAudioCodec_StereoCheck1_Imm0=0x39C300
OFFSET_CommitAudioCodec_StereoCheck2_Imm0=0x398665

OFFSET_CreateAudioFrame_Channels_MovImm2=0x390070

OFFSET_CapturedAudioProcessor_MonoDownmix_NopJmp=0x35ECFC

OFFSET_AudioEncoderOpusConfig_Ctor_Channels_Imm02=0x7699D5
OFFSET_AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02=0x7693AE

OFFSET_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k=0x7699DF
OFFSET_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k=0x7693B8
OFFSET_AudioEncoderOpusConfig_Ctor_FrameMs_Imm10=0x7699C6
OFFSET_AudioEncoderOpusConfig_Ctor_Application_ImmAudio=0x7699EA
OFFSET_RecreateEncoderInstance_FecBranch_Jmp=0x99E1B7
OFFSET_MultiChannelRecreateEncoder_FecBranch_Jmp=0x964958
OFFSET_SetFec_EnableBranch_Jmp=0x99E9E6
OFFSET_RecreateEncoderInstance_DtxBranch_Jmp=0x99E2A1
OFFSET_MultiChannelRecreateEncoder_DtxBranch_Jmp=0x964A8E
OFFSET_SetDtx_EnableBranch_Jmp=0x99EA86
OFFSET_CopyRedEncodeImpl_RedundantCopy_JmpNear=0x7A6025

OFFSET_RecreateEncoder_BitrateCalcLow_Channels_Mov248k=0x9652BD
OFFSET_RecreateEncoder_BitrateCalcMid_Channels_Mov248k=0x9652DB
OFFSET_RecreateEncoder_BitrateCalcHigh_Channels_Mov248k=0x9652F0
OFFSET_MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k=0x99D630
OFFSET_MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k=0x99D64E
OFFSET_MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k=0x99D663
OFFSET_AudioBitrateAdaptorCalc32k_Channels_Mov248k=0x973708
OFFSET_AudioBitrateAdaptorCalc48k_Channels_Mov248k=0x973717
OFFSET_AudioBitrateAdaptorCalc60k_Channels_Mov248k=0x973726

OFFSET_ApplySettings_BitrateImul_Imm248k=0x39005C
OFFSET_SetTargetBitrate_Mulss_Nop6=0x99F045
OFFSET_GetMultipliedBitrate_Mulss_Nop7=0x99FB82

OFFSET_SelectSampleRate_Constant_Imm48k=0x39005A

OFFSET_WebRtcSplHighPass_Entry_Ret=0x71F110

OFFSET_hp_cutoff_Callback_InjectShellcode=0x762640
OFFSET_dc_reject_Callback_InjectShellcode=0x7627F0

OFFSET_ChannelDownmix_Entry_Ret=0x98E420

OFFSET_AudioEncoderOpusConfig_IsOK_MovTrueRet=0x769B70

FILE_OFFSET_ADJUSTMENT=0

REQUIRED_OFFSET_NAMES=(
    CommitAudioCodec_StereoCheck1_Imm0 CommitAudioCodec_StereoCheck2_Imm0
    CreateAudioFrame_Channels_MovImm2
    CapturedAudioProcessor_MonoDownmix_NopJmp
    AudioEncoderOpusConfig_Ctor_Channels_Imm02 AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02
    AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k
    AudioEncoderOpusConfig_Ctor_FrameMs_Imm10 AudioEncoderOpusConfig_Ctor_Application_ImmAudio
    RecreateEncoderInstance_FecBranch_Jmp MultiChannelRecreateEncoder_FecBranch_Jmp SetFec_EnableBranch_Jmp
    RecreateEncoderInstance_DtxBranch_Jmp MultiChannelRecreateEncoder_DtxBranch_Jmp SetDtx_EnableBranch_Jmp
    CopyRedEncodeImpl_RedundantCopy_JmpNear
    RecreateEncoder_BitrateCalcLow_Channels_Mov248k RecreateEncoder_BitrateCalcMid_Channels_Mov248k RecreateEncoder_BitrateCalcHigh_Channels_Mov248k
    MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k
    AudioBitrateAdaptorCalc32k_Channels_Mov248k AudioBitrateAdaptorCalc48k_Channels_Mov248k AudioBitrateAdaptorCalc60k_Channels_Mov248k
    ApplySettings_BitrateImul_Imm248k
    SetTargetBitrate_Mulss_Nop6 GetMultipliedBitrate_Mulss_Nop7
    SelectSampleRate_Constant_Imm48k
    WebRtcSplHighPass_Entry_Ret hp_cutoff_Callback_InjectShellcode dc_reject_Callback_InjectShellcode ChannelDownmix_Entry_Ret
    AudioEncoderOpusConfig_IsOK_MovTrueRet
)

# endregion Offsets

# region Validation bytes (anchors)
ORIG_CreateAudioFrame_Channels_MovImm2='{0x49, 0x39, 0xC4, 0x4C, 0x0F, 0x43, 0xE0}'
ORIG_CapturedAudioProcessor_MonoDownmix_NopJmp='{0x84, 0xC0, 0x74, 0x0D, 0x83, 0xBB, 0x80, 0x00, 0x00, 0x00, 0x09, 0x0F, 0x8F}'
ORIG_SelectSampleRate_Constant_Imm48k='{0x41, 0xBD, 0x00, 0x7D, 0x00, 0x00}'
ORIG_AudioEncoderOpusConfig_IsOK_MovTrueRet='{0x55, 0x48, 0x89, 0xE5, 0x8B, 0x0F, 0x31, 0xC0}'
ORIG_ChannelDownmix_Entry_Ret='{0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56}'
ORIG_WebRtcSplHighPass_Entry_Ret='{0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56}'
ORIG_hp_cutoff_Callback_InjectShellcode='{0x55, 0x48, 0x89, 0xE5}'
ORIG_dc_reject_Callback_InjectShellcode='{0x55, 0x48, 0x89, 0xE5}'
ORIG_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k='{0x00, 0x7D, 0x00, 0x00}'
ORIG_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k='{0x00, 0x7D, 0x00, 0x00}'
ORIG_ApplySettings_BitrateImul_Imm248k='{0x00, 0x7D, 0x00}'
ORIG_SetTargetBitrate_Mulss_Nop6='{0xF3, 0x0F, 0x59, 0x44, 0x81, 0xEC}'
ORIG_GetMultipliedBitrate_Mulss_Nop7='{0xF3, 0x0F, 0x59, 0x44, 0x81, 0xEC}'
# endregion Validation bytes (anchors)

PATCH_SUCCESS=false

# region Logging
log_info()  { echo -e "${WHITE}[--]${NC} $1"; echo "[INFO] $1" >> "$LOG_FILE" 2>/dev/null; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; echo "[OK] $1" >> "$LOG_FILE" 2>/dev/null; }
log_warn()  { echo -e "${YELLOW}[!!]${NC} $1"; echo "[WARN] $1" >> "$LOG_FILE" 2>/dev/null; }
log_error() { echo -e "${RED}[XX]${NC} $1"; echo "[ERROR] $1" >> "$LOG_FILE" 2>/dev/null; }
# endregion Logging

banner() {
    echo ""
    echo -e "${CYAN}===== Discord Voice Quality Patcher v${SCRIPT_VERSION} =====${NC}"
    echo -e "${CYAN}      48 kHz | 248 kbps | Stereo${NC}"
    echo -e "${CYAN}      Platform: Linux | Multi-Client${NC}"
    echo -e "${CYAN}===============================================${NC}"
    echo ""
}

show_settings() {
    echo -e "Config: ${SAMPLE_RATE}Hz, ${BITRATE}kbps, Stereo (Linux)"
    if $PATCH_LOCAL_ONLY; then
        echo -e "Voice bundle: ${YELLOW}local node only (--patch-local)${NC}"
    else
        echo -e "Voice bundle: ${GREEN}download stock module from GitHub, then patch${NC}"
    fi
    echo ""
}

# region CLI
SILENT_MODE=false
PATCH_ALL=false
PATCH_LOCAL_ONLY=false

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "  --skip-backup   Don't create backup before patching"
    echo "  --restore       Restore from backup"
    echo "  --list-backups  Show available backups"
    echo "  --silent        No prompts, patch all clients"
    echo "  --patch-all     Patch all clients (no selection menu)"
    echo "  --patch-local   Do not download the stock voice bundle from GitHub; patch"
    echo "                  the discord_voice.node already on disk (advanced)"
    echo "  --help          Show this help"
    echo ""
    echo "By default the patcher downloads the unpatched Linux voice module bundle from"
    echo "GitHub (same source as the Windows patcher, Linux folder), installs it over"
    echo "each client's voice folder, then applies patches. Override VOICE_BACKUP_API"
    echo "or set DISCORD_VOICE_PATCHER_GITHUB_TOKEN / GITHUB_TOKEN for private forks or API limits."
    echo ""
    echo "Examples:"
    echo "  $0
    echo "  $0 --restore
    echo "  $0 --silent
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --skip-backup) SKIP_BACKUP=true ;;
        --restore) RESTORE_MODE=true ;;
        --list-backups) mkdir -p "$BACKUP_DIR"; ls -la "$BACKUP_DIR/" 2>/dev/null || echo "No backups found"; exit 0 ;;
        --silent|-s) SILENT_MODE=true; PATCH_ALL=true ;;
        --patch-all) PATCH_ALL=true ;;
        --patch-local) PATCH_LOCAL_ONLY=true ;;
        --help|-h) usage ;;
        *)
            echo "Unknown option: $arg"
            usage
            ;;
    esac
done
# endregion CLI

# region Init
mkdir -p "$CACHE_DIR" "$BACKUP_DIR" "$TEMP_DIR"
echo "=== Discord Voice Patcher Log ===" > "$LOG_FILE"
echo "Started: $(date)" >> "$LOG_FILE"
echo "Platform: Linux" >> "$LOG_FILE"
# endregion Init

# region Backup retention
prune_voice_backups() {
    [[ -d "$BACKUP_DIR" ]] || return 0
    local removed=0 f bn k i j
    local -a list odd

    while IFS= read -r -d '' f; do
        [[ -f "$f" ]] || continue
        rm -f "$f" 2>/dev/null && removed=$((removed + 1)) || true
    done < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'discord_voice.node.*.backup' -mtime "+${MAX_BACKUP_AGE_DAYS}" -print0 2>/dev/null)

    declare -A seen=()
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        bn=$(basename "$f")
        if [[ "$bn" =~ ^discord_voice\.node\.(.+)\.[0-9]{8}_[0-9]{6}\.backup$ ]]; then
            seen["${BASH_REMATCH[1]}"]=1
        fi
    done < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'discord_voice.node.*.backup' 2>/dev/null)

    for k in "${!seen[@]}"; do
        list=()
        mapfile -t list < <(ls -1t "$BACKUP_DIR"/discord_voice.node."${k}".*.backup 2>/dev/null || true)
        local n=${
        if (( n > MAX_BACKUPS_PER_CLIENT )); then
            for (( i = MAX_BACKUPS_PER_CLIENT; i < n; i++ )); do
                rm -f "${list[$i]}" 2>/dev/null && removed=$((removed + 1)) || true
            done
        fi
    done

    odd=()
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        bn=$(basename "$f")
        [[ "$bn" =~ ^discord_voice\.node\.(.+)\.[0-9]{8}_[0-9]{6}\.backup$ ]] && continue
        odd+=("$f")
    done < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'discord_voice.node.*.backup' 2>/dev/null)

    if (( ${
        mapfile -t odd < <(for f in "${odd[@]}"; do stat -c $'%Y\t%n' "$f" 2>/dev/null; done | sort -rn | cut -f2-)
        for (( j = MAX_BACKUPS_PER_CLIENT; j < ${
            rm -f "${odd[$j]}" 2>/dev/null && removed=$((removed + 1)) || true
        done
    fi

    if (( removed > 0 )); then
        log_info "Pruned old voice backups: removed $removed file(s) (max $MAX_BACKUPS_PER_CLIENT per client, max age ${MAX_BACKUP_AGE_DAYS}d)."
    fi
}

prune_voice_backups
# endregion Backup retention

# region Voice bundle (GitHub)
download_linux_voice_bundle_from_github() {
    local py=""
    if command -v python3 &>/dev/null; then
        py="python3"
    elif command -v python &>/dev/null && python -c "import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)" 2>/dev/null; then
        py="python"
    fi
    if [[ -z "$py" ]]; then
        log_error "Python 3.6+ is required to download the voice bundle from GitHub."
        log_error "  Install python3, or re-run with --patch-local to patch your existing node only."
        return 1
    fi

    log_info "Downloading voice bundle from GitHub..."
    log_info "  API: ${VOICE_BACKUP_API:0:80}..."
    log_info "  Dest: $VOICE_BACKUP_DIR"

    if ! VOICE_BACKUP_DIR="$VOICE_BACKUP_DIR" VOICE_BACKUP_API="$VOICE_BACKUP_API" "$py" - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)

def main() -> None:
    dest = os.environ.get("VOICE_BACKUP_DIR", "").strip()
    api = os.environ.get("VOICE_BACKUP_API", "").strip()
    if not dest or not api:
        die("VOICE_BACKUP_DIR / VOICE_BACKUP_API must be set")
    token = (
        os.environ.get("DISCORD_VOICE_PATCHER_GITHUB_TOKEN", "").strip()
        or os.environ.get("GITHUB_TOKEN", "").strip()
    )
    os.makedirs(dest, exist_ok=True)
    for name in os.listdir(dest):
        p = os.path.join(dest, name)
        if os.path.isdir(p):
            import shutil
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                os.remove(p)
            except OSError:
                pass

    req = urllib.request.Request(api)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "DiscordVoicePatcher-Linux")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            payload = r.read()
    except urllib.error.HTTPError as e:
        if e.code == 403:
            die("GitHub API returned 403 (rate limit or auth). Set DISCORD_VOICE_PATCHER_GITHUB_TOKEN or GITHUB_TOKEN, or try again later.")
        die(f"GitHub API HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        die(f"GitHub API request failed: {e}")

    try:
        items = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        die(f"Invalid JSON from GitHub API: {e}")

    if not isinstance(items, list):
        die("Unexpected GitHub API response (expected a list of directory entries)")

    n = 0
    for item in items:
        if not isinstance(item, dict) or item.get("type") != "file":
            continue
        name = item.get("name")
        url = item.get("download_url")
        if not name or not url:
            continue
        out = os.path.join(dest, name)
        freq = urllib.request.Request(url)
        freq.add_header("User-Agent", "DiscordVoicePatcher-Linux")
        if token:
            freq.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(freq, timeout=120) as fr:
                data = fr.read()
        except urllib.error.HTTPError as e:
            die(f"Failed to download {name}: HTTP {e.code}")
        except urllib.error.URLError as e:
            die(f"Failed to download {name}: {e}")
        if len(data) == 0:
            die(f"Downloaded empty file: {name}")
        with open(out, "wb") as f:
            f.write(data)
        n += 1

    if n == 0:
        die("No files downloaded from the voice bundle folder (empty listing or API error).")
    print(n)

if __name__ == "__main__":
    main()
PY
    then
        log_error "Voice bundle download failed."
        return 1
    fi

    local node="$VOICE_BACKUP_DIR/discord_voice.node"
    if [[ ! -f "$node" ]]; then
        log_error "discord_voice.node missing after download: $node"
        return 1
    fi

    local sz md5
    sz=$(stat -c%s "$node" 2>/dev/null || echo "0")
    if [[ "$sz" != "$EXPECTED_SIZE" ]]; then
        log_error "Downloaded discord_voice.node size $sz != expected $EXPECTED_SIZE"
        log_error "  Refresh offsets in this script for your repo bundle, or fix VOICE_BACKUP_API."
        return 1
    fi

    if command -v md5sum &>/dev/null; then
        md5=$(md5sum "$node" | cut -d' ' -f1)
    elif command -v md5 &>/dev/null; then
        md5=$(md5 -q "$node")
    else
        log_warn "Could not verify MD5 (no md5sum/md5); continuing with size check only."
        log_ok "Voice bundle downloaded ($(basename "$VOICE_BACKUP_DIR"))"
        return 0
    fi

    if [[ "${md5,,}" != "${EXPECTED_MD5,,}" ]]; then
        log_error "Downloaded discord_voice.node MD5 $md5 != patcher stock $EXPECTED_MD5"
        log_error "  Update EXPECTED_MD5 / offsets in this script to match your GitHub bundle."
        return 1
    fi

    log_ok "Voice bundle verified (stock MD5) - $(ls -1 "$VOICE_BACKUP_DIR" 2>/dev/null | wc -l) file(s)"
    return 0
}

install_linux_voice_bundle_for_client() {
    local node_path="$1"
    local voice_dir
    voice_dir=$(dirname "$node_path")

    if [[ ! -d "$VOICE_BACKUP_DIR" ]] || [[ -z "$(ls -A "$VOICE_BACKUP_DIR" 2>/dev/null)" ]]; then
        log_error "Voice bundle cache empty: $VOICE_BACKUP_DIR"
        return 1
    fi

    log_info "Installing stock voice module from bundle into:"
    log_info "  $voice_dir"

    if [[ ! -d "$voice_dir" ]]; then
        log_error "Voice directory does not exist: $voice_dir"
        return 1
    fi

    find "$voice_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    if ! cp -a "$VOICE_BACKUP_DIR"/. "$voice_dir"/; then
        log_error "Failed to copy voice bundle into $voice_dir"
        return 1
    fi

    if [[ ! -f "$node_path" ]]; then
        log_error "discord_voice.node not present after bundle install: $node_path"
        return 1
    fi

    log_ok "Stock voice files installed"
    return 0
}
# endregion Voice bundle (GitHub)

# region Discord process detection
DISCORD_PIDS=""

check_discord_running() {
    DISCORD_PIDS=""
    local pids pid cmdline filtered_pids=""
    pids=$(pgrep -f '[D]iscord' 2>/dev/null | head -50 || true)
    [[ -z "$pids" ]] && return 1

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
        [[ -z "$cmdline" ]] && continue

        [[ "$cmdline" =~ discord_voice_patcher ]] && continue

        if [[ "$cmdline" =~ (^|/)(Discord|DiscordCanary|DiscordPTB|DiscordDevelopment)(/| |$) ]] ||
           [[ "$cmdline" =~ /opt/discord[^_] ]] ||
           [[ "$cmdline" =~ /usr/(share|lib)/discord ]] ||
           [[ "$cmdline" =~ com\.discordapp\.Discord ]] ||
           [[ "$cmdline" =~ /snap/discord/ ]]; then
            filtered_pids+="$pid "
        fi
    done <<< "$pids"

    filtered_pids="${filtered_pids% }"
    if [[ -n "$filtered_pids" ]]; then
        DISCORD_PIDS="$filtered_pids"
        return 0
    fi
    return 1
}

handle_discord_running() {
    if ! check_discord_running; then
        return 0
    fi

    echo ""
    log_warn "Discord is currently running."
    log_warn "Patching while Discord is running can cause:"
    log_warn "  - Crashes if the voice module is in use"
    log_warn "  - Patches being overwritten when Discord restarts"
    echo ""

    if $SILENT_MODE; then
        log_info "Silent mode: Attempting to close Discord..."
        terminate_discord
        return $?
    fi

    echo -e "  [${WHITE}1${NC}] Close Discord and continue patching"
    echo -e "  [${WHITE}2${NC}] Continue without closing (not recommended)"
    echo -e "  [${WHITE}3${NC}] Cancel"
    echo ""

    read -rp "  Choice [1]: " choice
    case "${choice:-1}" in
        1)
            terminate_discord
            return $?
            ;;
        2)
            log_warn "Continuing with Discord running - patches may not take effect until restart"
            return 0
            ;;
        3)
            log_info "Cancelled. Close Discord manually and re-run."
            exit 0
            ;;
        *)
            terminate_discord
            return $?
            ;;
    esac
}
# endregion Discord process detection

terminate_discord() {
    log_info "Closing Discord processes..."

    local pid killed=false
    if check_discord_running && [[ -n "$DISCORD_PIDS" ]]; then
        for pid in $DISCORD_PIDS; do
            kill "$pid" 2>/dev/null && killed=true || true
        done
    fi

    if ! $killed; then
        log_ok "No Discord processes to close"
        return 0
    fi

    local attempts=0
    while (( attempts < 20 )); do
        if ! check_discord_running; then
            log_ok "Discord closed successfully"
            sleep 1
            return 0
        fi
        sleep 0.5
        attempts=$(( attempts + 1 ))
    done

    log_warn "Discord didn't shut down gracefully, forcing..."
    if check_discord_running && [[ -n "$DISCORD_PIDS" ]]; then
        for pid in $DISCORD_PIDS; do
            kill -9 "$pid" 2>/dev/null || true
        done
    fi

    sleep 1

    if check_discord_running; then
        log_error "Failed to close Discord. Please close it manually."
        return 1
    fi

    log_ok "Discord closed"
    return 0
}

# region Discord Client Detection
declare -a CLIENT_NAMES=()
declare -a CLIENT_NODES=()

find_discord_clients() {
    log_info "Scanning for Discord installations..."

    local search_bases=(
        "$DETECT_HOME/.config/discord"
        "$DETECT_HOME/.config/discordcanary"
        "$DETECT_HOME/.config/discordptb"
        "$DETECT_HOME/.config/discorddevelopment"
        "$DETECT_HOME/.var/app/com.discordapp.Discord/config/discord"
        "$DETECT_HOME/.var/app/com.discordapp.DiscordCanary/config/discordcanary"
        "/snap/discord/current/usr/share/discord/resources"
        "/opt/discord/resources"
        "/opt/discord-canary/resources"
        "/opt/discord-ptb/resources"
        "/usr/share/discord/resources"
        "/usr/lib/discord/resources"
    )
    local search_names=(
        "Discord Stable"
        "Discord Canary"
        "Discord PTB"
        "Discord Development"
        "Discord (Flatpak)"
        "Discord Canary (Flatpak)"
        "Discord (Snap)"
        "Discord (/opt)"
        "Discord Canary (/opt)"
        "Discord PTB (/opt)"
        "Discord (/usr/share)"
        "Discord (/usr/lib)"
    )

    local found_paths=()
    local i base name found_nodes latest resolved dup fp fsize

    for i in "${!search_bases[@]}"; do
        base="${search_bases[$i]}"
        name="${search_names[$i]}"

        [[ -d "$base" ]] || continue

        found_nodes=$(find "$base" -maxdepth 10 -name "discord_voice.node" -type f 2>/dev/null | head -5 || true)
        [[ -z "$found_nodes" ]] && continue

        latest=$(echo "$found_nodes" | while read -r f; do
            stat -c '%Y %n' "$f" 2>/dev/null || echo "0 $f"
        done | sort -rn | head -1 | cut -d' ' -f2-)

        if [[ -n "$latest" && -f "$latest" ]]; then
            resolved=$(readlink -f "$latest" 2>/dev/null || echo "$latest")
            dup=false
            for fp in "${found_paths[@]+"${found_paths[@]}"}"; do
                [[ "$fp" == "$resolved" ]] && { dup=true; break; }
            done
            $dup && continue

            if [[ ! -r "$latest" ]]; then
                log_warn "Found but unreadable: $latest"
                continue
            fi
            fsize=$(stat -c%s "$latest" 2>/dev/null || echo "0")
            if (( fsize == 0 )); then
                log_warn "Found but empty (0 bytes): $latest"
                continue
            fi

            CLIENT_NAMES+=("$name")
            CLIENT_NODES+=("$latest")
            found_paths+=("$resolved")
            log_ok "Found: $name"
            log_info "  Path: $latest"
            log_info "  Size: $(numfmt --to=iec "$fsize" 2>/dev/null || echo "${fsize} bytes")"
        fi
    done

    if [[ ${
        log_error "No Discord installations found!"
        echo ""
        echo "Expected discord_voice.node in one of:"
        echo "  ~/.config/discord/app-*/modules/discord_voice-*/discord_voice/"
        echo "  ~/.config/discordcanary/app-*/modules/discord_voice-*/discord_voice/"
        echo "  ~/.config/discordptb/app-*/modules/discord_voice-*/discord_voice/"
        echo "  ~/.config/discorddevelopment/app-*/modules/discord_voice-*/discord_voice/"
        echo "  ~/.var/app/com.discordapp.Discord/config/discord/..."
        echo "  /opt/discord/... /usr/share/discord/... /snap/discord/..."
        echo ""
        echo "Make sure Discord has been opened and you've joined a voice channel"
        echo "at least once so the voice module gets downloaded."
        if [[ -n "${SUDO_USER:-}" ]] && [[ "$(id -u 2>/dev/null)" -eq 0 ]]; then
            echo ""
            echo "Tip: Checked config for user $SUDO_USER ($DETECT_HOME)."
            echo "If Discord is installed for another user, run without sudo as that user."
        fi
        return 1
    fi

    log_ok "Found ${
    return 0
}
# endregion Discord Client Detection


# region Binary Verification
verify_binary() {
    local node_path="$1"
    local name="$2"

    if [[ ! -f "$node_path" ]]; then
        log_error "Binary not found: $node_path"
        return 1
    fi
    if [[ ! -r "$node_path" ]]; then
        log_error "Binary not readable: $node_path"
        log_error "  Try: chmod +r '$node_path'"
        return 1
    fi

    local fsize
    fsize=$(stat -c%s "$node_path" 2>/dev/null || echo "0")

    if [[ "$fsize" -ne "$EXPECTED_SIZE" ]]; then
        log_error "Binary size mismatch for $name"
        log_error "  Expected: $EXPECTED_SIZE bytes"
        log_error "  Got:      $fsize bytes"
        log_error "  This version of discord_voice.node is not supported by these offsets."
        log_error "  The offsets in this script are for MD5: $EXPECTED_MD5"
        return 1
    fi

    local actual_md5
    if command -v md5sum &>/dev/null; then
        if ! actual_md5=$(md5sum "$node_path" 2>/dev/null | cut -d' ' -f1); then
            log_error "Failed to compute md5 for $name"
            return 1
        fi
    elif command -v md5 &>/dev/null; then
        if ! actual_md5=$(md5 -q "$node_path" 2>/dev/null); then
            log_error "Failed to compute md5 for $name"
            return 1
        fi
    else
        log_error "No md5sum or md5 found - cannot verify binary integrity"
        log_error "  Install coreutils: sudo apt install coreutils"
        return 1
    fi

    if [[ "$actual_md5" == "$EXPECTED_MD5" ]]; then
        log_ok "Binary verified (stock MD5)"
        return 0
    fi

    log_warn "MD5 != stock (often already patched). Continuing; patcher validates sites."
    return 0
}
# endregion Binary Verification


# region Backup Management
backup_node() {
    local source="$1"
    local client_name="$2"

    if $SKIP_BACKUP; then
        log_warn "Skipping backup (--skip-backup)"
        return 0
    fi

    if [[ ! -f "$source" ]]; then
        log_error "Cannot backup: file not found: $source"
        return 1
    fi

    local sanitized
    sanitized=$(echo "$client_name" | tr ' ' '_' | tr -d '()[]')

    local latest_backup
    latest_backup=$(ls -1t "$BACKUP_DIR"/discord_voice.node."${sanitized}".*.backup 2>/dev/null | head -1 || true)

    if [[ -n "$latest_backup" && -f "$latest_backup" ]]; then
        if cmp -s "$source" "$latest_backup"; then
            log_ok "Backup already exists and is identical (skipping)"
            return 0
        fi
    fi

    local backup_path="$BACKUP_DIR/discord_voice.node.${sanitized}.$(date +%Y%m%d_%H%M%S).backup"
    if ! cp "$source" "$backup_path" 2>/dev/null; then
        log_error "Failed to create backup at $backup_path"
        log_error "  Check disk space and permissions on $BACKUP_DIR"
        return 1
    fi
    log_ok "Backup: $(basename "$backup_path")"

    if ! cmp -s "$source" "$backup_path"; then
        log_error "Backup verification failed! Backup does not match source."
        rm -f "$backup_path"
        return 1
    fi

    prune_voice_backups
    return 0
}

restore_from_backup() {
    banner
    log_info "Available backups:"
    echo ""

    local backups=()
    while IFS= read -r f; do
        backups+=("$f")
    done < <(ls -1t "$BACKUP_DIR"/*.backup 2>/dev/null)

    if [[ ${
        log_error "No backups found in $BACKUP_DIR"
        exit 1
    fi

    for i in "${!backups[@]}"; do
        local bk="${backups[$i]}"
        local bsize
        bsize=$(stat -c%s "$bk" 2>/dev/null || echo "?")
        local bdate
        bdate=$(stat -c%y "$bk" 2>/dev/null | cut -d. -f1 || echo "unknown")
        echo -e "  [$(( i + 1 ))] ${bdate} - $(numfmt --to=iec "$bsize" 2>/dev/null || echo "$bsize") - $(basename "$bk")"
    done
    echo ""

    read -rp "Select backup (1-${
    if [[ -z "$sel" ]]; then sel=1; fi
    if [[ ! "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${
        log_error "Invalid selection"; exit 1
    fi
    local backup_file="${backups[$(( sel - 1 ))]}"

    local bfsize
    bfsize=$(stat -c%s "$backup_file" 2>/dev/null || echo "0")
    if (( bfsize == 0 )); then
        log_error "Selected backup is empty (0 bytes) - possibly corrupted"
        exit 1
    fi

    if check_discord_running; then
        log_warn "Discord is running. It should be closed before restoring."
        handle_discord_running
    fi

    find_discord_clients || exit 1
    echo ""
    for i in "${!CLIENT_NAMES[@]}"; do
        echo -e "  [$(( i + 1 ))] ${CLIENT_NAMES[$i]}"
        echo -e "      ${DIM}${CLIENT_NODES[$i]}${NC}"
    done
    echo ""
    read -rp "Restore to which client? (1-${
    if [[ -z "$csel" ]]; then csel=1; fi
    if [[ ! "$csel" =~ ^[0-9]+$ ]] || (( csel < 1 || csel > ${
        log_error "Invalid client selection"; exit 1
    fi
    local target="${CLIENT_NODES[$(( csel - 1 ))]}"
    local target_name="${CLIENT_NAMES[$(( csel - 1 ))]}"

    echo ""
    log_info "Backup:  $(basename "$backup_file")"
    log_info "Target:  $target"
    log_info "Client:  $target_name"
    echo ""
    read -rp "Replace target with backup? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_warn "Cancelled"; exit 0
    fi

    if ! cp "$backup_file" "$target" 2>/dev/null; then
        log_error "Failed to restore! Check permissions on $target"
        exit 1
    fi

    if ! cmp -s "$backup_file" "$target"; then
        log_error "Restore verification failed! File may be corrupted."
        exit 1
    fi

    log_ok "Restored successfully! Restart Discord to apply."
    exit 0
}
# endregion Backup Management


# region Compiler Detection
COMPILER=""
COMPILER_TYPE=""

find_compiler() {
    log_info "Searching for C++ compiler..."
    if command -v g++ &>/dev/null; then
        COMPILER="g++"
        COMPILER_TYPE="GCC"
        local ver
        ver=$(g++ --version 2>/dev/null | head -1 || echo 'g++ (version unknown)')
        log_ok "Found g++ ($ver)"
        return 0
    elif command -v clang++ &>/dev/null; then
        COMPILER="clang++"
        COMPILER_TYPE="Clang"
        local ver
        ver=$(clang++ --version 2>/dev/null | head -1 || echo 'clang++ (version unknown)')
        log_ok "Found clang++ ($ver)"
        return 0
    fi
    log_error "No C++ compiler found!"
    echo ""
    echo "Install one with:"
    echo "  Ubuntu/Debian:  sudo apt install g++"
    echo "  Fedora/RHEL:    sudo dnf install gcc-c++"
    echo "  Arch:           sudo pacman -S gcc"
    echo "  openSUSE:       sudo zypper install gcc-c++"
    return 1
}
# endregion Compiler Detection


# region Source Code Generation

generate_amplifier_source() {
    cat > "$TEMP_DIR/amplifier.cpp" << 'AMPEOF'
#define GAIN_MULTIPLIER 1
#include <cstdint>
#include <xmmintrin.h>
extern "C" void hp_cutoff(const float* in, int cutoff_Hz, float* out, int* hp_mem, int len, int channels, int Fs, int arch)
{
    int* st = (hp_mem - 3553);
    *(int*)(st + 3557) = 1002;
    *(int*)((char*)st + 160) = -1;
    *(int*)((char*)st + 164) = -1;
    *(int*)((char*)st + 184) = 0;
    float scale = 1.0f;
#if GAIN_MULTIPLIER > 1
    if (channels > 0) {
        __m128 v = _mm_cvtsi32_ss(_mm_setzero_ps(), channels);
        v = _mm_rsqrt_ss(v);
        scale = _mm_cvtss_f32(v);
    }
#endif
    for (unsigned long i = 0; i < (unsigned long)(channels * len); i++) {
        float sample = in[i];
        out[i] = sample * (float)GAIN_MULTIPLIER * scale;
    }
}
extern "C" void dc_reject(const float* in, float* out, int* hp_mem, int len, int channels, int Fs)
{
    int* st = (hp_mem - 3553);
    *(int*)(st + 3557) = 1002;
    *(int*)((char*)st + 160) = -1;
    *(int*)((char*)st + 164) = -1;
    *(int*)((char*)st + 184) = 0;
    float scale = 1.0f;
#if GAIN_MULTIPLIER > 1
    if (channels > 0) {
        __m128 v = _mm_cvtsi32_ss(_mm_setzero_ps(), channels);
        v = _mm_rsqrt_ss(v);
        scale = _mm_cvtss_f32(v);
    }
#endif
    for (int i = 0; i < channels * len; i++) {
        float sample = in[i];
        out[i] = sample * (float)GAIN_MULTIPLIER * scale;
    }
}
AMPEOF
}

validate_required_offsets() {
    local missing=()
    for name in "${REQUIRED_OFFSET_NAMES[@]}"; do
        local var="OFFSET_$name"
        local val="${!var:-}"
        if [[ -z "$val" ]]; then
            missing+=("$var")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing or empty required offset(s): ${missing[*]}"
        log_error "Refresh the build fingerprint block at the top of this script."
        return 1
    fi
    return 0
}

generate_patcher_source() {
    validate_required_offsets || exit 1

    cat > "$TEMP_DIR/patcher.cpp" << 'PATCHEOF'
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#define SAMPLE_RATE SAMPLERATE_VAL
#define BITRATE BITRATE_VAL
#define BITRATE_BPS BITRATE_BPS_VAL
extern "C" void dc_reject(const float*, float*, int*, int, int, int);
extern "C" void hp_cutoff(const float*, int, float*, int*, int, int, int, int);
namespace Offsets {
    constexpr uint32_t CommitAudioCodec_StereoCheck1_Imm0             = OFFSET_VAL_CommitAudioCodec_StereoCheck1_Imm0;
    constexpr uint32_t CommitAudioCodec_StereoCheck2_Imm0             = OFFSET_VAL_CommitAudioCodec_StereoCheck2_Imm0;
    constexpr uint32_t CreateAudioFrame_Channels_MovImm2            = OFFSET_VAL_CreateAudioFrame_Channels_MovImm2;
    constexpr uint32_t CapturedAudioProcessor_MonoDownmix_NopJmp                     = OFFSET_VAL_CapturedAudioProcessor_MonoDownmix_NopJmp;
    constexpr uint32_t AudioEncoderOpusConfig_Ctor_Channels_Imm02 = OFFSET_VAL_AudioEncoderOpusConfig_Ctor_Channels_Imm02;
    constexpr uint32_t AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02    = OFFSET_VAL_AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02;
    constexpr uint32_t AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k                = OFFSET_VAL_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k;
    constexpr uint32_t AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k                = OFFSET_VAL_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k;
    constexpr uint32_t AudioEncoderOpusConfig_Ctor_FrameMs_Imm10        = OFFSET_VAL_AudioEncoderOpusConfig_Ctor_FrameMs_Imm10;
    constexpr uint32_t AudioEncoderOpusConfig_Ctor_Application_ImmAudio   = OFFSET_VAL_AudioEncoderOpusConfig_Ctor_Application_ImmAudio;
    constexpr uint32_t RecreateEncoderInstance_FecBranch_Jmp   = OFFSET_VAL_RecreateEncoderInstance_FecBranch_Jmp;
    constexpr uint32_t MultiChannelRecreateEncoder_FecBranch_Jmp = OFFSET_VAL_MultiChannelRecreateEncoder_FecBranch_Jmp;
    constexpr uint32_t SetFec_EnableBranch_Jmp               = OFFSET_VAL_SetFec_EnableBranch_Jmp;
    constexpr uint32_t RecreateEncoderInstance_DtxBranch_Jmp   = OFFSET_VAL_RecreateEncoderInstance_DtxBranch_Jmp;
    constexpr uint32_t MultiChannelRecreateEncoder_DtxBranch_Jmp = OFFSET_VAL_MultiChannelRecreateEncoder_DtxBranch_Jmp;
    constexpr uint32_t SetDtx_EnableBranch_Jmp               = OFFSET_VAL_SetDtx_EnableBranch_Jmp;
    constexpr uint32_t CopyRedEncodeImpl_RedundantCopy_JmpNear       = OFFSET_VAL_CopyRedEncodeImpl_RedundantCopy_JmpNear;
    constexpr uint32_t RecreateEncoder_BitrateCalcLow_Channels_Mov248k = OFFSET_VAL_RecreateEncoder_BitrateCalcLow_Channels_Mov248k;
    constexpr uint32_t RecreateEncoder_BitrateCalcMid_Channels_Mov248k = OFFSET_VAL_RecreateEncoder_BitrateCalcMid_Channels_Mov248k;
    constexpr uint32_t RecreateEncoder_BitrateCalcHigh_Channels_Mov248k = OFFSET_VAL_RecreateEncoder_BitrateCalcHigh_Channels_Mov248k;
    constexpr uint32_t MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k = OFFSET_VAL_MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k;
    constexpr uint32_t MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k = OFFSET_VAL_MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k;
    constexpr uint32_t MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k = OFFSET_VAL_MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k;
    constexpr uint32_t AudioBitrateAdaptorCalc32k_Channels_Mov248k = OFFSET_VAL_AudioBitrateAdaptorCalc32k_Channels_Mov248k;
    constexpr uint32_t AudioBitrateAdaptorCalc48k_Channels_Mov248k = OFFSET_VAL_AudioBitrateAdaptorCalc48k_Channels_Mov248k;
    constexpr uint32_t AudioBitrateAdaptorCalc60k_Channels_Mov248k = OFFSET_VAL_AudioBitrateAdaptorCalc60k_Channels_Mov248k;
    constexpr uint32_t ApplySettings_BitrateImul_Imm248k            = OFFSET_VAL_ApplySettings_BitrateImul_Imm248k;
    constexpr uint32_t SetTargetBitrate_Mulss_Nop6         = OFFSET_VAL_SetTargetBitrate_Mulss_Nop6;
    constexpr uint32_t GetMultipliedBitrate_Mulss_Nop7     = OFFSET_VAL_GetMultipliedBitrate_Mulss_Nop7;
    constexpr uint32_t SelectSampleRate_Constant_Imm48k                      = OFFSET_VAL_SelectSampleRate_Constant_Imm48k;
    constexpr uint32_t WebRtcSplHighPass_Entry_Ret                    = OFFSET_VAL_WebRtcSplHighPass_Entry_Ret;
    constexpr uint32_t hp_cutoff_Callback_InjectShellcode              = OFFSET_VAL_hp_cutoff_Callback_InjectShellcode;
    constexpr uint32_t dc_reject_Callback_InjectShellcode                          = OFFSET_VAL_dc_reject_Callback_InjectShellcode;
    constexpr uint32_t ChannelDownmix_Entry_Ret                       = OFFSET_VAL_ChannelDownmix_Entry_Ret;
    constexpr uint32_t AudioEncoderOpusConfig_IsOK_MovTrueRet        = OFFSET_VAL_AudioEncoderOpusConfig_IsOK_MovTrueRet;
    constexpr uint32_t FILE_OFFSET_ADJUSTMENT            = OFFSET_VAL_FileAdjustment;
};
class DiscordPatcher {
private:
    std::string modulePath;
    bool ApplyPatches(void* fileData, long long fileSize) {
        printf("Validating binary before patching...\n");
        constexpr long long MIN_EXPECTED_SIZE = 70LL * 1024 * 1024;
        constexpr long long MAX_EXPECTED_SIZE = 110LL * 1024 * 1024;
        if (fileSize < MIN_EXPECTED_SIZE || fileSize > MAX_EXPECTED_SIZE) {
            printf("ERROR: File size %.2f MB is outside expected range (70-110 MB)\n",
                   fileSize / (1024.0 * 1024.0));
            printf("This may not be the correct discord_voice.node for these offsets.\n");
            return false;
        }
        auto CheckBytes = [&](uint32_t offset, const unsigned char* expected, size_t len) -> bool {
            uint32_t fileOffset = offset - Offsets::FILE_OFFSET_ADJUSTMENT;
            if ((long long)(fileOffset + len) > fileSize) return false;
            return memcmp((char*)fileData + fileOffset, expected, len) == 0;
        };
        auto PatchBytes = [&](uint32_t offset, const char* bytes, size_t len) -> bool {
            uint32_t fileOffset = offset - Offsets::FILE_OFFSET_ADJUSTMENT;
            if ((long long)(fileOffset + len) > fileSize) {
                printf("ERROR: Patch at 0x%X (len %zu) exceeds file size!\n", offset, len);
                return false;
            }
            memcpy((char*)fileData + fileOffset, bytes, len);
            return true;
        };
        auto ReadU32LE = [&](uint32_t offset, uint32_t& value) -> bool {
            uint32_t fileOffset = offset - Offsets::FILE_OFFSET_ADJUSTMENT;
            if ((long long)(fileOffset + 4) > fileSize) return false;
            memcpy(&value, (char*)fileData + fileOffset, 4);
            return true;
        };
        auto OrigOrAlt = [&](uint32_t off,
                             const unsigned char* orig, size_t origLen,
                             const unsigned char* alt, size_t altLen) -> bool {
            return CheckBytes(off, orig, origLen) || CheckBytes(off, alt, altLen);
        };
        const unsigned char orig_caf[]      = ORIG_VAL_CreateAudioFrame_Channels_MovImm2;
        const unsigned char patch_caf[]     = {0x49, 0xC7, 0xC4, 0x02, 0x00, 0x00, 0x00};
        const unsigned char orig_mdm[]      = ORIG_VAL_CapturedAudioProcessor_MonoDownmix_NopJmp;
        const unsigned char patch_mdm[]     = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                               0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xE9};
        const unsigned char orig_48[]       = ORIG_VAL_SelectSampleRate_Constant_Imm48k;
        const unsigned char patch_48[]      = {0x41, 0xBD, 0x80, 0xBB, 0x00, 0x00};
        const unsigned char orig_isok[]     = ORIG_VAL_AudioEncoderOpusConfig_IsOK_MovTrueRet;
        const unsigned char patch_isok[]    = {0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3};
        const unsigned char orig_dnmix[]    = ORIG_VAL_ChannelDownmix_Entry_Ret;
        const unsigned char patch_ret[]     = {0xC3};
        const unsigned char orig_hp[]       = ORIG_VAL_WebRtcSplHighPass_Entry_Ret;
        const unsigned char orig_hpcut[]    = ORIG_VAL_hp_cutoff_Callback_InjectShellcode;
        const unsigned char orig_dcrej[]    = ORIG_VAL_dc_reject_Callback_InjectShellcode;
        const unsigned char orig_enc1[]     = ORIG_VAL_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k;
        const unsigned char orig_enc2[]     = ORIG_VAL_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k;
        const unsigned char patch_enc248[]  = {PATCH_ENC4_VAL};
        const unsigned char orig_ebm[]      = ORIG_VAL_ApplySettings_BitrateImul_Imm248k;
        const unsigned char patch_ebm248[]  = {PATCH_ENC3_VAL};
        const unsigned char orig_stb[]      = ORIG_VAL_SetTargetBitrate_Mulss_Nop6;
        const unsigned char patch_mulss6[]  = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        const unsigned char orig_gmb[]      = ORIG_VAL_GetMultipliedBitrate_Mulss_Nop7;
        const unsigned char orig_fec_on[]   = {0x01};
        const unsigned char patch_fec_off[] = {0x00};
        const unsigned char ms20[]          = {0x14};
        const unsigned char ms10[]          = {0x0A};
        const unsigned char appAudio[]      = {0x01};
        const unsigned char appVoip[]       = {0x00};
        const unsigned char orig_ch_one[]   = {0x01};
        const unsigned char patch_ch_two[]  = {0x02};
        const unsigned char orig_sdp[]      = {0x02};
        const unsigned char patch_sdp[]     = {0x00};
        constexpr size_t injProbe = 24;
        bool o_caf  = OrigOrAlt(Offsets::CreateAudioFrame_Channels_MovImm2, orig_caf, sizeof(orig_caf), patch_caf, sizeof(patch_caf));
        bool o_mdm  = OrigOrAlt(Offsets::CapturedAudioProcessor_MonoDownmix_NopJmp, orig_mdm, sizeof(orig_mdm), patch_mdm, sizeof(patch_mdm));
        bool o_48   = OrigOrAlt(Offsets::SelectSampleRate_Constant_Imm48k, orig_48, sizeof(orig_48), patch_48, sizeof(patch_48));
        bool o_isok = OrigOrAlt(Offsets::AudioEncoderOpusConfig_IsOK_MovTrueRet, orig_isok, sizeof(orig_isok), patch_isok, sizeof(patch_isok));
        bool o_dn   = OrigOrAlt(Offsets::ChannelDownmix_Entry_Ret, orig_dnmix, sizeof(orig_dnmix), patch_ret, sizeof(patch_ret));
        bool o_hp   = OrigOrAlt(Offsets::WebRtcSplHighPass_Entry_Ret, orig_hp, sizeof(orig_hp), patch_ret, sizeof(patch_ret));
        bool o_hpc  = CheckBytes(Offsets::hp_cutoff_Callback_InjectShellcode, orig_hpcut, sizeof(orig_hpcut))
                   || CheckBytes(Offsets::hp_cutoff_Callback_InjectShellcode, (const unsigned char*)hp_cutoff, injProbe);
        bool o_dcr  = CheckBytes(Offsets::dc_reject_Callback_InjectShellcode, orig_dcrej, sizeof(orig_dcrej))
                   || CheckBytes(Offsets::dc_reject_Callback_InjectShellcode, (const unsigned char*)dc_reject, injProbe);
        bool o_e1   = OrigOrAlt(Offsets::AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k, orig_enc1, sizeof(orig_enc1), patch_enc248, sizeof(patch_enc248));
        bool o_e2   = OrigOrAlt(Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k, orig_enc2, sizeof(orig_enc2), patch_enc248, sizeof(patch_enc248));
        bool o_ebm  = OrigOrAlt(Offsets::ApplySettings_BitrateImul_Imm248k, orig_ebm, sizeof(orig_ebm), patch_ebm248, sizeof(patch_ebm248));
        bool o_stb  = OrigOrAlt(Offsets::SetTargetBitrate_Mulss_Nop6, orig_stb, sizeof(orig_stb), patch_mulss6, sizeof(patch_mulss6));
        bool o_gmb  = OrigOrAlt(Offsets::GetMultipliedBitrate_Mulss_Nop7, orig_gmb, sizeof(orig_gmb), patch_mulss6, sizeof(patch_mulss6));
        bool o_frame = OrigOrAlt(Offsets::AudioEncoderOpusConfig_Ctor_FrameMs_Imm10, ms20, 1, ms10, 1);
        bool o_app   = OrigOrAlt(Offsets::AudioEncoderOpusConfig_Ctor_Application_ImmAudio, appAudio, 1, appVoip, 1);
        bool o_ch1  = OrigOrAlt(Offsets::AudioEncoderOpusConfig_Ctor_Channels_Imm02, orig_ch_one, 1, patch_ch_two, 1);
        bool o_ch2  = OrigOrAlt(Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02, orig_ch_one, 1, patch_ch_two, 1);
        bool o_ess1 = OrigOrAlt(Offsets::CommitAudioCodec_StereoCheck1_Imm0, orig_sdp, 1, patch_sdp, 1);
        bool o_ess2 = OrigOrAlt(Offsets::CommitAudioCodec_StereoCheck2_Imm0, orig_sdp, 1, patch_sdp, 1);
        printf("  CreateAudioFrame_Channels_MovImm2 (0x%06X): %s\n", Offsets::CreateAudioFrame_Channels_MovImm2, o_caf ? "OK" : "MISMATCH");
        printf("  CapturedAudioProcessor_MonoDownmix_NopJmp          (0x%06X): %s\n", Offsets::CapturedAudioProcessor_MonoDownmix_NopJmp, o_mdm ? "OK" : "MISMATCH");
        printf("  SelectSampleRate_Constant_Imm48k           (0x%06X): %s\n", Offsets::SelectSampleRate_Constant_Imm48k, o_48 ? "OK" : "MISMATCH");
        printf("  AudioEncoderConfigIsOk (0x%06X): %s\n", Offsets::AudioEncoderOpusConfig_IsOK_MovTrueRet, o_isok ? "OK" : "MISMATCH");
        printf("  ChannelDownmix_Entry_Ret            (0x%06X): %s\n", Offsets::ChannelDownmix_Entry_Ret, o_dn ? "OK" : "MISMATCH");
        printf("  WebRtcSplHighPass_Entry_Ret         (0x%06X): %s\n", Offsets::WebRtcSplHighPass_Entry_Ret, o_hp ? "OK" : "MISMATCH");
        printf("  hp_cutoff_Callback_InjectShellcode   (0x%06X): %s\n", Offsets::hp_cutoff_Callback_InjectShellcode, o_hpc ? "OK" : "MISMATCH");
        printf("  dc_reject_Callback_InjectShellcode               (0x%06X): %s\n", Offsets::dc_reject_Callback_InjectShellcode, o_dcr ? "OK" : "MISMATCH");
        printf("  AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k     (0x%06X): %s\n", Offsets::AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k, o_e1 ? "OK" : "MISMATCH");
        printf("  AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k     (0x%06X): %s\n", Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k, o_e2 ? "OK" : "MISMATCH");
        printf("  ApplySettings_BitrateImul_Imm248k (0x%06X): %s\n", Offsets::ApplySettings_BitrateImul_Imm248k, o_ebm ? "OK" : "MISMATCH");
        printf("  SetTargetBitrateMulss  (0x%06X): %s\n", Offsets::SetTargetBitrate_Mulss_Nop6, o_stb ? "OK" : "MISMATCH");
        printf("  GetMultipliedBitrate   (0x%06X): %s\n", Offsets::GetMultipliedBitrate_Mulss_Nop7, o_gmb ? "OK" : "MISMATCH");
        printf("  EncoderConfigFrameSize (0x%06X): %s\n", Offsets::AudioEncoderOpusConfig_Ctor_FrameMs_Imm10, o_frame ? "OK" : "MISMATCH");
        printf("  EncoderConfigApplication (0x%06X): %s\n", Offsets::AudioEncoderOpusConfig_Ctor_Application_ImmAudio, o_app ? "OK" : "MISMATCH");
        printf("  OpusConfigSetChannels  (0x%06X): %s\n", Offsets::AudioEncoderOpusConfig_Ctor_Channels_Imm02, o_ch1 ? "OK" : "MISMATCH");
        printf("  MultiChannelOpusCh     (0x%06X): %s\n", Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02, o_ch2 ? "OK" : "MISMATCH");
        printf("  CommitAudioCodec_StereoCheck1_Imm0  (0x%06X): %s\n", Offsets::CommitAudioCodec_StereoCheck1_Imm0, o_ess1 ? "OK" : "MISMATCH");
        printf("  CommitAudioCodec_StereoCheck2_Imm0  (0x%06X): %s\n", Offsets::CommitAudioCodec_StereoCheck2_Imm0, o_ess2 ? "OK" : "MISMATCH");
        if (!o_caf || !o_mdm || !o_48 || !o_isok || !o_dn || !o_hp || !o_hpc || !o_dcr ||
            !o_e1 || !o_e2 || !o_ebm || !o_stb || !o_gmb || !o_frame || !o_app || !o_ch1 || !o_ch2 || !o_ess1 || !o_ess2) {
            printf("\nERROR: Binary validation FAILED - unexpected bytes at patch sites.\n");
            printf("This discord_voice.node does not match the expected build.\n");
            printf("These offsets cannot be safely applied to a different version.\n");
            return false;
        }
        printf("  Validation OK.\n\n");
        int patchCount = 0;
        printf("Applying patches...\n");
        printf("  [1/5] Enabling stereo audio...\n");
        if (!PatchBytes(Offsets::CommitAudioCodec_StereoCheck1_Imm0, "\x00", 1)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::CommitAudioCodec_StereoCheck2_Imm0, "\x00", 1)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::CreateAudioFrame_Channels_MovImm2, "\x49\xC7\xC4\x02\x00\x00\x00", 7)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::CapturedAudioProcessor_MonoDownmix_NopJmp,
                        "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xE9", 13)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::AudioEncoderOpusConfig_Ctor_Channels_Imm02, "\x02", 1)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02, "\x02", 1)) return false;
        patchCount++;
        printf("  [2/5] Enabling 48kHz sample rate...\n");
        if (!PatchBytes(Offsets::SelectSampleRate_Constant_Imm48k, "\x41\xBD\x80\xBB\x00\x00", 6)) return false;
        patchCount++;
        printf("  [3/5] Setting bitrate to %dkbps...\n", BITRATE);
        if (!PatchBytes(Offsets::AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k, "PATCH_ENC4_ESC", 4)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k, "PATCH_ENC4_ESC", 4)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::ApplySettings_BitrateImul_Imm248k, "PATCH_ENC3_ESC", 3)) return false;
        patchCount++;
        auto PatchFlatR13d248k7 = [&](uint32_t offset, const char* label) -> bool {
            const unsigned char flat[] = {0x41, 0xBD, 0xC0, 0xC8, 0x03, 0x00, 0x90};
            const unsigned char tierLow[] = {0x45, 0x69, 0xED, 0xE0, 0x2E, 0x00, 0x00};
            const unsigned char tierMid[] = {0x45, 0x69, 0xED, 0x20, 0x4E, 0x00, 0x00};
            const unsigned char tierHigh[] = {0x45, 0x69, 0xED, 0x00, 0x7D, 0x00, 0x00};
            if (CheckBytes(offset, flat, 7)) return true;
            if (!CheckBytes(offset, tierLow, 7) && !CheckBytes(offset, tierMid, 7) && !CheckBytes(offset, tierHigh, 7)) {
                printf("ERROR: %s unexpected bytes\n", label);
                return false;
            }
            return PatchBytes(offset, (const char*)flat, 7);
        };
        auto PatchFlatR13d248k6 = [&](uint32_t offset, const char* label) -> bool {
            const unsigned char flat[] = {0x41, 0xBD, 0xC0, 0xC8, 0x03, 0x00};
            const unsigned char tierLow[] = {0x69, 0xED, 0xE0, 0x2E, 0x00, 0x00};
            const unsigned char tierMid[] = {0x69, 0xED, 0x20, 0x4E, 0x00, 0x00};
            const unsigned char tierHigh[] = {0x69, 0xED, 0x00, 0x7D, 0x00, 0x00};
            if (CheckBytes(offset, flat, 6)) return true;
            if (!CheckBytes(offset, tierLow, 6) && !CheckBytes(offset, tierMid, 6) && !CheckBytes(offset, tierHigh, 6)) {
                printf("ERROR: %s unexpected bytes\n", label);
                return false;
            }
            return PatchBytes(offset, (const char*)flat, 6);
        };
        auto PatchFlatEdx248k = [&](uint32_t offset, const char* label) -> bool {
            const unsigned char flat[] = {0xBA, 0xC0, 0xC8, 0x03, 0x00, 0x90};
            const unsigned char tier32k[] = {0x69, 0xD6, 0x00, 0x7D, 0x00, 0x00};
            const unsigned char tier48k[] = {0x69, 0xD6, 0x80, 0xBB, 0x00, 0x00};
            const unsigned char tier60k[] = {0x69, 0xD6, 0x60, 0xEA, 0x00, 0x00};
            if (CheckBytes(offset, flat, 6)) return true;
            if (!CheckBytes(offset, tier32k, 6) && !CheckBytes(offset, tier48k, 6) && !CheckBytes(offset, tier60k, 6)) {
                printf("ERROR: %s unexpected bytes\n", label);
                return false;
            }
            return PatchBytes(offset, (const char*)flat, 6);
        };
        printf("  [BITRATE] RecreateEncoder tiers -> flat 248k...\n");
        if (!PatchFlatR13d248k7(Offsets::RecreateEncoder_BitrateCalcLow_Channels_Mov248k, "RecreateEncoder tier-low")) return false;
        patchCount++;
        if (!PatchFlatR13d248k7(Offsets::RecreateEncoder_BitrateCalcMid_Channels_Mov248k, "RecreateEncoder tier-mid")) return false;
        patchCount++;
        if (!PatchFlatR13d248k7(Offsets::RecreateEncoder_BitrateCalcHigh_Channels_Mov248k, "RecreateEncoder tier-high")) return false;
        patchCount++;
        printf("  [BITRATE] MultiChannelRecreate tiers -> flat 248k...\n");
        if (!PatchFlatR13d248k6(Offsets::MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k, "MultiChannel tier-low")) return false;
        patchCount++;
        if (!PatchFlatR13d248k6(Offsets::MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k, "MultiChannel tier-mid")) return false;
        patchCount++;
        if (!PatchFlatR13d248k6(Offsets::MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k, "MultiChannel tier-high")) return false;
        patchCount++;
        printf("  [BITRATE] AudioBitrateAdaptor tiers -> flat 248k...\n");
        if (!PatchFlatEdx248k(Offsets::AudioBitrateAdaptorCalc32k_Channels_Mov248k, "AudioBitrateAdaptor tier32k")) return false;
        patchCount++;
        if (!PatchFlatEdx248k(Offsets::AudioBitrateAdaptorCalc48k_Channels_Mov248k, "AudioBitrateAdaptor tier48k")) return false;
        patchCount++;
        if (!PatchFlatEdx248k(Offsets::AudioBitrateAdaptorCalc60k_Channels_Mov248k, "AudioBitrateAdaptor tier60k")) return false;
        patchCount++;
        if (!PatchBytes(Offsets::SetTargetBitrate_Mulss_Nop6, "\x90\x90\x90\x90\x90\x90", 6)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::GetMultipliedBitrate_Mulss_Nop7, "\x90\x90\x90\x90\x90\x90", 6)) return false;
        patchCount++;
        printf("  [3b/5] Opus encoder config (10ms frames, kAudio)...\n");
        {
            if (CheckBytes(Offsets::AudioEncoderOpusConfig_Ctor_FrameMs_Imm10, ms10, 1)) {
                printf("  frame_size_ms already 10\n");
            } else if (!CheckBytes(Offsets::AudioEncoderOpusConfig_Ctor_FrameMs_Imm10, ms20, 1)) {
                printf("ERROR: AudioEncoderOpusConfig_Ctor_FrameMs_Imm10 unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::AudioEncoderOpusConfig_Ctor_FrameMs_Imm10, "\x0A", 1)) return false;
            else patchCount++;
            if (CheckBytes(Offsets::AudioEncoderOpusConfig_Ctor_Application_ImmAudio, appAudio, 1)) {
                printf("  application kAudio already set\n");
            } else if (!CheckBytes(Offsets::AudioEncoderOpusConfig_Ctor_Application_ImmAudio, appVoip, 1)) {
                printf("ERROR: AudioEncoderOpusConfig_Ctor_Application_ImmAudio unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::AudioEncoderOpusConfig_Ctor_Application_ImmAudio, "\x01", 1)) return false;
            else patchCount++;
        }
        printf("  [3c/5] Disabling Opus FEC/DTX runtime...\n");
        {
            const unsigned char jnz[] = {0x75};
            const unsigned char jz[] = {0x74};
            const unsigned char jmp[] = {0xEB};
            if (CheckBytes(Offsets::RecreateEncoderInstance_FecBranch_Jmp, jmp, 1)) {
                printf("  RecreateEncoder ForceDisableFec already patched\n");
            } else if (!CheckBytes(Offsets::RecreateEncoderInstance_FecBranch_Jmp, jnz, 1)) {
                printf("ERROR: RecreateEncoderInstance_FecBranch_Jmp unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::RecreateEncoderInstance_FecBranch_Jmp, "\xEB", 1)) return false;
            else patchCount++;
            if (CheckBytes(Offsets::MultiChannelRecreateEncoder_FecBranch_Jmp, jmp, 1)) {
                printf("  MultiChannel Recreate ForceDisableFec already patched\n");
            } else if (!CheckBytes(Offsets::MultiChannelRecreateEncoder_FecBranch_Jmp, jnz, 1)) {
                printf("ERROR: MultiChannelRecreateEncoder_FecBranch_Jmp unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::MultiChannelRecreateEncoder_FecBranch_Jmp, "\xEB", 1)) return false;
            else patchCount++;
            if (CheckBytes(Offsets::SetFec_EnableBranch_Jmp, jmp, 1)) {
                printf("  SetFec ForceDisable already patched\n");
            } else if (!CheckBytes(Offsets::SetFec_EnableBranch_Jmp, jz, 1)) {
                printf("ERROR: SetFec_EnableBranch_Jmp unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::SetFec_EnableBranch_Jmp, "\xEB", 1)) return false;
            else patchCount++;
            if (CheckBytes(Offsets::RecreateEncoderInstance_DtxBranch_Jmp, jmp, 1)) {
                printf("  RecreateEncoder ForceDisableDtx already patched\n");
            } else if (!CheckBytes(Offsets::RecreateEncoderInstance_DtxBranch_Jmp, jnz, 1)) {
                printf("ERROR: RecreateEncoderInstance_DtxBranch_Jmp unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::RecreateEncoderInstance_DtxBranch_Jmp, "\xEB", 1)) return false;
            else patchCount++;
            if (CheckBytes(Offsets::MultiChannelRecreateEncoder_DtxBranch_Jmp, jmp, 1)) {
                printf("  MultiChannel Recreate ForceDisableDtx already patched\n");
            } else if (!CheckBytes(Offsets::MultiChannelRecreateEncoder_DtxBranch_Jmp, jnz, 1)) {
                printf("ERROR: MultiChannelRecreateEncoder_DtxBranch_Jmp unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::MultiChannelRecreateEncoder_DtxBranch_Jmp, "\xEB", 1)) return false;
            else patchCount++;
            if (CheckBytes(Offsets::SetDtx_EnableBranch_Jmp, jmp, 1)) {
                printf("  SetDtx ForceDisable already patched\n");
            } else if (!CheckBytes(Offsets::SetDtx_EnableBranch_Jmp, jz, 1)) {
                printf("ERROR: SetDtx_EnableBranch_Jmp unexpected byte\n");
                return false;
            } else if (!PatchBytes(Offsets::SetDtx_EnableBranch_Jmp, "\xEB", 1)) return false;
            else patchCount++;
            {
                unsigned char cur6[6] = {0};
                uint32_t fo = Offsets::CopyRedEncodeImpl_RedundantCopy_JmpNear - Offsets::FILE_OFFSET_ADJUSTMENT;
                if ((long long)(fo + 6) > fileSize) {
                    printf("ERROR: CopyRedEncodeImpl_RedundantCopy_JmpNear out of range\n");
                    return false;
                }
                memcpy(cur6, (char*)fileData + fo, 6);
                if (cur6[0] == 0xE9) {
                    printf("  CopyRed skip RED already patched\n");
                } else if (cur6[0] != 0x0F || cur6[1] != 0x84) {
                    printf("ERROR: CopyRedEncodeImpl_RedundantCopy_JmpNear unexpected bytes\n");
                    return false;
                } else {
                    unsigned char patch6[6];
                    patch6[0] = 0xE9;
                    patch6[1] = cur6[2];
                    patch6[2] = cur6[3];
                    patch6[3] = cur6[4];
                    patch6[4] = cur6[5];
                    patch6[5] = 0x90;
                    if (!PatchBytes(Offsets::CopyRedEncodeImpl_RedundantCopy_JmpNear, (const char*)patch6, 6)) return false;
                    patchCount++;
                }
            }
        }
        printf("  [4/5] Disabling audio filters...\n");
        if (!PatchBytes(Offsets::WebRtcSplHighPass_Entry_Ret, "\xC3", 1)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::ChannelDownmix_Entry_Ret, "\xC3", 1)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::AudioEncoderOpusConfig_IsOK_MovTrueRet, "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8)) return false;
        patchCount++;
        printf("  [5/5] Injecting amplifier...\n");
        if (!PatchBytes(Offsets::hp_cutoff_Callback_InjectShellcode, (const char*)hp_cutoff, 0x180)) return false;
        patchCount++;
        if (!PatchBytes(Offsets::dc_reject_Callback_InjectShellcode, (const char*)dc_reject, 0x180)) return false;
        patchCount++;
        {
            uint32_t bitrate1 = 0, bitrate2 = 0;
            if (!ReadU32LE(Offsets::AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k, bitrate1) ||
                !ReadU32LE(Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k, bitrate2)) {
                printf("ERROR: Failed to read back bitrate value for verification.\n");
                return false;
            }
            if (bitrate1 != BITRATE_BPS || bitrate2 != BITRATE_BPS) {
                printf("ERROR: Bitrate mismatch after patching (got %u / %u, expected %u)\n",
                       bitrate1, bitrate2, (unsigned)BITRATE_BPS);
                return false;
            }
            printf("  Verified bitrate (Opus & MultiChannelOpus): %u / %u bps\n", bitrate1, bitrate2);
            const unsigned char nop6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (!CheckBytes(Offsets::SetTargetBitrate_Mulss_Nop6, nop6, 6) ||
                !CheckBytes(Offsets::GetMultipliedBitrate_Mulss_Nop7, nop6, 6)) {
                printf("ERROR: Actual encode mulss NOP verification failed\n");
                return false;
            }
            printf("  Verified mulss NOPs OK\n");
        }
        {
            uint32_t imulBitrateValue = 0;
            if (!ReadU32LE(Offsets::ApplySettings_BitrateImul_Imm248k, imulBitrateValue)) {
                printf("ERROR: Failed to read back ApplySettings bitrate immediate for verification.\n");
                return false;
            }
            if ((imulBitrateValue & 0xFFFFFFu) != (BITRATE_BPS & 0xFFFFFFu)) {
                printf("ERROR: ApplySettings bitrate immediate mismatch (got 0x%06X, expected 0x%06X)\n",
                       (unsigned)(imulBitrateValue & 0xFFFFFFu), (unsigned)(BITRATE_BPS & 0xFFFFFFu));
                return false;
            }
            const unsigned char flatR13_6[] = {0x41, 0xBD, 0xC0, 0xC8, 0x03, 0x00};
            const unsigned char flatR13_7[] = {0x41, 0xBD, 0xC0, 0xC8, 0x03, 0x00, 0x90};
            const unsigned char flatEdx[] = {0xBA, 0xC0, 0xC8, 0x03, 0x00, 0x90};
            if (!CheckBytes(Offsets::RecreateEncoder_BitrateCalcLow_Channels_Mov248k, flatR13_7, 7) ||
                !CheckBytes(Offsets::RecreateEncoder_BitrateCalcMid_Channels_Mov248k, flatR13_7, 7) ||
                !CheckBytes(Offsets::RecreateEncoder_BitrateCalcHigh_Channels_Mov248k, flatR13_7, 7) ||
                !CheckBytes(Offsets::MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k, flatR13_6, 6) ||
                !CheckBytes(Offsets::MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k, flatR13_6, 6) ||
                !CheckBytes(Offsets::MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k, flatR13_6, 6) ||
                !CheckBytes(Offsets::AudioBitrateAdaptorCalc32k_Channels_Mov248k, flatEdx, 6) ||
                !CheckBytes(Offsets::AudioBitrateAdaptorCalc48k_Channels_Mov248k, flatEdx, 6) ||
                !CheckBytes(Offsets::AudioBitrateAdaptorCalc60k_Channels_Mov248k, flatEdx, 6)) {
                printf("ERROR: Flat 248k bitrate patch verification failed.\n");
                return false;
            }
            printf("  Verified ApplySettings + flat 248k bitrate locks (10 sites)\n");
        }
        {
            uint32_t frameMs = 0, appMode = 0;
            if (!ReadU32LE(Offsets::AudioEncoderOpusConfig_Ctor_FrameMs_Imm10, frameMs) ||
                !ReadU32LE(Offsets::AudioEncoderOpusConfig_Ctor_Application_ImmAudio, appMode)) {
                printf("ERROR: Failed to read back frame/application bytes for verification.\n");
                return false;
            }
            if ((frameMs & 0xFFu) != 10u) {
                printf("ERROR: frame_size_ms verification failed (got %u, expected 10)\n", (unsigned)(frameMs & 0xFFu));
                return false;
            }
            if ((appMode & 0xFFu) != 1u) {
                printf("ERROR: application mode verification failed (got %u, expected 1 kAudio)\n", (unsigned)(appMode & 0xFFu));
                return false;
            }
            printf("  Verified 10ms frames + kAudio application mode\n");
            const unsigned char fecJmp[] = {0xEB};
            if (!CheckBytes(Offsets::RecreateEncoderInstance_FecBranch_Jmp, fecJmp, 1) ||
                !CheckBytes(Offsets::MultiChannelRecreateEncoder_FecBranch_Jmp, fecJmp, 1) ||
                !CheckBytes(Offsets::SetFec_EnableBranch_Jmp, fecJmp, 1) ||
                !CheckBytes(Offsets::RecreateEncoderInstance_DtxBranch_Jmp, fecJmp, 1) ||
                !CheckBytes(Offsets::MultiChannelRecreateEncoder_DtxBranch_Jmp, fecJmp, 1) ||
                !CheckBytes(Offsets::SetDtx_EnableBranch_Jmp, fecJmp, 1)) {
                printf("ERROR: FEC/DTX runtime lock verification failed\n");
                return false;
            }
            unsigned char cr6[6] = {0};
            uint32_t crFo = Offsets::CopyRedEncodeImpl_RedundantCopy_JmpNear - Offsets::FILE_OFFSET_ADJUSTMENT;
            memcpy(cr6, (char*)fileData + crFo, 6);
            if (cr6[0] != 0xE9) {
                printf("ERROR: CopyRed verification failed\n");
                return false;
            }
            printf("  Verified FEC/DTX/RED runtime force-disable\n");
        }
        {
            uint32_t ch1 = 0, ch2 = 0;
            (void)ReadU32LE(Offsets::AudioEncoderOpusConfig_Ctor_Channels_Imm02, ch1);
            (void)ReadU32LE(Offsets::AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02, ch2);
            if ((ch1 & 0xFF) != 2 || (ch2 & 0xFF) != 2) {
                printf("ERROR: Stereo channel verification failed (got 0x%02X / 0x%02X, expected 0x02)\n",
                       (unsigned)(ch1 & 0xFF), (unsigned)(ch2 & 0xFF));
                return false;
            }
            printf("  Verified Opus channels byte: 0x%02X\n", (unsigned)(ch1 & 0xFF));
            printf("  Verified MultiChannel Opus channels byte: 0x%02X\n", (unsigned)(ch2 & 0xFF));
        }
        {
            const unsigned char ess0[] = {0x00};
            const unsigned char caf[] = {0x49, 0xC7, 0xC4, 0x02, 0x00, 0x00, 0x00};
            const unsigned char mdm[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xE9};
            const unsigned char k48[] = {0x41, 0xBD, 0x80, 0xBB, 0x00, 0x00};
            const unsigned char ret[] = {0xC3};
            const unsigned char isOk[] = {0x48, 0xC7, 0xC0, 0x01};
            if (!CheckBytes(Offsets::CommitAudioCodec_StereoCheck1_Imm0, ess0, 1) ||
                !CheckBytes(Offsets::CommitAudioCodec_StereoCheck2_Imm0, ess0, 1) ||
                !CheckBytes(Offsets::CreateAudioFrame_Channels_MovImm2, caf, 7) ||
                !CheckBytes(Offsets::CapturedAudioProcessor_MonoDownmix_NopJmp, mdm, 13) ||
                !CheckBytes(Offsets::SelectSampleRate_Constant_Imm48k, k48, 6) ||
                !CheckBytes(Offsets::WebRtcSplHighPass_Entry_Ret, ret, 1) ||
                !CheckBytes(Offsets::ChannelDownmix_Entry_Ret, ret, 1) ||
                !CheckBytes(Offsets::AudioEncoderOpusConfig_IsOK_MovTrueRet, isOk, 4)) {
                printf("ERROR: Goal chain verification failed (stereo/48k/filter bypass)\n");
                return false;
            }
            printf("  Verified goal chain: stereo, 48kHz, filter bypass, flat encode path\n");
        }
        printf("\n  Applied %d patches successfully!\n", patchCount);
        return true;
    }
public:
    DiscordPatcher(const std::string& path) : modulePath(path) {}
    bool PatchFile() {
        printf("\n================================================\n");
        printf("  Discord Voice Quality Patcher (Linux)\n");
        printf("================================================\n");
        printf("  Target:  %s\n", modulePath.c_str());
        printf("  Config:  %dkHz, %dkbps, Stereo\n", SAMPLE_RATE/1000, BITRATE);
        printf("================================================\n\n");
        printf("Opening file for patching...\n");
        int fd = open(modulePath.c_str(), O_RDWR);
        if (fd < 0) {
            printf("ERROR: Cannot open file: %s (errno=%d: %s)\n",
                   modulePath.c_str(), errno, strerror(errno));
            if (errno == EACCES)
                printf("Check file permissions. You may need: chmod +w <file>\n");
            else if (errno == ETXTBSY)
                printf("File is in use by another process. Close Discord first.\n");
            return false;
        }
        struct stat st;
        if (fstat(fd, &st) < 0) {
            printf("ERROR: Cannot stat file (errno=%d: %s)\n", errno, strerror(errno));
            close(fd);
            return false;
        }
        long long fileSize = st.st_size;
        printf("File size: %.2f MB\n", fileSize / (1024.0 * 1024.0));
        void* fileData = mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (fileData == MAP_FAILED) {
            printf("ERROR: Cannot mmap file (errno=%d: %s)\n", errno, strerror(errno));
            close(fd);
            return false;
        }
        if (!ApplyPatches(fileData, fileSize)) {
            munmap(fileData, fileSize);
            close(fd);
            return false;
        }
        printf("\nSyncing patched file to disk...\n");
        if (msync(fileData, fileSize, MS_SYNC) != 0) {
            printf("WARNING: msync failed (errno=%d: %s) - data may not be fully written\n",
                   errno, strerror(errno));
        }
        munmap(fileData, fileSize);
        close(fd);
        printf("\n================================================\n");
        printf("  SUCCESS! Patching Complete!\n");
        printf("  Audio: %dkHz | %dkbps | Stereo\n", SAMPLE_RATE/1000, BITRATE);
        printf("================================================\n\n");
        return true;
    }
};
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <path_to_discord_voice.node>\n", argv[0]);
        return 1;
    }
    DiscordPatcher patcher(argv[1]);
    return patcher.PatchFile() ? 0 : 1;
}
PATCHEOF

    PATCH_ENC4_ARRAY=$(python3 -c "import struct; print(', '.join(f'0x{b:02X}' for b in struct.pack('<I', $BITRATE_BPS)))")
    PATCH_ENC4_ESC=$(python3 -c "import struct; print(''.join(f'\\\\x{b:02X}' for b in struct.pack('<I', $BITRATE_BPS)))")
    PATCH_ENC3_ARRAY=$(python3 -c "import struct; print(', '.join(f'0x{b:02X}' for b in struct.pack('<I', $BITRATE_BPS)[:3]))")
    PATCH_ENC3_ESC=$(python3 -c "import struct; print(''.join(f'\\\\x{b:02X}' for b in struct.pack('<I', $BITRATE_BPS)[:3]))")
    sed -i "s/SAMPLERATE_VAL/$SAMPLE_RATE/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/BITRATE_VAL/$BITRATE/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/BITRATE_BPS_VAL/$BITRATE_BPS/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/PATCH_ENC4_VAL/$PATCH_ENC4_ARRAY/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/PATCH_ENC4_ESC/$PATCH_ENC4_ESC/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/PATCH_ENC3_VAL/$PATCH_ENC3_ARRAY/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/PATCH_ENC3_ESC/$PATCH_ENC3_ESC/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_CommitAudioCodec_StereoCheck1_Imm0/${OFFSET_CommitAudioCodec_StereoCheck1_Imm0}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_CommitAudioCodec_StereoCheck2_Imm0/${OFFSET_CommitAudioCodec_StereoCheck2_Imm0}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_CreateAudioFrame_Channels_MovImm2/${OFFSET_CreateAudioFrame_Channels_MovImm2}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_CapturedAudioProcessor_MonoDownmix_NopJmp/${OFFSET_CapturedAudioProcessor_MonoDownmix_NopJmp}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioEncoderOpusConfig_Ctor_Channels_Imm02/${OFFSET_AudioEncoderOpusConfig_Ctor_Channels_Imm02}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02/${OFFSET_AudioEncoderMultiChannelOpusConfig_Ctor_Channels_Imm02}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k/${OFFSET_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k/${OFFSET_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioEncoderOpusConfig_Ctor_FrameMs_Imm10/${OFFSET_AudioEncoderOpusConfig_Ctor_FrameMs_Imm10}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioEncoderOpusConfig_Ctor_Application_ImmAudio/${OFFSET_AudioEncoderOpusConfig_Ctor_Application_ImmAudio}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_RecreateEncoderInstance_FecBranch_Jmp/${OFFSET_RecreateEncoderInstance_FecBranch_Jmp}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_MultiChannelRecreateEncoder_FecBranch_Jmp/${OFFSET_MultiChannelRecreateEncoder_FecBranch_Jmp}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_SetFec_EnableBranch_Jmp/${OFFSET_SetFec_EnableBranch_Jmp}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_RecreateEncoderInstance_DtxBranch_Jmp/${OFFSET_RecreateEncoderInstance_DtxBranch_Jmp}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_MultiChannelRecreateEncoder_DtxBranch_Jmp/${OFFSET_MultiChannelRecreateEncoder_DtxBranch_Jmp}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_SetDtx_EnableBranch_Jmp/${OFFSET_SetDtx_EnableBranch_Jmp}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_CopyRedEncodeImpl_RedundantCopy_JmpNear/${OFFSET_CopyRedEncodeImpl_RedundantCopy_JmpNear}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_RecreateEncoder_BitrateCalcLow_Channels_Mov248k/${OFFSET_RecreateEncoder_BitrateCalcLow_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_RecreateEncoder_BitrateCalcMid_Channels_Mov248k/${OFFSET_RecreateEncoder_BitrateCalcMid_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_RecreateEncoder_BitrateCalcHigh_Channels_Mov248k/${OFFSET_RecreateEncoder_BitrateCalcHigh_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k/${OFFSET_MultiChannelRecreate_BitrateCalcLow_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k/${OFFSET_MultiChannelRecreate_BitrateCalcMid_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k/${OFFSET_MultiChannelRecreate_BitrateCalcHigh_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioBitrateAdaptorCalc32k_Channels_Mov248k/${OFFSET_AudioBitrateAdaptorCalc32k_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioBitrateAdaptorCalc48k_Channels_Mov248k/${OFFSET_AudioBitrateAdaptorCalc48k_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioBitrateAdaptorCalc60k_Channels_Mov248k/${OFFSET_AudioBitrateAdaptorCalc60k_Channels_Mov248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_ApplySettings_BitrateImul_Imm248k/${OFFSET_ApplySettings_BitrateImul_Imm248k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_SetTargetBitrate_Mulss_Nop6/${OFFSET_SetTargetBitrate_Mulss_Nop6}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_GetMultipliedBitrate_Mulss_Nop7/${OFFSET_GetMultipliedBitrate_Mulss_Nop7}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_SelectSampleRate_Constant_Imm48k/${OFFSET_SelectSampleRate_Constant_Imm48k}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_WebRtcSplHighPass_Entry_Ret/${OFFSET_WebRtcSplHighPass_Entry_Ret}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_hp_cutoff_Callback_InjectShellcode/${OFFSET_hp_cutoff_Callback_InjectShellcode}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_dc_reject_Callback_InjectShellcode/${OFFSET_dc_reject_Callback_InjectShellcode}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_ChannelDownmix_Entry_Ret/${OFFSET_ChannelDownmix_Entry_Ret}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_AudioEncoderOpusConfig_IsOK_MovTrueRet/${OFFSET_AudioEncoderOpusConfig_IsOK_MovTrueRet}/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/OFFSET_VAL_FileAdjustment/$FILE_OFFSET_ADJUSTMENT/g" "$TEMP_DIR/patcher.cpp"

    sed -i "s/ORIG_VAL_CreateAudioFrame_Channels_MovImm2/$ORIG_CreateAudioFrame_Channels_MovImm2/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_CapturedAudioProcessor_MonoDownmix_NopJmp/$ORIG_CapturedAudioProcessor_MonoDownmix_NopJmp/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_SelectSampleRate_Constant_Imm48k/$ORIG_SelectSampleRate_Constant_Imm48k/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_AudioEncoderOpusConfig_IsOK_MovTrueRet/$ORIG_AudioEncoderOpusConfig_IsOK_MovTrueRet/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_ChannelDownmix_Entry_Ret/$ORIG_ChannelDownmix_Entry_Ret/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_WebRtcSplHighPass_Entry_Ret/$ORIG_WebRtcSplHighPass_Entry_Ret/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_hp_cutoff_Callback_InjectShellcode/$ORIG_hp_cutoff_Callback_InjectShellcode/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_dc_reject_Callback_InjectShellcode/$ORIG_dc_reject_Callback_InjectShellcode/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k/$ORIG_AudioEncoderOpusConfig_Ctor_Bitrate_Imm248k/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k/$ORIG_AudioEncoderMultiChannelOpusConfig_Ctor_Bitrate_Imm248k/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_ApplySettings_BitrateImul_Imm248k/$ORIG_ApplySettings_BitrateImul_Imm248k/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_SetTargetBitrate_Mulss_Nop6/$ORIG_SetTargetBitrate_Mulss_Nop6/g" "$TEMP_DIR/patcher.cpp"
    sed -i "s/ORIG_VAL_GetMultipliedBitrate_Mulss_Nop7/$ORIG_GetMultipliedBitrate_Mulss_Nop7/g" "$TEMP_DIR/patcher.cpp"
}
# endregion Source Code Generation


# region Compilation
compile_patcher() {
    log_info "Compiling patcher with $COMPILER_TYPE..." >&2

    local exe="$TEMP_DIR/DiscordVoicePatcher"
    rm -f "$exe"

    if ! $COMPILER -O2 -std=c++17 \
        "$TEMP_DIR/patcher.cpp" \
        "$TEMP_DIR/amplifier.cpp" \
        -o "$exe" 2>"$TEMP_DIR/build.log"; then
        log_error "Compilation failed! Build log:" >&2
        echo "" >&2
        cat "$TEMP_DIR/build.log" >&2
        echo "" >&2
        log_info "Source files preserved in $TEMP_DIR for debugging" >&2
        return 1
    fi

    if [[ ! -f "$exe" ]]; then
        log_error "Compilation produced no output binary" >&2
        return 1
    fi
    local exe_size
    exe_size=$(stat -c%s "$exe" 2>/dev/null || echo "0")
    if (( exe_size < 4096 )); then
        log_error "Compiled binary is suspiciously small (${exe_size} bytes)" >&2
        return 1
    fi

    chmod +x "$exe"
    log_ok "Compilation successful ($(numfmt --to=iec "$exe_size" 2>/dev/null || echo "${exe_size}B"))" >&2
    echo "$exe"
    return 0
}
# endregion Compilation


# region Client Selection
SELECTED_CLIENTS=""

select_clients() {
    echo ""
    echo -e "${CYAN}  Installed Discord clients:${NC}"
    echo ""
    for i in "${!CLIENT_NAMES[@]}"; do
        echo -e "  [$(( i + 1 ))] ${WHITE}${CLIENT_NAMES[$i]}${NC}"
        echo -e "      ${DIM}${CLIENT_NODES[$i]}${NC}"
    done
    echo ""
    echo -e "  [${WHITE}A${NC}] Patch all clients"
    echo -e "  [${WHITE}C${NC}] Cancel"
    echo ""

    read -rp "  Choice: " choice

    case "${choice^^}" in
        C) log_warn "Cancelled"; exit 0 ;;
        A|"") SELECTED_CLIENTS="all"; return 0 ;;
        [0-9]*)
            if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
                log_error "Invalid selection"; exit 1
            fi
            if (( choice >= 1 && choice <= ${
                SELECTED_CLIENTS="$(( choice - 1 ))"
                return 0
            fi
            log_error "Selection out of range (1-${
            ;;
        *) log_error "Invalid selection"; exit 1 ;;
    esac
}
# endregion Client Selection


# region Patch a single client
patch_client() {
    local idx="$1"
    local name="${CLIENT_NAMES[$idx]}"
    local node_path="${CLIENT_NODES[$idx]}"

    echo ""
    log_info "=== Processing: $name ==="
    log_info "Node: $node_path"

    if ! $PATCH_LOCAL_ONLY; then
        if ! backup_node "$node_path" "$name"; then
            if ! $SKIP_BACKUP; then
                log_error "Backup failed, aborting patch for safety"
                return 1
            fi
        fi
        if ! install_linux_voice_bundle_for_client "$node_path"; then
            return 1
        fi
    fi

    if ! verify_binary "$node_path" "$name"; then
        return 1
    fi

    if $PATCH_LOCAL_ONLY; then
        if ! backup_node "$node_path" "$name"; then
            if ! $SKIP_BACKUP; then
                log_error "Backup failed, aborting patch for safety"
                return 1
            fi
        fi
    fi

    if [[ ! -w "$node_path" ]]; then
        log_warn "File not writable, attempting chmod..."
        chmod +w "$node_path" 2>/dev/null || {
            log_error "Cannot make file writable. Try: sudo chmod +w '$node_path'"
            return 1
        }
    fi

    if command -v fuser &>/dev/null; then
        if fuser "$node_path" &>/dev/null; then
            log_warn "File is currently open by another process"
            log_warn "  This is expected if Discord was recently closed. Proceeding..."
        fi
    fi

    log_info "Generating source files..."
    generate_amplifier_source
    generate_patcher_source
    log_ok "Source files generated"

    local exe
    exe=$(compile_patcher) || return 1

    log_info "Applying binary patches..."
    if "$exe" "$node_path"; then
        log_ok "Successfully patched $name!"
        return 0
    else
        log_error "Patcher failed for $name"
        log_info "Source files preserved in $TEMP_DIR for debugging"
        return 1
    fi
}
# endregion Patch a single client


# region Cleanup
cleanup() {
    [[ -d "${TEMP_DIR:-}" ]] || return 0

    if [[ "$PATCH_SUCCESS" == "true" ]]; then
        rm -f "$TEMP_DIR/patcher.cpp" "$TEMP_DIR/amplifier.cpp" \
              "$TEMP_DIR/DiscordVoicePatcher" "$TEMP_DIR/build.log" 2>/dev/null
    else
        rm -f "$TEMP_DIR/DiscordVoicePatcher" 2>/dev/null
    fi
}
# endregion Cleanup


# region Main
main() {
    banner

    if $RESTORE_MODE; then
        restore_from_backup
        exit 0
    fi

    show_settings

    find_discord_clients || exit 1

    find_compiler || exit 1

    if ! $PATCH_LOCAL_ONLY; then
        download_linux_voice_bundle_from_github || exit 1
    else
        log_info "Patch-local mode: skipping GitHub voice bundle download."
    fi

    if $PATCH_ALL; then
        SELECTED_CLIENTS="all"
    else
        select_clients
    fi

    handle_discord_running

    local success=0
    local failed=0
    local total=0
    local i

    if [[ "$SELECTED_CLIENTS" == "all" ]]; then
        total=${
        for i in "${!CLIENT_NAMES[@]}"; do
            if patch_client "$i"; then
                success=$(( success + 1 ))
            else
                failed=$(( failed + 1 ))
            fi
        done
    else
        total=1
        if patch_client "$SELECTED_CLIENTS"; then
            success=1
        else
            failed=1
        fi
    fi

    if [[ "$failed" -eq 0 ]]; then
        PATCH_SUCCESS=true
    fi

    cleanup

    echo ""
    echo -e "${CYAN}===============================================${NC}"
    if [[ "$failed" -eq 0 ]]; then
        echo -e "${GREEN}  [OK] PATCHING COMPLETE: $success/$total successful${NC}"
    else
        echo -e "${YELLOW}  PATCHING: $success/$total successful, $failed failed${NC}"
    fi
    echo -e "${CYAN}===============================================${NC}"
    echo ""
    echo "Restart Discord to apply changes."
}

trap cleanup EXIT
main "$@"
# endregion Main
