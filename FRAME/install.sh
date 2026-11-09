#!/usr/bin/env bash
# User-only FRAME installer. Also supports: curl .../FRAME/install.sh | bash -s -- ...
set -euo pipefail
umask 077
fail() { printf 'comb install: %s\n' "$*" >&2; exit 1; }
source_dir=''
profile=release
while (($#)); do
    case $1 in
        --source) (($# >= 2)) || fail '--source requires a directory'; source_dir=$2; shift 2 ;;
        --profile) (($# >= 2)) || fail '--profile requires release or dev'; profile=$2; shift 2 ;;
        --help) printf 'Usage: bash install.sh [--source REPOSITORY_ROOT] [--profile release|dev]\n'; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[[ $profile == release || $profile == dev ]] || fail 'Profile must be release or dev.'
for tool in git cargo rustc node npm systemctl realpath sha256sum timeout ssh; do
    command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool. Install it yourself; no sudo or toolchain bootstrap is performed."
done
systemctl --user show-environment >/dev/null || fail 'A running systemd user session is required.'
root=${COMB_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/comb-install}
bin_dir=${COMB_BIN_DIR:-$HOME/.local/bin}
data=${COMB_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/comb}
service=${COMB_SERVICE_NAME:-comb.service}
service_dir=${COMB_SERVICE_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}
unit=$service_dir/$service
[[ $service =~ ^[a-zA-Z0-9][a-zA-Z0-9_.@-]*\.service$ ]] || fail 'Invalid service name (expected a simple .service basename).'
safe_path() {
    local p=$1 part current=''
    [[ $p == /* && $p != / && ! $p =~ [[:cntrl:]] ]] || fail "Unsafe absolute path: $p"
    [[ $(realpath -ms -- "$p") == "$p" ]] || fail "Path must be normalized: $p"
    IFS=/ read -r -a parts <<< "$p"
    for part in "${parts[@]}"; do
        [[ -n $part ]] || continue
        current=$current/$part
        [[ ! -L $current ]] || fail "Symlink path refused: $current"
    done
}
overlap() { [[ $1 == "$2" || $1 == "$2/"* || $2 == "$1/"* ]]; }
for p in "$HOME" "$root" "$bin_dir" "$bin_dir/comb" "$data" "$unit"; do safe_path "$p"; done
[[ $root != "$HOME" && $HOME != "$root/"* && $bin_dir != "$HOME" ]] || fail 'Refusing unsafe home/ancestor installation.'
for p in "$bin_dir" "$data" "$unit"; do overlap "$root" "$p" && fail 'Install root must not overlap binary, data, or unit paths.'; done
for p in "$bin_dir/comb" "$unit"; do overlap "$data" "$p" && fail 'Data must not overlap installed files.'; done
reinstall=false
if [[ -e $root/.comb-install-owner ]]; then
    [[ -f $root/uninstall.sh && ! -L $root/uninstall.sh ]] || fail 'Invalid owned installation.'
    bash "$root/uninstall.sh" --check
    mapfile -t old < "$root/.comb-install-owner"
    [[ ${old[2]} == "$bin_dir/comb" && ${old[3]} == "$unit" && ${old[4]} == "$data" && ${old[5]} == "$service" ]] || fail 'Existing installation uses different overrides; uninstall it first.'
    reinstall=true
else
    [[ ! -e $root || ( -d $root && -z $(find "$root" -mindepth 1 -maxdepth 1 -print -quit) ) ]] || fail 'Install root contains foreign files.'
    [[ ! -e $bin_dir/comb && ! -e $unit ]] || fail 'Binary or unit is foreign; refusing overwrite.'
fi
for shell_file in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
    safe_path "$shell_file"
    [[ ! -e $shell_file || ( -f $shell_file && -O $shell_file ) ]] || fail 'Foreign shell startup file.'
    if ! $reinstall && [[ -f $shell_file ]] && grep -qF '# >>> comb PATH >>>' "$shell_file"; then
        fail "Existing unmanaged comb PATH block: $shell_file"
    fi
done
printf 'COMB user installation: build trusted Rust source and GUI assets; install without sudo.\n'
printf 'Program: %s\nCommand: %s/comb\nEncrypted identity/CELL data (preserved): %s\nUser service: %s\n' "$root" "$bin_dir" "$data" "$service"
printf 'The daemon starts in a locked/setup-waiting state, with no Git/peer listeners until you run comb and unlock it. Your password is not saved in the service. A restart/reboot requires unlocking again.\n'
printf 'First use explains identity creation and the encrypted recovery file. Keep that file AND its original password protected: it restores identity authority, not repository contents by itself. Keep encrypted CELL backups too; COMB has no provider password reset or recovery override. Copy recovery material offline, verify the copy, and never delete the last usable copy.\n'
if $reinstall; then printf 'Reinstallation will replace owned program files and restart FRAME locked; identity, repository state and recovery files are preserved.\n'; fi
work=$(mktemp -d "${TMPDIR:-/tmp}/comb-build.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
if [[ -z $source_dir && -n ${BASH_SOURCE[0]:-} ]]; then
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    for candidate in "$script_dir" "$script_dir/.."; do
        if [[ -f $candidate/Cargo.toml && -f $candidate/FRAME/Cargo.toml && -d $candidate/FRAME/webgui ]]; then
            source_dir=$candidate
            break
        fi
    done
fi
if [[ -z $source_dir ]]; then
    git clone --depth 1 --branch main https://github.com/DallinJacksonE/comb.git "$work/source"
    source_dir=$work/source
fi
source_dir=$(realpath -e -- "$source_dir")
[[ -f $source_dir/Cargo.toml && -f $source_dir/FRAME/Cargo.toml && -d $source_dir/FRAME/webgui ]] || fail 'Source must be a comb repository root.'
validate_uninstaller() {
    local cleanup=$1
    [[ -f $cleanup && ! -L $cleanup ]] || fail "Source uninstaller missing or unsafe: $cleanup. Installation was not changed. For unpublished local code, run bash FRAME/install.sh --source /absolute/path/to/comb."
    bash -n "$cleanup" || fail "Source uninstaller is invalid Bash: $cleanup. Installation was not changed."
}
validate_uninstaller "$source_dir/FRAME/uninstall.sh"
printf 'Building source checkout: %s\n' "$source_dir"
export CARGO_TARGET_DIR=$work/target
build_flags=()
target_profile=debug
if [[ $profile == release ]]; then build_flags=(--release); target_profile=release; fi
(cd "$source_dir"; cargo build --locked "${build_flags[@]}" --package comb-frame --bin comb)
(cd "$source_dir/FRAME/webgui"; npm ci; npm run build)
[[ -x $work/target/$target_profile/comb ]] || fail "Built executable missing: $work/target/$target_profile/comb. Check Cargo build.target/CARGO_BUILD_TARGET overrides; installation was not changed."
[[ -f $source_dir/FRAME/webgui/dist/index.html ]] || fail "Built GUI index missing: $source_dir/FRAME/webgui/dist/index.html. Installation was not changed."
validate_uninstaller "$source_dir/FRAME/uninstall.sh"
[[ -z $(find "$source_dir/FRAME/webgui/dist" -type l -print -quit) ]] || fail 'Symlinks in built assets are not supported.'
# Check every new destination against the OLD receipt before stopping/removing it.
# Directories matter too: merging into an unknown directory would claim user state.
declare -A owned_files=() owned_dirs=()
if $reinstall; then
    while IFS= read -r -d '' p; do owned_files["$p"]=1; done < "$root/.comb-install-files"
    while IFS= read -r -d '' p; do owned_dirs["$p"]=1; done < "$root/.comb-install-dirs"
fi
check_destination() {
    local dest=$1 kind=$2
    safe_path "$dest"
    if [[ -e $dest ]]; then
        if [[ $kind == directory ]]; then
            [[ -d $dest && ${owned_dirs[$dest]:-} == 1 ]] || fail "Foreign destination directory: $dest"
        else
            [[ -f $dest && ${owned_files[$dest]:-} == 1 ]] || fail "Foreign destination file: $dest"
        fi
    fi
}
for p in "$root/bin" "$root/assets"; do check_destination "$p" directory; done
for p in "$root/bin/comb" "$root/uninstall.sh" "$root/.comb-install-path-block" "$bin_dir/comb" "$unit"; do check_destination "$p" file; done
while IFS= read -r -d '' p; do
    dest=$root/assets/${p#"$source_dir/FRAME/webgui/dist/"}
    if [[ -d $p ]]; then check_destination "$dest" directory; else check_destination "$dest" file; fi
done < <(find "$source_dir/FRAME/webgui/dist" -mindepth 1 -print0)
# Derive receipts from build outputs, never scan the installed tree (which may
# contain unrelated user files that must remain unowned).
{ printf '%s\0' "$root/bin/comb"; while IFS= read -r -d '' p; do printf '%s\0' "$root/assets/${p#"$source_dir/FRAME/webgui/dist/"}"; done < <(find "$source_dir/FRAME/webgui/dist" -type f -print0); } > "$work/new-files"
{ while IFS= read -r -d '' p; do printf '%s\0' "$root/assets/${p#"$source_dir/FRAME/webgui/dist/"}"; done < <(find "$source_dir/FRAME/webgui/dist" -depth -mindepth 1 -type d -print0); printf '%s\0' "$root/assets" "$root/bin"; } > "$work/new-dirs"
if $reinstall; then bash "$root/uninstall.sh"; fi
mkdir -p -- "$root/bin" "$root/assets" "$bin_dir" "$(dirname -- "$unit")"
install -m 755 "$work/target/$target_profile/comb" "$root/bin/comb"
shell_quote() { local s=$1; s=${s//\'/\'\\\'\'}; printf "'%s'" "$s"; }
{
    printf '#!/usr/bin/env bash\nexport COMB_DATA_DIR=${COMB_DATA_DIR:-'
    shell_quote "$data"; printf '}\nexec '
    shell_quote "$root/bin/comb"; printf ' "$@"\n'
} > "$bin_dir/comb"
chmod 755 "$bin_dir/comb"
install -m 755 "$source_dir/FRAME/uninstall.sh" "$root/uninstall.sh"
cp -R -- "$source_dir/FRAME/webgui/dist/." "$root/assets/"
# systemd's argument parser is not a shell: escape literal specifiers/dollars.
unit_quote() {
    local s=$1
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//%/%%}
    # systemd does not expand environment variables in argv[0].
    if [[ ${2:-argument} != executable ]]; then s=${s//\$/\$\$}; fi
    printf '"%s"' "$s"
}
{
    printf '# comb managed user service\n[Unit]\nDescription=comb FRAME (starts locked)\nAfter=network.target\n\n[Service]\nType=simple\nExecStart='
    unit_quote "$root/bin/comb" executable; printf ' --data '; unit_quote "$data"
    printf ' serve --managed --assets '; unit_quote "$root/assets"; printf ' --sync-seconds 15\nRestart=on-failure\nRestartSec=5\nUMask=0077\n\n[Install]\nWantedBy=default.target\n'
} > "$unit"
{
    printf '# >>> comb PATH >>>\ncase ":$PATH:" in\n    *:'
    shell_quote "$bin_dir"; printf ':*) ;;\n    *) export PATH='
    shell_quote "$bin_dir"; printf ':"$PATH" ;;\nesac\n# <<< comb PATH <<<\n'
} > "$root/.comb-install-path-block"
for shell_file in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
    printf '\n' >> "$shell_file"
    cat "$root/.comb-install-path-block" >> "$shell_file"
done
printf '%s\n' 'comb-install-v1' "$root" "$bin_dir/comb" "$unit" "$data" "$service" > "$root/.comb-install-owner"
{ cat "$work/new-files"; printf '%s\0' "$root/uninstall.sh" "$root/.comb-install-path-block" "$bin_dir/comb" "$unit"; } > "$root/.comb-install-files"
cp -- "$work/new-dirs" "$root/.comb-install-dirs"
while IFS= read -r -d '' file; do sha256sum -- "$file"; done < "$root/.comb-install-files" > "$root/.comb-install-hashes"
systemctl --user daemon-reload
systemctl --user enable --now "$service" || fail "Service startup failed. Files remain installed; inspect: systemctl --user status $service"
deadline=$((SECONDS + 30))
ready=false
while ((SECONDS < deadline)); do
    systemctl --user is-active --quiet "$service" || fail "Service is not active. Inspect: journalctl --user -u $service"
    if timeout --kill-after=1s 2s "$root/bin/comb" --data "$data" service-status >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.1
done
$ready || fail "Service private IPC did not become ready within 30s. Inspect: journalctl --user -u $service"
systemctl --user is-active --quiet "$service" || fail "Service stopped after readiness. Inspect: journalctl --user -u $service"
printf 'Installed comb. FRAME starts locked; private service IPC is ready. Run comb for initial setup/unlock. Keep your recovery material safe and separate; no password is stored.\n'
printf 'Open a new shell (or source ~/.profile) for PATH. Installed CLI: %s/comb\n' "$bin_dir"
