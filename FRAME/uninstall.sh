#!/usr/bin/env bash
# Remove only installer-owned program files. Never delete user data or recovery trees.
set -euo pipefail
umask 077
fail() { printf 'comb uninstall: %s\n' "$*" >&2; exit 1; }
check=false
if [[ $# == 1 && $1 == --check ]]; then check=true
elif (($#)); then fail 'Usage: uninstall.sh [--check] (no purge option; all data is always preserved)'; fi
safe_path() {
    local p=$1 part current='' parts
    [[ $p == /* && $p != / && ! $p =~ [[:cntrl:]] && $(realpath -ms -- "$p") == "$p" ]] || fail "Unsafe path: $p"
    IFS=/ read -r -a parts <<< "$p"
    for part in "${parts[@]}"; do
        [[ -n $part ]] || continue
        current=$current/$part
        [[ ! -L $current ]] || fail "Symlink path refused: $current"
    done
}
root=${COMB_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/comb-install}
# An installed copy carries its own location, independent of cwd or environment.
if [[ -n ${BASH_SOURCE[0]:-} ]]; then
    self_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    if [[ -f $self_dir/.comb-install-owner ]]; then root=$self_dir; fi
fi
safe_path "$root"
[[ $root != "$HOME" && $HOME != "$root/"* ]] || fail 'Unsafe installation root.'
for name in owner files hashes dirs; do
    safe_path "$root/.comb-install-$name"
    [[ -f $root/.comb-install-$name && -O $root/.comb-install-$name ]] || fail 'No owned installation found.'
done
mapfile -t receipt < "$root/.comb-install-owner"
[[ ${receipt[0]:-} == comb-install-v1 && ${receipt[1]:-} == "$root" && ${#receipt[@]} == 6 ]] || fail 'Invalid ownership marker.'
binary=${receipt[2]}; unit=${receipt[3]}; data=${receipt[4]}; service=${receipt[5]}
[[ $service =~ ^[a-zA-Z0-9][a-zA-Z0-9_.@-]*\.service$ && $unit == */"$service" && $binary == */comb ]] || fail 'Invalid ownership paths.'
for file in "$binary" "$unit" "$data"; do safe_path "$file"; done
[[ $data != "$root" && $data != "$root/"* && $root != "$data/"* ]] || fail 'Data overlaps installation.'
mapfile -d '' -t files < "$root/.comb-install-files"
((${#files[@]} >= 4)) || fail 'Invalid file manifest.'
for file in "${files[@]}"; do
    safe_path "$file"
    case $file in
        "$root/bin/comb"|"$root/assets/"*|"$root/uninstall.sh"|"$root/.comb-install-path-block"|"$binary"|"$unit") ;;
        *) fail "Foreign manifest path: $file" ;;
    esac
    [[ -f $file && -O $file ]] || fail "Missing/foreign installed file: $file"
done
# Compare hashes in manifest order, not arbitrary paths from a checksum file.
{ for file in "${files[@]}"; do sha256sum -- "$file"; done; } | cmp -s - "$root/.comb-install-hashes" || fail 'Installed files changed; refusing to remove foreign files.'
mapfile -d '' -t dirs < "$root/.comb-install-dirs"
for dir in "${dirs[@]}"; do
    safe_path "$dir"
    [[ $dir == "$root/bin" || $dir == "$root/assets" || $dir == "$root/assets/"* ]] || fail 'Foreign directory manifest path.'
done
for shell_file in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
    safe_path "$shell_file"
    [[ ! -e $shell_file || ( -f $shell_file && -O $shell_file ) ]] || fail 'Foreign shell startup file.'
    if [[ -f $shell_file ]] && grep -qF '# >>> comb PATH >>>' "$shell_file"; then
        awk '/^# >>> comb PATH >>>$/ {block=1} block {print} /^# <<< comb PATH <<<$/{block=0}' "$shell_file" | cmp -s - "$root/.comb-install-path-block" || fail "Modified PATH block in $shell_file; refusing to edit it."
    fi
done
if $check; then exit 0; fi
systemctl --user disable --now "$service"
for shell_file in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [[ -f $shell_file ]] && grep -qF '# >>> comb PATH >>>' "$shell_file"; then
        shell_tmp=$(mktemp "$HOME/.comb-shell.XXXXXXXX")
        if ! awk '/^# >>> comb PATH >>>$/ {block=1; next} /^# <<< comb PATH <<<$/{block=0; next} !block {print}' "$shell_file" > "$shell_tmp"; then
            rm -- "$shell_tmp"; fail "Could not update $shell_file"
        fi
        chmod --reference="$shell_file" "$shell_tmp"
        mv -- "$shell_tmp" "$shell_file"
    fi
done
for file in "${files[@]}"; do rm -- "$file"; done
for dir in "${dirs[@]}"; do rmdir -- "$dir" 2>/dev/null || true; done
rm -- "$root/.comb-install-hashes" "$root/.comb-install-files" "$root/.comb-install-dirs" "$root/.comb-install-owner"
# Never recurse: unknown files and directories (including empty trees) survive.
rmdir -- "$root" 2>/dev/null || true
systemctl --user daemon-reload
printf 'Removed comb program and user service. All data and recovery material preserved at %s\n' "$data"
