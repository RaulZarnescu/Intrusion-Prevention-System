# Shared fetch -> transform -> validate -> atomic-replace core for the blocklist update
# scripts. Not a standalone entry point -- sourced by update_threat_intel.sh (IP feed) and
# update_sni_blocklist.sh (domain feed), which set the run_update() args and optionally
# override transform() before calling it. One core means a fix to the download/atomic-write
# logic (e.g. a source going down) only has to happen once.
set -euo pipefail

# Identity by default; a caller redefines this before calling run_update() to reshape the
# feed (e.g. pulling the domain column out of a hosts-file format).
transform() { cat; }

run_update() {
    local source_url="$1" output_file="$2" min_entries="$3" sanity_regex="$4"

    local tmp_file
    tmp_file="$(mktemp "${output_file}.XXXXXX")"
    trap 'rm -f "$tmp_file"' RETURN

    if ! curl -fsS --max-time 30 "$source_url" | transform > "$tmp_file"; then
        echo "[!] Download failed, keeping existing $output_file" >&2
        return 1
    fi

    local entry_count
    entry_count=$(grep -vc '^[[:space:]]*#\|^[[:space:]]*$' "$tmp_file" || true)

    if [ "$entry_count" -lt "$min_entries" ]; then
        echo "[!] Downloaded file only has $entry_count entries (expected >= $min_entries), refusing to replace $output_file" >&2
        return 1
    fi

    if ! grep -qE "$sanity_regex" "$tmp_file"; then
        echo "[!] Downloaded file doesn't look right (sanity regex failed), refusing to replace $output_file" >&2
        return 1
    fi

    chmod 644 "$tmp_file"
    mv -f "$tmp_file" "$output_file"
    trap - RETURN

    echo "[+] $output_file updated: $entry_count entries from $source_url"
}
