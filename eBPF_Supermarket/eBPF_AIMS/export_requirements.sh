#!/usr/bin/env bash
set -euo pipefail

OUTPUT_FILE="requirements.txt"

get_os_pretty_name() {
	awk -F= '/^PRETTY_NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release 2>/dev/null || true
}

{
	echo "# OS: $(get_os_pretty_name)"
	echo "# Kernel: $(uname -r)"
	echo "# Python: $(python3 --version 2>/dev/null || echo 'python3 not found')"
	echo "# Generated: $(date -Is)"
	echo "#"
	echo "# APT packages (versions on this machine):"
} > "$OUTPUT_FILE"

APT_PKGS="build-essential clang llvm libelf-dev zlib1g-dev pkg-config linux-headers-$(uname -r) bpftool sysstat iperf3 stress-ng fio python3 python3-venv python3-pip"

if command -v dpkg-query >/dev/null 2>&1; then
	dpkg-query -W -f='${Package}=${Version}\n' $APT_PKGS 2>/dev/null | sed 's/^/# /' >> "$OUTPUT_FILE" || true
fi

{
	echo
	echo "# Python packages:"
} >> "$OUTPUT_FILE"

if command -v python3 >/dev/null 2>&1; then
	python3 -m pip freeze >> "$OUTPUT_FILE" || true
else
	echo "# python3 not found; skip pip freeze" >> "$OUTPUT_FILE"
fi

echo "Wrote $OUTPUT_FILE" 