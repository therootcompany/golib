#!/bin/sh
# Sync winpath package from Go standard library
# Downloads source files to orig/ and applies patches from patches/

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ORIG_DIR="$SCRIPT_DIR/orig"
PATCHES_DIR="$SCRIPT_DIR/patches"

# Go version to sync from (override with GO_VERSION env)
GO_VERSION="${GO_VERSION:-go1.26.1}"
GO_BASE_URL="https://raw.githubusercontent.com/golang/go/${GO_VERSION}/src"

# Source files to download
# Format: "local_file::source_path"
SOURCES="
path_lite.go::internal/filepathlite/path.go
path_lite_windowsspecific.go::internal/filepathlite/path_windows.go
path_windowsspecific.go::path/filepath/path_windows.go
"

download() {
	local dest="$1"
	local src="$2"
	local url="$GO_BASE_URL/$src"

	printf "  Downloading %s... " "$dest"
	if curl -fsSL "$url" -o "$dest.tmp"; then
		mv "$dest.tmp" "$dest"
		echo "OK"
	else
		rm -f "$dest.tmp"
		echo "FAILED"
		return 1
	fi
}

show_agent_instructions() {
	cat <<'EOF'

AGENT: PATCH APPLICATION FAILED
AGENT: 
AGENT: The Go source files have diverged from the patches.
AGENT: 
AGENT: To manually update:
AGENT:   1. Run: ./sync.sh download
AGENT:      This downloads original files to orig/
AGENT:   2. Compare orig/*.go with current *.go
AGENT:   3. Update patches/*.diff files
AGENT:   4. Run: ./sync.sh
AGENT: 
AGENT: Key transformations for winpath:
AGENT:   - Package name: 'package winpath'
AGENT:   - Replace internal/stringslite with strings
AGENT:   - Remove internal/* imports
AGENT:   - Remove IsLocal, Localize, isLocal, localize, isReservedName functions
AGENT:   - Change join(elem []string) to Join(elem ...string)
AGENT:   - Export: Clean, Join, Split, Ext, Base, Dir, IsAbs, VolumeName, ToSlash, FromSlash
EOF
}

cmd_download() {
	echo "Downloading source files to orig/..."
	mkdir -p "$ORIG_DIR"
	for entry in $SOURCES; do
		local_file="${entry%%::*}"
		source_path="${entry#*::}"
		if ! download "$ORIG_DIR/$local_file" "$source_path"; then
			echo ""
			echo "ERROR: Failed to download $source_path"
			echo "AGENT: Check if Go version $GO_VERSION exists in golang/go repository"
			exit 1
		fi
	done
	echo ""
	echo "Download complete. Original files in: $ORIG_DIR/"
}

cmd_patch() {
	if ! test -d "$PATCHES_DIR"; then
		echo "ERROR: No patches directory found"
		echo "AGENT: Create patches/ directory with .diff files"
		exit 1
	fi

	# Copy original files to working directory first
	for entry in $SOURCES; do
		local_file="${entry%%::*}"
		if test -f "$ORIG_DIR/$local_file"; then
			cp "$ORIG_DIR/$local_file" "$SCRIPT_DIR/$local_file"
		fi
	done

	echo "Applying patches..."
	patch_failed=""
	for patch in "$PATCHES_DIR"/*.diff; do
		if test -f "$patch"; then
			patch_name=$(basename "$patch")
			printf "  Applying %s... " "$patch_name"
			if patch -d "$SCRIPT_DIR" -p1 <"$patch" 2>/dev/null; then
				echo "OK"
			else
				echo "FAILED"
				patch_failed=1
			fi
		fi
	done
	echo ""

	if test -n "$patch_failed"; then
		show_agent_instructions
		exit 1
	fi
}

cmd_verify() {
	printf "Verifying build... "
	if ! go build . 2>&1; then
		echo "FAILED"
		show_agent_instructions
		exit 1
	fi

	if ! go vet . 2>&1; then
		echo "FAILED (vet)"
		show_agent_instructions
		exit 1
	fi

	printf "Running tests... "
	if ! go test -v . 2>&1; then
		echo "FAILED (tests)"
		exit 1
	fi
}

cmd_diff() {
	echo "Generating diffs..."
	mkdir -p "$PATCHES_DIR"
	for entry in $SOURCES; do
		local_file="${entry%%::*}"
		if test -f "$ORIG_DIR/$local_file" && test -f "$SCRIPT_DIR/$local_file"; then
			diff -u "$ORIG_DIR/$local_file" "$SCRIPT_DIR/$local_file" >"$PATCHES_DIR/${local_file%.go}.diff" 2>/dev/null || true
			echo "  Created patches/${local_file%.go}.diff"
		fi
	done
	echo ""
	echo "Diffs created in: $PATCHES_DIR/"
}

main() {
	case "${1:-}" in
	download)
		cmd_download
		;;
	diff)
		cmd_download
		cmd_diff
		;;
	*)
		# Default: download, patch, and verify
		cmd_download
		if test -d "$PATCHES_DIR"; then
			cmd_patch
		fi
		cmd_verify
		echo ""
		echo "Sync complete: path/winpath/"
		;;
	esac
}

main "$@"
