#!/bin/sh
# Installs the obdcracker command on macOS or Linux, from nothing but a shell:
#
#   curl -fsSL https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.sh | sh
#   wget -qO- https://raw.githubusercontent.com/DaSonOfPoseidon/OBDCracker/main/scripts/install.sh | sh
#
# It installs a C linker and rustup if they're missing, downloads the source (no Git needed), builds
# the CLI into ~/.cargo/bin and, on Linux, gives you access to serial ports. Run it again to update.
# Options go after `sh -s --`, e.g. `| sh -s -- --ref some-branch`.
#
# Everything is in functions and `main` runs on the last line, so a cut-off download runs nothing,
# and a command that reads stdin can't eat the rest of a piped script.

set -eu

REPO=DaSonOfPoseidon/OBDCracker
# Marks a directory this script made, so it never replaces one it didn't
MARKER=.obdcracker-install

usage() {
	cat <<EOF
Usage: install.sh [--ref REF] [--dir DIR] [--source PATH]

  --ref REF      branch, tag or commit to build [default: main]
  --dir DIR      where the source and build cache live [default: ${XDG_DATA_HOME:-\$HOME/.local/share}/obdcracker]
  --source PATH  build this checkout instead of downloading one (--ref is then ignored)
EOF
}

say() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# Prints a URL's body to stdout.
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl --proto '=https' --tlsv1.2 -fsSL "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget --https-only -qO- "$1"
	else
		die "need curl or wget to download $1"
	fi
}

# Sets SUDO to what runs a command as root: nothing when already root.
find_sudo() {
	if [ "$(id -u)" = 0 ]; then
		SUDO=
	elif command -v sudo >/dev/null 2>&1; then
		SUDO=sudo
	else
		die "need root to install packages, and sudo isn't installed: re-run as root"
	fi
}

ensure_linker_macos() {
	if xcode-select -p >/dev/null 2>&1; then
		note "Xcode Command Line Tools: already installed"
		return
	fi
	say "Installing the Xcode Command Line Tools (Rust needs their linker)"
	xcode-select --install || true
	die "finish the Command Line Tools install in the window that opened, then run this script again"
}

# Whether cc can build and link a program: a bare cc (gcc without libc6-dev, say) isn't enough.
can_link() {
	command -v cc >/dev/null 2>&1 &&
		printf 'int main(void) { return 0; }\n' | cc -x c - -o "$TMP/link-test" >/dev/null 2>&1
}

ensure_linker_linux() {
	# A distro's minimal image can lack both curl and wget once the script is already local
	downloader=
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		downloader=curl
	fi
	if can_link && [ -z "$downloader" ]; then
		note "C compiler and linker (cc): already installed"
		return
	fi
	say "Installing a C compiler and linker (Rust needs one)${downloader:+, and curl}"
	find_sudo
	if command -v apt-get >/dev/null 2>&1; then
		$SUDO apt-get update </dev/null
		# shellcheck disable=SC2086 # $downloader is empty or one word
		$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates $downloader </dev/null
	elif command -v dnf >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		$SUDO dnf install -y gcc glibc-devel $downloader </dev/null
	elif command -v pacman >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		$SUDO pacman -S --needed --noconfirm base-devel $downloader </dev/null
	elif command -v zypper >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		$SUDO zypper --non-interactive install gcc glibc-devel $downloader </dev/null
	else
		die "no apt-get, dnf, pacman or zypper found: install a C compiler (gcc or clang) yourself, then run this again"
	fi
	can_link || die "installed a compiler, but cc still can't build a program: install your distro's C build tools (e.g. build-essential)"
}

ensure_rustup() {
	if command -v rustup >/dev/null 2>&1; then
		note "rustup: already installed"
		return
	fi
	if [ -x "$CARGO_BIN/rustup" ]; then
		note "rustup: already installed in $CARGO_BIN"
		PATH="$CARGO_BIN:$PATH"
		return
	fi
	say "Installing rustup"
	tmp_rustup="$TMP/rustup-init.sh"
	fetch https://sh.rustup.rs >"$tmp_rustup"
	# The source tree's rust-toolchain.toml picks the toolchain, so don't install a default one
	sh "$tmp_rustup" -y --default-toolchain none --profile minimal </dev/null
	PATH="$CARGO_BIN:$PATH"
	command -v rustup >/dev/null 2>&1 || die "rustup installed, but it isn't in $CARGO_BIN"
}

# Downloads REF into DIR/src, replacing the copy from the last run only once the new one is complete.
download_source() {
	say "Downloading $REPO at $REF"
	archive="$TMP/source.tar.gz"
	fetch "https://codeload.github.com/$REPO/tar.gz/$REF" >"$archive" ||
		die "couldn't download $REF: check the name, and that it's pushed to GitHub"
	rm -rf "$DIR/src.new"
	mkdir "$DIR/src.new"
	tar -xzf "$archive" -C "$DIR/src.new" --strip-components=1
	[ -f "$DIR/src.new/Cargo.toml" ] || die "the download has no Cargo.toml; is '$REF' an OBDCracker ref?"
	rm -rf "$DIR/src"
	mv "$DIR/src.new" "$DIR/src"
	SRC="$DIR/src"
}

# Prepares DIR, refusing to take over a non-empty directory that this script didn't create.
prepare_dir() {
	if [ -d "$DIR" ] && [ ! -f "$DIR/$MARKER" ] && [ -n "$(ls -A "$DIR")" ]; then
		die "$DIR already exists and wasn't made by this script; pick another --dir (or --source to build a checkout)"
	fi
	mkdir -p "$DIR"
	# Absolute, because the build runs from inside the source tree
	DIR=$(cd "$DIR" && pwd)
	: >"$DIR/$MARKER"
}

build() {
	say "Building obdcracker (the first run also downloads the pinned Rust toolchain)"
	cd "$SRC"
	# Install what rust-toolchain.toml pins. rustup 1.28+ does it with `toolchain install`; older
	# rustup doesn't take that without a name, but installs it on `show`.
	rustup toolchain install </dev/null || rustup show </dev/null
	# The build cache lives outside the source, so a re-run only rebuilds what changed
	# --root pins where the binary goes, whatever CARGO_INSTALL_ROOT or Cargo's install.root say,
	# so it lands in the directory rustup put on PATH
	cargo install --path crates/obdcracker-cli --locked --force --target-dir "$DIR/target" \
		--root "$CARGO_HOME_DIR" </dev/null
}

# Linux: the serial ports' group must include you, or opening one fails with "permission denied".
ensure_serial_access_linux() {
	[ "$(id -u)" = 0 ] && return
	group=
	for dev in /dev/ttyUSB* /dev/ttyACM*; do
		if [ -e "$dev" ]; then
			group=$(stat -c %G "$dev")
			break
		fi
	done
	if [ -z "$group" ]; then
		for candidate in dialout uucp; do
			if getent group "$candidate" >/dev/null 2>&1; then
				group=$candidate
				break
			fi
		done
	fi
	if [ -z "$group" ] || [ "$group" = root ]; then
		note "couldn't tell which group owns serial ports; if opening one says 'permission denied', add yourself to it"
		return
	fi
	if id -nG | tr ' ' '\n' | grep -qx "$group"; then
		note "serial ports: you're already in the '$group' group"
		return
	fi
	say "Adding you to the '$group' group so you can open serial ports"
	find_sudo
	$SUDO usermod -aG "$group" "$(id -un)" </dev/null
	RELOGIN=1
}

verify() {
	say "Checking the install"
	"$CARGO_BIN/obdcracker" --version
	if ! ports=$("$CARGO_BIN/obdcracker" ports 2>&1); then
		note "couldn't list serial ports: $ports"
	elif [ -n "$ports" ]; then
		note "serial ports:"
		printf '%s\n' "$ports" | sed 's/^/      /'
	else
		note "no serial ports found: plug in the adapter and run 'obdcracker ports'"
	fi
	if [ "$OS" = Darwin ]; then
		note "on macOS use the /dev/cu.* port, not /dev/tty.*"
	fi
}

main() {
	REF=main
	DIR=${XDG_DATA_HOME:-$HOME/.local/share}/obdcracker
	SRC=
	while [ $# -gt 0 ]; do
		case $1 in
		--ref | --dir | --source)
			[ $# -ge 2 ] || die "$1 needs a value"
			case $1 in
			--ref) REF=$2 ;;
			--dir) DIR=$2 ;;
			--source) SRC=$2 ;;
			esac
			shift 2
			;;
		--ref=*) REF=${1#*=} && shift ;;
		--dir=*) DIR=${1#*=} && shift ;;
		--source=*) SRC=${1#*=} && shift ;;
		-h | --help) usage && exit 0 ;;
		*) usage >&2 && die "unknown option: $1" ;;
		esac
	done
	[ -n "$DIR" ] || die "--dir is empty"
	if [ -z "$SRC" ]; then
		case $REF in
		'' | -* | *..* | *[!A-Za-z0-9._/-]*) die "not a branch, tag or commit: '$REF'" ;;
		esac
	fi

	OS=$(uname -s)
	CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
	CARGO_BIN=$CARGO_HOME_DIR/bin
	RELOGIN=
	path_had_cargo=
	case ":$PATH:" in *":$CARGO_BIN:"*) path_had_cargo=1 ;; esac

	TMP=$(mktemp -d)
	trap 'rm -rf "$TMP"' EXIT

	case $OS in
	Darwin) ensure_linker_macos ;;
	Linux) ensure_linker_linux ;;
	*) die "this script supports macOS and Linux; on Windows use scripts/install.ps1" ;;
	esac
	ensure_rustup
	prepare_dir
	if [ -n "$SRC" ]; then
		[ -f "$SRC/Cargo.toml" ] || die "--source $SRC has no Cargo.toml"
		SRC=$(cd "$SRC" && pwd)
		note "building the checkout in $SRC"
	else
		download_source
	fi
	build
	if [ "$OS" = Linux ]; then
		ensure_serial_access_linux
	fi
	verify

	say "Done. Next, with the adapter plugged into the car and the ignition on:"
	note "obdcracker ports                       # find the adapter's port"
	note "obdcracker --serial <PORT> adapter     # check the adapter; sends nothing to the car"
	note "obdcracker --serial <PORT> vin"
	if [ -z "$path_had_cargo" ]; then
		note "open a new terminal first, so $CARGO_BIN is on your PATH"
	fi
	if [ -n "$RELOGIN" ]; then
		note "log out and back in first, so the new group applies"
	fi
}

main "$@"
