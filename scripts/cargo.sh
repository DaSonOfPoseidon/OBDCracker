#!/bin/sh
# Runs cargo in a container so the host needs only Docker. The rustup and registry volumes keep the
# pinned toolchain and downloaded crates between runs. The labels keep these throwaway containers out
# of monitoring alerts (ContainerGone) and WUD. The memory limit replaces the host's 1 GB default,
# which a parallel rustc build goes over (#126).
set -e
cd "$(dirname "$0")/.."
exec docker run --rm -i \
	--label monitoring.ignore=true --label wud.watch=false \
	--memory 6g --memory-swap 6g \
	-v "$PWD:/src" -w /src \
	-v obdcracker-rustup:/usr/local/rustup \
	-v obdcracker-cargo:/usr/local/cargo/registry \
	rust:1-slim cargo "$@"
