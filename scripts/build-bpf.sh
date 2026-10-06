#!/bin/sh
# Compile the cgroup socket-marking BPF program for the local Linux kernel ABI.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

command -v clang >/dev/null 2>&1 || {
	printf '%s\n' 'build-bpf: clang is required.' >&2
	exit 1
}

mkdir -p "$repo_dir/build"
clang -O2 -g -target bpf -c \
	"$repo_dir/bpf/mark-sockets.bpf.c" \
	-o "$repo_dir/build/mark-sockets.bpf.o"
printf 'Built %s\n' "$repo_dir/build/mark-sockets.bpf.o"
