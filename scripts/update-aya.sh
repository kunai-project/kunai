#!/bin/bash
echo "Updating aya userland"
cargo update -p aya

echo
echo "Updating aya-bpf"
cd kunai-ebpf
cargo update -p aya-bpf
