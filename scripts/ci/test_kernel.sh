#!/bin/bash

# currently this test will work with a host running on amd64
# aarch64 will be emulated and is not optimized to run on a aarch64 host

set -euxo pipefail

system_arch=$(uname -m)
qemu_arch=${ARCH:-$system_arch}

if [[ "$qemu_arch" == "x86_64" ]]; then
    arch="amd64"
elif [[ "$qemu_arch" == "aarch64" ]]; then
    arch="arm64"
else
    echo "unimplemented architecture: $qemu_arch"
    exit 1
fi

if [[ "$arch" == "amd64" ]]; then
    cargo xtask build --release -- --bin tests
elif [[ "$arch" == "arm64" ]]; then
    CC=aarch64-linux-gnu-gcc CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo xtask build --release --target aarch64-unknown-linux-gnu
else
    echo "cannot compile"
    exit 1
fi

tmp_dir=$(mktemp -d)
kernel="${!#}"
initramfs=${tmp_dir}/initramfs.img


# building initramfs with our test binary as init
cp target/${qemu_arch}-unknown-linux-gnu/release/tests $tmp_dir/init
echo "init" | cpio -D $tmp_dir -o -H newc > $initramfs

distro="ubuntu"
while read version
do
    base_url=https://kernel.ubuntu.com/mainline/${version}/${arch}/
    image=$(curl -L $base_url | grep -oP 'linux-image-unsigned-.*?-generic.*?\.deb' | grep "${arch}.deb" | grep -F "linux-image-unsigned-${kernel}" | tail -n 1  || true)
    if [[ $image ]]
    then
        break
    fi
done < <(curl https://kernel.ubuntu.com/mainline/ | grep -oP 'href="v\d+\.\d+(\.\d+)?/"' | cut -d '"' -f 2 | tr -d '/' | sort -rV | grep -E "v${kernel}($|\.)")
        
# no kernel found
if [[ ! $image ]]
then
    echo "no image found for kernel ${kernel}"
    exit 1
fi

precise_version=$(cut -d '_' -f 2 <<<$image)

cache_root="cache/vmlinuz"
cache_dir="${cache_root}/${arch}/${distro}/${image}"

if [[ ! -d $cache_dir ]]
then
    if [[ $(grep -oP "\.deb$"<<<$image) ]]
    then
        curl -k ${base_url}${image} | dpkg --fsys-tarfile - | tar -C ${tmp_dir} --wildcards --extract "./boot/*vmlinuz*"
    else
        curl -k ${base_url}${image} | tar -zC ${tmp_dir} --wildcards --extract "boot/*vmlinuz*" 2>/dev/null
    fi
    # we create cache dir
    mkdir -p $cache_dir
    mv ${tmp_dir}/boot/vmlinuz* $cache_dir
fi

# running qemu
kernel_logs=${tmp_dir}/kernel.log
QEMU_ARGS=()
if [[ -c /dev/kvm && $(echo $@ | grep -c -- '--accel') > 0 ]]
then
    QEMU_ARGS+=(-accel kvm)
fi

if [[ "$arch" == "amd64" ]]; then
    qemu-system-x86_64 -smp 4 -kernel ${cache_dir}/vmlinuz* -m 2G -initrd $initramfs -append "lsm=bpf console=ttyS0" -nographic ${QEMU_ARGS[@]} | tee ${kernel_logs}
elif [[ "$arch" == "arm64" ]]; then
    # we need to run cortex-a57 otherwise older kernels won't boot
    # we need to remove console=ttyS0
    qemu-system-aarch64 -M virt -smp 4 -cpu cortex-a57 -kernel ${cache_dir}/vmlinuz* -m 2G -initrd $initramfs -append "lsm=bpf" -nographic ${QEMU_ARGS[@]} | tee ${kernel_logs}
else
    echo "inimplemented arch: $arch"
    exit 1
fi

tail -n 30 $kernel_logs | grep 'SUCCESS' > /dev/null

