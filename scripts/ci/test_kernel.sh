#!/bin/bash
set -euxo pipefail

cargo xtask build --release -- --bin tests

tmp_dir=$(mktemp -d)
kernel="${!#}"
initramfs=${tmp_dir}/initramfs.img


# building initramfs with our test binary as init
cp target/x86_64-unknown-linux-gnu/release/tests $tmp_dir/init
echo "init" | cpio -D $tmp_dir -o -H newc > $initramfs

distro="ubuntu"
while read version
do
    base_url=https://kernel.ubuntu.com/mainline/${version}/amd64/
    image=$(curl -L $base_url | grep -oP 'linux-image-unsigned-.*?-generic.*?amd64.deb' | grep -F "linux-image-unsigned-${kernel}" | tail -n 1  || true)
    if [[ $image ]]
    then
        break
    fi
done < <(curl https://kernel.ubuntu.com/mainline/ | grep -oP 'href="v\d+\.\d+(\.\d+)?/"' | cut -d '"' -f 2 | tr -d '/' | sort -rV | grep "v${kernel}")
        

# no kernel found
if [[ ! $image ]]
then
    echo "no image found for kernel ${kernel}"
    exit 1
fi

if [[ $(echo $@ | grep -c -- '--cache-key') > 0 ]]
then
    echo "amd64-vmlinuz-$(md5sum <<<$image | cut -d ' ' -f 1)"
    exit 0
fi

precise_version=$(cut -d '_' -f 2 <<<$image)

cache_root="cache/vmlinuz"
cache_dir="${cache_root}/amd64/${distro}/${image}"

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

qemu-system-x86_64 -kernel ${cache_dir}/vmlinuz* -m 512m -initrd $initramfs -append "lsm=bpf console=ttyS0" -nographic ${QEMU_ARGS[@]} | tee ${kernel_logs}

tail -n 30 $kernel_logs | grep 'SUCCESS' > /dev/null

