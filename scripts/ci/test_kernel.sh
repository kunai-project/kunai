#!/bin/bash
set -euxo pipefail

cargo xtask build --release -- --bin tests

tmp_dir=$(mktemp -d)
kernel="${!#}"
debian_url="https://ftp.us.debian.org/debian/pool/main/l/linux/"
# there is no https for ubuntu.com !!!!
ubuntu_url="http://security.ubuntu.com/ubuntu/pool/main/l/linux/"
initramfs=${tmp_dir}/initramfs.img


# building initramfs with our test binary as init
cp target/x86_64-unknown-linux-musl/release/tests $tmp_dir/init
echo "init" | cpio -D $tmp_dir -o -H newc > $initramfs

distro="debian"
base_url="$debian_url"

image=$(curl -k $base_url | grep -oP "linux-image-.*?-cloud-amd64-unsigned.*?.deb" | grep -F "linux-image-${kernel}" | tail -n 1 || true)

if [[ ! $image ]]
then
    distro="ubuntu"
    base_url="$ubuntu_url"
    image=$(curl $base_url | grep -oP 'linux-image-unsigned-.*?-generic.*?amd64.deb' | grep -F "linux-image-unsigned-${kernel}" | tail -n 1)

    # no kernel found even in ubuntu repo
    if [[ ! $image ]]
    then
        echo "no image found for kernel ${kernel}"
        exit 1
    fi
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
    curl -k ${base_url}${image} | dpkg --fsys-tarfile - | tar -C ${tmp_dir} --wildcards --extract "./boot/*vmlinuz*"
    # we create cache dir
    mkdir -p $cache_dir
    mv ${tmp_dir}/boot/vmlinuz* $cache_dir
fi

# running qemu
kernel_logs=${tmp_dir}/kernel.log
QEMU_ARGS=()
if [ -c /dev/kvm ]
then
    QEMU_ARGS+=(-accel kvm)
fi

qemu-system-x86_64 -kernel ${cache_dir}/vmlinuz* -m 512m -initrd $initramfs -append console=ttyS0 -nographic ${QEMU_ARGS[@]} | tee ${kernel_logs}

tail -n 30 $kernel_logs | grep 'SUCCESS' > /dev/null

