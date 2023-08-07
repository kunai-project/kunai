typedef long long unsigned int __u64;
typedef __u64 u64;
typedef unsigned int __u32;
typedef __u32 u32;
typedef __u32 __wsum;
typedef short unsigned int __u16;
typedef __u16 u16;
typedef unsigned char __u8;
typedef __u8 u8;

/* This file aims at containing minimal types needed to be able to compile shim.c */

// Base types
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef long long int __s64;
typedef __s64 s64;
typedef int __s32;
typedef __s32 s32;
typedef short int __s16;
typedef __s16 s16;
typedef signed char __s8;
typedef __s8 s8;

// Kernel types
typedef long unsigned int __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef long int __kernel_long_t;
typedef int __kernel_pid_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef long long int __kernel_loff_t;
typedef long long int __kernel_time64_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef u32 __kernel_dev_t;
typedef short unsigned int __kernel_sa_family_t;
typedef int __kernel_rwf_t;
typedef __kernel_long_t __kernel_ptrdiff_t;
typedef __kernel_long_t __kernel_off_t;
typedef int __kernel_key_t;
typedef short unsigned int __kernel_old_uid_t;
typedef short unsigned int __kernel_old_gid_t;
typedef unsigned int __kernel_mode_t;
typedef int __kernel_ipc_pid_t;
typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_gid_t;
typedef __kernel_long_t __kernel_old_time_t;
typedef __kernel_long_t __kernel_suseconds_t;
typedef int __kernel_mqd_t;
typedef int __kernel_daddr_t;

typedef __kernel_uid32_t uid_t;
typedef __kernel_gid32_t gid_t;
typedef __kernel_pid_t pid_t;
typedef __kernel_size_t size_t;