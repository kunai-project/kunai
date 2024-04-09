// do not depends on types from the kernel headers
#include "types.h"

// uncomment if BPF_CORE_READ must be used
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
IMPORTANT: it seems defining and using typedefs (for structs) in shim
makes it fail at linking, so don't do it.

* Using anonymous structs seems to make the linking fail

*/

// this just a simple C macro to make easier shim definition
// the macro prefix the function name by "shim_" so that doing we can
// easily filter the shim functions to bindgen.
#define _SHIM_GETTER(ret, proto, accessed_member)                \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return __builtin_preserve_access_index(accessed_member); \
	}

#define _SHIM_GETTER_BPF_CORE_READ(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                \
	{                                                       \
		return BPF_CORE_READ(struc, memb);                  \
	}

#define _SHIM_GETTER_BPF_CORE_READ_BITFIELD(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                         \
	{                                                                \
		return BPF_CORE_READ_BITFIELD_PROBED(struc, memb);           \
	}

#define _SHIM_GETTER_BPF_CORE_READ_USER(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return BPF_CORE_READ_USER(struc, memb);                  \
	}

#define _SHIM_GETTER_BPF_CORE_READ_RECAST(ret, proto, old_struct, new_struct, memb) \
	__attribute__((always_inline)) ret proto                                        \
	{                                                                               \
		struct old_struct *old = (void *)new_struct;                                \
		return BPF_CORE_READ(old, memb);                                            \
	}

// macro used to define a function to check if a field exists
#define _FIELD_EXISTS_DEF(_struct, memb, memb_name)                                                       \
	__attribute__((always_inline)) _Bool shim_##_struct##_##memb_name##_##exists(struct _struct *_struct) \
	{                                                                                                     \
		return bpf_core_field_exists(_struct->memb);                                                      \
	}

#define SHIM_BITFIELD(struc, memb)                                                                                                  \
	_SHIM_GETTER_BPF_CORE_READ_BITFIELD(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define SHIM(struc, memb)                                                                                                              \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb)             \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define SHIM_WITH_NAME(struc, memb, memb_name)                                                                                              \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb_name(struct struc *struc), struc, memb)             \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb_name##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb_name)

#define SHIM_REF(struc, memb)                                                                                             \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb(struct struc *struc), &(struc->memb))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb)) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM(struc, memb)                                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM_WITH_NAME(struc, memb, memb_name)                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb_name)

#define SHIM_ENUM_VALUE(enum_type, enum_value)                                      \
	__attribute__((always_inline)) unsigned int shim_##enum_type##_##enum_value()   \
	{                                                                               \
		return bpf_core_enum_value(enum enum_type, enum_value);                     \
	}                                                                               \
	__attribute__((always_inline)) _Bool shim_##enum_type##_##enum_value##_exists() \
	{                                                                               \
		return bpf_core_enum_value_exists(enum enum_type, enum_value);              \
	}

struct kgid_t
{
	gid_t val;
} __attribute__((preserve_access_index));
// SHIM(kgid_t, val);

struct kuid_t
{
	uid_t val;
} __attribute__((preserve_access_index));

// SHIM(kuid_t, val);

// Defining shim for cred struct
// We just need to define the fields we need to access

struct cred
{
	struct kuid_t uid;
	struct kgid_t gid;
} __attribute__((preserve_access_index));

_SHIM_GETTER_BPF_CORE_READ(uid_t, shim_cred_uid(struct cred *pcred), pcred, uid.val);
_SHIM_GETTER_BPF_CORE_READ(gid_t, shim_cred_gid(struct cred *pcred), pcred, gid.val);
// SHIM_WITH_NAME(cred, uid.val, uid);
// SHIM_WITH_NAME(cred, gid.val, gid);
// SHIM_REF(cred, uid);
// SHIM_REF(cred, gid);

struct qstr
{
	__u64 hash_len;
	const unsigned char *name;
}
__attribute__((preserve_access_index));

SHIM(qstr, name);
SHIM(qstr, hash_len);

struct vfsmount
{
	struct dentry *mnt_root;
} __attribute__((preserve_access_index));

SHIM(vfsmount, mnt_root);

struct mountpoint;

struct mount
{
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	struct mountpoint *mnt_mp;
} __attribute__((preserve_access_index));

SHIM(mount, mnt_parent);
SHIM(mount, mnt_mountpoint);
SHIM_REF(mount, mnt)
SHIM(mount, mnt_mp)

__attribute__((always_inline)) struct mount *shim_mount_from_vfsmount(struct vfsmount *vfs)
{
	struct mount *mount = 0;
	struct vfsmount *vfsmount = __builtin_preserve_access_index(&(mount->mnt));
	__u64 offset = (void *)vfsmount - (void *)mount;
	return ((void *)vfs - offset);
}

struct super_block
{
	struct dentry *s_root;
} __attribute__((preserve_access_index));

SHIM(super_block, s_root);

struct dentry
{
	unsigned int d_flags;
	struct dentry *d_parent;
	struct qstr d_name;
	struct super_block *d_sb;
	struct inode *d_inode;
} __attribute__((preserve_access_index));

SHIM(dentry, d_parent);
SHIM(dentry, d_flags);
SHIM_REF(dentry, d_name);
SHIM(dentry, d_sb);
SHIM(dentry, d_inode)

struct mountpoint
{
	struct dentry *m_dentry;
} __attribute__((preserve_access_index));

SHIM(mountpoint, m_dentry);

struct path
{
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

SHIM(path, mnt);
SHIM(path, dentry);

typedef __s64 time64_t;

struct timespec64
{
	time64_t tv_sec;
	long int tv_nsec;
};

typedef short unsigned int umode_t;
typedef long long int __kernel_loff_t;
typedef __kernel_loff_t loff_t;

struct inode
{
	umode_t i_mode;
	unsigned long i_ino;
	struct super_block *i_sb;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	union
	{
		struct timespec64 i_ctime;
		struct timespec64 __i_ctime;
	};
} __attribute__((preserve_access_index));

SHIM(inode, i_ino);
SHIM(inode, i_mode);
SHIM(inode, i_sb);
SHIM(inode, i_size);
SHIM(inode, i_atime);
SHIM(inode, i_mtime);
SHIM(inode, i_ctime);
SHIM(inode, __i_ctime);

struct file
{
	struct inode *f_inode;
	struct path f_path;
	void *private_data;
} __attribute__((preserve_access_index));

SHIM_REF(file, f_path);
SHIM(file, f_inode);
SHIM(file, private_data);

struct fd
{
	struct file *file;
	unsigned int flags;
} __attribute__((preserve_access_index));

SHIM(fd, file);
SHIM(fd, flags);

struct mm_struct
{
	unsigned long arg_start;
	unsigned long arg_end;
	struct file *exe_file;
} __attribute__((preserve_access_index));

SHIM(mm_struct, arg_start);
SHIM(mm_struct, arg_end);
SHIM(mm_struct, exe_file);

// Defining shim for task_struct
// We just need to define the fields we need to access
#define COMM_LEN 16

struct ns_common
{
	unsigned int inum;
} __attribute__((preserve_access_index));

SHIM(ns_common, inum);

struct mnt_namespace
{
	struct ns_common ns;
	struct mount *root;
	unsigned int mounts; /* # of mounts in the namespace */
} __attribute__((preserve_access_index));

SHIM_REF(mnt_namespace, ns);
SHIM(mnt_namespace, root);
SHIM(mnt_namespace, mounts);

#define __NEW_UTS_LEN 64

struct new_utsname
{
	char sysname[__NEW_UTS_LEN + 1];
	char nodename[__NEW_UTS_LEN + 1];
	char release[__NEW_UTS_LEN + 1];
	char version[__NEW_UTS_LEN + 1];
	char machine[__NEW_UTS_LEN + 1];
	char domainname[__NEW_UTS_LEN + 1];
} __attribute__((preserve_access_index));

ARRAY_SHIM(new_utsname, sysname);
ARRAY_SHIM(new_utsname, nodename);
ARRAY_SHIM(new_utsname, release);
ARRAY_SHIM(new_utsname, version);
ARRAY_SHIM(new_utsname, machine);
ARRAY_SHIM(new_utsname, domainname);

struct uts_namespace
{
	struct new_utsname name;
	struct ns_common ns;
} __attribute__((preserve_access_index));

SHIM_REF(uts_namespace, ns);
SHIM_REF(uts_namespace, name);

struct nsproxy
{
	struct mnt_namespace *mnt_ns;
	struct uts_namespace *uts_ns;
} __attribute__((preserve_access_index));

SHIM(nsproxy, mnt_ns);
SHIM(nsproxy, uts_ns);

struct kernfs_node
{
	struct kernfs_node *parent;
	const char *name;
} __attribute__((preserve_access_index));

SHIM(kernfs_node, parent);
SHIM(kernfs_node, name);

struct cgroup
{
	struct kernfs_node *kn; /* cgroup kernfs entry */
} __attribute__((preserve_access_index));

SHIM(cgroup, kn);

struct cgroup_subsys_state
{
	struct cgroup *cgroup;
} __attribute__((preserve_access_index));

SHIM(cgroup_subsys_state, cgroup);

// Task group related information
struct task_group
{
	struct cgroup_subsys_state css;
} __attribute__((preserve_access_index));

SHIM_REF(task_group, css);

struct fdtable
{
	unsigned int max_fds;
	struct file **fd; /* current fd array */
} __attribute__((preserve_access_index));

SHIM(fdtable, max_fds);
SHIM(fdtable, fd);

struct files_struct
{
	struct fdtable *fdt;
	struct file *fd_array[1];
} __attribute__((preserve_access_index));

ARRAY_SHIM(files_struct, fd_array);
SHIM(files_struct, fdt);

struct task_struct
{
	unsigned int flags;
	pid_t pid;
	__u64 start_time;
	// attempt to make compatible with older kernels
	union
	{
		__u64 start_boottime;
		__u64 real_start_time;
	};
	pid_t tgid;
	unsigned char comm[COMM_LEN];
	struct cred *cred; // gives an example of nested access
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct mm_struct *mm;
	struct files_struct *files;
	struct nsproxy *nsproxy;
	struct task_group *sched_task_group;
} __attribute__((preserve_access_index));

SHIM(task_struct, flags);
SHIM(task_struct, start_time);
SHIM(task_struct, start_boottime);
SHIM(task_struct, real_start_time);
ARRAY_SHIM(task_struct, comm);
SHIM(task_struct, pid);
SHIM(task_struct, tgid);
SHIM(task_struct, cred);
SHIM(task_struct, group_leader);
SHIM(task_struct, real_parent);
SHIM(task_struct, mm);
SHIM(task_struct, files);
SHIM(task_struct, nsproxy);
SHIM(task_struct, sched_task_group);

#define KSYM_NAME_LEN 512

struct bpf_ksym
{

	unsigned char name[KSYM_NAME_LEN];
} __attribute__((preserve_access_index));

ARRAY_SHIM(bpf_ksym, name);

#define BPF_OBJ_NAME_LEN 16U

struct bpf_prog_aux
{
	__u32 id;
	unsigned char name[BPF_OBJ_NAME_LEN];
	const unsigned char *attach_func_name;
	__u32 verified_insns;
	struct bpf_ksym ksym;
} __attribute__((preserve_access_index));

SHIM(bpf_prog_aux, id);
ARRAY_SHIM(bpf_prog_aux, name);
SHIM(bpf_prog_aux, attach_func_name);
SHIM(bpf_prog_aux, verified_insns)
SHIM_REF(bpf_prog_aux, ksym);

#define BPF_TAG_SIZE 8
enum bpf_prog_type
{
	PROG_TYPE
};

enum bpf_attach_type
{
	ATTACH_TYPE
};

struct bpf_prog
{
	__u32 len;
	// these are enums it does not work defining them like that
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	unsigned char tag[BPF_TAG_SIZE];
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
} __attribute__((preserve_access_index));

SHIM(bpf_prog, aux);
SHIM(bpf_prog, orig_prog);
ARRAY_SHIM(bpf_prog, tag);
SHIM(bpf_prog, type);
SHIM(bpf_prog, expected_attach_type);
SHIM(bpf_prog, len);

struct sock_filter
{				/* Filter block */
	__u16 code; /* Actual filter code */
	__u8 jt;	/* Jump true */
	__u8 jf;	/* Jump false */
	__u32 k;	/* Generic multiuse field */
} __attribute__((preserve_access_index));

SHIM(sock_filter, code);
SHIM(sock_filter, jt);
SHIM(sock_filter, jf);
SHIM(sock_filter, k);

struct sock_fprog
{
	unsigned short len;
	struct sock_filter *filter;
} __attribute__((preserve_access_index));

SHIM(sock_fprog, len);
SHIM(sock_fprog, filter);

struct sock_fprog_kern
{
	u16 len;
	struct sock_filter *filter;
} __attribute__((preserve_access_index));

SHIM(sock_fprog_kern, len);
SHIM(sock_fprog_kern, filter);

struct linux_binprm
{
	struct mm_struct *mm;
	struct file *file;
	struct cred *cred;
} __attribute__((preserve_access_index));

SHIM(linux_binprm, mm);
SHIM(linux_binprm, file);
SHIM(linux_binprm, cred);

struct load_info
{
	const unsigned char *name;
} __attribute__((preserve_access_index));

SHIM(load_info, name);

typedef __u64 __addrpair;
typedef __u32 __portpair;

struct in6_addr
{
	union
	{
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
} __attribute__((preserve_access_index));

ARRAY_SHIM_WITH_NAME(in6_addr, in6_u.u6_addr8, u6_addr8);

typedef short unsigned int __kernel_sa_family_t;
typedef __kernel_sa_family_t sa_family_t;

struct sockaddr
{
	sa_family_t sa_family;
} __attribute__((preserve_access_index));

SHIM(sockaddr, sa_family);

struct in_addr
{
	__be32 s_addr;
} __attribute((preserve_access_index));

struct sockaddr_in
{
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
} __attribute__((preserve_access_index));

SHIM(sockaddr_in, sin_family);
SHIM(sockaddr_in, sin_port);
SHIM_WITH_NAME(sockaddr_in, sin_addr.s_addr, s_addr);

struct sockaddr_in6
{
	short unsigned int sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
} __attribute__((preserve_access_index));

SHIM(sockaddr_in6, sin6_family);
SHIM(sockaddr_in6, sin6_port);
SHIM_REF(sockaddr_in6, sin6_addr);

struct sock_common
{
	union
	{
		__addrpair skc_addrpair;
	};

	union
	{
		__portpair skc_portpair;
	};

	unsigned short skc_family;

	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;

} __attribute__((preserve_access_index));

SHIM(sock_common, skc_family);
SHIM(sock_common, skc_addrpair);
// SHIM(sock_common, struct_skc_addrpair.skc_daddr);
SHIM(sock_common, skc_portpair);
SHIM_REF(sock_common, skc_v6_daddr);
SHIM_REF(sock_common, skc_v6_rcv_saddr);

struct sk_buff
{
	unsigned int len;
	unsigned char *data;
} __attribute__((preserve_access_index));

SHIM(sk_buff, len);
SHIM(sk_buff, data);

struct sk_buff_list
{
	struct sk_buff *next;
	struct sk_buff *prev;
} __attribute__((preserve_access_index));

SHIM(sk_buff_list, next);
SHIM(sk_buff_list, prev);

struct sk_buff_head
{
	struct sk_buff *next;
	struct sk_buff *prev;
	struct sk_buff_list list;

	__u32 qlen;
	// spinlock_t lock; // unused for the moment
} __attribute__((preserve_access_index));

SHIM(sk_buff_head, next);
SHIM(sk_buff_head, prev);
SHIM_REF(sk_buff_head, list);
SHIM(sk_buff_head, qlen);

struct sock
{
	struct sock_common __sk_common;
	__u8 sk_protocol;
	__u16 sk_type;
	struct sk_buff_head sk_receive_queue;
} __attribute__((preserve_access_index));

SHIM_REF(sock, __sk_common);
SHIM_BITFIELD(sock, sk_protocol);
SHIM_BITFIELD(sock, sk_type);
SHIM_REF(sock, sk_receive_queue)

struct socket
{
	struct sock *sk;
} __attribute__((preserve_access_index));

SHIM(socket, sk);

struct iovec
{
	void *iov_base;
	__kernel_size_t iov_len;
} __attribute__((preserve_access_index));

SHIM(iovec, iov_base);
SHIM(iovec, iov_len);

enum iter_type
{
	/* iter types */
	ITER_IOVEC,
	ITER_KVEC,
	ITER_BVEC,
	ITER_PIPE,
	ITER_XARRAY,
	ITER_DISCARD,
	ITER_UBUF,
};

SHIM_ENUM_VALUE(iter_type, ITER_IOVEC);
SHIM_ENUM_VALUE(iter_type, ITER_KVEC);
SHIM_ENUM_VALUE(iter_type, ITER_BVEC);
SHIM_ENUM_VALUE(iter_type, ITER_PIPE);
SHIM_ENUM_VALUE(iter_type, ITER_XARRAY);
SHIM_ENUM_VALUE(iter_type, ITER_DISCARD);
SHIM_ENUM_VALUE(iter_type, ITER_UBUF);

struct iov_iter
{
	union
	{
		u8 iter_type;
		unsigned int type;
	};
	size_t count;
	union
	{
		struct iovec *iov;
		struct iovec *__iov;
		void *ubuf;
	};

	union
	{
		unsigned long nr_segs;
	};
} __attribute__((preserve_access_index));

SHIM(iov_iter, iter_type);
SHIM(iov_iter, type);
SHIM(iov_iter, count);
SHIM(iov_iter, nr_segs);
SHIM(iov_iter, ubuf);
SHIM(iov_iter, iov);
SHIM(iov_iter, __iov);

struct msghdr
{
	struct iov_iter msg_iter;
} __attribute__((preserve_access_index));

SHIM_REF(msghdr, msg_iter);

struct user_msghdr
{
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
} __attribute__((preserve_access_index));

SHIM(user_msghdr, msg_name);
SHIM(user_msghdr, msg_namelen);
SHIM(user_msghdr, msg_iov);
SHIM(user_msghdr, msg_iovlen);

struct kernel_clone_args
{
	u64 flags;
} __attribute__((preserve_access_index));

SHIM(kernel_clone_args, flags);
