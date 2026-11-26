# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking changes

- `ancestors` is emitted as a list instead of a `|`-joined string.
- DNS names in `dns_query` events are lowercased (ASCII letters only), in
  the query, in answer records and in the `hostname` of later network
  events. Domain IoCs and rules must use lowercase.
- The `hostname` of `connect` and `send_data` events comes only from DNS
  answers received by the same process since its last `execve`, so a
  process can no longer label another one's connections with names it
  forged. Applications resolving through a local service instead of port
  53 (glibc `nss-resolve` with systemd-resolved, nscd) now get `?`.
- DNS names are escaped label by label: invalid UTF-8 bytes are written as
  `\xNN` and a `.` inside a label as `\x2e`, so a label holding a dot cannot
  pass for several labels.
- DNS TXT records keep every string in packet order, joined with `;`.
  Invalid UTF-8 bytes are written as `\xNN` and a `;` inside a string as
  `\x3b`. Keys, values and duplicates are no longer dropped.
- Invalid UTF-8 in event text is written as `\xNN` instead of U+FFFD, a
  dropped argument or a dropped event. A `\` right before `xNN` is doubled
  so the text decodes back to the exact bytes. Rules matching such paths
  must use the escaped form. Requires gene 0.9.
- `kunai replay` no longer runs rule actions (`kill`, `scan-files`).
  Detections are still printed.
- User and group names of container tasks come from the host's tables.
  In-container names moved to the `namespace` field of each identity (e.g.
  `creds.effective.namespace.user`). `task.namespaces` is always present,
  with `mnt` and `user` set to `null` when unknown.
- `kunai-common` API: `String::as_str` and `comm_str` are removed,
  `to_string_lossy` is renamed `escaped` and `to_argv` returns
  `Vec<String>`. `get_clk_tck` returns `u64` and fails on a `CLK_TCK`
  outside `1..=NS_PER_SEC`; `KeyError::InvalidClkTck` is removed, such a
  value is reported as `KeyError::Io`.
- Building from source: `xtask` and its aliases (`xrun`, `xbuild`,
  `xrelease`) are removed in favour of standard `cargo` commands.

### Added

- `creds_tampered` event: reports a task whose credentials (user and group
  ids, capabilities) differ from the ones Kunai tracked since its creation
  or its last `commit_creds`.
- Rules can include or exclude events, for finer control over event
  selection (gene 0.7).
- Rule operators from gene 0.9: `matches` (alias of `~=`), `contains`,
  `startswith`, `endswith`, and their case-insensitive forms `imatches`,
  `iequals`, `icontains`, `istartswith`, `iendswith` (ASCII letters only).
- `query_type` field in `dns_query` events, and support for many more DNS
  record types.
- `magic` field describing the file type in file hashes.
- `rotate_interval` output option to rotate logs by time.
- `kunai uninstall` command. `--all` also removes configuration and logs,
  `--force` skips confirmation prompts.
- `KUNAI_HOST_UUID_SEED` environment variable to derive a stable host UUID,
  e.g. in containers. Without it the machine id is used, then
  `/proc/sys/kernel/random/boot_id`, then a random UUID.
- The `mmap`, `mprotect`, `exit`, `prctl` and `init_module` probes use raw
  tracepoints, so they load on Android kernels.
- Kunai starts on kernels without `CONFIG_USER_NS`.

### Changed

- The container name comes from the `nodename` of the thread that emitted
  the event.
- A process stays alive as long as one of its threads runs: a thread group
  leader calling `pthread_exit` no longer marks the process as exited.
  Re-parenting uses the last parent the child saw.
- File tampering errors report both the kernel and the userland values.

### Security

- The `kill` action signals the thread group through a pidfd, and only if
  the start time of its leader still matches the event, so a reused PID is
  never killed. A mismatch is logged and failed attempts are not retried.
  Where seccomp blocks `pidfd_open` (Docker < 20.10), kills fail with a
  logged error.
- `kill` refuses PID 0 and -1.
- A mount namespace opened for enrichment is checked against the one in
  the event; on mismatch the event is not enriched.
- `/etc/passwd` and `/etc/group` read from a container must be regular
  files of at most 1 MiB and 16384 entries. Rejected files are remembered
  per file identity instead of being parsed again on every event.
- Cached file hashes and signatures are keyed by device, inode and ctime,
  so a same-size file with copied times no longer inherits previous
  results.
- Files larger than 100 MB are not hashed or scanned with YARA.
- File scans never open special files for reading, cap reads at the
  opened length and publish no digest when a read fails.

### Fixed

- `SIGTERM` (e.g. `systemctl stop`) shuts Kunai down cleanly, so buffered
  events are no longer lost.
- Events from Kunai's own worker threads are no longer reported.
- Events read on different CPUs are no longer delivered out of order.
- Hibernation and resume problems caused by the `syscore_resume` probe.
- Corrupted data read from `bio_vec`-backed I/O.
- Mount namespaces are released when their last process exits. They were
  kept alive with their tmpfs mounts, which could lead to OOM kills on
  hosts running many short-lived jailed jobs.
- Process tracking memory shrinks back after a fork storm.
- Probes follow recent kernel changes (`io_uring` checked up to Linux 7.3,
  `security_task_alloc`, `vfs_unlink`).
- On kernels 6.13 and later, the inode ctime reported by eBPF no longer
  differs from `stat()` (multigrain flag in `i_ctime_nsec`).
- `/etc/passwd` and `/etc/group` load independently: a missing `passwd` no
  longer hides group names, and a missing file in a container no longer
  falls back to the host's tables.

[Unreleased]: https://github.com/kunai-project/kunai/compare/v0.6.2...HEAD
