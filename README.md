<img width="500" height="500" alt="emblem-debian-white" src="https://github.com/user-attachments/assets/6ef8eb64-5ca4-4f19-908e-b746acc7dec1" />

# Arvor Linux

ARM Readme: https://github.com/NextFerret/arvor/blob/main/README-ARM.md

**Arvor Linux** is a Debian-based distribution built around transactional system updates on a fully mutable root filesystem. The system applies upgrades atomically using LVM snapshots, ensuring that the environment either completes an operation successfully or reverts to its previous state without breaking the OS.

---

## Architecture

The system relies on a custom infrastructure to handle updates, snapshots, and system health:

- **arvorctl**: CLI tool to inspect boot health, check file diffs, and trigger instant rollbacks.
- **arvor-guard**: Background service monitoring Thin Pool storage, preventing out-of-space lockups by auto-cleaning stale snapshots.
- **Weld**: C++ transactional package manager featuring multithreading, package redirection, and pre-transaction snapshots.
- **nsm**: Snapshot Manager responsible for creating, managing, and restoring system states.
- **lxsm**: Lightweight sandbox environment manager for testing.

---

## Managing Snapshots

System health and snapshot states are managed via `arvorctl`. You can check the current status, create instantaneous manual snapshots, and validate the current boot:

```bash
arvorctl status
arvorctl snapshot [name]
arvorctl mark-ok
```

---

## Package Manager (`weld`)

`weld` is the native package manager written in C++. It handles metadata synchronization, parallel downloads, and repository rules with built-in security hardening.

**Features:**
- Multi-threaded metadata sync and `.deb` batch downloading.
- Pre-transaction snapshot protection to secure the host state before applying packages.
- Running kernel modules preservation (caches `/lib/modules/$(uname -r)` during kernel updates to prevent running driver failures before reboot).
- Strict SHA256 checksum enforcement and path traversal protection.
- Strict Minisign Obligation for Repositories Based on Weld.
- Verify Transactions Using a pivot_root before the host 

**Common Commands:**
```
  install       <pkgs...>   Install packages or local .deb archives 
  remove        <pkgs...>   Remove packages from the system
  purge         <pkgs...>   Remove packages along with their configuration files
  upgrade       [pkgs...]   Upgrade all packages, or only those specified
  dist-upgrade               Perform a full system release upgrade
  rollback                   Revert the last transaction using its pre-transaction snapshot
  search        <term>      Search the package index (supports -p <page>)
  info          <pkg>       Show package origin, version and SHA256
  why           <pkg>       Show why a package is installed (reverse dependencies)
  depends       <pkg>       List a package's direct dependencies
  list                      List all installed packages
  sync                      Refresh repository metadata (APT + Weld)
  clean                     Clear the APT and Weld package caches
  autoclean                 Remove obsolete packages from the APT and Weld caches
  --apply-host              Skip sandbox verification and apply directly to the host
  -y, --yes                 Assume yes to all confirmation prompts
  --vb                      Enable verbose transaction logging
  -h, --help                Show this help message
  -v, --version             Show the Weld version
```

---

## System Requirements

**Minimum:**
- **CPU:** x86_64 processor
- **Memory:** 4 GB RAM
- **Storage:** 36 GB available disk space

**Recommended:**
- SSD
- 8 GB RAM or more

---

## Technical Notes

- **Filesystem Layout**: The system is fully mutable. We do not use OverlayFS due to its history of privilege escalation vulnerabilities, nor do we use read-only root filesystems.
- **Update Model**: Arvor implements its own transactional update model based on LVM snapshots and `weld` pre-transaction states.
- **Underlying Language**: Starting with **Arvor 2.1** (Project Xesta), most core utilities were migrated from Python to C and C++ to improve performance and reduce runtime dependencies.
- **Snapshot Backend**: The original Btrfs-based snapshot manager (NF-Tree) was deprecated in favor of **NSM (NextFerret Snapshot Manager)**, providing a cleaner architecture and serving as the foundation for future releases.

---

# License
The Arvor License V1 (TALV1)
