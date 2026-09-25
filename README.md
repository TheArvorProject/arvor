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

**Common Commands:**
```
weld sync            # Refresh repository metadata
weld install <pkg>  # Install packages (chroot-verified before host application)
weld upgrade        # Upgrade installed packages transactionally
weld rollback        # Revert the last package operation using pre-transaction snapshot
weld info <pkg>     # Display repository origin, version, SHA256, and replacement rules
weld why <pkg>      # Explain why a package is installed (reverse dependency tree)
weld depends <pkg>  # List forward dependencies
weld list           # List all installed packages
weld clean          # Clear the entire package cache
weld autoclean      # Remove obsolete cached package files
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
