#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <linux/types.h>
#include <map>
#include <memory>
#include <optional>
#include <print>
#include <regex>
#include <sched.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

extern "C" {

struct lxsm_command {
    const char* name;
    const char* description;
    int (*handler)(int argc, char** argv);
};

const lxsm_command* lxsm_plugin_register(void);
bool lxsm_sandbox_exists(const char* name);
bool lxsm_sandbox_path(const char* name, char* out_buf, unsigned int buf_size);
const char* lxsm_version(void);

}

namespace lxsm {

namespace fs = std::filesystem;

namespace abi {

inline constexpr const char* version_str = "0.1.0";
inline constexpr const char* sandbox_root_str = "/nsm/sandboxes";
inline constexpr const char* plugin_root_str = "/nsm/lxsm/plugins";

[[nodiscard]] inline const char* version() noexcept { return version_str; }
[[nodiscard]] inline const char* sandbox_root() noexcept { return sandbox_root_str; }
[[nodiscard]] inline const char* plugin_root() noexcept { return plugin_root_str; }

[[nodiscard]] inline bool sandbox_exists(std::string_view name) noexcept {
    if (name.empty()) return false;
    if (name.find('/') != std::string_view::npos) return false;
    std::error_code ec;
    return fs::is_directory(fs::path(sandbox_root_str) / std::string(name), ec);
}

[[nodiscard]] inline fs::path sandbox_path(std::string_view name) noexcept {
    return fs::path(sandbox_root_str) / std::string(name);
}

}

namespace detail {

struct argv_holder {
    std::vector<char*> ptrs;
    std::vector<std::string> storage;

    [[nodiscard]] char** data() noexcept { return ptrs.data(); }
};

[[nodiscard]] inline bool is_root() noexcept {
    return ::geteuid() == 0;
}

[[nodiscard]] argv_holder make_argv(std::vector<std::string> args) {
    argv_holder h;
    h.storage = std::move(args);
    h.ptrs.reserve(h.storage.size() + 1);
    for (auto& s : h.storage) h.ptrs.push_back(s.data());
    h.ptrs.push_back(nullptr);
    return h;
}

struct dl_deleter {
    void operator()(void* h) const noexcept {
        if (h) dlclose(h);
    }
};
using dl_handle = std::shared_ptr<void>;

[[nodiscard]] inline dl_handle make_dl_handle(void* raw) noexcept {
    return dl_handle(raw, dl_deleter{});
}

[[nodiscard]] std::vector<unsigned int> blocked_syscalls() {
    return std::vector<unsigned int>{
        static_cast<unsigned int>(__NR_mount),
        static_cast<unsigned int>(__NR_umount2),
        static_cast<unsigned int>(__NR_ptrace),
        static_cast<unsigned int>(__NR_kexec_load),
        static_cast<unsigned int>(__NR_kexec_file_load),
        static_cast<unsigned int>(__NR_open_by_handle_at),
        static_cast<unsigned int>(__NR_init_module),
        static_cast<unsigned int>(__NR_finit_module),
        static_cast<unsigned int>(__NR_delete_module),
        static_cast<unsigned int>(__NR_iopl),
        static_cast<unsigned int>(__NR_ioperm),
        static_cast<unsigned int>(__NR_acct),
        static_cast<unsigned int>(__NR_settimeofday),
        static_cast<unsigned int>(__NR_clock_settime),
        static_cast<unsigned int>(__NR_syslog),
        static_cast<unsigned int>(__NR_reboot),
        static_cast<unsigned int>(__NR_pivot_root),
        static_cast<unsigned int>(__NR_swapon),
        static_cast<unsigned int>(__NR_swapoff),
        static_cast<unsigned int>(__NR_perf_event_open),
        static_cast<unsigned int>(__NR_personality),
        static_cast<unsigned int>(__NR_process_vm_writev),
        static_cast<unsigned int>(__NR_nfsservctl),
        static_cast<unsigned int>(__NR_bpf),
        static_cast<unsigned int>(__NR_unshare),
        static_cast<unsigned int>(__NR_setns),
        static_cast<unsigned int>(__NR_keyctl),
        static_cast<unsigned int>(__NR_request_key),
        static_cast<unsigned int>(__NR_add_key),
        static_cast<unsigned int>(__NR_mknod),
        static_cast<unsigned int>(__NR_mknodat),
        static_cast<unsigned int>(__NR_move_mount),
        static_cast<unsigned int>(__NR_open_tree),
        static_cast<unsigned int>(__NR_fsopen),
        static_cast<unsigned int>(__NR_fsconfig),
        static_cast<unsigned int>(__NR_fsmount),
        static_cast<unsigned int>(__NR_fspick),
        static_cast<unsigned int>(__NR_mount_setattr),
        static_cast<unsigned int>(__NR_pidfd_getfd),
        static_cast<unsigned int>(__NR_chroot),
    };
}

[[nodiscard]] std::vector<sock_filter> build_seccomp_filter() {
    auto blocked = blocked_syscalls();
    std::vector<sock_filter> f;
    f.reserve(blocked.size() * 2 + 4);

    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        static_cast<__u32>(offsetof(struct seccomp_data, arch))));
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64, 1, 0));
    f.push_back(BPF_STMT(BPF_RET | BPF_K,
        SECCOMP_RET_KILL_PROCESS));

    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        static_cast<__u32>(offsetof(struct seccomp_data, nr))));

    for (auto s : blocked) {
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s, 0, 1));
        f.push_back(BPF_STMT(BPF_RET | BPF_K,
            SECCOMP_RET_KILL_PROCESS));
    }

    f.push_back(BPF_STMT(BPF_RET | BPF_K,
        SECCOMP_RET_ALLOW));
    return f;
}

[[nodiscard]] std::expected<void, std::string> install_seccomp_filter() {
    auto filter = build_seccomp_filter();
    sock_fprog prog{};
    prog.len = static_cast<unsigned short>(filter.size());
    prog.filter = filter.data();

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        return std::unexpected(std::string("seccomp: ") + std::strerror(errno));
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> write_file(const std::string& path, std::string_view content) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return std::unexpected(std::string("open ") + path + ": " + std::strerror(errno));
    }
    std::size_t total = 0;
    while (total < content.size()) {
        ssize_t n = ::write(fd, content.data() + total, content.size() - total);
        if (n < 0) {
            ::close(fd);
            return std::unexpected(std::string("write ") + path + ": " + std::strerror(errno));
        }
        total += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return {};
}

[[nodiscard]] std::expected<void, std::string> setup_user_namespace() {
    uid_t uid = ::getuid();
    gid_t gid = ::getgid();

    int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET;
    if (unshare(flags) < 0) {
        return std::unexpected(std::string("unshare: ") + std::strerror(errno));
    }

    if (auto r = write_file("/proc/self/setgroups", "deny\n"); !r) return r;

    {
        std::string s = "0 " + std::to_string(uid) + " 1\n";
        if (auto r = write_file("/proc/self/uid_map", s); !r) return r;
    }
    {
        std::string s = "0 " + std::to_string(gid) + " 1\n";
        if (auto r = write_file("/proc/self/gid_map", s); !r) return r;
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> setup_root_namespaces() {
    int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET;
    if (unshare(flags) < 0) {
        return std::unexpected(std::string("unshare: ") + std::strerror(errno));
    }

    if (mount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr) < 0) {
        return std::unexpected(std::string("make / private: ") + std::strerror(errno));
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> mount_proc() {
    unsigned long flags = MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_REC;
    if (mount("proc", "/proc", "proc", flags, nullptr) < 0) {
        return std::unexpected(std::string("mount proc: ") + std::strerror(errno));
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> mount_devpts() {
    std::error_code ec;
    fs::create_directories("/dev/pts", ec);
    if (ec) {
        return std::unexpected(std::string("mkdir /dev/pts: ") + ec.message());
    }
    unsigned long flags = MS_NOSUID | MS_NOEXEC;
    if (mount("devpts", "/dev/pts", "devpts", flags, "ptmxmode=0666,mode=0620,gid=5") < 0) {
        return std::unexpected(std::string("mount devpts: ") + std::strerror(errno));
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> setup_pivot_root(const fs::path& new_root) {
    std::error_code ec;
    fs::create_directories(new_root, ec);
    if (ec) {
        return std::unexpected(std::string("mkdir new_root: ") + ec.message());
    }

    if (mount(new_root.c_str(), new_root.c_str(), nullptr, MS_BIND | MS_REC, nullptr) < 0) {
        return std::unexpected(std::string("bind new_root: ") + std::strerror(errno));
    }

    if (mount(nullptr, new_root.c_str(), nullptr, MS_PRIVATE | MS_REC, nullptr) < 0) {
        return std::unexpected(std::string("make new_root private: ") + std::strerror(errno));
    }

    fs::path put_old = new_root / ".old_root";
    fs::create_directory(put_old, ec);
    if (ec) {
        return std::unexpected(std::string("mkdir .old_root: ") + ec.message());
    }

    if (chdir(new_root.c_str()) < 0) {
        return std::unexpected(std::string("chdir new_root: ") + std::strerror(errno));
    }

    if (syscall(SYS_pivot_root, ".", ".old_root") < 0) {
        return std::unexpected(std::string("pivot_root: ") + std::strerror(errno));
    }

    if (umount2(".old_root", MNT_DETACH) < 0) {
        return std::unexpected(std::string("umount old_root: ") + std::strerror(errno));
    }

    fs::remove("/.old_root", ec);
    if (chdir("/") < 0) {
        return std::unexpected(std::string("chdir /: ") + std::strerror(errno));
    }
    return {};
}

[[nodiscard]] std::string read_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

[[nodiscard]] std::string spoof_cpuinfo() {
    auto content = read_file("/proc/cpuinfo");
    if (content.empty()) return {};

    const char* model = std::getenv("CPU_SPOOFING_MODEL");
    const char* vendor = std::getenv("CPU_MANUFACTURER_SPOOFING");
    if (!model && !vendor) return content;

    std::istringstream in(content);
    std::ostringstream out;
    std::string line;
    while (std::getline(in, line)) {
        auto try_replace = [&](const char* prefix, const char* value) -> bool {
            std::string_view sv(line);
            if (!sv.starts_with(prefix)) return false;
            auto pos = line.find(':');
            if (pos == std::string::npos) return false;
            out << line.substr(0, pos + 2) << value << '\n';
            return true;
        };
        if (model && try_replace("model name", model)) continue;
        if (vendor && try_replace("vendor_id", vendor)) continue;
        out << line << '\n';
    }
    return out.str();
}

[[nodiscard]] std::expected<void, std::string> apply_cpu_spoofing() {
    const char* env = std::getenv("CPU_SPOOFING");
    if (!env || std::string_view(env) != "1") return {};

    auto content = spoof_cpuinfo();
    if (content.empty()) return {};

    int fd = static_cast<int>(syscall(SYS_memfd_create, "lxsm_cpuinfo", MFD_CLOEXEC));
    if (fd < 0) {
        return std::unexpected(std::string("memfd_create: ") + std::strerror(errno));
    }

    std::size_t total = 0;
    while (total < content.size()) {
        ssize_t n = ::write(fd, content.data() + total, content.size() - total);
        if (n < 0) {
            ::close(fd);
            return std::unexpected(std::string("write fake cpuinfo: ") + std::strerror(errno));
        }
        total += static_cast<std::size_t>(n);
    }

    char fd_path[64];
    std::snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (mount(fd_path, "/proc/cpuinfo", nullptr, MS_BIND, nullptr) < 0) {
        ::close(fd);
        return std::unexpected(std::string("bind cpuinfo: ") + std::strerror(errno));
    }
    ::close(fd);
    return {};
}

[[nodiscard]] std::expected<void, std::string> drop_privileges(uid_t target_uid, gid_t target_gid) {
    if (setgid(target_gid) < 0) return std::unexpected(std::string("setgid: ") + std::strerror(errno));
    if (setuid(target_uid) < 0) return std::unexpected(std::string("setuid: ") + std::strerror(errno));
    return {};
}

struct user_info {
    uid_t uid;
    gid_t gid;
    std::string home;
    std::string shell;
};

[[nodiscard]] std::expected<user_info, std::string> lookup_user(const fs::path& sandbox_path,
                                                                  std::string_view username) {
    fs::path passwd_path = sandbox_path / "etc/passwd";
    if (!fs::exists(passwd_path)) {
        return std::unexpected(std::format(
            "{} does not exist — sandbox looks incomplete or corrupted, recreate it with -c", passwd_path.string()));
    }
    std::ifstream in(passwd_path);
    if (!in) {
        return std::unexpected(std::string("open passwd: ") + std::strerror(errno));
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string name, x, uid_s, gid_s, gecos, home, shell;
        if (std::getline(ss, name, ':') &&
            std::getline(ss, x, ':') &&
            std::getline(ss, uid_s, ':') &&
            std::getline(ss, gid_s, ':') &&
            std::getline(ss, gecos, ':') &&
            std::getline(ss, home, ':') &&
            std::getline(ss, shell)) {
            if (name == username) {
                try {
                    uid_t u = static_cast<uid_t>(std::stoul(uid_s));
                    gid_t g = static_cast<gid_t>(std::stoul(gid_s));
                    return user_info{u, g, home, shell};
                } catch (...) {
                    return std::unexpected(std::string("invalid uid/gid in passwd"));
                }
            }
        }
    }
    return std::unexpected(std::format("user '{}' not found in sandbox", username));
}

[[nodiscard]] std::expected<void, std::string> exec_shell(const std::string& cmd,
                                                          const user_info& info,
                                                          std::string_view username) {
    std::string shell = info.shell.empty() ? "/bin/sh" : info.shell;
    std::string home = info.home.empty() ? "/" : info.home;

    if (chdir(home.c_str()) < 0) {
        chdir("/");
    }

    setenv("HOME", home.c_str(), 1);
    setenv("USER", std::string(username).c_str(), 1);
    setenv("LOGNAME", std::string(username).c_str(), 1);
    setenv("SHELL", shell.c_str(), 1);

    std::vector<std::string> storage;
    if (cmd.empty()) {
        auto slash = shell.find_last_of('/');
        std::string base = slash == std::string::npos ? shell : shell.substr(slash + 1);
        storage.push_back(shell);
        storage.push_back("-" + base);
    } else {
        storage.push_back(shell);
        storage.push_back("-c");
        storage.push_back(cmd);
    }

    auto holder = make_argv(std::move(storage));
    execv(shell.c_str(), holder.data());
    return std::unexpected(std::string("execv: ") + std::strerror(errno));
}

[[nodiscard]] std::expected<void, std::string> force_unmount_all(const fs::path& target) {
    std::ifstream in("/proc/self/mountinfo");
    if (!in) {
        return std::unexpected(std::string("open /proc/self/mountinfo: ") + std::strerror(errno));
    }

    std::string target_str = target.string();
    if (target_str.back() != '/') target_str.push_back('/');

    std::vector<std::string> mounts;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string mount_id, parent_id, dev, root, mount_point;
        if (ss >> mount_id >> parent_id >> dev >> root >> mount_point) {
            std::string mp_norm = mount_point;
            if (mp_norm.back() != '/') mp_norm.push_back('/');
            if (mp_norm == target_str ||
                (mp_norm.size() > target_str.size() &&
                mp_norm.compare(0, target_str.size(), target_str) == 0)) {
                mounts.push_back(mount_point);
            }
        }
    }

    std::sort(mounts.begin(), mounts.end(),
        [](const std::string& a, const std::string& b) {
            return a.size() > b.size();
        });

    for (const auto& m : mounts) {
        umount2(m.c_str(), MNT_DETACH);
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> run_chroot(const fs::path& sandbox_path,
                                                          std::vector<std::string> args) {
    std::vector<std::string> storage;
    storage.push_back("/usr/sbin/chroot");
    storage.push_back(sandbox_path.string());
    for (auto& a : args) storage.push_back(std::move(a));
    auto holder = make_argv(std::move(storage));

    pid_t pid = fork();
    if (pid < 0) {
        return std::unexpected(std::string("fork: ") + std::strerror(errno));
    }
    if (pid == 0) {
        execvp("chroot", holder.data());
        std::perror("execvp chroot");
        std::_Exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return std::unexpected(std::string("waitpid: ") + std::strerror(errno));
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return std::unexpected(std::format("chroot {} failed (status {})",
            args.empty() ? "" : args[0], status));
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> clear_shadow_password(const fs::path& sandbox_path,
                                                                      std::string_view username) {
    fs::path shadow_path = sandbox_path / "etc/shadow";
    std::ifstream in(shadow_path);
    if (!in) {
        return std::unexpected(std::string("open shadow: ") + std::strerror(errno));
    }

    std::ostringstream out;
    std::string line;
    bool found = false;
    while (std::getline(in, line)) {
        auto colon = line.find(':');
        if (colon != std::string::npos && colon == username.size() &&
            line.compare(0, colon, username) == 0) {
            auto second_colon = line.find(':', colon + 1);
            if (second_colon != std::string::npos) {
                line = line.substr(0, colon + 1) + line.substr(second_colon);
                found = true;
            }
        }
        out << line << '\n';
    }
    in.close();

    if (!found) {
        return std::unexpected(std::format("user '{}' not found in shadow", username));
    }

    std::ofstream ofs(shadow_path, std::ios::trunc);
    if (!ofs) {
        return std::unexpected(std::string("open shadow for write: ") + std::strerror(errno));
    }
    ofs << out.str();
    if (!ofs) {
        return std::unexpected(std::string("write shadow: ") + std::strerror(errno));
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> write_hosts_entry(const fs::path& sandbox_path,
                                                                  std::string_view name) {
    fs::path hosts_path = sandbox_path / "etc/hosts";
    std::ofstream out(hosts_path, std::ios::app);
    if (!out) {
        return std::unexpected(std::string("open hosts: ") + std::strerror(errno));
    }
    out << "127.0.1.1\t" << name << '\n';
    if (!out) {
        return std::unexpected(std::string("write hosts: ") + std::strerror(errno));
    }
    return {};
}

[[nodiscard]] std::expected<void, std::string> lock_root_password(const fs::path& sandbox_path) {
    if (auto r = clear_shadow_password(sandbox_path, "root"); !r) {
        return std::unexpected(std::format("clear root password: {}", r.error()));
    }

    fs::path pam_su = sandbox_path / "etc/pam.d/su";
    std::ifstream in(pam_su);
    if (in) {
        std::ostringstream content;
        content << in.rdbuf();
        in.close();
        std::string s = content.str();
        if (s.find("nullok") == std::string::npos) {
            std::string fixed = std::regex_replace(s,
                std::regex("pam_unix\\.so"), "pam_unix.so nullok");
            std::ofstream out(pam_su);
            if (out) out << fixed;
        }
    }

    return {};
}

[[nodiscard]] std::expected<void, std::string> setup_lxsm_user(const fs::path& sandbox_path) {
    if (auto r = run_chroot(sandbox_path, {
        "/usr/sbin/useradd", "-m", "-G", "sudo", "-s", "/bin/bash", "lxsm"
    }); !r) {
        return std::unexpected(std::format("useradd lxsm: {}", r.error()));
    }

    if (auto r = clear_shadow_password(sandbox_path, "lxsm"); !r) {
        return std::unexpected(std::format("clear lxsm password: {}", r.error()));
    }

    fs::path sudoers = sandbox_path / "etc/sudoers.d/lxsm";
    std::ofstream out(sudoers);
    if (out) {
        out << "lxsm ALL=(ALL) NOPASSWD: ALL\n";
        out.close();
        fs::permissions(sudoers, fs::perms::owner_read | fs::perms::group_read,
                        fs::perm_options::replace);
    }

    fs::path pam_su = sandbox_path / "etc/pam.d/su";
    std::ifstream in(pam_su);
    if (in) {
        std::ostringstream content;
        content << in.rdbuf();
        in.close();
        std::string s = content.str();
        if (s.find("nullok") == std::string::npos) {
            std::string fixed = std::regex_replace(s,
                std::regex("pam_unix\\.so"), "pam_unix.so nullok");
            std::ofstream out2(pam_su);
            if (out2) out2 << fixed;
        }
    }

    return {};
}

[[nodiscard]] std::uintmax_t compute_size(const fs::path& p) {
    std::uintmax_t total = 0;
    std::error_code ec;
    auto opts = fs::directory_options::skip_permission_denied;
    for (auto it = fs::recursive_directory_iterator(p, opts, ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        std::error_code fec;
        if (it->is_regular_file(fec)) {
            total += it->file_size(fec);
        }
    }
    return total;
}

[[nodiscard]] std::string format_size(std::uintmax_t bytes) {
    constexpr std::array<const char*, 5> units = {"B", "KiB", "MiB", "GiB", "TiB"};
    size_t idx = 0;
    double val = static_cast<double>(bytes);
    while (val >= 1024.0 && idx < units.size() - 1) {
        val /= 1024.0;
        ++idx;
    }
    return std::format("{:.2f} {}", val, units[idx]);
}

struct plugin_entry {
    const lxsm_command* command;
    dl_handle handle;
};

[[nodiscard]] std::map<std::string, plugin_entry> load_plugins() {
    std::map<std::string, plugin_entry> result;
    fs::path plugin_dir = abi::plugin_root();
    std::error_code ec;
    if (!fs::exists(plugin_dir, ec)) return result;

    for (const auto& entry : fs::directory_iterator(plugin_dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".so") continue;

        dl_handle handle = make_dl_handle(dlopen(entry.path().c_str(), RTLD_NOW | RTLD_LOCAL));
        if (!handle) continue;

        auto reg = reinterpret_cast<const lxsm_command* (*)()>(
            dlsym(handle.get(), "lxsm_plugin_register"));
        if (!reg) continue;

        const lxsm_command* cmd = reg();
        if (!cmd) continue;

        for (const lxsm_command* c = cmd; c && c->name; ++c) {
            if (!result.contains(c->name)) {
                result.emplace(c->name, plugin_entry{c, handle});
            }
        }
    }
    return result;
}

}

namespace commands {

namespace cli {

struct option_spec {
    std::string_view flag;
    bool takes_value;
};

class parser {
public:
    parser(int argc, char** argv, std::initializer_list<option_spec> specs)
        : argc_(argc), argv_(argv) {
        for (auto& s : specs) specs_.emplace(s.flag, s.takes_value);
    }

    [[nodiscard]] std::optional<std::string> get(std::string_view flag) const {
        for (int i = 0; i < argc_; ++i) {
            std::string_view a(argv_[i]);
            if (a != flag) continue;
            auto it = specs_.find(flag);
            if (it == specs_.end() || !it->second) return std::string{};
            if (i + 1 >= argc_) {
                std::println(stderr, "E: flag '{}' requires a value", flag);
                return std::nullopt;
            }
            std::string_view next(argv_[i + 1]);
            if (!next.empty() && next[0] == '-' && next.size() > 1) {
                std::println(stderr, "E: flag '{}' missing value (got '{}')", flag, next);
                return std::nullopt;
            }
            return std::string(argv_[i + 1]);
        }
        return std::nullopt;
    }

    [[nodiscard]] bool has(std::string_view flag) const {
        for (int i = 0; i < argc_; ++i) {
            if (std::string_view(argv_[i]) == flag) return true;
        }
        return false;
    }

    [[nodiscard]] bool validate() const {
        for (int i = 0; i < argc_; ++i) {
            std::string_view a(argv_[i]);
            if (a.empty() || a[0] != '-') continue;
            if (!specs_.contains(a)) {
                std::println(stderr, "E: unknown flag '{}'", a);
                return false;
            }
        }
        return true;
    }

private:
    int argc_;
    char** argv_;
    std::map<std::string_view, bool> specs_;
};

}

[[nodiscard]] int create(int argc, char** argv) {
    if (!detail::is_root()) {
        std::println(stderr, "E: This Script Needs Root Privileges");
        return 1;
    }

    cli::parser p(argc, argv, {
        {"-n", true}, {"-d", true}, {"-r", true}, {"-url", true}, {"--no-mesa", false}
    });
    if (!p.validate()) return 1;

    auto name = p.get("-n");
    auto distro = p.get("-d");
    auto release = p.get("-r");
    auto url = p.get("-url");
    bool skip_mesa = p.has("--no-mesa");

    if (!name || name->empty() || !distro || distro->empty() || !release || release->empty()) {
        std::println(stderr, "Usage: lxsm -c -n <name> -d <distro> -r <release> -url <url> [--no-mesa]");
        return 1;
    }

    if (abi::sandbox_exists(*name)) {
        std::println(stderr, "Sandbox already exists: {}", *name);
        return 1;
    }

    fs::path path = abi::sandbox_path(*name);
    std::error_code ec;
    fs::create_directories(path, ec);
    if (ec) {
        std::println(stderr, "mkdir: {}", ec.message());
        return 1;
    }

    std::vector<std::string> storage = {
        "debootstrap",
        "--arch=amd64",
    };
    if (!skip_mesa) {
        storage.push_back("--include=mesa-utils,libgl1-mesa-dri,mesa-va-drivers,mesa-vulkan-drivers,sudo");
    }
    storage.push_back(*release);
    storage.push_back(path.string());
    if (url && !url->empty()) storage.push_back(*url);

    auto holder = detail::make_argv(std::move(storage));

    pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        return 1;
    }
    if (pid == 0) {
        execvp("debootstrap", holder.data());
        std::perror("execvp debootstrap");
        std::_Exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        std::perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::println(stderr, "debootstrap failed (status {})", status);
        std::error_code cleanup_ec;
        fs::remove_all(path, cleanup_ec);
        if (cleanup_ec) {
            std::println(stderr, "warning: cleanup of {} failed: {}",
                path.string(), cleanup_ec.message());
        } else {
            std::println(stderr, "cleaned up partial sandbox: {}", path.string());
        }
        return 1;
    }

    if (auto r = detail::write_hosts_entry(path, *name); !r) {
        std::println(stderr, "warning: {}", r.error());
    }

    if (auto r = detail::lock_root_password(path); !r) {
        std::println(stderr, "warning: {}", r.error());
    }

    if (auto r = detail::setup_lxsm_user(path); !r) {
        std::println(stderr, "warning: {}", r.error());
    }

    std::println("Sandbox created: {} at {}", *name, path.string());
    return 0;
}

[[nodiscard]] int remove(int argc, char** argv) {
    if (!detail::is_root()) {
        std::println(stderr, "E: This Script Needs Root Privileges");
        return 1;
    }

    cli::parser p(argc, argv, {{"-n", true}});
    if (!p.validate()) return 1;
    auto name = p.get("-n");

    if (!name || name->empty()) {
        std::println(stderr, "Usage: lxsm -d -n <name>");
        return 1;
    }

    if (!abi::sandbox_exists(*name)) {
        std::println(stderr, "Sandbox not found: {}", *name);
        return 1;
    }

    fs::path path = abi::sandbox_path(*name);
    if (auto r = detail::force_unmount_all(path); !r) {
        std::println(stderr, "warning: {}", r.error());
    }

    std::error_code ec;
    fs::remove_all(path, ec);
    if (ec) {
        std::println(stderr, "remove: {}", ec.message());
        return 1;
    }

    std::println("Sandbox removed: {}", *name);
    return 0;
}

[[nodiscard]] int enter(int argc, char** argv) {
    cli::parser p(argc, argv, {{"-n", true}, {"--root", false}, {"--nobody", false}, {"-s", true}});
    if (!p.validate()) return 1;
    auto name = p.get("-n");
    auto cmd = p.get("-s");

    std::string target_user = "lxsm";
    if (p.has("--root")) target_user = "root";
    else if (p.has("--nobody")) target_user = "nobody";

    if (!name || name->empty()) {
        std::println(stderr, "Usage: lxsm -e -n <name> [--root|--nobody] [-s <cmd>]");
        return 1;
    }

    if (!abi::sandbox_exists(*name)) {
        std::println(stderr, "Sandbox not found: {}", *name);
        return 1;
    }

    if (detail::is_root()) {
        if (auto r = detail::setup_root_namespaces(); !r) {
            std::println(stderr, "{}", r.error());
            return 1;
        }
    } else {
        if (auto r = detail::setup_user_namespace(); !r) {
            std::println(stderr, "{}", r.error());
            return 1;
        }
    }

    fs::path path = abi::sandbox_path(*name);

    auto info = detail::lookup_user(path, target_user);
    if (!info) {
        std::println(stderr, "lookup_user: {}", info.error());
        return 1;
    }
    uid_t target_uid = info->uid;
    gid_t target_gid = info->gid;

    pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        return 1;
    }

    if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            std::perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        if (WIFSIGNALED(status)) {
            std::println(stderr, "sandbox terminated by signal {}", WTERMSIG(status));
        }
        return 1;
    }

    if (auto r = detail::setup_pivot_root(path); !r) {
        std::println(stderr, "{}", r.error());
        std::_Exit(1);
    }

    if (auto r = detail::mount_proc(); !r) {
        std::println(stderr, "{}", r.error());
        std::_Exit(1);
    }

    if (auto r = detail::mount_devpts(); !r) {
        std::println(stderr, "{}", r.error());
        std::_Exit(1);
    }

    if (auto r = detail::apply_cpu_spoofing(); !r) {
        std::println(stderr, "{}", r.error());
        std::_Exit(1);
    }

    if (auto r = detail::install_seccomp_filter(); !r) {
        std::println(stderr, "{}", r.error());
        std::_Exit(1);
    }

    if (auto r = detail::drop_privileges(target_uid, target_gid); !r) {
        std::println(stderr, "{}", r.error());
        std::_Exit(1);
    }

    if (auto r = detail::exec_shell(cmd.value_or(""), *info, target_user); !r) {
        std::println(stderr, "{}", r.error());
        std::_Exit(1);
    }
    std::unreachable();
}

[[nodiscard]] int list(int argc, char** argv) {
    (void)argc;
    (void)argv;

    fs::path root = abi::sandbox_root();
    std::error_code ec;
    if (!fs::exists(root, ec)) {
        std::println("No sandboxes.");
        return 0;
    }

    std::println("{:<20} {:>15}", "NAME", "SIZE");

    for (const auto& entry : fs::directory_iterator(root, ec)) {
        if (ec) break;
        if (!entry.is_directory()) continue;
        auto name = entry.path().filename().string();
        auto size = detail::compute_size(entry.path());
        std::println("{:<20} {:>15}", name, detail::format_size(size));
    }
    return 0;
}

}

}

extern "C" bool lxsm_sandbox_exists(const char* name) {
    return lxsm::abi::sandbox_exists(name ? name : "");
}

extern "C" bool lxsm_sandbox_path(const char* name, char* out_buf, unsigned int buf_size) {
    if (!name || !out_buf || buf_size == 0) return false;
    auto p = lxsm::abi::sandbox_path(name);
    auto s = p.string();
    if (s.size() + 1 > buf_size) return false;
    std::memcpy(out_buf, s.c_str(), s.size() + 1);
    return true;
}

extern "C" const char* lxsm_version(void) {
    return lxsm::abi::version();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::println(stderr, "Usage: lxsm <command> [options]");
        std::println(stderr, "  -c  create   -n <name> -d <distro> -r <release> -url <url>");
        std::println(stderr, "  -d  delete   -n <name>");
        std::println(stderr, "  -e  enter    -n <name> [--root|--nobody] [-s <cmd>]");
        std::println(stderr, "  -l  list");
        return 1;
    }

    std::string_view cmd = argv[1];
    int sub_argc = argc - 2;
    char** sub_argv = argv + 2;

    if (cmd == "-c") return lxsm::commands::create(sub_argc, sub_argv);
    if (cmd == "-d") return lxsm::commands::remove(sub_argc, sub_argv);
    if (cmd == "-e") return lxsm::commands::enter(sub_argc, sub_argv);
    if (cmd == "-l") return lxsm::commands::list(sub_argc, sub_argv);

    auto plugins = lxsm::detail::load_plugins();
    auto it = plugins.find(std::string(cmd));
    if (it != plugins.end()) {
        return it->second.command->handler(argc - 1, argv + 1);
    }

    std::println(stderr, "Unknown command: {}", cmd);
    return 1;
}
