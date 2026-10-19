// © NextFerret,2026,The Arvor License (TAL)
// Maintainer: Hludwig (@hludwig-nf)

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <expected>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <meta>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <spawn.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace arvor {

namespace col {
inline constexpr std::string_view reset  = "\033[0m";
inline constexpr std::string_view bold   = "\033[1m";
inline constexpr std::string_view cyan   = "\033[1;36m";
inline constexpr std::string_view green  = "\033[1;32m";
inline constexpr std::string_view yellow = "\033[1;33m";
inline constexpr std::string_view red    = "\033[1;31m";
inline constexpr std::string_view gray   = "\033[38;2;148;163;184m";
}

inline constexpr std::string_view kNsm         = "/usr/bin/nsm";
inline constexpr std::string_view kLvs         = "/usr/sbin/lvs";
inline constexpr std::string_view kLvchange    = "/usr/sbin/lvchange";
inline constexpr std::string_view kBootSuccess = "/usr/bin/arvor-boot-success";

inline constexpr std::string_view kRunFlag  = "/run/bootisok";
inline constexpr std::string_view kDiskFlag = "/var/lib/arvor/bootisok";

inline constexpr std::array<std::string_view, 3> kSnapshotDirs{
    "/nsm/snapshots/manual",
    "/nsm/snapshots/auto",
    "/nsm/snapshots/auto/daemon",
};

inline constexpr std::array<std::string_view, 4> kDiffDirs{
    "etc", "usr/bin", "usr/lib", "var/lib/dpkg",
};

inline constexpr std::size_t kNewNameMax   = 64;
inline constexpr std::size_t kDiffDepth    = 3;
inline constexpr std::size_t kDiffFileCap  = 200;
inline constexpr std::string_view kNsmRollbackOk = "SUCCESS:";

[[nodiscard]] std::string_view trim(std::string_view s) noexcept
{
    constexpr std::string_view ws = " \t\r\n\v\f";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string_view::npos) return {};
    const auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

void fail(std::string_view msg)
{
    std::println(stderr, "{}Error:{} {}", col::red, col::reset, msg);
}

[[nodiscard]] bool is_root() noexcept { return ::geteuid() == 0; }

[[nodiscard]] bool name_chars_ok(std::string_view s) noexcept
{
    return std::ranges::all_of(s, [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
    });
}

[[nodiscard]] bool valid_new_name(std::string_view s) noexcept
{
    return !s.empty() && s.size() <= kNewNameMax && s.front() != '-' &&
           s.front() != '.' && name_chars_ok(s);
}

struct ExecResult {
    int code = -1;
    std::string output;
};

[[nodiscard]] std::expected<ExecResult, std::string>
exec_abs(std::string_view path, std::span<const std::string_view> args, bool capture)
    pre(!path.empty() && path.front() == '/')
    post(r: r.has_value() || !r.error().empty())
{
    const std::string program{path};
    if (::access(program.c_str(), X_OK) != 0)
        return std::unexpected(std::format("{}: {}", program, std::strerror(errno)));

    std::vector<std::string> store;
    store.reserve(args.size() + 1);
    store.push_back(program);
    for (auto a : args) store.emplace_back(a);

    std::vector<char*> argv;
    argv.reserve(store.size() + 1);
    for (auto& s : store) argv.push_back(s.data());
    argv.push_back(nullptr);

    static char env_path[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    static char env_lang[] = "LC_ALL=C";
    char* envp[] = {env_path, env_lang, nullptr};

    int pfd[2] = {-1, -1};
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);

    if (capture) {
        if (::pipe2(pfd, O_CLOEXEC) != 0) {
            posix_spawn_file_actions_destroy(&fa);
            return std::unexpected(std::format("pipe2: {}", std::strerror(errno)));
        }
        posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&fa, pfd[1], STDERR_FILENO);
    }

    pid_t pid = 0;
    const int rc = ::posix_spawn(&pid, program.c_str(), &fa, nullptr, argv.data(), envp);
    posix_spawn_file_actions_destroy(&fa);

    if (capture) ::close(pfd[1]);
    if (rc != 0) {
        if (capture) ::close(pfd[0]);
        return std::unexpected(std::format("{}: {}", program, std::strerror(rc)));
    }

    ExecResult res;
    if (capture) {
        char buf[4096];
        for (;;) {
            const ssize_t n = ::read(pfd[0], buf, sizeof(buf));
            if (n > 0) { res.output.append(buf, static_cast<std::size_t>(n)); continue; }
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        ::close(pfd[0]);
    }

    int st = 0;
    while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    res.code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return res;
}

[[nodiscard]] std::expected<ExecResult, std::string>
run(std::string_view path, std::initializer_list<std::string_view> args, bool capture)
{
    return exec_abs(path, std::span<const std::string_view>{args.begin(), args.size()}, capture);
}

struct SnapshotMeta {
    std::string kind;
    std::string type;
    std::string name;
    std::string timestamp;
    std::string origin_mount;
    std::string origin_source;
    std::string origin_vg;
    std::string origin_lv;
    std::string origin_lvpath;
    std::string snapshot_lvpath;
};

template <typename T>
[[nodiscard]] bool assign_field(T& obj, std::string_view key, std::string_view val)
{
    bool hit = false;
    template for (constexpr auto m : std::define_static_array(
                      std::meta::nonstatic_data_members_of(
                          ^^T, std::meta::access_context::unchecked()))) {
        if (!hit && key == std::meta::identifier_of(m)) {
            obj.[:m:] = std::string{val};
            hit = true;
        }
    }
    return hit;
}

struct SnapshotEntry {
    SnapshotMeta meta;
    fs::path dir;

    [[nodiscard]] std::string name() const { return dir.filename().string(); }
};

[[nodiscard]] std::optional<SnapshotMeta> read_meta(const fs::path& dir)
{
    std::ifstream in{dir / "meta"};
    if (!in) return std::nullopt;

    SnapshotMeta m;
    std::string line;
    while (std::getline(in, line)) {
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const auto key = trim(std::string_view{line}.substr(0, eq));
        const auto val = trim(std::string_view{line}.substr(eq + 1));
        (void)assign_field(m, key, val);
    }
    if (m.kind.empty() || m.snapshot_lvpath.empty()) return std::nullopt;
    return m;
}

[[nodiscard]] std::vector<SnapshotEntry> list_snapshots()
{
    std::vector<SnapshotEntry> out;
    for (auto base : kSnapshotDirs) {
        std::error_code ec;
        fs::directory_iterator it{fs::path{base}, ec};
        if (ec) continue;
        for (const auto& e : it) {
            std::error_code dec;
            if (!e.is_directory(dec)) continue;
            if (auto m = read_meta(e.path()))
                out.push_back({std::move(*m), e.path()});
        }
    }
    std::ranges::sort(out, {}, [](const SnapshotEntry& s) { return s.name(); });
    return out;
}

[[nodiscard]] std::optional<SnapshotEntry> find_snapshot(std::string_view name)
    pre(!name.empty())
{
    for (auto& s : list_snapshots())
        if (s.name() == name) return std::move(s);
    return std::nullopt;
}

struct RootVolume {
    std::string device;
    std::string vg;
    std::string lv;

    [[nodiscard]] std::string lvpath() const { return std::format("/dev/{}/{}", vg, lv); }
};

[[nodiscard]] std::optional<std::string> root_device()
{
    std::ifstream in{"/proc/self/mountinfo"};
    if (!in) return std::nullopt;

    std::optional<std::string> source;
    std::string line;
    while (std::getline(in, line)) {
        std::vector<std::string_view> f;
        std::string_view sv{line};
        while (!sv.empty()) {
            const auto sp = sv.find(' ');
            f.push_back(sv.substr(0, sp));
            if (sp == std::string_view::npos) break;
            sv.remove_prefix(sp + 1);
        }
        if (f.size() < 10 || f[4] != "/") continue;
        const auto dash = std::ranges::find(f, std::string_view{"-"});
        if (dash == f.end() || std::distance(dash, f.end()) < 3) continue;
        source = std::string{*(dash + 2)};
    }
    return source;
}

[[nodiscard]] std::optional<std::pair<std::string, std::string>>
split_dm_name(std::string_view n)
{
    std::string vg, lv;
    bool in_lv = false;
    for (std::size_t i = 0; i < n.size(); ++i) {
        const char c = n[i];
        std::string& cur = in_lv ? lv : vg;
        if (c != '-') { cur.push_back(c); continue; }
        if (i + 1 < n.size() && n[i + 1] == '-') { cur.push_back('-'); ++i; continue; }
        if (in_lv) return std::nullopt;
        in_lv = true;
    }
    if (!in_lv || vg.empty() || lv.empty()) return std::nullopt;
    return std::pair{std::move(vg), std::move(lv)};
}

[[nodiscard]] std::optional<RootVolume> resolve_root()
{
    auto dev = root_device();
    if (!dev) return std::nullopt;

    constexpr std::string_view mapper = "/dev/mapper/";
    constexpr std::string_view devdir = "/dev/";

    if (dev->starts_with(mapper)) {
        if (auto p = split_dm_name(std::string_view{*dev}.substr(mapper.size())))
            return RootVolume{*dev, std::move(p->first), std::move(p->second)};
        return std::nullopt;
    }
    if (dev->starts_with(devdir)) {
        const auto rest = std::string_view{*dev}.substr(devdir.size());
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos) return std::nullopt;
        const auto lv = rest.substr(slash + 1);
        if (lv.empty() || lv.contains('/')) return std::nullopt;
        return RootVolume{*dev, std::string{rest.substr(0, slash)}, std::string{lv}};
    }
    return std::nullopt;
}

[[nodiscard]] bool lv_has_boot_ok_tag(const RootVolume& root)
{
    const auto path = root.lvpath();
    auto r = run(kLvs, {"--noheadings", "-o", "lv_tags", path}, true);
    return r && r->code == 0 && r->output.contains("boot_ok");
}

[[nodiscard]] std::string lv_delta_percent(const SnapshotMeta& m)
{
    auto r = run(kLvs, {"--noheadings", "-o", "data_percent", m.snapshot_lvpath}, true);
    if (!r || r->code != 0) return "?";
    const auto v = trim(r->output);
    return v.empty() ? "?" : std::string{v};
}

enum class Command { status, snapshot, diff, rollback, mark_ok, help };

struct CommandInfo {
    std::string_view usage;
    std::string_view description;
};

[[nodiscard]] constexpr CommandInfo info(Command c) noexcept
{
    switch (c) {
        case Command::status:   return {"",         "Display boot health, root volume, and snapshots"};
        case Command::snapshot: return {" [name]",  "Create a new snapshot of root through nsm (auto-named if omitted)"};
        case Command::diff:     return {" <name>",  "Inspect file differences between live system and a snapshot"};
        case Command::rollback: return {" <name>",  "Roll back the root volume to the specified snapshot through nsm"};
        case Command::mark_ok:  return {"",         "Manually validate and mark current boot state as healthy"};
        case Command::help:     return {"",         "Show this help message"};
    }
    return {};
}

[[nodiscard]] std::string dashed(std::string_view id)
{
    std::string s{id};
    std::ranges::replace(s, '_', '-');
    return s;
}

[[nodiscard]] std::optional<Command> parse_command(std::string_view arg)
{
    struct Alias { std::string_view text; Command cmd; };
    static constexpr std::array<Alias, 6> aliases{{
        {"snap", Command::snapshot}, {"revert", Command::rollback},
        {"verify", Command::mark_ok}, {"-h", Command::help},
        {"--help", Command::help}, {"", Command::help},
    }};
    for (const auto& a : aliases)
        if (a.text == arg) return a.cmd;

    std::optional<Command> found;
    template for (constexpr auto e : std::define_static_array(
                      std::meta::enumerators_of(^^Command))) {
        if (dashed(std::meta::identifier_of(e)) == arg) found = [:e:];
    }
    return found;
}

int cmd_help()
{
    std::println("{}{}arvorctl - Arvor Linux Atomic Management Tool{}\n", col::cyan, col::bold, col::reset);
    std::println("Usage: arvorctl [command] [options]\n");
    std::println("Commands:");
    template for (constexpr auto e : std::define_static_array(
                      std::meta::enumerators_of(^^Command))) {
        constexpr Command c = [:e:];
        const auto ci = info(c);
        const auto head = std::format("{}{}", dashed(std::meta::identifier_of(e)), ci.usage);
        std::println("  {}{:<22}{} {}", col::bold, head, col::reset, ci.description);
    }
    std::println("");
    return 0;
}

int cmd_status()
{
    std::println("{}{}=== Arvor Linux Atomic System Status ==={}\n", col::cyan, col::bold, col::reset);

    const auto root = resolve_root();
    const std::string device = root ? root->device : "Unknown";
    std::println("{}Root Device:{}       {}", col::bold, col::reset, device);
    std::println("{}Volume Group:{}      {}", col::bold, col::reset, root ? root->vg : "N/A");
    std::println("{}Root Volume:{}       {}", col::bold, col::reset, root ? root->lv : "N/A");

    std::println("\n{}[Boot Health Verification]{}", col::bold, col::reset);
    if (root && lv_has_boot_ok_tag(*root))
        std::println("  LVM Metadata Tag:      {}Active (boot_ok verified){}", col::green, col::reset);
    else
        std::println("  LVM Metadata Tag:      {}Missing (Dirty / Unverified){}", col::red, col::reset);

    const auto flag_line = [](std::string_view label, std::string_view path) {
        if (fs::exists(fs::path{path}))
            std::println("  {}{}Present ({}){}", label, col::green, path, col::reset);
        else
            std::println("  {}{}Missing{}", label, col::red, col::reset);
    };
    flag_line("Runtime Flag:          ", kRunFlag);
    flag_line("Persistent Disk Flag:  ", kDiskFlag);

    std::println("\n{}[Active Root Volume]{}", col::bold, col::reset);
    if (root)
        std::println("  {}● Running Root:{}  {}", col::cyan, col::reset, root->lvpath());
    else
        std::println("  {}Unable to identify running root volume.{}", col::red, col::reset);

    std::println("\n{}[Snapshots of Root]{}", col::bold, col::reset);
    if (!root) {
        std::println("  {}Unable to inspect LVM volume group.{}", col::red, col::reset);
    } else {
        std::size_t shown = 0;
        for (const auto& s : list_snapshots()) {
            if (s.meta.kind != "root" || s.meta.origin_vg != root->vg || s.meta.origin_lv != root->lv)
                continue;
            std::println("  {}●{} {}  {}(Delta: {}%, Created: {}){}", col::green, col::reset, s.name(),
                         col::gray, lv_delta_percent(s.meta),
                         s.meta.timestamp.empty() ? "unknown" : s.meta.timestamp, col::reset);
            ++shown;
        }
        if (shown == 0)
            std::println("  {}No snapshots found for root volume.{}", col::gray, col::reset);
    }
    std::println("");
    return 0;
}

[[nodiscard]] std::string default_snapshot_name()
{
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
    ::localtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "snap_%Y%m%d_%H%M%S", &tm);
    return buf;
}

int cmd_snapshot(std::string_view requested)
{
    const std::string name = requested.empty() ? default_snapshot_name() : std::string{requested};

    if (!is_root()) { fail("Root privileges required to create snapshots."); return 1; }
    if (!valid_new_name(name)) {
        fail(std::format("Invalid snapshot name (use [A-Za-z0-9._-], max {} chars, no leading '-' or '.').",
                         kNewNameMax));
        return 1;
    }
    const auto root = resolve_root();
    if (!root) { fail("Could not identify root LVM volume."); return 1; }

    std::vector<std::string> before;
    for (const auto& s : list_snapshots()) before.push_back(s.name());

    std::println("{}Creating snapshot '{}' of {} through nsm...{}", col::cyan, name, root->lvpath(), col::reset);
    std::fflush(stdout);

    const auto r = run(kNsm, {"create", name}, false);
    if (!r) { fail(r.error()); return 1; }
    if (r->code != 0) {
        std::println("{}Failed to create snapshot (nsm exit code {}).{}", col::red, r->code, col::reset);
        return 1;
    }

    std::vector<std::string> created;
    for (const auto& s : list_snapshots()) {
        if (s.meta.kind != "root") continue;
        if (std::ranges::find(before, s.name()) == before.end()) created.push_back(s.name());
    }
    if (created.empty()) {
        std::println("{}Failed to create snapshot (nsm produced no new snapshot).{}", col::red, col::reset);
        return 1;
    }
    for (const auto& n : created)
        std::println("{}✔ Snapshot '{}' created successfully.{}", col::green, n, col::reset);
    return 0;
}

int cmd_rollback(std::string_view target)
{
    if (target.empty()) {
        fail("No snapshot specified.");
        std::println("Usage: arvorctl rollback <snapshot_name>");
        return 1;
    }
    if (!is_root()) { fail("Root privileges required to perform rollbacks."); return 1; }

    const auto snap = find_snapshot(target);
    if (!snap) { fail(std::format("Snapshot '{}' does not exist.", target)); return 1; }
    const std::string name = snap->name();

    std::println("{}{}WARNING:{} You are about to roll back the {} filesystem to snapshot '{}'.",
                 col::yellow, col::bold, col::reset, snap->meta.kind, name);
    std::println("The merge operation will occur and take effect immediately or upon next boot.\n");
    std::print("Are you sure you want to proceed? [y/N]: ");
    std::fflush(stdout);

    std::string answer;
    std::getline(std::cin, answer);
    if (answer != "y" && answer != "Y") {
        std::println("Aborted.");
        return 0;
    }

    std::println("{}Merging snapshot {} through nsm...{}", col::cyan, snap->meta.snapshot_lvpath, col::reset);
    const auto r = run(kNsm, {"rollback", name}, true);
    if (!r) { fail(r.error()); return 1; }
    std::print("{}", r->output);

    if (r->code != 0 || !r->output.contains(kNsmRollbackOk)) {
        std::println("{}Failed to merge snapshot.{}", col::red, col::reset);
        return 1;
    }
    std::println("{}✔ Rollback scheduled successfully! Please reboot your system to finalize the rollback.{}",
                 col::green, col::reset);
    return 0;
}

class SnapshotMount {
public:
    SnapshotMount() = default;
    SnapshotMount(const SnapshotMount&) = delete;
    SnapshotMount& operator=(const SnapshotMount&) = delete;

    ~SnapshotMount()
    {
        if (mounted_) ::umount2(dir_.c_str(), MNT_DETACH);
        if (!dir_.empty()) { std::error_code ec; fs::remove(dir_, ec); }
        if (activated_) (void)run(kLvchange, {"-an", lvpath_}, true);
    }

    [[nodiscard]] bool open(const std::string& lvpath)
    {
        lvpath_ = lvpath;

        if (!fs::exists(fs::path{lvpath_})) {
            const auto r = run(kLvchange, {"-ay", "-K", lvpath_}, true);
            if (!r || r->code != 0) return false;
            activated_ = true;
        }

        char tmpl[] = "/tmp/.arvor_diff_XXXXXX";
        if (::mkdtemp(tmpl) == nullptr) return false;
        dir_ = tmpl;

        struct Try { const char* fstype; const char* opts; };
        static constexpr std::array<Try, 5> tries{{
            {"xfs", "nouuid"}, {"xfs", "nouuid,norecovery"},
            {"ext4", nullptr}, {"ext3", nullptr}, {"btrfs", nullptr},
        }};
        for (const auto& t : tries) {
            if (::mount(lvpath_.c_str(), dir_.c_str(), t.fstype, MS_RDONLY, t.opts) == 0) {
                mounted_ = true;
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] const fs::path& root() const noexcept { return dir_; }

private:
    fs::path dir_;
    std::string lvpath_;
    bool mounted_ = false;
    bool activated_ = false;
};

[[nodiscard]] std::vector<fs::path> walk_files(const fs::path& base, const fs::path& sub)
{
    std::vector<fs::path> out;
    std::error_code ec;
    fs::recursive_directory_iterator it{base / sub, fs::directory_options::skip_permission_denied, ec};
    const fs::recursive_directory_iterator end;
    while (!ec && it != end && out.size() < kDiffFileCap) {
        std::error_code sec;
        const auto st = it->symlink_status(sec);
        if (!sec) {
            if (fs::is_directory(st)) {
                if (static_cast<std::size_t>(it.depth()) + 1 >= kDiffDepth)
                    it.disable_recursion_pending();
            } else if (fs::is_regular_file(st)) {
                out.push_back(it->path().lexically_relative(base));
            }
        }
        it.increment(ec);
    }
    return out;
}

[[nodiscard]] bool same_content(const fs::path& a, const fs::path& b)
{
    std::error_code ea, eb;
    if (fs::file_size(a, ea) != fs::file_size(b, eb) || ea || eb) return ea || eb;

    std::ifstream fa{a, std::ios::binary}, fb{b, std::ios::binary};
    if (!fa || !fb) return true;

    std::array<char, 65536> ba, bb;
    while (fa && fb) {
        fa.read(ba.data(), ba.size());
        fb.read(bb.data(), bb.size());
        const auto na = fa.gcount();
        if (na != fb.gcount() || !std::equal(ba.begin(), ba.begin() + na, bb.begin())) return false;
    }
    return true;
}

[[nodiscard]] bool path_exists(const fs::path& p)
{
    std::error_code ec;
    return fs::exists(fs::symlink_status(p, ec));
}

int cmd_diff(std::string_view target)
{
    if (target.empty()) {
        fail("No snapshot specified.");
        std::println("Usage: arvorctl diff <snapshot_name>");
        return 1;
    }
    if (!is_root()) { fail("Root privileges required to inspect snapshots."); return 1; }

    const auto snap = find_snapshot(target);
    if (!snap) { fail(std::format("Snapshot '{}' does not exist.", target)); return 1; }

    SnapshotMount mnt;
    std::println("{}Mounting snapshot '{}' (read-only)...{}", col::cyan, snap->meta.snapshot_lvpath, col::reset);
    if (!mnt.open(snap->meta.snapshot_lvpath)) {
        std::println("{}Failed to mount snapshot.{}", col::red, col::reset);
        return 1;
    }

    std::println("{}Comparing live system vs snapshot '{}' (/etc, /usr/bin, /usr/lib, /var/lib)...{}\n",
                 col::bold, snap->name(), col::reset);

    const fs::path live{"/"};
    std::size_t count = 0;

    for (auto d : kDiffDirs) {
        const fs::path sub{d};
        std::error_code e1, e2;
        if (!fs::is_directory(live / sub, e1) || !fs::is_directory(mnt.root() / sub, e2)) continue;

        for (const auto& rel : walk_files(live, sub)) {
            const auto other = mnt.root() / rel;
            if (!path_exists(other)) {
                std::println("  {}+ [ADDED]{}    /{}", col::green, col::reset, rel.string());
                ++count;
            } else if (!same_content(live / rel, other)) {
                std::println("  {}~ [MODIFIED]{} /{}", col::yellow, col::reset, rel.string());
                ++count;
            }
        }
        for (const auto& rel : walk_files(mnt.root(), sub)) {
            if (!path_exists(live / rel)) {
                std::println("  {}- [DELETED]{}  /{}", col::red, col::reset, rel.string());
                ++count;
            }
        }
    }

    std::println("");
    if (count == 0)
        std::println("{}✔ No file differences detected between live system and snapshot '{}'.{}",
                     col::green, snap->name(), col::reset);
    else
        std::println("{}Total differences found:{} {}", col::bold, col::reset, count);
    return 0;
}

int cmd_mark_ok()
{
    const auto r = run(kBootSuccess, {}, false);
    if (!r) { fail(std::format("{} not found or not executable.", kBootSuccess)); return 1; }
    if (r->code != 0) { fail(std::format("{} failed (exit code {}).", kBootSuccess, r->code)); return 1; }
    std::println("{}✔ System marked as healthy.{}", col::green, col::reset);
    return 0;
}

}

int main(int argc, char** argv)
{
    using namespace arvor;

    std::vector<std::string_view> args(argv + 1, argv + argc);
    const std::string_view first = args.empty() ? std::string_view{} : args[0];
    const std::string_view second = args.size() > 1 ? args[1] : std::string_view{};

    const auto cmd = parse_command(first);
    if (!cmd) {
        std::println(stderr, "{}Unknown command: {}{}", col::red, first, col::reset);
        (void)cmd_help();
        return 1;
    }

    switch (*cmd) {
        case Command::status:   return cmd_status();
        case Command::snapshot: return cmd_snapshot(second);
        case Command::diff:     return cmd_diff(second);
        case Command::rollback: return cmd_rollback(second);
        case Command::mark_ok:  return cmd_mark_ok();
        case Command::help:     return cmd_help();
    }
    return 1;
}
