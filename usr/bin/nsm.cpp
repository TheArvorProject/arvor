#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>
#include <meta>

namespace nsm {

namespace fs = std::filesystem;

inline constexpr std::string_view nsm_base = "/nsm";
inline constexpr std::string_view snapshot_base = "/nsm/snapshots";
inline constexpr std::string_view auto_dir = "/nsm/snapshots/auto";
inline constexpr std::string_view daemon_auto_dir = "/nsm/snapshots/auto/daemon";
inline constexpr std::string_view manual_dir = "/nsm/snapshots/manual";
inline constexpr std::string_view root_source = "/";
inline constexpr std::string_view home_source = "/home";
inline constexpr std::string_view meta_file = "meta";
inline constexpr std::string_view nsm_version = "11.1";
inline constexpr std::size_t keep_latest = 6;
inline constexpr double thinpool_limit = 93.0;
inline constexpr std::size_t lv_name_max = 127;
inline constexpr std::size_t user_name_max = 64;
inline constexpr std::size_t ts_len = 19;
inline constexpr std::size_t max_holders = 4096;
inline constexpr int evict_attempts = 5;
inline constexpr double gib = 1073741824.0;
inline constexpr std::size_t str_buf = 512;
inline constexpr std::size_t output_cap = 8 * 1024 * 1024;

inline constexpr std::array<std::string_view, 3> snapshot_dirs = {manual_dir, auto_dir, daemon_auto_dir};
inline constexpr std::array<std::string_view, 2> auto_dirs = {auto_dir, daemon_auto_dir};

enum class OutputFormat { text, json, ztslo };

inline void write_line(std::FILE* f, std::string_view s) {
    std::fwrite(s.data(), 1, s.size(), f);
    std::fputc('\n', f);
}

inline void say(std::string_view s) { write_line(stdout, s); }
inline void say_err(std::string_view s) { write_line(stderr, s); }

struct Ctx {
    OutputFormat fmt = OutputFormat::text;
    bool structured() const { return fmt != OutputFormat::text; }
    void line(std::string_view s) const { fmt == OutputFormat::text ? say(s) : say_err(s); }
    void warn(std::string_view s) const { say_err(s); }
};

inline std::string trim(std::string s) {
    const char* ws = " \t\n\v\f\r";
    std::size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return {};
    std::size_t e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

inline bool valid_name(std::string_view s, std::size_t max) {
    if (s.empty() || s.size() > max || s.front() == '.') return false;
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!std::isalnum(u) && c != '_' && c != '.' && c != '+' && c != '-') return false;
    }
    return true;
}

inline std::string_view ts_part(std::string_view s) {
    return s.size() > ts_len ? s.substr(s.size() - ts_len) : s;
}

inline std::string timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[64];
    std::strftime(buf, sizeof buf, "%Y-%m-%d_%H-%M-%S", &tm);
    return buf;
}

[[noreturn]] inline void exec_argv(const std::vector<std::string>& argv) {
    std::vector<char*> av;
    av.reserve(argv.size() + 1);
    for (const auto& a : argv) av.push_back(const_cast<char*>(a.c_str()));
    av.push_back(nullptr);
    if (!argv.empty() && argv.front().starts_with('/')) {
        execv(av[0], av.data());
    } else {
        std::vector<std::string> dirs;
        if (const char* path = std::getenv("PATH")) {
            std::string_view pv = path;
            std::size_t start = 0;
            while (start <= pv.size()) {
                std::size_t end = pv.find(':', start);
                std::string_view dir = pv.substr(
                    start, end == std::string_view::npos ? std::string_view::npos : end - start);
                if (!dir.empty()) dirs.emplace_back(dir);
                if (end == std::string_view::npos) break;
                start = end + 1;
            }
        }
        if (dirs.empty())
            dirs.insert(dirs.end(), {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
                                     "/sbin", "/bin"});
        for (const auto& d : dirs) {
            std::string full = std::format("{}/{}", d, argv.empty() ? "" : argv.front());
            execv(full.c_str(), av.data());
            if (errno != ENOENT && errno != ENOTDIR && errno != EACCES) break;
        }
    }
    _exit(127);
}

inline int spawn(const std::vector<std::string>& argv, std::string* out, bool merge_err, bool* truncated) {
    if (truncated) *truncated = false;
    if (out) out->clear();
    int pfd[2] = {-1, -1};
    if (out && pipe2(pfd, O_CLOEXEC) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        if (out) {
            close(pfd[0]);
            close(pfd[1]);
        }
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        int so = out ? pfd[1] : devnull;
        int se = (out && merge_err) ? pfd[1] : devnull;
        if (so >= 0) dup2(so, STDOUT_FILENO);
        if (se >= 0) dup2(se, STDERR_FILENO);
        exec_argv(argv);
    }
    if (out) {
        close(pfd[1]);
        char buf[4096];
        for (;;) {
            bool full = out->size() >= output_cap;
            std::size_t want = full ? sizeof buf : std::min(sizeof buf, output_cap - out->size());
            ssize_t n = read(pfd[0], buf, want);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            if (full) {
                if (truncated) *truncated = true;
            } else {
                out->append(buf, static_cast<std::size_t>(n));
            }
        }
        close(pfd[0]);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

struct CmdResult {
    int rc = -1;
    bool truncated = false;
    std::string out;
};

inline CmdResult run(std::vector<std::string> argv, bool merge_err) {
    CmdResult r;
    r.rc = spawn(argv, &r.out, merge_err, &r.truncated);
    return r;
}

inline CmdResult run(std::initializer_list<std::string_view> argv, bool merge_err = false) {
    std::vector<std::string> v;
    v.reserve(argv.size());
    for (std::string_view a : argv) v.emplace_back(a);
    return run(std::move(v), merge_err);
}

inline int run_quiet(std::initializer_list<std::string_view> argv) {
    std::vector<std::string> v;
    for (std::string_view a : argv) v.emplace_back(a);
    return spawn(v, nullptr, false, nullptr);
}

inline bool ensure_dir(const fs::path& path) {
    std::error_code ec;
    fs::create_directories(path, ec);
    return !ec;
}

inline std::optional<std::string> json_string_field(const std::string& json, std::string_view key) {
    std::string pat = std::format("\"{}\"", key);
    std::size_t p = 0;
    while ((p = json.find(pat, p)) != std::string::npos) {
        std::size_t q = p + pat.size();
        p = q;
        while (q < json.size() && std::isspace(static_cast<unsigned char>(json[q]))) q++;
        if (q >= json.size() || json[q] != ':') continue;
        q++;
        while (q < json.size() && std::isspace(static_cast<unsigned char>(json[q]))) q++;
        if (q >= json.size() || json[q] != '"') return std::nullopt;
        q++;
        std::string out;
        while (q < json.size() && json[q] != '"') {
            if (json[q] == '\\' && q + 1 < json.size()) q++;
            out.push_back(json[q++]);
        }
        if (q >= json.size()) return std::nullopt;
        return out;
    }
    return std::nullopt;
}

inline std::optional<std::string> read_mount_field(std::string_view target, std::string_view field) {
    CmdResult r = run({"findmnt", "-no", field, "--target", std::string(target)});
    if (r.rc != 0) return std::nullopt;
    std::string s = trim(std::move(r.out));
    if (s.empty()) return std::nullopt;
    return s;
}

inline bool lvm_report(const char* tool, const std::string& target, const char* fields, CmdResult& r) {
    r = run({tool, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", fields, target});
    return r.rc == 0 && !r.truncated;
}

inline std::optional<std::string> lvm_field(const char* tool, const std::string& target, const char* field) {
    CmdResult r;
    if (!lvm_report(tool, target, field, r)) return std::nullopt;
    return json_string_field(r.out, field);
}

struct LvmInfo {
    std::string vg;
    std::string lv;
    std::string lvpath;
    std::string segtype;
    bool is_thin = false;
};

inline std::optional<LvmInfo> resolve_lvm_info(const std::string& source) {
    CmdResult r;
    if (!lvm_report("lvs", source, "vg_name,lv_name,segtype", r)) return std::nullopt;
    auto vg = json_string_field(r.out, "vg_name");
    auto lv = json_string_field(r.out, "lv_name");
    auto seg = json_string_field(r.out, "segtype");
    if (!vg || !lv || !seg || vg->empty() || lv->empty() || seg->empty()) return std::nullopt;
    LvmInfo info;
    info.vg = *vg;
    info.lv = *lv;
    info.segtype = *seg;
    info.lvpath = std::format("/dev/{}/{}", *vg, *lv);
    info.is_thin = info.segtype.find("thin") != std::string::npos;
    return info;
}

inline double get_vg_free_gb(const std::string& vg) {
    auto v = lvm_field("vgs", vg, "vg_free");
    if (!v) return 0.0;
    return static_cast<double>(std::strtoull(v->c_str(), nullptr, 10)) / gib;
}

inline const char* classic_snapshot_size(double free_gb) {
    if (free_gb >= 10.0) return "5G";
    if (free_gb >= 5.0) return "3G";
    if (free_gb >= 2.0) return "1.5G";
    if (free_gb >= 1.0) return "1G";
    return nullptr;
}

inline bool fstype_supported(std::string_view mountpoint) {
    auto fstype = read_mount_field(mountpoint, "FSTYPE");
    if (!fstype) return false;
    return *fstype == "xfs" || *fstype == "ext4" || *fstype == "ext3" || *fstype == "btrfs";
}

inline bool freeze_mount(std::string_view mp) {
    return run({"fsfreeze", "-f", std::string(mp)}, true).rc == 0;
}

inline void unfreeze_mount(std::string_view mp) {
    run({"fsfreeze", "-u", std::string(mp)}, true);
}

inline bool delete_snapshot_lv(const std::string& lvpath) {
    return run({"lvremove", "-fy", lvpath}, true).rc == 0;
}

inline bool lv_exists(const std::string& lvpath) {
    return run({"lvs", lvpath}).rc == 0;
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

struct CreateResult {
    std::string snapshot_name;
    std::string type;
    std::string message;
    long long exit_code = 0;
};

struct RollbackResult {
    std::string snapshot_name;
    std::string message;
    long long exit_code = 0;
};

struct DeleteResult {
    std::string snapshot_name;
    std::string message;
    std::vector<std::string> matches;
    long long exit_code = 0;
};

struct SearchResults {
    std::string term;
    std::vector<std::string> matches;
    long long count = 0;
    long long exit_code = 0;
};

struct ListResult {
    std::vector<std::string> manual;
    std::vector<std::string> apt;
    std::vector<std::string> daemon;
    long long exit_code = 0;
};

struct AutodelResult {
    std::vector<std::string> removed;
    long long exit_code = 0;
};

struct VersionResult {
    std::string version;
    std::string architecture;
    long long exit_code = 0;
};

using FieldValue = std::variant<std::string, long long, std::vector<std::string>>;

struct Field {
    std::string name;
    FieldValue value;
};

struct SnapNames {
    std::vector<std::string> roots;
    std::vector<std::string> homes;
};

struct CreateOutcome {
    bool ok = false;
    std::string snapname;
    std::string error;
};

struct Outcome {
    bool ok = false;
    std::string msg;
};

template <class F, class T>
void for_each_field(const T& value, F&& fn) {
    template for (constexpr auto member :
                      std::define_static_array(std::meta::nonstatic_data_members_of(
                          ^^T, std::meta::access_context::current()))) {
        fn(std::meta::identifier_of(member), value.[:member:]);
    }
}

template <class T>
void set_member_by_name(T& value, std::string_view key, const std::string& val) {
    template for (constexpr auto member :
                      std::define_static_array(std::meta::nonstatic_data_members_of(
                          ^^T, std::meta::access_context::current()))) {
        if (key == std::meta::identifier_of(member)) {
            value.[:member:] = val;
            return;
        }
    }
}

template <class S>
std::vector<Field> to_fields(const S& s) {
    std::vector<Field> out;
    for_each_field(s, [&](std::string_view name, const auto& value) {
        using V = std::remove_cvref_t<decltype(value)>;
        if constexpr (std::same_as<V, std::string>) {
            out.push_back({std::string(name), value});
        } else if constexpr (std::same_as<V, long long>) {
            out.push_back({std::string(name), value});
        } else if constexpr (std::same_as<V, std::vector<std::string>>) {
            out.push_back({std::string(name), value});
        } else {
            static_assert(sizeof(V) == 0, "unsupported field type");
        }
    });
    return out;
}

template <class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

inline std::string json_escape(std::string_view s) {
    std::string out;
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                out += std::format("\\u{:04x}", static_cast<unsigned char>(c));
            } else {
                out += c;
            }
        }
    }
    return out;
}

inline std::string to_json(const std::vector<Field>& fields) {
    std::string out = "{\n";
    for (std::size_t i = 0; i < fields.size(); i++) {
        const auto& f = fields[i];
        std::string value = std::visit(overloaded{
            [](const std::string& s) { return std::format("\"{}\"", json_escape(s)); },
            [](long long v) { return std::format("{}", v); },
            [](const std::vector<std::string>& v) -> std::string {
                if (v.empty()) return "[]";
                std::string a = "[\n";
                for (std::size_t j = 0; j < v.size(); j++) {
                    a += std::format("    \"{}\"", json_escape(v[j]));
                    if (j + 1 < v.size()) a += ",";
                    a += "\n";
                }
                a += "  ]";
                return a;
            }}, f.value);
        out += std::format("  \"{}\": {}{}\n", json_escape(f.name), value, i + 1 < fields.size() ? "," : "");
    }
    out += "}";
    return out;
}

inline std::string ztslo_escape(std::string_view s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            out += ' ';
        } else {
            out += c;
        }
    }
    return out;
}

inline std::string to_ztslo(const std::vector<Field>& fields) {
    std::string out = "ztslo.start\n}\n";
    std::vector<std::string> names;
    names.reserve(fields.size());
    for (const auto& f : fields) names.push_back(f.name);
    auto has_name = [&](const std::string& n) {
        return std::ranges::find(names, n) != names.end();
    };
    for (const auto& f : fields) {
        if (auto* v = std::get_if<std::vector<std::string>>(&f.value)) {
            std::string count_name = std::format("{}_count", f.name);
            if (!has_name(count_name))
                out += std::format("define variable {} as \"{}\"\n", count_name, v->size());
            for (std::size_t i = 0; i < v->size(); i++)
                out += std::format("define variable {}_{} as \"{}\"\n", f.name, i + 1, ztslo_escape((*v)[i]));
        } else {
            std::string val = std::visit(overloaded{
                [](const std::string& s) { return s; },
                [](long long x) { return std::format("{}", x); },
                [](const std::vector<std::string>&) { return std::string(); }}, f.value);
            out += std::format("define variable {} as \"{}\"\n", f.name, ztslo_escape(val));
        }
    }
    out += "}\nztslo.end";
    return out;
}

inline void emit(const Ctx& ctx, const std::vector<Field>& fields) {
    if (ctx.fmt == OutputFormat::json) {
        say(to_json(fields));
    } else if (ctx.fmt == OutputFormat::ztslo) {
        say(to_ztslo(fields));
    }
}

inline bool write_snapshot_meta(const fs::path& dir, const SnapshotMeta& meta) {
    std::string content;
    for_each_field(meta, [&](std::string_view name, const auto& value) {
        content += std::format("{}={}\n", name, value);
    });
    fs::path tmp = dir / std::format("{}.tmp.{}", meta_file, static_cast<long>(getpid()));
    FILE* f = std::fopen(tmp.c_str(), "w");
    if (!f) return false;
    bool ok = std::fwrite(content.data(), 1, content.size(), f) == content.size();
    ok = std::fflush(f) == 0 && ok;
    ok = fsync(fileno(f)) == 0 && ok;
    ok = std::fclose(f) == 0 && ok;
    if (!ok || std::rename(tmp.c_str(), (dir / meta_file).c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

inline bool read_snapshot_meta(const fs::path& dir, SnapshotMeta& meta) {
    meta = SnapshotMeta{};
    std::ifstream in(dir / meta_file);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(std::move(line));
        std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        set_member_by_name(meta, key, val);
    }
    return !meta.kind.empty() && !meta.snapshot_lvpath.empty();
}

inline void remove_snapshot_meta(const fs::path& dir) {
    std::error_code ec;
    fs::remove(dir / meta_file, ec);
    fs::remove(dir, ec);
}

inline bool remove_snapshot_at(const fs::path& dir) {
    SnapshotMeta meta;
    if (read_snapshot_meta(dir, meta) && !delete_snapshot_lv(meta.snapshot_lvpath) &&
        lv_exists(meta.snapshot_lvpath)) {
        say_err(std::format("Warning: failed to remove snapshot LV '{}'.", meta.snapshot_lvpath));
        return false;
    }
    remove_snapshot_meta(dir);
    return true;
}

inline std::optional<fs::path> find_snapshot(std::string_view name) {
    if (!valid_name(name, str_buf - 1)) return std::nullopt;
    for (auto d : snapshot_dirs) {
        fs::path dir = fs::path(d) / name;
        std::error_code ec;
        if (fs::exists(dir / meta_file, ec)) return dir;
    }
    return std::nullopt;
}

inline bool delete_snapshot(std::string_view name) {
    auto dir = find_snapshot(name);
    if (!dir) return false;
    SnapshotMeta meta;
    if (!read_snapshot_meta(*dir, meta)) return false;
    return remove_snapshot_at(*dir);
}

inline std::string_view snapshot_base_dir(std::string_view type, std::string_view name) {
    if (name == "nsmd") return daemon_auto_dir;
    return type == "auto" ? auto_dir : manual_dir;
}

inline void sort_by_timestamp(std::vector<std::string>& v) {
    std::ranges::sort(v, [](const std::string& a, const std::string& b) {
        std::string_view ta = ts_part(a), tb = ts_part(b);
        int c = ta.compare(tb);
        return c != 0 ? c < 0 : a < b;
    });
}

inline SnapNames collect_snapshots(std::string_view dir) {
    SnapNames out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(fs::path(dir), ec)) {
        std::string name = e.path().filename().string();
        if (name.empty() || name.front() == '.') continue;
        std::error_code ec2;
        if (!fs::exists(e.path() / meta_file, ec2)) continue;
        if (name.starts_with("root-")) {
            out.roots.push_back(std::move(name));
        } else if (name.starts_with("home-")) {
            out.homes.push_back(std::move(name));
        }
    }
    sort_by_timestamp(out.roots);
    sort_by_timestamp(out.homes);
    return out;
}

inline bool user_part(std::string_view snap, std::string& out) {
    if (!snap.starts_with("root-") && !snap.starts_with("home-")) return false;
    std::string_view p = snap.substr(5);
    if (p.starts_with("auto-")) {
        p.remove_prefix(5);
    } else if (p.starts_with("manual-")) {
        p.remove_prefix(7);
    } else {
        return false;
    }
    if (p.size() <= ts_len + 1) return false;
    std::size_t n = p.size() - ts_len - 1;
    if (p[n] != '-') return false;
    out = p.substr(0, n);
    return true;
}

inline std::vector<std::string> find_by_term(std::string_view term) {
    std::vector<std::string> out;
    for (int pass = 0; pass < 2 && out.empty(); pass++) {
        for (auto d : snapshot_dirs) {
            SnapNames s = collect_snapshots(d);
            auto check = [&](const std::string& name) {
                bool hit = false;
                if (pass == 0) {
                    std::string part;
                    hit = user_part(name, part) && part == term;
                } else {
                    hit = name.find(term) != std::string::npos;
                }
                if (hit) out.push_back((fs::path(d) / name).string());
            };
            for (const auto& n : s.roots) check(n);
            for (const auto& n : s.homes) check(n);
        }
    }
    sort_by_timestamp(out);
    return out;
}

inline std::vector<std::string> group_names(std::string_view dir) {
    SnapNames s = collect_snapshots(dir);
    s.roots.insert(s.roots.end(), s.homes.begin(), s.homes.end());
    return std::move(s.roots);
}

inline std::vector<std::string> drop_oldest(std::string_view dir, const std::vector<std::string>& names) {
    std::vector<std::string> removed;
    for (std::size_t i = 0; names.size() - i > keep_latest; i++) {
        fs::path p = fs::path(dir) / names[i];
        if (remove_snapshot_at(p)) removed.push_back(names[i]);
    }
    return removed;
}

inline std::vector<std::string> cleanup_dir(std::string_view dir) {
    SnapNames s = collect_snapshots(dir);
    std::vector<std::string> removed = drop_oldest(dir, s.roots);
    std::vector<std::string> more = drop_oldest(dir, s.homes);
    removed.insert(removed.end(), more.begin(), more.end());
    return removed;
}

inline std::vector<std::string> autodel_snapshots() {
    std::vector<std::string> removed;
    for (auto d : auto_dirs) {
        std::vector<std::string> r = cleanup_dir(d);
        removed.insert(removed.end(), r.begin(), r.end());
    }
    return removed;
}

inline std::optional<std::string> get_lv_pool(const std::string& lvpath) {
    auto pool = lvm_field("lvs", lvpath, "pool_lv");
    if (!pool || pool->empty()) return std::nullopt;
    return pool;
}

inline double get_thinpool_usage(const std::string& vg, const std::string& pool) {
    auto v = lvm_field("lvs", std::format("{}/{}", vg, pool), "data_percent");
    if (!v) return 0.0;
    return std::strtod(v->c_str(), nullptr);
}

inline void purge_auto_snapshots(const Ctx& ctx, const std::string& vg, const std::string& pool) {
    std::vector<std::string> paths;
    for (auto d : auto_dirs) {
        SnapNames s = collect_snapshots(d);
        for (const auto& n : s.roots) paths.push_back((fs::path(d) / n).string());
        for (const auto& n : s.homes) paths.push_back((fs::path(d) / n).string());
    }
    sort_by_timestamp(paths);
    double usage = get_thinpool_usage(vg, pool);
    for (std::size_t i = 0; i < paths.size() && usage >= thinpool_limit; i++)
        if (remove_snapshot_at(paths[i])) usage = get_thinpool_usage(vg, pool);
    if (usage >= thinpool_limit)
        ctx.line(std::format(
            "Warning: Thin pool {}/{} is still at {:.2f}% with no automatic snapshots left. "
            "Manual snapshots are never removed automatically; use 'delete <name>'.",
            vg, pool, usage));
}

inline void monitor_thinpool(const Ctx& ctx, std::string_view mountpoint) {
    auto source = read_mount_field(mountpoint, "SOURCE");
    if (!source) return;
    auto info = resolve_lvm_info(*source);
    if (!info || !info->is_thin) return;
    auto pool = get_lv_pool(info->lvpath);
    if (!pool) return;
    double usage = get_thinpool_usage(info->vg, *pool);
    if (usage < thinpool_limit) return;
    ctx.line(std::format("Warning: Thin pool {}/{} usage is {:.2f}% (threshold {:.0f}% passed).",
                         info->vg, *pool, usage, thinpool_limit));
    autodel_snapshots();
    if (get_thinpool_usage(info->vg, *pool) >= thinpool_limit)
        purge_auto_snapshots(ctx, info->vg, *pool);
}

inline bool initramfs_has_lvm_hook() {
    struct utsname un;
    if (uname(&un) != 0) return false;
    std::string initrd = std::format("/boot/initrd.img-{}", un.release);
    CmdResult r = run({"lsinitramfs", initrd});
    return r.rc == 0 && r.out.find("lvm") != std::string::npos;
}

inline pid_t parent_of(pid_t pid) {
    std::string path = std::format("/proc/{}/stat", static_cast<long>(pid));
    std::ifstream in(path);
    std::string line;
    if (!in || !std::getline(in, line)) return 0;
    std::size_t p = line.rfind(')');
    if (p == std::string::npos) return 0;
    std::size_t q = p + 1;
    auto skip_spaces = [&](std::size_t& i) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) i++;
    };
    skip_spaces(q);
    if (q >= line.size()) return 0;
    q++;
    skip_spaces(q);
    std::size_t start = q;
    while (q < line.size() && std::isdigit(static_cast<unsigned char>(line[q]))) q++;
    if (q == start) return 0;
    return static_cast<pid_t>(std::strtol(line.substr(start, q - start).c_str(), nullptr, 10));
}

inline bool in_own_chain(pid_t pid) {
    for (pid_t p = getpid(); p > 1; p = parent_of(p))
        if (p == pid) return true;
    return false;
}

inline std::vector<pid_t> home_holders() {
    std::vector<pid_t> pids;
    CmdResult r = run({"fuser", "-m", std::string(home_source)});
    std::size_t start = 0;
    while (pids.size() < max_holders) {
        std::size_t end = start;
        while (end < r.out.size() && !std::isspace(static_cast<unsigned char>(r.out[end]))) end++;
        if (end > start) {
            std::string tok = r.out.substr(start, end - start);
            char* e = nullptr;
            long v = std::strtol(tok.c_str(), &e, 10);
            if (e != tok.c_str() && v > 0) pids.push_back(static_cast<pid_t>(v));
        }
        if (end >= r.out.size()) break;
        start = end + 1;
    }
    return pids;
}

inline void evict_holders() {
    for (int attempt = 0; attempt < evict_attempts; attempt++) {
        std::vector<pid_t> pids = home_holders();
        std::size_t signalled = 0;
        for (pid_t pid : pids) {
            if (pid <= 1 || in_own_chain(pid)) continue;
            kill(pid, attempt < 2 ? SIGTERM : SIGKILL);
            signalled++;
        }
        if (signalled == 0) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

inline CreateOutcome create_snapshot(const Ctx& ctx, std::string_view mountpoint, std::string_view prefix,
                                     std::string_view type, std::string_view name) {
    auto source = read_mount_field(mountpoint, "SOURCE");
    if (!source) {
        std::string e = std::format("Error: cannot resolve source for {}.", mountpoint);
        ctx.warn(e);
        return {false, "", e};
    }
    if (!fstype_supported(mountpoint)) {
        std::string e = std::format("Error: {} filesystem is not supported (xfs/ext4/ext3/btrfs required).", mountpoint);
        ctx.warn(e);
        return {false, "", e};
    }
    auto info = resolve_lvm_info(*source);
    if (!info) {
        std::string e = std::format("Error: {} is not an LVM volume or cannot be resolved.", mountpoint);
        ctx.warn(e);
        return {false, "", e};
    }
    std::optional<std::string> snap_size;
    if (!info->is_thin) {
        double free_gb = get_vg_free_gb(info->vg);
        const char* sz = classic_snapshot_size(free_gb);
        if (!sz) {
            std::string e = std::format(
                "Error: Insufficient free space in volume group {} (1.0G required, {:.2f}G available).",
                info->vg, free_gb);
            ctx.warn(e);
            return {false, "", e};
        }
        snap_size = sz;
    }
    std::string ts = timestamp();
    std::string snapname = std::format("{}-{}-{}-{}", prefix, type, name, ts);
    if (snapname.size() > lv_name_max) {
        ctx.warn("Error: snapshot name is too long.");
        return {false, "", "Error: snapshot name is too long."};
    }
    fs::path snapdir = fs::path(snapshot_base_dir(type, name)) / snapname;
    if (!ensure_dir(snapdir)) {
        ctx.warn("Error: cannot create snapshot metadata directory.");
        return {false, snapname, "Error: cannot create snapshot metadata directory."};
    }
    bool frozen = mountpoint != root_source && freeze_mount(mountpoint);
    CmdResult r = info->is_thin
        ? run({"lvcreate", "-s", "-n", snapname, info->lvpath}, true)
        : run({"lvcreate", "-L", *snap_size, "-s", "-n", snapname, info->lvpath}, true);
    if (frozen) unfreeze_mount(mountpoint);
    if (r.rc != 0) {
        std::string e = trim(r.out);
        if (e.empty()) e = "Error: lvcreate failed.";
        ctx.warn(e);
        remove_snapshot_meta(snapdir);
        return {false, snapname, e};
    }
    SnapshotMeta meta;
    meta.kind = prefix;
    meta.type = type;
    meta.name = snapname;
    meta.timestamp = ts;
    meta.origin_mount = mountpoint;
    meta.origin_source = *source;
    meta.origin_vg = info->vg;
    meta.origin_lv = info->lv;
    meta.origin_lvpath = info->lvpath;
    meta.snapshot_lvpath = std::format("/dev/{}/{}", info->vg, snapname);
    if (!write_snapshot_meta(snapdir, meta)) {
        ctx.warn("Error: snapshot was created, but metadata could not be written.");
        return {false, snapname, "Error: snapshot was created, but metadata could not be written."};
    }
    ctx.line(std::format("Created ({}): {}", type, snapname));
    return {true, snapname, ""};
}

inline Outcome rollback_home(const Ctx& ctx, const SnapshotMeta& meta, bool force) {
    sync();
    if (force) evict_holders();
    bool unmounted = umount("/home") == 0 || errno == EINVAL;
    if (!unmounted) {
        std::vector<pid_t> pids = home_holders();
        ctx.line(std::format(
            "Warning: /home is busy ({} process(es) holding it); the merge will be deferred.", pids.size()));
        if (force)
            ctx.line("Processes of your own session still hold it. Leave /home and run again, or reboot.");
        else
            ctx.line("Run again with --force to stop them (your own session is never touched).");
    } else {
        run({"lvchange", "-an", meta.origin_lvpath}, true);
    }
    CmdResult r = run({"lvconvert", "--merge", meta.snapshot_lvpath}, true);
    bool ok = r.rc == 0;
    if (!ok) ctx.warn(std::format("Rollback failed: {}", trim(r.out)));
    if (unmounted) {
        run({"lvchange", "-ay", meta.origin_lvpath}, true);
        run_quiet({"mount", "/home"});
    }
    if (!ok) return {false, "Rollback failed."};
    if (unmounted) return {true, "SUCCESS: Home rollback complete. REBOOT may be required if the merge is pending."};
    return {true, "SUCCESS: Home rollback scheduled. REBOOT REQUIRED."};
}

inline Outcome rollback_root(const Ctx& ctx, const SnapshotMeta& meta) {
    if (!initramfs_has_lvm_hook()) {
        ctx.line("Warning: LVM hook not detected in initramfs.");
        ctx.line("The merge is scheduled but may not apply on reboot.");
        ctx.line("Run: update-initramfs -u   then reboot.");
    }
    CmdResult r = run({"lvconvert", "--merge", meta.snapshot_lvpath}, true);
    if (r.rc != 0) {
        ctx.warn(std::format("Rollback failed: {}", trim(r.out)));
        return {false, "Rollback failed."};
    }
    return {true, "SUCCESS: Root rollback scheduled. REBOOT REQUIRED."};
}

constexpr std::string_view compiled_arch() {
#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "aarch64";
#elif defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 64
    return "riscv64";
#elif defined(__powerpc64__)
    return "ppc64le";
#elif defined(__s390x__)
    return "s390x";
#elif defined(__loongarch64)
    return "loongarch64";
#elif defined(__i386__) || defined(_M_IX86)
    return "i686";
#else
    return "unknown";
#endif
}

inline void print_usage(const Ctx& ctx, std::string_view prog) {
    ctx.line(std::format("Usage: {} <command> [argument] [options]", prog));
    ctx.line("");
    ctx.line("Commands:");
    ctx.line("  create <name>    Create snapshots on XFS/ext4/LVM volumes");
    ctx.line("                   Auto type if name matches 'apt', 'apt-*', or 'nsmd'");
    ctx.line("  rollback <name> [--force]");
    ctx.line("                   Roll back to named snapshot");
    ctx.line("                   --force stops processes holding /home (never your own session)");
    ctx.line("  delete <name>    Delete a snapshot by full name, or by the name you gave it");
    ctx.line("                   (asks which one when several match)");
    ctx.line("  search <term>    List snapshots matching a term (name part first, then substring)");
    ctx.line("  list             List all snapshots");
    ctx.line("  autodel          Delete oldest automatic snapshots, keeping the latest 6");
    ctx.line("  version, -v      Show version and compiled architecture");
    ctx.line("");
    ctx.line("Options:");
    ctx.line("  -json            Print the command response as JSON on stdout");
    ctx.line("  -ztslo           Print the command response in ZTSLO format on stdout");
}

inline int cmd_create(const Ctx& ctx, const std::string& name) {
    CreateResult res{name, "", "", 1};
    if (!valid_name(name, user_name_max)) {
        ctx.warn(std::format(
            "Error: invalid snapshot name (use letters, digits, '_', '.', '+', '-'; max {} chars).",
            user_name_max));
        res.message = "invalid snapshot name";
    } else if (!ensure_dir(auto_dir) || !ensure_dir(daemon_auto_dir) || !ensure_dir(manual_dir)) {
        ctx.warn(std::format("Error: cannot create {}.", snapshot_base));
        res.message = "cannot create snapshot base directory";
    } else {
        bool isauto = name == "nsmd" || name.starts_with("apt");
        res.type = isauto ? "automatic" : "manual";
        CreateOutcome out = create_snapshot(ctx, root_source, "root", isauto ? "auto" : "manual", name);
        res.exit_code = out.ok ? 0 : 1;
        res.snapshot_name = out.snapname.empty() ? name : out.snapname;
        res.message = out.error;
        if (isauto) autodel_snapshots();
        monitor_thinpool(ctx, root_source);
        monitor_thinpool(ctx, home_source);
    }
    std::vector<Field> fields = to_fields(res);
    if (ctx.fmt == OutputFormat::ztslo)
        for (auto& f : fields)
            if (f.name == "type") f.name = "snapshot_type";
    emit(ctx, fields);
    return static_cast<int>(res.exit_code);
}

inline int cmd_rollback(const Ctx& ctx, const std::string& name, bool force) {
    RollbackResult res{name, "", 1};
    auto dir = find_snapshot(name);
    if (!dir) {
        ctx.warn(std::format("Error: Snapshot '{}' not found.", name));
        res.message = "snapshot not found";
    } else {
        SnapshotMeta meta;
        if (!read_snapshot_meta(*dir, meta)) {
            ctx.warn("Error: Snapshot metadata could not be read.");
            res.message = "snapshot metadata could not be read";
        } else if (meta.kind == "root") {
            Outcome o = rollback_root(ctx, meta);
            res.exit_code = o.ok ? 0 : 1;
            res.message = o.msg;
        } else if (meta.kind == "home") {
            Outcome o = rollback_home(ctx, meta, force);
            res.exit_code = o.ok ? 0 : 1;
            res.message = o.msg;
        } else {
            ctx.warn("Error: invalid snapshot kind.");
            res.message = "invalid snapshot kind";
        }
    }
    emit(ctx, to_fields(res));
    return static_cast<int>(res.exit_code);
}

inline int cmd_delete(const Ctx& ctx, const std::string& term) {
    DeleteResult res{term, "", {}, 1};
    auto dir = find_snapshot(term);
    if (dir) {
        if (delete_snapshot(term)) {
            ctx.line("Snapshot deleted successfully.");
            res.exit_code = 0;
        } else {
            ctx.warn("Error: snapshot deletion failed.");
            res.message = "snapshot deletion failed";
        }
        emit(ctx, to_fields(res));
        return static_cast<int>(res.exit_code);
    }
    if (!valid_name(term, str_buf - 1)) {
        ctx.warn(std::format("Error: snapshot '{}' not found.", term));
        res.message = "snapshot not found";
        emit(ctx, to_fields(res));
        return 1;
    }
    std::vector<std::string> m = find_by_term(term);
    if (m.empty()) {
        ctx.warn(std::format("Error: no snapshot matches '{}'.", term));
        res.message = "no snapshot matches the term";
        emit(ctx, to_fields(res));
        return 1;
    }
    std::vector<std::string> names;
    for (const auto& p : m) names.push_back(fs::path(p).filename().string());
    res.matches = names;
    res.message = "multiple snapshots match the term";
    if (ctx.fmt == OutputFormat::text) {
        ctx.line(std::format("Snapshots called \"{}\":", term));
        for (std::size_t i = 0; i < names.size(); i++)
            ctx.line(std::format("  {} - {}", i + 1, names[i]));
        if (!isatty(STDIN_FILENO)) {
            ctx.warn("Not a terminal: run again with the full snapshot name.");
            return 1;
        }
        ctx.line(std::format("Which one to delete? [1-{}, empty to cancel]: ", names.size()));
        std::string line;
        if (!std::getline(std::cin, line)) line.clear();
        line = trim(std::move(line));
        if (line.empty()) {
            ctx.line("Cancelled.");
            return 1;
        }
        bool numeric = !line.empty() && std::ranges::all_of(line, [](unsigned char c) { return std::isdigit(c); });
        long k = numeric ? std::strtol(line.c_str(), nullptr, 10) : 0;
        if (!numeric || k < 1 || static_cast<std::size_t>(k) > names.size()) {
            ctx.warn("Error: invalid choice.");
            return 1;
        }
        if (remove_snapshot_at(fs::path(m[k - 1]))) {
            ctx.line("Snapshot deleted successfully.");
            return 0;
        }
        ctx.warn("Error: snapshot deletion failed.");
        return 1;
    }
    emit(ctx, to_fields(res));
    return 1;
}

inline int cmd_search(const Ctx& ctx, const std::string& term) {
    std::vector<std::string> paths = find_by_term(term);
    std::vector<std::string> names;
    for (const auto& p : paths) names.push_back(fs::path(p).filename().string());
    SearchResults res{term, names, static_cast<long long>(names.size()), names.empty() ? 1 : 0};
    if (ctx.fmt == OutputFormat::text) {
        if (names.empty()) {
            ctx.warn(std::format("Error: no snapshot matches '{}'.", term));
        } else {
            ctx.line(std::format("Snapshots matching \"{}\":", term));
            for (std::size_t i = 0; i < names.size(); i++)
                ctx.line(std::format("  {} - {}", i + 1, names[i]));
        }
    }
    emit(ctx, to_fields(res));
    return static_cast<int>(res.exit_code);
}

inline int cmd_list(const Ctx& ctx) {
    ListResult res{group_names(manual_dir), group_names(auto_dir), group_names(daemon_auto_dir), 0};
    if (ctx.fmt == OutputFormat::text) {
        auto list_group = [&](std::string_view title, std::string_view dir) {
            ctx.line("");
            ctx.line(title);
            ctx.line("  Snapshots:");
            std::vector<std::string> names = group_names(dir);
            if (names.empty()) ctx.line("    (none)");
            for (const auto& n : names) ctx.line(std::format("    {}", n));
        };
        list_group("Manual Snapshots", manual_dir);
        list_group("apt Snapshots", auto_dir);
        list_group("nsm Daemon Snapshots", daemon_auto_dir);
        ctx.line("");
    }
    emit(ctx, to_fields(res));
    return 0;
}

inline int cmd_autodel(const Ctx& ctx) {
    std::vector<std::string> removed = autodel_snapshots();
    monitor_thinpool(ctx, root_source);
    monitor_thinpool(ctx, home_source);
    AutodelResult res{removed, 0};
    emit(ctx, to_fields(res));
    return 0;
}

inline int cmd_version(const Ctx& ctx) {
    VersionResult res{std::string(nsm_version), std::string(compiled_arch()), 0};
    if (ctx.fmt == OutputFormat::text)
        ctx.line(std::format("nsm {} ({})", nsm_version, compiled_arch()));
    emit(ctx, to_fields(res));
    return 0;
}

inline int nsm_main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    std::vector<std::string> pos;
    bool want_version = false, want_help = false, have_json = false, have_ztslo = false;
    for (const std::string& a : args) {
        if (a == "-json" || a == "--json") {
            have_json = true;
        } else if (a == "-ztslo" || a == "--ztslo") {
            have_ztslo = true;
        } else if (a == "-v" || a == "--version" || a == "version") {
            want_version = true;
        } else if (a == "-h" || a == "--help" || a == "help") {
            want_help = true;
        } else {
            pos.push_back(a);
        }
    }
    if (have_json && have_ztslo) {
        say_err("Error: -json and -ztslo are mutually exclusive.");
        return 2;
    }
    Ctx ctx;
    ctx.fmt = have_json ? OutputFormat::json : have_ztslo ? OutputFormat::ztslo : OutputFormat::text;
    std::string prog = argc > 0 && argv[0] ? fs::path(argv[0]).filename().string() : "nsm";
    if (want_version) return cmd_version(ctx);
    if (want_help || pos.empty()) {
        print_usage(ctx, prog);
        return want_help ? 0 : 1;
    }
    static constexpr std::array<std::string_view, 4> needs_arg = {"create", "rollback", "delete", "search"};
    if (geteuid() != 0) {
        say_err("Error: root privileges required.");
        return 1;
    }
    setenv("LC_ALL", "C", 1);
    const std::string& cmd = pos[0];
    if (std::ranges::find(needs_arg, std::string_view(cmd)) != needs_arg.end() && pos.size() < 2) {
        print_usage(ctx, prog);
        return 1;
    }
    std::string arg = pos.size() > 1 ? pos[1] : std::string();
    if (cmd == "create") return cmd_create(ctx, arg);
    if (cmd == "rollback") {
        bool force = false;
        if (pos.size() > 2) {
            if (pos.size() > 3 || pos[2] != "--force") {
                print_usage(ctx, prog);
                return 1;
            }
            force = true;
        }
        return cmd_rollback(ctx, arg, force);
    }
    if (cmd == "delete") return cmd_delete(ctx, arg);
    if (cmd == "search") return cmd_search(ctx, arg);
    if (cmd == "list") return cmd_list(ctx);
    if (cmd == "autodel") return cmd_autodel(ctx);
    if (cmd == "version") return cmd_version(ctx);
    ctx.warn(std::format("Error: unknown command '{}'", cmd));
    print_usage(ctx, prog);
    return 1;
}

}

int main(int argc, char** argv) { return nsm::nsm_main(argc, argv); }
