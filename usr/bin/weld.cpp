// © NextFerret,2026,The Arvor License (TAL)
// Maintainer: Hludwig (@hludwig-nf)

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cctype>
#include <contracts>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <meta>
#include <memory>
#include <mutex>
#include <print>
#include <set>
#include <signal.h>
#include <source_location>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <pthread.h>
#include <stddef.h>

#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <apt-pkg/acquire.h>
#include <apt-pkg/acquire-item.h>
#include <apt-pkg/algorithms.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/clean.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/debfile.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/init.h>
#include <apt-pkg/install-progress.h>
#include <apt-pkg/packagemanager.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/pkgrecords.h>
#include <apt-pkg/policy.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/tagfile.h>
#include <apt-pkg/update.h>
#include <apt-pkg/upgrade.h>
#include <apt-pkg/version.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif

#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif

#ifndef SECCOMP_RET_DATA
#define SECCOMP_RET_DATA 0x0000ffffU
#endif

#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 0xc000003e
#endif

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xc00000b7
#endif

#ifndef AUDIT_ARCH_I386
#define AUDIT_ARCH_I386 0x40000003
#endif

#ifndef AUDIT_ARCH_ARM
#define AUDIT_ARCH_ARM 0x40000028
#endif

#ifndef AUDIT_ARCH_RISCV64
#define AUDIT_ARCH_RISCV64 0xc00000f3
#endif

#ifndef AUDIT_ARCH_PPC64LE
#define AUDIT_ARCH_PPC64LE 0xc0000015
#endif

#ifndef AUDIT_ARCH_S390X
#define AUDIT_ARCH_S390X 0xc0000016
#endif

#if defined(__x86_64__)
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_I386
#elif defined(__arm__)
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_RISCV64
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_PPC64LE
#elif defined(__s390x__)
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_S390X
#else
#define SECCOMP_TARGET_ARCH 0
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif

#ifndef _LINUX_CAPABILITY_VERSION_3
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#endif

#ifndef CAP_CHOWN
#define CAP_CHOWN 0
#endif
#ifndef CAP_DAC_OVERRIDE
#define CAP_DAC_OVERRIDE 1
#endif
#ifndef CAP_FOWNER
#define CAP_FOWNER 3
#endif
#ifndef CAP_FSETID
#define CAP_FSETID 4
#endif
#ifndef CAP_KILL
#define CAP_KILL 5
#endif
#ifndef CAP_SETGID
#define CAP_SETGID 6
#endif
#ifndef CAP_SETUID
#define CAP_SETUID 7
#endif
#ifndef CAP_SETPCAP
#define CAP_SETPCAP 8
#endif
#ifndef CAP_NET_BIND_SERVICE
#define CAP_NET_BIND_SERVICE 10
#endif
#ifndef CAP_NET_RAW
#define CAP_NET_RAW 13
#endif
#ifndef CAP_SYS_CHROOT
#define CAP_SYS_CHROOT 18
#endif
#ifndef CAP_MKNOD
#define CAP_MKNOD 27
#endif
#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE 29
#endif
#ifndef CAP_SETFCAP
#define CAP_SETFCAP 31
#endif

#ifdef arvor_version
#define ARVOR_VERSION arvor_version
#else
#define ARVOR_VERSION "arvor linux 0.0"
#endif

namespace fs = std::filesystem;

namespace {
std::mutex g_cout_mutex;
}

void handle_contract_violation(const std::contracts::contract_violation& v) {
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    std::print(stderr, "E: contract violation: {}\n", v.comment());
    std::fflush(stderr);
    std::_Exit(1);
}

template <typename T>
consteval std::string_view type_name() {
    constexpr auto info = ^^T;
    constexpr auto name = std::meta::identifier_of(info);
    return name;
}

template <typename... Ts>
constexpr std::size_t pack_size() {
    return sizeof...(Ts);
}

namespace {

constexpr std::string_view kTreeRoot = "/nsm/weld/root";
constexpr std::string_view kNfTreeBin = "/usr/bin/nsm";
constexpr std::string_view kAutoSnapDir = "/nsm/snapshots/auto";

constexpr std::string_view kWeldEtcDir = "/etc/weld";
constexpr std::string_view kWeldSourcesFile = "/etc/weld/sources.list";
constexpr std::string_view kWeldSourcesDir = "/etc/weld/sources.list.d";
constexpr std::string_view kWeldCacheDir = "/etc/weld/cache";
constexpr std::string_view kWeldTrustedKeysDir = "/etc/weld/trusted_keys";

constexpr std::size_t kWeldMinMemMb = 256;
constexpr std::size_t kWeldMaxMetadataSize = 8ULL * 1024 * 1024;
constexpr std::size_t kWeldMaxDownloadSize = 1024ULL * 1024 * 1024;

std::string g_tree_root{kTreeRoot};
std::string g_nf_tree_bin{kNfTreeBin};
std::string g_auto_snap_dir{kAutoSnapDir};
std::string g_weld_etc_dir{kWeldEtcDir};
std::string g_weld_sources_file{kWeldSourcesFile};
std::string g_weld_sources_dir{kWeldSourcesDir};
std::string g_weld_cache_dir{kWeldCacheDir};
std::string g_weld_trusted_keys_dir{kWeldTrustedKeysDir};

std::atomic<bool> g_sandbox_active{false};
std::atomic<bool> g_assume_yes{false};
std::atomic<bool> g_force_reinstall{false};
std::atomic<bool> g_simulate_mode{false};

std::string g_cached_root_dev;
std::string g_cached_vg_name;
std::string g_cached_snap_dev;
std::string g_cached_snap_lv_name;
std::once_flag g_cleanup_once;

std::atomic<int> g_dpkg_lock_fd{-1};

namespace {

[[maybe_unused]] bool read_random_bytes(unsigned char* buf, std::size_t n) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    std::size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) { close(fd); return false; }
        got += static_cast<std::size_t>(r);
    }
    close(fd);
    return true;
}

[[maybe_unused]]
std::string random_suffix(std::size_t n = 8) {
    unsigned char buf[8];
    if (n > sizeof(buf)) n = sizeof(buf);
    if (!read_random_bytes(buf, n)) {
        return std::to_string(std::time(nullptr) & 0xffffffff);
    }
    static constexpr std::string_view kHex = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kHex[(buf[i] >> 4) & 0xF]);
        out.push_back(kHex[buf[i] & 0xF]);
    }
    return out;
}

bool is_valid_package_name(std::string_view name) {
    if (name.empty() || name.size() > 256) return false;
    if (name[0] == '-' || name[0] == '=' || name[0] == '/' || name[0] == ':') return false;
    if (name[0] == '.' && name.size() > 1 && name[1] == '.') return false;
    for (char c : name) {
        if (c == '=' || c == '/' || c == ':' || c == '\0' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            return false;
        }
    }
    if (name.find("..") != std::string_view::npos) return false;
    return true;
}

void sanitize_child_environment() {
    static constexpr std::array<const char*, 14> kDangerousEnv = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_BIND_NOW",
        "LD_PROFILE", "LD_SHOW_AUXV", "LD_TRACE_LOADED_OBJECTS",
        "LD_VERBOSE", "LD_WARN", "LDPATH", "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH", "PYTHONPATH", "PERL5OPT"
    };
    for (const char* var : kDangerousEnv) {
        unsetenv(var);
    }
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("LC_ALL", "C", 1);
    setenv("LANG", "C", 1);
}

int open_no_follow(const std::string& path, int flags, mode_t mode = 0) {
    auto parent_pos = path.find_last_of('/');
    std::string parent = (parent_pos == std::string::npos) ? "." : path.substr(0, parent_pos);
    std::string base = (parent_pos == std::string::npos) ? path : path.substr(parent_pos + 1);
    int parent_fd = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0) return -1;
    int fd = openat(parent_fd, base.c_str(), flags | O_NOFOLLOW | O_CLOEXEC, mode);
    close(parent_fd);
    return fd;
}

}

std::string weld_arch() {
#if defined(__x86_64__)
    return "amd64";
#elif defined(__aarch64__)
    return "arm64";
#elif defined(__i386__)
    return "i386";
#elif defined(__arm__)
    return "armhf";
#elif defined(__riscv) && __riscv_xlen == 64
    return "riscv64";
#elif defined(__powerpc64__)
    return "ppc64el";
#elif defined(__s390x__)
    return "s390x";
#else
    return "unknown";
#endif
}

std::string weld_version_str() {
    return std::format("Weld 4.4 ({})", weld_arch());
}

template <typename... Args>
void safe_log(Args&&... args) {
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    (std::cout << ... << args);
    std::cout.flush();
}

void log_error(std::string_view msg) {
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    std::print(stderr, "E: {}\n", msg);
    std::fflush(stderr);
}

void log_warning(std::string_view msg) {
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    std::print(stderr, "W: {}\n", msg);
    std::fflush(stderr);
}

std::string trim_str(std::string_view s) {
    constexpr std::string_view kWhitespace = " \n\r\t<>";
    auto start = s.find_first_not_of(kWhitespace);
    if (start == std::string_view::npos) return {};
    auto end = s.find_last_not_of(kWhitespace);
    return std::string{s.substr(start, end - start + 1)};
}

std::string trim_copy(std::string_view s) {
    constexpr std::string_view kWhitespace = " \n\r\t";
    auto start = s.find_first_not_of(kWhitespace);
    if (start == std::string_view::npos) return {};
    auto end = s.find_last_not_of(kWhitespace);
    return std::string{s.substr(start, end - start + 1)};
}

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() && value.substr(value.size() - suffix.size()) == suffix;
}

std::string to_lower_copy(std::string_view s) {
    std::string r;
    r.reserve(s.size());
    std::ranges::transform(s, std::back_inserter(r),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return r;
}

std::string hex_encode(std::span<const unsigned char> data)
    post(r: !r.empty()) {
    static constexpr std::string_view kHex = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (auto b : data) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

std::vector<unsigned char> base64_decode_buf(std::string_view s) {
    if (s.empty()) return {};
    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) return {};
    BIO* mem = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
    if (!mem) { BIO_free_all(b64); return {}; }
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    std::vector<unsigned char> out(s.size());
    int n = BIO_read(b64, out.data(), static_cast<int>(s.size()));
    BIO_free_all(b64);
    if (n <= 0) return {};
    out.resize(static_cast<std::size_t>(n));
    return out;
}

bool compute_blake2b512(std::span<const unsigned char> data, std::span<unsigned char, 64> out)
    pre(!out.empty()) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    const EVP_MD* md = EVP_blake2b512();
    if (!md) { EVP_MD_CTX_free(ctx); return false; }
    if (EVP_DigestInit_ex(ctx, md, nullptr) == 1) {
        if (EVP_DigestUpdate(ctx, data.data(), data.size()) == 1) {
            unsigned int out_len = 0;
            if (EVP_DigestFinal_ex(ctx, out.data(), &out_len) == 1 && out_len == 64) ok = true;
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool verify_ed25519(std::span<const unsigned char> msg,
                    std::span<const unsigned char, 64> sig,
                    std::span<const unsigned char, 32> pubkey)
    pre(!msg.empty() || msg.data() != nullptr) pre(!sig.empty()) pre(!pubkey.empty()) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), 32);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        int rc = EVP_DigestVerify(ctx, sig.data(), 64, msg.data(), msg.size());
        if (rc == 1) ok = true;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

struct MinisignPublicKey {
    unsigned char key_id[8];
    unsigned char pubkey[32];
};

struct MinisignSignature {
    unsigned char sig_alg[2];
    unsigned char key_id[8];
    unsigned char sig[64];
    std::string trusted_comment;
    unsigned char global_sig[64];
};

bool parse_minisign_pub_blob(const std::vector<unsigned char>& blob, MinisignPublicKey& key)
    pre(blob.size() == 0 || blob.data() != nullptr) {
    if (blob.size() != 42) return false;
    if (blob[0] != 'E' || blob[1] != 'd') return false;
    std::memcpy(key.key_id, blob.data() + 2, 8);
    std::memcpy(key.pubkey, blob.data() + 10, 32);
    return true;
}

bool parse_minisign_sig_blob(const std::vector<unsigned char>& blob, MinisignSignature& sig)
    pre(blob.size() == 0 || blob.data() != nullptr) {
    if (blob.size() != 74) return false;
    std::memcpy(sig.sig_alg, blob.data(), 2);
    bool prehashed = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'D');
    bool raw_ed = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'd');
    if (!prehashed && !raw_ed) return false;
    std::memcpy(sig.key_id, blob.data() + 2, 8);
    std::memcpy(sig.sig, blob.data() + 10, 64);
    return true;
}

bool parse_minisign_pub_file(const std::string& content, MinisignPublicKey& key) {
    std::stringstream ss(content);
    std::string line;
    int line_num = 0;
    while (std::getline(ss, line)) {
        ++line_num;
        if (line_num != 2) continue;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        auto blob = base64_decode_buf(line);
        return parse_minisign_pub_blob(blob, key);
    }
    return false;
}

bool parse_minisign_sig_file(const std::string& content, MinisignSignature& sig) {
    std::stringstream ss(content);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        lines.push_back(line);
    }
    if (lines.size() < 4) return false;
    auto sig_blob = base64_decode_buf(lines[1]);
    if (!parse_minisign_sig_blob(sig_blob, sig)) return false;
    static constexpr std::string_view kTrustedPrefix = "trusted comment: ";
    if (!starts_with(lines[2], kTrustedPrefix)) return false;
    sig.trusted_comment = lines[2].substr(kTrustedPrefix.size());
    auto global_blob = base64_decode_buf(lines[3]);
    if (global_blob.size() != 64) return false;
    std::memcpy(sig.global_sig, global_blob.data(), 64);
    return true;
}

bool verify_minisign_signature(const std::string& content, const MinisignSignature& sig,
                               const MinisignPublicKey& key) {
    if (std::memcmp(sig.key_id, key.key_id, 8) != 0) return false;
    bool prehashed = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'D');
    bool raw_ed = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'd');
    if (!prehashed && !raw_ed) return false;

    if (raw_ed) {
        std::span<const unsigned char> msg{reinterpret_cast<const unsigned char*>(content.data()), content.size()};
        std::span<const unsigned char, 64> sig_span{sig.sig, 64};
        std::span<const unsigned char, 32> key_span{key.pubkey, 32};
        if (!verify_ed25519(msg, sig_span, key_span)) {
            return false;
        }
    } else {
        unsigned char hash[64];
        std::span<const unsigned char> data{reinterpret_cast<const unsigned char*>(content.data()), content.size()};
        std::span<unsigned char, 64> hash_span{hash, 64};
        if (!compute_blake2b512(data, hash_span)) {
            return false;
        }
        std::span<const unsigned char, 64> sig_span{sig.sig, 64};
        std::span<const unsigned char, 32> key_span{key.pubkey, 32};
        std::span<const unsigned char> hash_msg{hash, 64};
        if (!verify_ed25519(hash_msg, sig_span, key_span)) return false;
    }

    std::vector<unsigned char> signed_comment;
    signed_comment.reserve(64 + sig.trusted_comment.size());
    signed_comment.insert(signed_comment.end(), sig.sig, sig.sig + 64);
    signed_comment.insert(signed_comment.end(),
                          sig.trusted_comment.begin(),
                          sig.trusted_comment.end());

    std::span<const unsigned char> comment_msg{signed_comment.data(), signed_comment.size()};
    std::span<const unsigned char, 64> gsig_span{sig.global_sig, 64};
    std::span<const unsigned char, 32> key_span{key.pubkey, 32};
    return verify_ed25519(comment_msg, gsig_span, key_span);
}

std::vector<MinisignPublicKey> load_trusted_minisign_keys() {
    std::vector<MinisignPublicKey> keys;
    DIR* dir = opendir(g_weld_trusted_keys_dir.c_str());
    if (!dir) return keys;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.size() < 5) continue;
        if (!ends_with(name, ".pub")) continue;
        std::string path = g_weld_trusted_keys_dir + "/" + name;
        std::ifstream in(path);
        if (!in) continue;
        std::stringstream buf;
        buf << in.rdbuf();
        MinisignPublicKey key;
        if (parse_minisign_pub_file(buf.str(), key)) keys.push_back(key);
    }
    closedir(dir);
    return keys;
}

[[maybe_unused]]
bool verify_repo_metadata_signature(const std::string& metadata, const std::string& sig_content,
                                     std::string& trusted_comment_out, std::string& error_out) {
    MinisignSignature sig;
    if (!parse_minisign_sig_file(sig_content, sig)) {
        error_out = "minisign signature is malformed";
        return false;
    }
    std::vector<MinisignPublicKey> keys = load_trusted_minisign_keys();
    if (keys.empty()) {
        error_out = std::format("no trusted minisign keys installed in {}", g_weld_trusted_keys_dir);
        return false;
    }
    bool key_seen = false;
    for (const auto& key : keys) {
        if (std::memcmp(key.key_id, sig.key_id, 8) != 0) continue;
        key_seen = true;
        if (verify_minisign_signature(metadata, sig, key)) {
            trusted_comment_out = sig.trusted_comment;
            return true;
        }
    }
    if (!key_seen) {
        error_out = std::format("no trusted key matches the signature key id {}", hex_encode(std::span<const unsigned char>{sig.key_id, 8}));
    } else {
        error_out = "signature verification failed for matched trusted key";
    }
    return false;
}

bool is_safe_argument(std::string_view arg) {
    if (arg.empty()) return false;
    if (arg.find('\0') != std::string_view::npos) return false;
    if (arg.find('\n') != std::string_view::npos) return false;
    if (arg.find('\r') != std::string_view::npos) return false;
    return true;
}

bool is_safe_device_path(std::string_view path) {
    if (path.empty()) return false;
    if (path[0] != '/') return false;
    if (path.find("..") != std::string_view::npos) return false;
    if (path.find('\0') != std::string_view::npos) return false;
    if (path.find('\n') != std::string_view::npos) return false;
    if (path.size() > 4096) return false;
    if (path.find(' ') != std::string_view::npos) return false;
    if (path.find(';') != std::string_view::npos) return false;
    if (path.find('|') != std::string_view::npos) return false;
    if (path.find('&') != std::string_view::npos) return false;
    if (path.find('$') != std::string_view::npos) return false;
    if (path.find('`') != std::string_view::npos) return false;
    if (path.find("()") != std::string_view::npos) return false;
    if (path.find('<') != std::string_view::npos) return false;
    if (path.find('>') != std::string_view::npos) return false;
    if (path.find('\\') != std::string_view::npos) return false;
    return true;
}

[[maybe_unused]]
std::string sanitize_filename(std::string_view raw) {
    auto pos_slash = raw.find_last_of('/');
    std::string base = (pos_slash == std::string_view::npos)
        ? std::string{raw}
        : std::string{raw.substr(pos_slash + 1)};
    auto start = base.find_first_not_of(" \n\r\t");
    std::string cleaned = (start == std::string::npos)
        ? std::string{}
        : base.substr(start, base.find_last_not_of(" \n\r\t") - start + 1);
    std::string safe;
    safe.reserve(cleaned.size());
    for (char c : cleaned) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-') {
            safe.push_back(c);
        }
    }
    while (!safe.empty() && (safe.front() == '-' || safe.front() == '.')) {
        safe.erase(safe.begin());
    }
    if (safe == "." || safe == "..") safe = "safe_file";
    return safe.empty() ? "safe_file" : safe;
}

std::string strip_inline_comment(std::string_view line) {
    std::string result;
    result.reserve(line.size());
    bool in_string = false;
    char string_quote = '\0';
    char prev = ' ';
    for (std::size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (in_string) {
            result.push_back(c);
            if (c == string_quote) in_string = false;
        } else if (c == '"' || c == '\'') {
            in_string = true;
            string_quote = c;
            result.push_back(c);
        } else if (c == '#' && (i == 0 || prev == ' ' || prev == '\t')) {
            break;
        } else {
            result.push_back(c);
        }
        prev = c;
    }
    return result;
}

std::string strip_quotes(std::string_view value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return std::string{value.substr(1, value.size() - 2)};
    }
    if (value.size() >= 2 && value.front() == '\'' && value.back() == '\'') {
        return std::string{value.substr(1, value.size() - 2)};
    }
    return std::string{value};
}

[[maybe_unused]]
bool path_is_directory(std::string_view path) {
    struct stat st{};
    return stat(std::string{path}.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool path_is_regular_file(std::string_view path) {
    struct stat st{};
    return stat(std::string{path}.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string path_basename(std::string_view path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string_view::npos) return std::string{path};
    return std::string{path.substr(pos + 1)};
}

std::string format_bytes(std::uint64_t bytes) post(r: !r.empty()) {
    if (bytes < 1024) return std::format("{} B", bytes);
    if (bytes < 1024ULL * 1024) {
        return std::format("{:.2f} KB", static_cast<double>(bytes) / 1024.0);
    }
    if (bytes < 1024ULL * 1024 * 1024) {
        return std::format("{:.2f} MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    }
    return std::format("{:.2f} GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
}

bool wait_for_child(pid_t pid, int& status) pre(pid > 0) {
    status = 0;
    while (true) {
        int rc = 0;
        pid_t ret = waitpid(pid, &rc, 0);
        if (ret == pid) {
            status = rc;
            return true;
        }
        if (ret == -1) {
            if (errno == EINTR) continue;
            status = -1;
            return false;
        }
        status = -1;
        return false;
    }
}

void exec_abs_argv(const std::vector<char*>& argv_ptrs)
    pre(!argv_ptrs.empty()) pre(argv_ptrs[0] != nullptr) {
    if (argv_ptrs.empty() || argv_ptrs[0] == nullptr) _exit(127);
    const char* binary = argv_ptrs[0];
    if (strchr(binary, '/')) {
        execv(binary, const_cast<char* const*>(argv_ptrs.data()));
    } else {
        static constexpr std::array<const char*, 4> kPaths = {
            "/usr/bin", "/bin", "/usr/sbin", "/sbin"
        };
        char fullpath[4096];
        for (const auto* p : kPaths) {
            std::snprintf(fullpath, sizeof(fullpath), "%s/%s", p, binary);
            execv(fullpath, const_cast<char* const*>(argv_ptrs.data()));
        }
    }
    _exit(127);
}

std::vector<char*> build_argv(const std::vector<std::string>& args) {
    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(args.size() + 1);
    for (const auto& a : args) argv_ptrs.push_back(const_cast<char*>(a.c_str()));
    argv_ptrs.push_back(nullptr);
    return argv_ptrs;
}

int exec_argv(const std::vector<std::string>& args, int stdout_fd = -1, int stderr_fd = -1, int extra_fd = -1) {
    if (args.empty()) return 1;
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        int devnull_r = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }
        if (stdout_fd >= 0 && stdout_fd != STDOUT_FILENO) dup2(stdout_fd, STDOUT_FILENO);
        if (stderr_fd >= 0 && stderr_fd != STDERR_FILENO) dup2(stderr_fd, STDERR_FILENO);
        if (extra_fd >= 0) {
            if (extra_fd != 3) dup2(extra_fd, 3);
            fcntl(3, F_SETFD, 0);
        }
        if (stdout_fd >= 0 && stdout_fd != STDOUT_FILENO && stdout_fd != STDERR_FILENO && stdout_fd != 3) close(stdout_fd);
        if (stderr_fd >= 0 && stderr_fd != STDERR_FILENO && stderr_fd != STDOUT_FILENO && stderr_fd != 3 && stderr_fd != stdout_fd) close(stderr_fd);
        if (extra_fd >= 0 && extra_fd != 3 && extra_fd != STDOUT_FILENO && extra_fd != STDERR_FILENO) close(extra_fd);
        DIR* dir = opendir("/proc/self/fd");
        if (dir) {
            int dir_fd = dirfd(dir);
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                int fd = atoi(entry->d_name);
                if (fd > 2 && fd != extra_fd && fd != dir_fd) close(fd);
            }
            closedir(dir);
        } else {
            long max_fd = sysconf(_SC_OPEN_MAX);
            int cap = (max_fd < 0 || max_fd > 4096) ? 1024 : static_cast<int>(max_fd);
            for (int fd = 4; fd < cap; ++fd) close(fd);
        }
        auto argv_ptrs = build_argv(args);
        exec_abs_argv(argv_ptrs);
    }
    int status = 0;
    if (!wait_for_child(pid, status)) return 1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

int exec_argv_devnull_out(const std::vector<std::string>& args) {
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int rc = exec_argv(args, devnull, devnull);
    if (devnull >= 0) close(devnull);
    return rc;
}

int exec_argv_devnull_out_checked(const std::vector<std::string>& args) {
    if (args.empty()) return 1;
    for (const auto& a : args) {
        if (!is_safe_argument(a)) return 1;
    }
    return exec_argv_devnull_out(args);
}

std::string exec_argv_capture(const std::vector<std::string>& args) {
    if (args.empty()) return {};
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return {};
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return {}; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        int devnull_r = open("/dev/null", O_RDONLY);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }
        for (int fd = 3; fd < 1024; ++fd) close(fd);
        auto argv_ptrs = build_argv(args);
        exec_abs_argv(argv_ptrs);
    }
    close(pipefd[1]);
    std::string result;
    char buf[512];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) result.append(buf, static_cast<std::size_t>(n));
    close(pipefd[0]);
    int status = 0;
    wait_for_child(pid, status);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return result;
    return {};
}

bool read_text_file(const std::string& path, std::string& content) pre(!path.empty());
bool write_text_file(const std::string& path, const std::string& content) pre(!path.empty());

bool read_text_file(const std::string& path, std::string& content) pre(!path.empty()) {
    std::ifstream in(path);
    if (!in) return false;
    std::stringstream buffer;
    buffer << in.rdbuf();
    content = buffer.str();
    return true;
}

bool write_text_file(const std::string& path, const std::string& content) pre(!path.empty()) {
    std::string dir = path;
    auto slash = dir.find_last_of('/');
    if (slash != std::string::npos) dir = dir.substr(0, slash);
    else dir = ".";
    char tmpl[4096];
    int n = std::snprintf(tmpl, sizeof(tmpl), "%s/.weld_XXXXXX", dir.c_str());
    if (n < 0 || static_cast<std::size_t>(n) >= sizeof(tmpl)) return false;
    sigset_t old_mask, block_mask;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGINT);
    sigaddset(&block_mask, SIGTERM);
    sigaddset(&block_mask, SIGQUIT);
    sigaddset(&block_mask, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &block_mask, &old_mask);
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
        return false;
    }
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(tmpl);
        pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
        return false;
    }
    bool write_ok = true;
    if (!content.empty()) {
        const char* data = content.data();
        std::size_t remaining = content.size();
        while (remaining > 0) {
            ssize_t written = write(fd, data, remaining);
            if (written < 0) {
                if (errno == EINTR) continue;
                write_ok = false;
                break;
            }
            data += written;
            remaining -= static_cast<std::size_t>(written);
        }
    }
    if (fsync(fd) != 0) write_ok = false;
    if (close(fd) != 0) write_ok = false;
    if (!write_ok) {
        unlink(tmpl);
        pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
        return false;
    }
    bool renamed = (rename(tmpl, path.c_str()) == 0);
    if (!renamed) unlink(tmpl);
    pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
    return renamed;
}

class ChrootSeccompManager {
public:
    static bool apply_filter(std::string& err_out) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            err_out = std::format("failed to set PR_SET_NO_NEW_PRIVS: {}", std::strerror(errno));
            return false;
        }
        std::vector<sock_filter> filter;
        filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            static_cast<uint32_t>(offsetof(struct seccomp_data, arch))));
#if SECCOMP_TARGET_ARCH != 0
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_TARGET_ARCH, 1, 0));
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#else
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#endif
        filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));

        static constexpr int kAllowedSyscalls[] = {
            __NR_read, __NR_write, __NR_readv, __NR_writev,
            __NR_pread64, __NR_pwrite64, __NR_preadv, __NR_pwritev,
#ifdef __NR_preadv2
            __NR_preadv2,
#endif
#ifdef __NR_pwritev2
            __NR_pwritev2,
#endif
#ifdef __NR_open
            __NR_open,
#endif
            __NR_openat,
#ifdef __NR_openat2
            __NR_openat2,
#endif
#ifdef __NR_creat
            __NR_creat,
#endif
#ifdef __NR_close
            __NR_close,
#endif
#ifdef __NR_close_range
            __NR_close_range,
#endif
            __NR_stat, __NR_fstat, __NR_lstat, __NR_newfstatat,
#ifdef __NR_statx
            __NR_statx,
#endif
            __NR_lseek,
            __NR_mmap, __NR_mprotect, __NR_munmap, __NR_brk,
#ifdef __NR_mremap
            __NR_mremap,
#endif
#ifdef __NR_madvise
            __NR_madvise,
#endif
#ifdef __NR_mlock
            __NR_mlock,
#endif
#ifdef __NR_munlock
            __NR_munlock,
#endif
#ifdef __NR_mlock2
            __NR_mlock2,
#endif
#ifdef __NR_mincore
            __NR_mincore,
#endif
#ifdef __NR_msync
            __NR_msync,
#endif
            __NR_getdents, __NR_getdents64,
            __NR_readlink, __NR_readlinkat,
            __NR_getcwd,
            __NR_chdir, __NR_fchdir,
            __NR_rename, __NR_renameat,
#ifdef __NR_renameat2
            __NR_renameat2,
#endif
            __NR_mkdir, __NR_mkdirat,
            __NR_rmdir,
            __NR_unlink, __NR_unlinkat,
            __NR_symlink, __NR_symlinkat,
            __NR_access, __NR_faccessat,
#ifdef __NR_faccessat2
            __NR_faccessat2,
#endif
            __NR_pipe, __NR_pipe2,
            __NR_dup, __NR_dup2, __NR_dup3,
            __NR_fcntl,
#ifdef __NR_fcntl64
            __NR_fcntl64,
#endif
            __NR_ioctl,
            __NR_socket, __NR_connect, __NR_sendto, __NR_recvfrom,
            __NR_getsockopt, __NR_setsockopt, __NR_getsockname, __NR_getpeername,
            __NR_shutdown,
#ifdef __NR_accept4
            __NR_accept4,
#endif
#ifdef __NR_listen
            __NR_listen,
#endif
            __NR_fork, __NR_vfork,
            __NR_clone,
#ifdef __NR_clone3
            __NR_clone3,
#endif
            __NR_wait4,
#ifdef __NR_waitid
            __NR_waitid,
#endif
            __NR_execve,
#ifdef __NR_execveat
            __NR_execveat,
#endif
            __NR_exit, __NR_exit_group,
            __NR_kill, __NR_tkill, __NR_tgkill,
            __NR_setpgid,
#ifdef __NR_setsid
            __NR_setsid,
#endif
            __NR_getppid,
            __NR_uname,
            __NR_getrlimit, __NR_setrlimit, __NR_prlimit64,
            __NR_clock_gettime,
#ifdef __NR_clock_gettime64
            __NR_clock_gettime64,
#endif
            __NR_gettimeofday,
            __NR_nanosleep,
#ifdef __NR_clock_nanosleep
            __NR_clock_nanosleep,
#endif
            __NR_fstatfs, __NR_statfs,
            __NR_getrandom,
            __NR_sysinfo,
#ifdef __NR_getentropy
            __NR_getentropy,
#endif
            __NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,
            __NR_setuid, __NR_setgid, __NR_setresuid, __NR_setresgid,
            __NR_getresuid, __NR_getresgid, __NR_getpgid,
#ifdef __NR_getsid
            __NR_getsid,
#endif
            __NR_futex,
            __NR_set_tid_address, __NR_set_robust_list,
#ifdef __NR_get_robust_list
            __NR_get_robust_list,
#endif
#ifdef __NR_rseq
            __NR_rseq,
#endif
            __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn,
            __NR_sigaltstack,
#ifdef __NR_restart_syscall
            __NR_restart_syscall,
#endif
            __NR_fchmod, __NR_fchmodat,
#ifdef __NR_fchmodat2
            __NR_fchmodat2,
#endif
            __NR_chmod, __NR_fchown, __NR_fchownat, __NR_chown, __NR_lchown,
            __NR_utimensat, __NR_utimes,
#ifdef __NR_futimesat
            __NR_futimesat,
#endif
            __NR_umask,
            __NR_getdents64,
            __NR_sched_yield, __NR_sched_getaffinity,
#ifdef __NR_sched_setaffinity
            __NR_sched_setaffinity,
#endif
            __NR_getxattr, __NR_lgetxattr, __NR_fgetxattr,
            __NR_listxattr, __NR_llistxattr, __NR_flistxattr,
            __NR_truncate, __NR_ftruncate,
#ifdef __NR_truncate64
            __NR_truncate64,
#endif
#ifdef __NR_ftruncate64
            __NR_ftruncate64,
#endif
#ifdef __NR_fadvise64
            __NR_fadvise64,
#endif
#ifdef __NR_arch_prctl
            __NR_arch_prctl,
#endif
#ifdef __NR_prctl
            __NR_prctl,
#endif
#ifdef __NR_getpriority
            __NR_getpriority,
#endif
#ifdef __NR_setpriority
            __NR_setpriority,
#endif
#ifdef __NR_clock_getres
            __NR_clock_getres,
#endif
#ifdef __NR_time
            __NR_time,
#endif
#ifdef __NR_get_mempolicy
            __NR_get_mempolicy,
#endif
        };

        for (int sys_nr : kAllowedSyscalls) {
            if (sys_nr <= 0) continue;
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                static_cast<uint32_t>(sys_nr), 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }

        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));

        struct sock_fprog prog;
        prog.len = static_cast<unsigned short>(filter.size());
        prog.filter = filter.data();
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            err_out = std::format("failed to load SECCOMP filter: {}", std::strerror(errno));
            return false;
        }
        return true;
    }
};

} // namespace (anonymous)

struct ConfigBackup {
    std::string os_release_orig;
    std::string apt_sources_orig;
    std::string weld_sources_orig;
    std::string os_release_new;
    std::string apt_sources_new;
    std::string weld_sources_new;
    bool backed_up = false;
    bool has_new = false;

    void backup() {
        os_release_orig.clear();
        apt_sources_orig.clear();
        weld_sources_orig.clear();
        read_text_file("/etc/os-release", os_release_orig);
        read_text_file("/etc/apt/sources.list", apt_sources_orig);
        read_text_file("/etc/weld/sources.list", weld_sources_orig);
        backed_up = true;
    }

    void set_new(std::string_view os, std::string_view apt, std::string_view weld) {
        os_release_new = os;
        apt_sources_new = apt;
        weld_sources_new = weld;
        has_new = true;
    }

    void restore_orig() {
        if (!backed_up) return;
        if (!os_release_orig.empty()) write_text_file("/etc/os-release", os_release_orig);
        else unlink("/etc/os-release");
        if (!apt_sources_orig.empty()) write_text_file("/etc/apt/sources.list", apt_sources_orig);
        else unlink("/etc/apt/sources.list");
        if (!weld_sources_orig.empty()) write_text_file("/etc/weld/sources.list", weld_sources_orig);
        else unlink("/etc/weld/sources.list");
    }

    void apply_new() {
        if (!has_new) return;
        if (!os_release_new.empty()) write_text_file("/etc/os-release", os_release_new);
        if (!apt_sources_new.empty()) write_text_file("/etc/apt/sources.list", apt_sources_new);
        if (!weld_sources_new.empty()) write_text_file("/etc/weld/sources.list", weld_sources_new);
    }
};

ConfigBackup g_config_backup;

struct WeldSource {
    std::string base_url;
    std::string release;
};

struct WeldRepoMetadata {
    std::string base_url;
    std::string release;
    std::string name;
    std::string maintainer;
    std::string trusted_comment;
    std::map<std::string, std::pair<std::string, std::string>> packages;
    std::map<std::string, std::string> descriptions;
    std::vector<std::string> required_packages;
    std::map<std::string, std::string> replaces;
};

struct WeldPackageCandidate {
    bool found = false;
    std::string base_url;
    std::string release;
    std::string file_name;
    std::string version;
    std::string sha256;
    std::string actual_pkg_name;
    std::string original_query_name;
    std::string description;
    bool is_replacement = false;
};

struct AptPackageState {
    bool found = false;
    bool installed = false;
    std::string installed_version;
    std::string candidate_version;
};

struct InstallDecision {
    std::string package_name;
    std::string apt_argument;
    std::string selected_version;
    bool from_weld = false;
};

enum class PrecheckResult { Proceed, NoChanges, Failed };

void perform_install_transaction(const std::vector<std::string>& pkgs, bool apply_host, bool is_upgrade = false);
bool run_libapt_transaction(const std::string& action, const std::vector<std::string>& targets,
                             int status_fd, bool quiet);
PrecheckResult precheck_transaction(const std::string& action, const std::vector<std::string>& pkgs, bool quiet);
std::string format_bytes_ext(std::uint64_t bytes);
std::vector<WeldRepoMetadata> load_cached_weld_metadata();

bool nf_tree_available() {
    return access(g_nf_tree_bin.c_str(), X_OK) == 0;
}

void show_help() {
    constexpr std::string_view kTitle = "\033[1;36m";
    constexpr std::string_view kHdr = "\033[1;97m";
    constexpr std::string_view kTx = "\033[38;5;114m";
    constexpr std::string_view kQx = "\033[38;5;179m";
    constexpr std::string_view kDim = "\033[2m";
    constexpr std::string_view kReset = "\033[0m";

    std::print("{}{}{}\n", kTitle, weld_version_str(), kReset);
    std::print("Usage: weld <command> [packages] [options]\n\n");

    std::print("{}Transaction Commands:{}\n", kHdr, kReset);
    std::print("  {}install{}       <pkgs...>   Install packages or local .deb archives\n", kTx, kReset);
    std::print("  {}remove{}        <pkgs...>   Remove packages from the system\n", kTx, kReset);
    std::print("  {}purge{}         <pkgs...>   Remove packages along with their configuration files\n", kTx, kReset);
    std::print("  {}upgrade{}       [pkgs...]   Upgrade all packages, or only those specified\n", kTx, kReset);
    std::print("  {}dist-upgrade{}               Perform a full system release upgrade\n", kTx, kReset);
    std::print("  {}rollback{}                   Revert the last transaction using its pre-transaction snapshot\n\n", kTx, kReset);

    std::print("{}Query Commands:{}\n", kHdr, kReset);
    std::print("  {}search{}        <term>      Search the package index (supports -p <page>)\n", kQx, kReset);
    std::print("  {}info{}          <pkg>       Show package origin, version and SHA256\n", kQx, kReset);
    std::print("  {}why{}           <pkg>       Show why a package is installed (reverse dependencies)\n", kQx, kReset);
    std::print("  {}depends{}       <pkg>       List a package's direct dependencies\n", kQx, kReset);
    std::print("  {}list{}                      List all installed packages\n\n", kQx, kReset);

    std::print("{}Maintenance Commands:{}\n", kHdr, kReset);
#ifdef allow_weld_repositories
    std::print("  sync                      Refresh repository metadata (APT + Weld)\n");
    std::print("  clean                     Clear the APT and Weld package caches\n");
    std::print("  autoclean                 Remove obsolete packages from the APT and Weld caches\n\n");
    std::print("{}Security:{}\n", kHdr, kReset);
    std::print("  Weld repositories are never trusted by default. Every repository\n");
    std::print("  metadata must be accompanied by a minisign signature and verified\n");
    std::print("  against the trusted keyring at {}.\n\n", g_weld_trusted_keys_dir);
#else
    std::print("  sync                      Refresh APT repository metadata\n");
    std::print("  clean                     Clear the APT package cache\n");
    std::print("  autoclean                 Remove obsolete packages from the APT cache\n\n");
    std::print("{}Security:{}\n", kHdr, kReset);
    std::print("  Weld repository support is not compiled in.\n");
    std::print("  Rebuild with -Dallow_weld_repositories to enable Weld repos.\n\n");
#endif

    std::print("{}Options:{}\n", kHdr, kReset);
    std::print("  {}--apply-host{}              Skip sandbox verification and apply directly to the host\n", kDim, kReset);
    std::print("  {}--reinstall{}               Reinstall packages even if already at the same version\n", kDim, kReset);
    std::print("  {}-s, --simulate, --dry-run{} Show what would be done without changing anything\n", kDim, kReset);
    std::print("  {}-y, --yes{}                 Assume yes to all confirmation prompts\n", kDim, kReset);
    std::print("  {}--vb{}                      Enable verbose transaction logging\n", kDim, kReset);
    std::print("  {}-h, --help{}                Show this help message\n", kDim, kReset);
    std::print("  {}-v, --version{}             Show the Weld version\n", kDim, kReset);
}

std::string get_root_device();
std::string get_root_fstype();
std::string get_vg_name(const std::string& lv_path);
bool is_lv_thin(const std::string& lv_path);
double get_vg_free_gb(const std::string& vg_name);
long do_pivot_root(const char* new_root, const char* put_old)
    pre(new_root != nullptr) pre(put_old != nullptr);

void bind_safe_dev_node(const std::string& host_path, const std::string& chroot_path, mode_t mode) {
    struct stat host_st{};
    int host_fd = open(host_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (host_fd < 0) return;
    if (fstat(host_fd, &host_st) != 0) { close(host_fd); return; }
    close(host_fd);

    int dst_fd = open_no_follow(chroot_path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (dst_fd < 0) {
        if (errno == EEXIST) {
            dst_fd = open_no_follow(chroot_path, O_WRONLY | O_NOFOLLOW);
            if (dst_fd < 0) return;
            struct stat dst_st{};
            if (fstat(dst_fd, &dst_st) != 0 || !S_ISCHR(dst_st.st_mode)) {
                close(dst_fd);
                return;
            }
        } else {
            return;
        }
    }
    (void)mode;
    close(dst_fd);

    exec_argv_devnull_out({"mount", "--bind", host_path, chroot_path});
}

void mount_fs() {
    std::error_code ec;
    fs::create_directories(g_tree_root + "/dev", ec);
    fs::create_directories(g_tree_root + "/dev/pts", ec);

    exec_argv_devnull_out({"mount", "-t", "devtmpfs", "-o", "nosuid,noexec,mode=755", "devtmpfs", g_tree_root + "/dev"});
    bind_safe_dev_node("/dev/null",   g_tree_root + "/dev/null",   S_IFCHR | 0666);
    bind_safe_dev_node("/dev/zero",   g_tree_root + "/dev/zero",   S_IFCHR | 0666);
    bind_safe_dev_node("/dev/random", g_tree_root + "/dev/random", S_IFCHR | 0666);
    bind_safe_dev_node("/dev/urandom", g_tree_root + "/dev/urandom", S_IFCHR | 0666);
    bind_safe_dev_node("/dev/full",   g_tree_root + "/dev/full",   S_IFCHR | 0666);
    bind_safe_dev_node("/dev/tty",    g_tree_root + "/dev/tty",    S_IFCHR | 0666);

    exec_argv_devnull_out({"mount", "-t", "devpts", "-o", "nosuid,noexec,mode=620,ptmxmode=666",
                            "devpts", g_tree_root + "/dev/pts"});
    exec_argv_devnull_out({"mount", "-t", "tmpfs", "-o", "nosuid,noexec,mode=755,size=512M",
                            "tmpfs", g_tree_root + "/dev/shm"});

    if (fs::exists("/dev/ptmx", ec)) {
        if (!fs::exists(g_tree_root + "/dev/ptmx", ec)) mknod((g_tree_root + "/dev/ptmx").c_str(), S_IFCHR | 0666, 0);
        exec_argv_devnull_out({"mount", "--bind", "/dev/ptmx", g_tree_root + "/dev/ptmx"});
    }

    exec_argv_devnull_out({"mount", "--bind", "/proc", g_tree_root + "/proc"});
    exec_argv_devnull_out({"mount", "-o", "remount,nosuid,nodev,hidepid=2", g_tree_root + "/proc"});
    exec_argv_devnull_out({"mount", "--bind", "/sys", g_tree_root + "/sys"});
    exec_argv_devnull_out({"mount", "-o", "remount,ro,nosuid,nodev,noexec", g_tree_root + "/sys"});

    exec_argv_devnull_out({"mount", "-t", "tmpfs", "tmpfs", g_tree_root + "/tmp",
                            "-o", "mode=1777,nosuid,nodev,noexec,size=2G"});
    exec_argv_devnull_out({"mount", "-t", "tmpfs", "tmpfs", g_tree_root + "/run",
                            "-o", "mode=755,nosuid,nodev,noexec,size=512M"});

    std::string resolv_target = g_tree_root + "/etc/resolv.conf";
    if (!fs::exists("/etc/resolv.conf")) return;
    if (!fs::exists(resolv_target, ec)) {
        std::ofstream touch(resolv_target);
    }
    exec_argv_devnull_out({"mount", "--bind", "/etc/resolv.conf", resolv_target});
}

void umount_fs() {
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/run"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/tmp"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/etc/resolv.conf"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/shm"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/pts"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/ptmx"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/null"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/zero"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/random"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/urandom"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/full"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/tty"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/proc"});
    exec_argv_devnull_out({"umount", "-l", g_tree_root + "/sys"});
}

std::string get_root_device() {
    std::string out = exec_argv_capture({"findmnt", "-n", "-o", "SOURCE", "/"});
    out = trim_str(out);
    auto bracket = out.find('[');
    if (bracket != std::string::npos) out = out.substr(0, bracket);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' '))
        out.pop_back();
    if (out.empty()) return "";
    if (!is_safe_device_path(out)) return "";
    if (!starts_with(out, "/dev/")) return "";
    return out;
}

std::string get_root_fstype() {
    std::string out = exec_argv_capture({"findmnt", "-n", "-o", "FSTYPE", "/"});
    return trim_str(out);
}

std::string get_vg_name(const std::string& lv_path) {
    std::string out = exec_argv_capture({"lvs", "--noheadings", "-o", "vg_name", lv_path});
    return trim_str(out);
}

bool is_lv_thin(const std::string& lv_path) {
    std::string out = exec_argv_capture({"lvs", "--noheadings", "-o", "segtype", lv_path});
    out = trim_str(out);
    return out.find("thin") != std::string::npos;
}

double get_vg_free_gb(const std::string& vg_name) {
    std::string out = exec_argv_capture({"vgs", "--noheadings", "-o", "vg_free", "--units", "g", vg_name});
    out = trim_str(out);
    auto g = out.find_first_of("gG");
    if (g != std::string::npos) out = out.substr(0, g);
    try { return std::stod(out); } catch (...) { return 0.0; }
}

void restrict_capabilities() {
    struct weld_cap_header {
        uint32_t version;
        int pid;
    };
    struct weld_cap_data {
        uint32_t effective;
        uint32_t permitted;
        uint32_t inheritable;
    };
    weld_cap_header hdr{};
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    weld_cap_data data[2] = {};
    uint32_t keep_mask =
        (1u << CAP_CHOWN) | (1u << CAP_DAC_OVERRIDE) | (1u << CAP_FOWNER) |
        (1u << CAP_FSETID) | (1u << CAP_KILL) | (1u << CAP_SETGID) |
        (1u << CAP_SETUID) | (1u << CAP_SETPCAP) | (1u << CAP_NET_BIND_SERVICE) |
        (1u << CAP_NET_RAW) | (1u << CAP_SYS_CHROOT) | (1u << CAP_MKNOD) |
        (1u << CAP_AUDIT_WRITE) | (1u << CAP_SETFCAP);
    data[0].effective = keep_mask;
    data[0].permitted = keep_mask;
    data[0].inheritable = 0;
    syscall(__NR_capset, &hdr, data);
}

long do_pivot_root(const char* new_root, const char* put_old)
    pre(new_root != nullptr) pre(put_old != nullptr) {
    return syscall(__NR_pivot_root, new_root, put_old);
}

bool check_system_memory(std::size_t min_mb) pre(min_mb > 0) {
    std::ifstream f("/proc/meminfo");
    if (!f) return true;
    std::string line;
    while (std::getline(f, line)) {
        if (!starts_with(line, "MemAvailable:")) continue;
        std::istringstream iss(line.substr(13));
        unsigned long kb = 0;
        iss >> kb;
        unsigned long mb = kb / 1024;
        if (mb < min_mb) {
            log_warning(std::format("insufficient system memory. available: {} MB, minimum required: {} MB.", mb, min_mb));
            log_warning("transaction aborted to prevent system instability.");
            return false;
        }
        return true;
    }
    return true;
}

void apply_strict_resource_limits() {
    struct rlimit rl{};
    rl.rlim_cur = 4096;
    rl.rlim_max = 8192;
    setrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = 8192;
    rl.rlim_max = 16384;
    setrlimit(RLIMIT_NPROC, &rl);
    rl.rlim_cur = 16ULL * 1024 * 1024 * 1024;
    rl.rlim_max = 32ULL * 1024 * 1024 * 1024;
    setrlimit(RLIMIT_FSIZE, &rl);
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
}

bool create_snapshot(const std::string& name)
    pre(!name.empty()) pre(name.find('/') == std::string::npos) {
    if (name.empty() || name.find('/') != std::string::npos) return false;
    if (nf_tree_available()) {
        if (exec_argv_devnull_out_checked({g_nf_tree_bin, "create", name}) == 0) return true;
    }
    std::string root_dev = get_root_device();
    std::string vg_name = get_vg_name(root_dev);
    if (!root_dev.empty() && !vg_name.empty() && is_safe_device_path(root_dev)) {
        std::string snap_name = name + "_" + std::to_string(std::time(nullptr));
        if (is_lv_thin(root_dev)) {
            return exec_argv_devnull_out_checked({"lvcreate", "-s", "-k", "n", "--name", snap_name, root_dev}) == 0;
        }
        return exec_argv_devnull_out_checked({"lvcreate", "-s", "--name", snap_name, "-k", "n", root_dev}) == 0;
    }
    return false;
}

bool manage_sandbox(const std::string& action)
    pre(action == "create" || action == "delete") {
    std::string root_dev = get_root_device();
    std::string vg_name = get_vg_name(root_dev);
    g_cached_root_dev = root_dev;
    g_cached_vg_name = vg_name;
    constexpr std::string_view kSnapLvName = "weld_sandbox_snap";
    const std::string& snap_lv_name = g_cached_snap_lv_name = std::string{kSnapLvName};
    const std::string& snap_dev = g_cached_snap_dev = "/dev/" + vg_name + "/" + snap_lv_name;

    if (action == "create") {
        umount_fs();
        for (int attempt = 0; attempt < 10; ++attempt) {
            if (exec_argv_devnull_out_checked({"umount", g_tree_root}) == 0) break;
            usleep(200000);
        }
        for (int i = 0; i < 20; ++i) {
            if (exec_argv_devnull_out_checked({"umount", "-l", g_tree_root}) != 0) break;
        }
        exec_argv_devnull_out_checked({"udevadm", "settle"});
        if (!snap_dev.empty() && is_safe_device_path(snap_dev)) {
            for (int attempt = 0; attempt < 10; ++attempt) {
                if (exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev}) == 0) break;
                usleep(200000);
            }
        }
        exec_argv_devnull_out_checked({"mkdir", "-p", "/nsm/weld"});

        if (root_dev.empty() || vg_name.empty() || !is_safe_device_path(root_dev)) {
            log_error("unable to determine the root LVM device or volume group.");
            return false;
        }

        bool thin = is_lv_thin(root_dev);
        int rc;
        if (thin) {
            rc = exec_argv_devnull_out_checked({"lvcreate", "-s", "-k", "n", "--name", snap_lv_name, root_dev});
        } else {
            log_warning("root logical volume is not thin-provisioned.");
            log_warning("falling back to thick snapshot. free VG space will be consumed.");
            double free_gb = get_vg_free_gb(vg_name);
            if (free_gb < 1.0) {
                log_error(std::format("insufficient free space in volume group: 1 GB required, {:.2f} GB available.", free_gb));
                return false;
            }
            std::string snap_size = "1G";
            if (free_gb >= 10.0) snap_size = "5G";
            else if (free_gb >= 5.0) snap_size = "3G";
            else if (free_gb >= 2.0) snap_size = "1.5G";
            rc = exec_argv_devnull_out_checked({"lvcreate", "-L", snap_size, "-s", "--name", snap_lv_name, root_dev});
        }
        if (rc != 0) {
            log_error(std::format("LVM snapshot of {} failed (exit code {}).", root_dev, rc));
            return false;
        }

        exec_argv_devnull_out_checked({"lvchange", "-ay", "--ignoreactivationskip", snap_dev});
        exec_argv_devnull_out_checked({"udevadm", "settle"});

        struct stat dev_st{};
        bool dev_ready = false;
        for (int attempt = 0; attempt < 50; ++attempt) {
            if (stat(snap_dev.c_str(), &dev_st) == 0 && S_ISBLK(dev_st.st_mode)) { dev_ready = true; break; }
            usleep(100000);
        }
        if (!dev_ready) {
            log_error(std::format("snapshot device {} did not become available in time.", snap_dev));
            exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev});
            return false;
        }
        exec_argv_devnull_out_checked({"mkdir", "-p", g_tree_root});
        exec_argv_devnull_out_checked({"udevadm", "settle"});
        std::string fstype = trim_str(exec_argv_capture({"blkid", "-s", "TYPE", "-o", "value", snap_dev}));
        if (fstype.empty()) fstype = get_root_fstype();

        int mount_rc;
        if (fstype == "xfs") {
            mount_rc = exec_argv_devnull_out_checked({"mount", "-t", "xfs", "-o", "nouuid", snap_dev, g_tree_root});
        } else if (fstype == "ext4" || fstype == "ext3" || fstype == "ext2") {
            mount_rc = exec_argv_devnull_out_checked({"mount", "-t", fstype, snap_dev, g_tree_root});
            if (mount_rc != 0 && thin) {
                for (int i = 0; i < 20; ++i) {
                    if (exec_argv_devnull_out_checked({"umount", "-l", g_tree_root}) != 0) break;
                }
                exec_argv_devnull_out_checked({"udevadm", "settle"});
                usleep(200000);
                mount_rc = exec_argv_devnull_out_checked({"mount", "-t", fstype, snap_dev, g_tree_root});
            }
        } else if (!fstype.empty() && fstype.find(',') == std::string::npos) {
            mount_rc = exec_argv_devnull_out_checked({"mount", "-t", fstype, snap_dev, g_tree_root});
        } else {
            mount_rc = exec_argv_devnull_out_checked({"mount", snap_dev, g_tree_root});
        }
        if (mount_rc != 0) {
            log_error(std::format("unable to mount snapshot at {} (exit code {}).", g_tree_root, mount_rc));
            exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev});
            return false;
        }

        struct stat st{};
        if (stat(g_tree_root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            log_error(std::format("sandbox root {} was not created.", g_tree_root));
            return false;
        }
        exec_argv_devnull_out_checked({"mkdir", "-p", g_tree_root + "/tmp"});
        exec_argv_devnull_out_checked({"chmod", "1777", g_tree_root + "/tmp"});
        g_sandbox_active.store(true);
        return true;
    } else if (action == "delete") {
        umount_fs();
        bool root_unmounted = false;
        for (int attempt = 0; attempt < 10; ++attempt) {
            if (exec_argv_devnull_out_checked({"umount", g_tree_root}) == 0) { root_unmounted = true; break; }
            usleep(200000);
        }
        if (!root_unmounted) exec_argv_devnull_out_checked({"umount", "-l", g_tree_root});
        exec_argv_devnull_out_checked({"udevadm", "settle"});
        if (!snap_dev.empty() && is_safe_device_path(snap_dev)) {
            for (int attempt = 0; attempt < 10; ++attempt) {
                if (exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev}) == 0) break;
                usleep(200000);
            }
        }
        g_sandbox_active.store(false);
        return true;
    }
    return false;
}

void cleanup_sandbox_on_exit();
void release_system_locks();
bool check_system_locks(bool quiet);

void cleanup_sandbox_on_exit() {
    std::call_once(g_cleanup_once, []() {
        if (g_sandbox_active.load()) {
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/run"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/tmp"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/etc/resolv.conf"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/shm"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/pts"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/ptmx"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/null"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/zero"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/random"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/urandom"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/full"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev/tty"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/dev"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/proc"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root + "/sys"});
            exec_argv_devnull_out({"umount", "-l", g_tree_root});

            std::string vg_name = !g_cached_vg_name.empty() ? g_cached_vg_name : get_vg_name(get_root_device());
            std::string snap_dev = g_cached_snap_dev;
            if (snap_dev.empty() && !vg_name.empty()) {
                snap_dev = "/dev/" + vg_name + "/weld_sandbox_snap";
            }
            if (!snap_dev.empty() && is_safe_device_path(snap_dev)) {
                exec_argv_devnull_out({"lvremove", "-f", snap_dev});
            }
            g_cached_snap_lv_name.clear();
            g_cached_snap_dev.clear();
            g_sandbox_active.store(false);
        }
        g_config_backup.restore_orig();
        release_system_locks();
    });
}

namespace {

void write_signal_msg(int sig) {
    static constexpr std::string_view kPrefix = "E: terminating on signal ";
    char buf[16];
    std::size_t pos = 0;
    if (pos + kPrefix.size() <= sizeof(buf)) {
        std::memcpy(buf + pos, kPrefix.data(), kPrefix.size());
        pos += kPrefix.size();
    }
    char digits[16];
    int len = 0;
    int s = sig;
    if (s == 0) { digits[len++] = '0'; }
    else { while (s > 0 && len < 16) { digits[len++] = static_cast<char>('0' + (s % 10)); s /= 10; } }
    for (int i = len - 1; i >= 0 && pos < sizeof(buf); --i) {
        buf[pos++] = digits[i];
    }
    if (pos < sizeof(buf)) buf[pos++] = '\n';
    ssize_t written = write(STDERR_FILENO, buf, pos);
    (void)written;
}

}

void handle_termination_signal(int sig) {
    write_signal_msg(sig);
    struct sigaction sa{};
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(sig, &sa, nullptr);
    raise(sig);
}

void setup_safety_handlers() {
    atexit(cleanup_sandbox_on_exit);
    struct sigaction sa{};
    sa.sa_handler = handle_termination_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
}

std::string get_latest_snapshot(const std::string& prefix) {
    DIR* dir = opendir(g_auto_snap_dir.c_str());
    if (!dir) return {};
    struct dirent* entry;
    std::vector<std::string> matches;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (starts_with(name, prefix)) matches.push_back(name);
    }
    closedir(dir);
    if (matches.empty()) return {};
    std::ranges::sort(matches);
    return matches.back();
}

void do_rollback(const std::string& prefix) {
    if (!nf_tree_available()) return;
    std::string root_snap = get_latest_snapshot("root-auto-" + prefix);
    if (!root_snap.empty()) {
        std::print("Rolling back to snapshot: {}\n", root_snap);
        exec_argv_devnull_out({g_nf_tree_bin, "rollback", root_snap});
    }
}

std::string format_bytes_ext(std::uint64_t bytes) {
    return format_bytes(bytes);
}

std::string render_sync_progress(int percentage, const std::string& label) {
    if (percentage < 0) percentage = 0;
    if (percentage > 100) percentage = 100;
    const int total_width = 60;
    std::string prefix = label + " ";
    std::string pct = std::format("{}%", percentage);
    while (pct.size() < 4) pct = " " + pct;
    int bar_width = total_width - static_cast<int>(prefix.size()) - static_cast<int>(pct.size()) - 1;
    if (bar_width < 1) bar_width = 1;
    int filled = (percentage * bar_width) / 100;
    std::string bar;
    bar.reserve(static_cast<std::size_t>(bar_width));
    for (int i = 0; i < filled; ++i) bar += '-';
    for (int i = filled; i < bar_width; ++i) bar += ' ';
    return std::format("\r{}{} {} {}", prefix, bar, "", pct);
}

std::string render_weld_progress(int percentage, const std::string& label) {
    if (percentage < 0) percentage = 0;
    if (percentage > 100) percentage = 100;
    const int bar_width = 32;
    int filled = (percentage * bar_width) / 100;
    std::string bar;
    bar.reserve(static_cast<std::size_t>(bar_width));
    for (int i = 0; i < filled; ++i) bar += '-';
    for (int i = filled; i < bar_width; ++i) bar += ' ';
    char pct_buf[16];
    std::snprintf(pct_buf, sizeof(pct_buf), "%3d%%", percentage);
    constexpr std::string_view kDim = "\033[38;5;250m";
    constexpr std::string_view kAccent = "\033[38;5;117m";
    constexpr std::string_view kReset = "\033[0m";
    return std::format("\r{}{}{} {}{}{} {}", kAccent, label, kReset, kDim, bar, kReset, pct_buf);
}

class WeldAcquireStatus final : public pkgAcquireStatus {
    int fd_;
    bool show_host_;
    std::string label_;
    int last_shown_ = -1;
public:
    WeldAcquireStatus(int fd, bool show_host, std::string label = "packages")
        : fd_(fd), show_host_(show_host), label_(std::move(label)) {}
    bool MediaChange(std::string, std::string) override { return false; }
    bool Pulse(pkgAcquire* owner) override {
        pkgAcquireStatus::Pulse(owner);
        int pct = static_cast<int>(Percent);
        if (fd_ >= 0) {
            std::string line = std::format("dlstatus:0:{}:Downloading\n", Percent);
            ssize_t written = write(fd_, line.c_str(), line.size());
            (void)written;
        } else if (show_host_ && pct != last_shown_) {
            std::cout << render_sync_progress(pct, label_) << std::flush;
            last_shown_ = pct;
        }
        return true;
    }
    void Stop() override {
        pkgAcquireStatus::Stop();
        if (fd_ < 0 && show_host_) std::cout << "\n";
    }
};

class WeldSyncStatus final : public pkgAcquireStatus {
    std::string label_;
    int last_pct_ = -1;
public:
    explicit WeldSyncStatus(std::string label) : label_(std::move(label)) {}
    bool MediaChange(std::string, std::string) override { return false; }
    bool Pulse(pkgAcquire* owner) override {
        pkgAcquireStatus::Pulse(owner);
        int pct = static_cast<int>(Percent);
        if (pct != last_pct_) {
            std::cout << render_sync_progress(pct, label_) << std::flush;
            last_pct_ = pct;
        }
        return true;
    }
    void Stop() override {
        pkgAcquireStatus::Stop();
        std::cout << render_sync_progress(100, label_) << "\n";
    }
};

std::string local_deb_package_name(const std::string& path) {
    FileFd fd;
    if (!fd.Open(path, FileFd::ReadOnly)) return "";
    debDebFile deb(fd);
    debDebFile::MemControlExtract extract;
    if (!extract.Read(deb)) return "";
    return extract.Section.FindS("Package");
}

bool register_local_debs(pkgSourceList* src_list, const std::vector<std::string>& targets,
                         std::map<std::string, std::string>& local_pkg_names, bool quiet) {
    for (const auto& t : targets) {
        if (!ends_with(t, ".deb")) continue;
        std::string pkg_name = local_deb_package_name(t);
        if (pkg_name.empty()) {
            if (!quiet) log_error(std::format("could not determine package name for {}", t));
            _error->DumpErrors();
            return false;
        }
        if (!src_list->AddVolatileFile(t)) {
            if (!quiet) log_error(std::format("failed to register local package {}", t));
            _error->DumpErrors();
            return false;
        }
        local_pkg_names[t] = pkg_name;
    }
    return true;
}

bool run_libapt_transaction(const std::string& action, const std::vector<std::string>& targets,
                             int status_fd, bool quiet) {
    if (status_fd >= 0) _config->Set("APT::Status-Fd", status_fd);
    _config->Set("Dpkg::Use-Pty", "false");
    _config->Set("APT::Sandbox::User", "root");

    pkgCacheFile cache_file;
    pkgSourceList* src_list = cache_file.GetSourceList();
    if (src_list == nullptr) { _error->DumpErrors(); return false; }

    std::map<std::string, std::string> local_pkg_names;
    if (!register_local_debs(src_list, targets, local_pkg_names, quiet)) return false;

    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();
    if (cache == nullptr || dep_cache == nullptr) { _error->DumpErrors(); return false; }

    pkgProblemResolver fixer(dep_cache);

    if (action == "install") {
        for (const auto& t : targets) {
            std::string pkg_name = ends_with(t, ".deb") ? local_pkg_names[t] : t;
            pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
            if (pkg.end()) {
                if (!quiet) log_error(std::format("package {} not found", pkg_name));
                return false;
            }
            fixer.Clear(pkg);
            fixer.Protect(pkg);
            if (g_force_reinstall.load()) dep_cache->SetReInstall(pkg, true);
            dep_cache->MarkInstall(pkg, true);
            if (!(*dep_cache)[pkg].Install()) {
                if (!quiet) log_error(std::format("unable to mark {} for installation", pkg_name));
                _error->DumpErrors();
                return false;
            }
        }
    } else if (action == "remove" || action == "purge") {
        bool purge = (action == "purge");
        for (const auto& pkg_name : targets) {
            pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
            if (pkg.end()) continue;
            fixer.Clear(pkg);
            fixer.Protect(pkg);
            dep_cache->MarkDelete(pkg, purge);
        }
    } else if (action == "upgrade") {
        if (!APT::Upgrade::Upgrade(*dep_cache,
                APT::Upgrade::FORBID_REMOVE_PACKAGES | APT::Upgrade::FORBID_INSTALL_NEW_PACKAGES)) {
            _error->DumpErrors();
            return false;
        }
    } else if (action == "dist-upgrade") {
        if (!APT::Upgrade::Upgrade(*dep_cache, APT::Upgrade::ALLOW_EVERYTHING)) {
            _error->DumpErrors();
            return false;
        }
    } else {
        if (!quiet) log_error(std::format("unknown transaction: {}", action));
        return false;
    }

    if (!fixer.Resolve(true) || _error->PendingError()) {
        if (!quiet) log_error("unable to resolve dependencies for this transaction");
        _error->DumpErrors();
        return false;
    }

    std::unique_ptr<pkgPackageManager> pm(_system->CreatePM(dep_cache));
    if (!pm) { _error->DumpErrors(); return false; }

    pkgAcquire fetcher;
    pkgRecords recs(*cache);

    if (!pm->GetArchives(&fetcher, src_list, &recs) || _error->PendingError()) {
        _error->DumpErrors();
        return false;
    }

    if (!quiet && status_fd < 0) {
        unsigned long long need = fetcher.FetchNeeded();
        if (need > 0) {
            if (need < 1024ULL * 1024)
                std::print("Downloading packages ({} KB)...\n", need / 1024);
            else
                std::print("Downloading packages ({} MB)...\n", need / 1024 / 1024);
        }
    }

    WeldAcquireStatus acquire_status(status_fd, !quiet && status_fd < 0);
    fetcher.SetLog(&acquire_status);
    if (fetcher.Run() != pkgAcquire::Continue) {
        _error->DumpErrors();
        return false;
    }

    std::unique_ptr<APT::Progress::PackageManager> pm_progress;
    if (status_fd >= 0)
        pm_progress = std::make_unique<APT::Progress::PackageManagerProgressFd>(status_fd);
    else
        pm_progress = std::make_unique<APT::Progress::PackageManager>();

    pkgPackageManager::OrderResult result = pm->DoInstall(pm_progress.get());
    if (result != pkgPackageManager::Completed) {
        _error->DumpErrors();
        return false;
    }
    return true;
}

#ifdef allow_weld_repositories
std::string normalize_weld_base_url(const std::string& raw_url) {
    std::string url = trim_copy(raw_url);
    if (!starts_with(url, "http://") && !starts_with(url, "https://"))
        url = "https://" + url;
    while (!url.empty() && url.back() == '/') url.pop_back();
    return url;
}

bool parse_weld_source_line(const std::string& raw_line, WeldSource& source) {
    std::string line = trim_copy(raw_line);
    if (line.empty() || line[0] == '#') return false;
    std::istringstream iss(line);
    std::string type, base_url, release;
    if (!(iss >> type >> base_url >> release)) return false;
    if (type != "deb") return false;
    base_url = normalize_weld_base_url(base_url);
    release = trim_copy(release);
    if (base_url.empty() || release.empty()) return false;
    source.base_url = base_url;
    source.release = release;
    return true;
}

void load_weld_sources_from_file(const std::string& path, std::vector<WeldSource>& sources) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        WeldSource source;
        if (parse_weld_source_line(line, source)) sources.push_back(source);
    }
}
#endif

std::vector<WeldSource> load_weld_sources() {
#ifndef allow_weld_repositories
    return {};
#else
    std::vector<WeldSource> sources;
    if (path_is_regular_file(g_weld_sources_file))
        load_weld_sources_from_file(g_weld_sources_file, sources);
    if (path_is_directory(g_weld_sources_dir)) {
        DIR* dir = opendir(g_weld_sources_dir.c_str());
        if (dir != nullptr) {
            std::vector<std::string> files;
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                std::string name = entry->d_name;
                if (name == "." || name == "..") continue;
                std::string path = g_weld_sources_dir + "/" + name;
                if (path_is_regular_file(path)) files.push_back(path);
            }
            closedir(dir);
            std::ranges::sort(files);
            for (const auto& path : files) load_weld_sources_from_file(path, sources);
        }
    }
    return sources;
#endif
}

bool parse_weld_repo_metadata_v2(const std::string& text, WeldRepoMetadata& metadata, std::string& error_out) {
    metadata.packages.clear();
    metadata.required_packages.clear();
    metadata.replaces.clear();
    metadata.descriptions.clear();
    metadata.name.clear();
    metadata.maintainer.clear();

    enum class Section { None, RepoInfo, Packages, Replaces, Required };
    Section current_section = Section::None;

    bool seen_repoinfo = false;
    bool seen_pkgs = false;
    bool seen_replaces = false;
    bool seen_required = false;

    struct TempPkg {
        std::string name;
        std::string description;
        std::string sha256;
        std::string deb;
    };
    struct TempReplaces {
        std::string name;
        std::string replaces;
    };
    struct TempRequired {
        std::string name;
    };

    TempPkg pending_pkg;
    bool has_pending_pkg = false;
    TempReplaces pending_rep;
    bool has_pending_rep = false;
    TempRequired pending_req;
    bool has_pending_req = false;

    std::string cur_repo_name;
    std::string cur_repo_maintainer;
    bool has_pending_repo = false;

    auto flush_repo = [&]() -> bool {
        if (!has_pending_repo) return true;
        if (cur_repo_name.empty() && cur_repo_maintainer.empty()) {
            has_pending_repo = false;
            return true;
        }
        if (cur_repo_name.empty()) {
            error_out = "repoinfo record missing required field: name";
            return false;
        }
        if (cur_repo_maintainer.empty()) {
            error_out = "repoinfo record missing required field: maintainer";
            return false;
        }
        metadata.name = cur_repo_name;
        metadata.maintainer = cur_repo_maintainer;
        cur_repo_name.clear();
        cur_repo_maintainer.clear();
        has_pending_repo = false;
        return true;
    };

    auto flush_pkg = [&]() -> bool {
        if (!has_pending_pkg) return true;
        if (pending_pkg.name.empty()) {
            has_pending_pkg = false;
            pending_pkg = TempPkg();
            return true;
        }
        if (pending_pkg.sha256.empty()) {
            error_out = std::format("package record for '{}' missing required field: sha256", pending_pkg.name);
            return false;
        }
        if (pending_pkg.deb.empty()) {
            error_out = std::format("package record for '{}' missing required field: deb", pending_pkg.name);
            return false;
        }
        metadata.packages[pending_pkg.name] = {pending_pkg.deb, pending_pkg.sha256};
        metadata.descriptions[pending_pkg.name] = pending_pkg.description;
        pending_pkg = TempPkg();
        has_pending_pkg = false;
        return true;
    };

    auto flush_rep = [&]() -> bool {
        if (!has_pending_rep) return true;
        if (pending_rep.name.empty()) {
            has_pending_rep = false;
            pending_rep = TempReplaces();
            return true;
        }
        if (pending_rep.replaces.empty()) {
            error_out = std::format("replaces record for '{}' missing required field: replaces", pending_rep.name);
            return false;
        }
        metadata.replaces[pending_rep.replaces] = pending_rep.name;
        pending_rep = TempReplaces();
        has_pending_rep = false;
        return true;
    };

    auto flush_req = [&]() -> bool {
        if (!has_pending_req) return true;
        if (pending_req.name.empty()) {
            has_pending_req = false;
            pending_req = TempRequired();
            return true;
        }
        metadata.required_packages.push_back(pending_req.name);
        pending_req = TempRequired();
        has_pending_req = false;
        return true;
    };

    std::stringstream ss(text);
    std::string raw_line;
    while (std::getline(ss, raw_line)) {
        std::string line = strip_inline_comment(raw_line);
        std::string trimmed = trim_copy(line);
        if (trimmed.empty()) continue;

        if (trimmed == "[repoinfo_st]") {
            current_section = Section::RepoInfo;
            has_pending_repo = false;
            cur_repo_name.clear();
            cur_repo_maintainer.clear();
            seen_repoinfo = true;
            continue;
        }
        if (trimmed == "[repoinfo_fn]") {
            if (current_section != Section::RepoInfo) {
                error_out = "[repoinfo_fn] without matching [repoinfo_st]";
                return false;
            }
            if (!flush_repo()) return false;
            current_section = Section::None;
            continue;
        }
        if (trimmed == "[pkgs_st]") {
            current_section = Section::Packages;
            has_pending_pkg = false;
            pending_pkg = TempPkg();
            seen_pkgs = true;
            continue;
        }
        if (trimmed == "[pkgs_fn]") {
            if (current_section != Section::Packages) {
                error_out = "[pkgs_fn] without matching [pkgs_st]";
                return false;
            }
            if (!flush_pkg()) return false;
            current_section = Section::None;
            continue;
        }
        if (trimmed == "[replaces_st]") {
            current_section = Section::Replaces;
            has_pending_rep = false;
            pending_rep = TempReplaces();
            seen_replaces = true;
            continue;
        }
        if (trimmed == "[replaces_fn]") {
            if (current_section != Section::Replaces) {
                error_out = "[replaces_fn] without matching [replaces_st]";
                return false;
            }
            if (!flush_rep()) return false;
            current_section = Section::None;
            continue;
        }
        if (trimmed == "[required_st]") {
            current_section = Section::Required;
            has_pending_req = false;
            pending_req = TempRequired();
            seen_required = true;
            continue;
        }
        if (trimmed == "[required_fn]") {
            if (current_section != Section::Required) {
                error_out = "[required_fn] without matching [required_st]";
                return false;
            }
            if (!flush_req()) return false;
            current_section = Section::None;
            continue;
        }

        if (trimmed == "}") {
            if (current_section == Section::RepoInfo) {
                if (!flush_repo()) return false;
                has_pending_repo = true;
            } else if (current_section == Section::Packages) {
                if (!flush_pkg()) return false;
                has_pending_pkg = true;
            } else if (current_section == Section::Replaces) {
                if (!flush_rep()) return false;
                has_pending_rep = true;
            } else if (current_section == Section::Required) {
                if (!flush_req()) return false;
                has_pending_req = true;
            }
            continue;
        }

        if (current_section == Section::None) continue;

        auto colon = trimmed.find(':');
        if (colon == std::string::npos) continue;

        std::string key = trim_copy(trimmed.substr(0, colon));
        std::string value = strip_quotes(trim_copy(trimmed.substr(colon + 1)));

        if (current_section == Section::RepoInfo) {
            if (!has_pending_repo) continue;
            if (key == "name") cur_repo_name = value;
            else if (key == "maintainer") cur_repo_maintainer = value;
        } else if (current_section == Section::Packages) {
            if (!has_pending_pkg) continue;
            if (key == "name") pending_pkg.name = value;
            else if (key == "description") pending_pkg.description = value;
            else if (key == "sha256") pending_pkg.sha256 = value;
            else if (key == "deb") pending_pkg.deb = value;
        } else if (current_section == Section::Replaces) {
            if (!has_pending_rep) continue;
            if (key == "name") pending_rep.name = value;
            else if (key == "replaces") pending_rep.replaces = value;
        } else if (current_section == Section::Required) {
            if (!has_pending_req) continue;
            if (key == "name") pending_req.name = value;
        }
    }

    if (!seen_repoinfo) {
        error_out = "missing [repoinfo_st]/[repoinfo_fn] section";
        return false;
    }
    if (!seen_pkgs) {
        error_out = "missing [pkgs_st]/[pkgs_fn] section";
        return false;
    }
    if (!seen_replaces) {
        error_out = "missing [replaces_st]/[replaces_fn] section";
        return false;
    }
    if (!seen_required) {
        error_out = "missing [required_st]/[required_fn] section";
        return false;
    }
    if (metadata.name.empty() || metadata.maintainer.empty()) {
        error_out = "repoinfo record missing required fields (name, maintainer)";
        return false;
    }
    return true;
}

struct CurlStringCtx {
    std::string* dest;
    std::size_t max_size;
    bool overflow = false;
};

std::size_t curl_string_write_cb(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    std::size_t total = size * nmemb;
    auto* ctx = static_cast<CurlStringCtx*>(userdata);
    if (ctx->dest->size() + total > ctx->max_size) {
        ctx->overflow = true;
        return 0;
    }
    ctx->dest->append(ptr, total);
    return total;
}

std::string curl_fetch_string(const std::string& url, const std::string& user_agent = "",
                              long timeout_sec = 30, std::size_t max_size = kWeldMaxMetadataSize) {
    if (url.empty()) return "";
    auto start = url.find_first_not_of(" \n\r\t");
    std::string norm_url = (start == std::string::npos)
        ? std::string{}
        : url.substr(start, url.find_last_not_of(" \n\r\t") - start + 1);
    if (norm_url.empty() || norm_url.front() == '-') return "";
    if (!starts_with(norm_url, "https://")) return "";
    if (norm_url.size() > 4096) return "";

    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string response;
    CurlStringCtx ctx{&response, max_size, false};
    curl_easy_setopt(curl, CURLOPT_URL, norm_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_string_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_sec);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (!user_agent.empty()) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());
    } else {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Weld/4.4");
    }

    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || response_code != 200) return "";
    if (ctx.overflow) return "";
    return response;
}

std::size_t curl_file_write_cb(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    FILE* fp = static_cast<FILE*>(userdata);
    return fwrite(ptr, size, nmemb, fp);
}

bool curl_download_file(const std::string& url, const std::string& dest_path, const std::string& user_agent = "") {
    if (url.empty() || dest_path.empty()) return false;
    if (!starts_with(url, "https://")) return false;

    FILE* fp = fopen(dest_path.c_str(), "wb");
    if (!fp) return false;
    CURL* curl = curl_easy_init();
    if (!curl) {
        fclose(fp);
        unlink(dest_path.c_str());
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_file_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (!user_agent.empty()) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());
    } else {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Weld/4.4");
    }

    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    fclose(fp);

    if (res != CURLE_OK || response_code != 200) {
        unlink(dest_path.c_str());
        return false;
    }
    return true;
}

bool sync_weld_metadata() {
#ifndef allow_weld_repositories
    return true;
#else
    std::vector<WeldSource> sources = load_weld_sources();
    if (sources.empty()) return true;

    exec_argv_devnull_out({"mkdir", "-p", g_weld_etc_dir});
    exec_argv_devnull_out({"mkdir", "-p", g_weld_trusted_keys_dir});

    std::vector<MinisignPublicKey> trusted_keys = load_trusted_minisign_keys();
    if (trusted_keys.empty()) {
        log_error(std::format("no trusted minisign keys found in {}", g_weld_trusted_keys_dir));
        log_error("to enable Weld repositories, install a valid '*.pub' keyring and run 'weld sync' again.");
        return false;
    }

    std::atomic<int> completed(0);
    int total = static_cast<int>(sources.size());
    safe_log(render_sync_progress(0, "Syncing Weld Repositories"));

    std::vector<std::future<bool>> futures;
    futures.reserve(sources.size());

    for (const auto& source : sources) {
        futures.push_back(std::async(std::launch::async, [source, &completed, total]() -> bool {
            std::string meta_url = source.base_url + "/releases/" + source.release + "/repo-metadata";
            std::string sig_url  = meta_url + ".minisig";

            std::string metadata = curl_fetch_string(meta_url);
            if (metadata.empty()) {
                safe_log("\nE: Failed to fetch repository metadata from ", meta_url, "\n");
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }

            std::string signature = curl_fetch_string(sig_url);
            if (signature.empty()) {
                safe_log("\nE: Repository ", source.base_url, " is missing its minisign signature.\n");
                safe_log("E: Expected signature file: ", sig_url, "\n");
                safe_log("E: Weld refuses to trust unsigned repository metadata.\n");
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }

            std::string trusted_comment;
            std::string verify_err;
            if (!verify_repo_metadata_signature(metadata, signature, trusted_comment, verify_err)) {
                safe_log("\nE: Signature verification failed for ", source.base_url, ": ", verify_err, "\n");
                safe_log("E: Weld refuses to use this repository.\n");
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }

            std::string safe_release = sanitize_filename(source.release);
            std::string release_dir = g_weld_etc_dir + "/" + safe_release;
            if (exec_argv_devnull_out({"mkdir", "-p", release_dir}) != 0) {
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }
            std::string output_path = release_dir + "/repo-metadata";
            if (!write_text_file(output_path, metadata)) {
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }
            std::string sig_output_path = release_dir + "/repo-metadata.minisig";
            if (!write_text_file(sig_output_path, signature)) {
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }
            int done = completed.fetch_add(1) + 1;
            int pct = (done * 100) / total;
            safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
            return true;
        }));
    }

    bool ok = true;
    for (auto& fut : futures) {
        if (!fut.get()) ok = false;
    }
    safe_log(render_sync_progress(100, "Syncing Weld Repositories"), "\n");
    return ok;
#endif
}

bool clean_apt_archives_cache() {
    std::string archives = _config->FindDir("Dir::Cache::archives");
    if (archives.empty()) archives = "/var/cache/apt/archives/";
    if (!archives.empty() && archives.back() != '/') archives += "/";

    std::error_code ec;
    if (!fs::exists(archives, ec)) {
        std::print("APT archives directory does not exist: {}\n", archives);
        return true;
    }

    bool removed_any = false;
    std::uint64_t bytes_freed = 0;

    for (const auto& entry : fs::directory_iterator(archives, ec)) {
        if (ec) {
            std::print("E: Failed to read APT archives directory: {}\n", archives);
            return false;
        }
        std::string name = entry.path().filename().string();
        if (name == "partial" || name == "lock") continue;

        std::error_code fec;
        if (!entry.is_regular_file(fec)) continue;

        std::uint64_t sz = entry.file_size(fec);
        std::error_code rm_ec;
        fs::remove(entry.path(), rm_ec);
        if (!rm_ec) {
            bytes_freed += sz;
            removed_any = true;
        }
    }

    if (removed_any)
        std::print("APT archives cleaned: {} ({} freed)\n", archives, format_bytes(bytes_freed));
    else
        std::print("APT archives already clean: {}\n", archives);
    return true;
}

bool clean_weld_cache_only() {
#ifndef allow_weld_repositories
    return true;
#else
    std::error_code ec;
    std::string cache_dir = g_weld_cache_dir;
    if (!fs::exists(cache_dir, ec)) {
        if (!fs::create_directories(cache_dir, ec)) {
            log_error(std::format("failed to create Weld cache directory: {}", cache_dir));
            return false;
        }
        std::print("Weld cache is already clean.\n");
        return true;
    }
    bool removed_any = false;
    for (const auto& entry : fs::directory_iterator(cache_dir, ec)) {
        if (ec) {
            log_error(std::format("failed to read Weld cache directory: {}", cache_dir));
            return false;
        }
        fs::remove_all(entry.path(), ec);
        if (ec) {
            log_error(std::format("failed to remove: {}", entry.path().string()));
            return false;
        }
        removed_any = true;
    }
    if (!fs::exists(cache_dir, ec) && !fs::create_directories(cache_dir, ec)) {
        log_error(std::format("failed to recreate Weld cache directory: {}", cache_dir));
        return false;
    }
    if (removed_any)
        std::print("Weld cache cleaned: {}\n", cache_dir);
    else
        std::print("Weld cache is already clean.\n");
    return true;
#endif
}

bool clean_weld_cache() {
    bool apt_ok = clean_apt_archives_cache();
    bool weld_ok = clean_weld_cache_only();
    return apt_ok && weld_ok;
}

class WeldArchiveCleaner final : public pkgArchiveCleaner {
public:
    std::size_t   removed_count = 0;
    std::uint64_t bytes_freed = 0;
protected:
    void Erase(int const dirfd, char const * const File,
               std::string const &Pkg, std::string const &Ver,
               struct stat const &St) override {
        (void)Pkg; (void)Ver;
        bytes_freed += static_cast<std::uint64_t>(St.st_size);
        if (unlinkat(dirfd, File, 0) == 0) ++removed_count;
    }
};

bool autoclean_apt_archives_cache() {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) {
        _error->DumpErrors();
        log_error("unable to open APT package cache for autoclean");
        return false;
    }

    std::string archives = _config->FindDir("Dir::Cache::archives");
    if (archives.empty()) archives = "/var/cache/apt/archives/";
    if (!archives.empty() && archives.back() != '/') archives += "/";

    std::error_code ec;
    if (!fs::exists(archives, ec)) {
        std::print("APT archives directory does not exist: {}\n", archives);
        return true;
    }
    if (!fs::exists(archives + "partial", ec)) {
        std::print("W: APT archives partial directory missing, skipping APT autoclean: {}partial/\n", archives);
        return true;
    }

    WeldArchiveCleaner cleaner;
    if (!cleaner.Go(archives, *cache)) {
        _error->DumpErrors();
        log_error(std::format("APT autoclean encountered errors while cleaning: {}", archives));
        return false;
    }
    _error->DumpErrors();

    if (cleaner.removed_count > 0) {
        std::print("APT autoclean removed {} obsolete .deb file(s) ({} freed)\n",
            cleaner.removed_count, format_bytes(cleaner.bytes_freed));
    } else {
        std::print("APT archives: no obsolete packages found.\n");
    }
    return true;
}

bool autoclean_weld_cache_only() {
#ifndef allow_weld_repositories
    return true;
#else
    std::error_code ec;
    std::string cache_dir = g_weld_cache_dir;
    if (!fs::exists(cache_dir, ec)) {
        std::print("Weld cache directory does not exist: {}\n", cache_dir);
        return true;
    }

    std::vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    std::set<std::string> valid_filenames;
    for (const auto& repo : repos) {
        for (const auto& entry : repo.packages) {
            valid_filenames.insert(path_basename(entry.second.first));
        }
    }

    bool removed_any = false;
    std::uint64_t bytes_freed = 0;

    for (const auto& rel_entry : fs::directory_iterator(cache_dir, ec)) {
        if (!rel_entry.is_directory()) continue;
        for (const auto& file_entry : fs::directory_iterator(rel_entry.path(), ec)) {
            if (!file_entry.is_regular_file()) continue;
            std::string filename = file_entry.path().filename().string();
            if (valid_filenames.find(filename) == valid_filenames.end()) {
                std::uint64_t sz = file_entry.file_size(ec);
                if (!ec) bytes_freed += sz;
                fs::remove(file_entry.path(), ec);
                if (!ec) {
                    std::print("Weld autoclean removed stale package: {}\n", filename);
                    removed_any = true;
                }
            }
        }
    }

    if (removed_any) {
        std::print("Weld autoclean finished. Space freed: {}\n", format_bytes(bytes_freed));
    } else {
        std::print("Weld cache is already clean. No obsolete packages found.\n");
    }
    return true;
#endif
}

bool autoclean_weld_cache() {
    bool apt_ok = autoclean_apt_archives_cache();
    bool weld_ok = autoclean_weld_cache_only();
    return apt_ok && weld_ok;
}

void print_install_already_present_message(const std::string& pkg_name, bool is_upgrade) {
    if (is_upgrade) {
        std::print("{} is already up to date.\n", pkg_name);
        return;
    }
    std::print("{} is already installed. To upgrade it, run weld upgrade {}\n", pkg_name, pkg_name);
    std::print("or weld upgrade with no arguments to upgrade all packages.\n");
    std::print("For large transactions, --apply-host skips the chroot verification step.\n");
}

std::vector<WeldRepoMetadata> load_cached_weld_metadata() {
#ifndef allow_weld_repositories
    return {};
#else
    std::vector<WeldRepoMetadata> repos;
    std::vector<WeldSource> sources = load_weld_sources();
    std::vector<MinisignPublicKey> trusted_keys = load_trusted_minisign_keys();
    if (trusted_keys.empty()) return repos;

    for (const auto& source : sources) {
        std::string path = g_weld_etc_dir + "/" + sanitize_filename(source.release) + "/repo-metadata";
        std::string content;
        if (!read_text_file(path, content)) continue;

        std::string sig_path = g_weld_etc_dir + "/" + sanitize_filename(source.release) + "/repo-metadata.minisig";
        std::string sig_content;
        if (!read_text_file(sig_path, sig_content)) {
            log_error(std::format("repository {} is missing its minisign signature file. refusing to load.",
                source.base_url));
            continue;
        }

        std::string trusted_comment;
        std::string verify_err;
        if (!verify_repo_metadata_signature(content, sig_content, trusted_comment, verify_err)) {
            log_error(std::format("cached signature for {} is invalid: {}. refusing to load.",
                source.base_url, verify_err));
            continue;
        }

        WeldRepoMetadata metadata;
        metadata.base_url = source.base_url;
        metadata.release = source.release;
        metadata.trusted_comment = trusted_comment;
        std::string parse_err;
        if (!parse_weld_repo_metadata_v2(content, metadata, parse_err)) {
            log_error(std::format("metadata for {} is malformed: {}. refusing to load.",
                source.base_url, parse_err));
            continue;
        }
        if (metadata.release.empty()) metadata.release = source.release;
        repos.push_back(metadata);
    }
    return repos;
#endif
}

int compare_versions(const std::string& a, const std::string& b)
    post(r: r >= -1 && r <= 1) {
    if (a.empty() && b.empty()) return 0;
    if (a.empty()) return -1;
    if (b.empty()) return 1;
    if (_system != nullptr && _system->VS != nullptr)
        return _system->VS->CmpVersion(a.c_str(), b.c_str());
    if (a == b) return 0;
    return a < b ? -1 : 1;
}

std::string extract_weld_version(const std::string& pkg_name, const std::string& file_name) {
    std::string base = path_basename(trim_copy(file_name));
    if (!ends_with(base, ".deb")) return "";
    std::string stem = base.substr(0, base.size() - 4);
    std::string rest;
    if (starts_with(stem, pkg_name + "_"))
        rest = stem.substr(pkg_name.size() + 1);
    else if (starts_with(stem, pkg_name + "-"))
        rest = stem.substr(pkg_name.size() + 1);
    else
        return "";
    auto split = rest.find_last_of('_');
    if (split != std::string::npos && split > 0) return rest.substr(0, split);
    split = rest.find_last_of('-');
    if (split != std::string::npos && split > 0) return rest.substr(0, split);
    return rest;
}

AptPackageState get_apt_package_state(pkgCacheFile& cache_file, const std::string& pkg_name) {
    AptPackageState state;
    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();
    if (cache == nullptr || dep_cache == nullptr) return state;
    pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
    if (pkg.end()) return state;
    state.found = true;
    if (pkg->CurrentVer != 0) {
        state.installed = true;
        state.installed_version = pkg.CurrentVer().VerStr();
    }
    pkgCache::VerIterator cand = dep_cache->GetCandidateVersion(pkg);
    if (!cand.end()) state.candidate_version = cand.VerStr();
    return state;
}

WeldPackageCandidate find_best_weld_candidate(const std::vector<WeldRepoMetadata>& repos, const std::string& pkg_name)
    pre(!pkg_name.empty()) {
    WeldPackageCandidate best;
    for (const auto& repo : repos) {
        auto it = repo.packages.find(pkg_name);
        if (it == repo.packages.end()) continue;
        WeldPackageCandidate candidate;
        candidate.found = true;
        candidate.base_url = repo.base_url;
        candidate.release = repo.release;
        candidate.file_name = it->second.first;
        candidate.sha256 = it->second.second;
        candidate.actual_pkg_name = pkg_name;
        candidate.original_query_name = pkg_name;
        candidate.is_replacement = false;
        candidate.description = repo.descriptions.count(pkg_name) ? repo.descriptions.at(pkg_name) : "";
        candidate.version = extract_weld_version(pkg_name, candidate.file_name);
        if (!best.found || compare_versions(candidate.version, best.version) > 0)
            best = candidate;
    }
    if (best.found) return best;

    for (const auto& repo : repos) {
        auto rep_it = repo.replaces.find(pkg_name);
        if (rep_it == repo.replaces.end()) continue;

        std::string target_weld_pkg = rep_it->second;
        auto it = repo.packages.find(target_weld_pkg);
        if (it == repo.packages.end()) continue;

        WeldPackageCandidate candidate;
        candidate.found = true;
        candidate.base_url = repo.base_url;
        candidate.release = repo.release;
        candidate.file_name = it->second.first;
        candidate.sha256 = it->second.second;
        candidate.actual_pkg_name = target_weld_pkg;
        candidate.original_query_name = pkg_name;
        candidate.is_replacement = true;
        candidate.description = repo.descriptions.count(target_weld_pkg) ? repo.descriptions.at(target_weld_pkg) : "";
        candidate.version = extract_weld_version(target_weld_pkg, candidate.file_name);
        if (!best.found || compare_versions(candidate.version, best.version) > 0)
            best = candidate;
    }
    return best;
}

std::string build_weld_download_url(const WeldPackageCandidate& candidate)
    pre(candidate.found) pre(!candidate.base_url.empty())
    pre(!candidate.release.empty()) pre(!candidate.file_name.empty())
    post(r: !r.empty()) {
    std::string file_name = trim_copy(candidate.file_name);
    while (!file_name.empty() && file_name.front() == '/') file_name.erase(file_name.begin());
    std::size_t pos = 0;
    while ((pos = file_name.find("..", pos)) != std::string::npos) {
        file_name.erase(pos, 2);
    }
    while (!file_name.empty() && file_name.front() == '/') file_name.erase(file_name.begin());
    return candidate.base_url + "/releases/" + candidate.release + "/" + file_name;
}

bool cache_weld_package(const WeldPackageCandidate& candidate, std::string& local_path) {
#ifndef allow_weld_repositories
    (void)candidate; (void)local_path;
    return false;
#else
    std::string safe_release = sanitize_filename(candidate.release);
    std::string safe_file = sanitize_filename(candidate.file_name);
    if (safe_release.empty() || safe_file.empty()) return false;
    std::string release_dir = g_weld_cache_dir + "/" + safe_release;
    if (exec_argv_devnull_out({"mkdir", "-p", release_dir}) != 0) return false;
    local_path = release_dir + "/" + safe_file;
    std::string url = build_weld_download_url(candidate);
    if (url.empty() || url.front() == '-') return false;
    if (!starts_with(url, "https://")) return false;
    return curl_download_file(url, local_path);
#endif
}

std::string calculate_sha256(const std::string& file_path) pre(!file_path.empty()) {
    std::ifstream in(file_path, std::ios::binary);
    if (!in) return "";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    char buf[65536];
    bool failed = false;
    while (in) {
        in.read(buf, sizeof(buf));
        std::streamsize got = in.gcount();
        if (got > 0) {
            if (EVP_DigestUpdate(ctx, buf, static_cast<std::size_t>(got)) != 1) {
                failed = true;
                break;
            }
        }
    }
    std::string result;
    if (!failed) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) == 1 && hash_len > 0) {
            result = hex_encode(std::span<const unsigned char>{hash, hash_len});
        }
    }
    EVP_MD_CTX_free(ctx);
    return result;
}

struct PendingWeldDownload {
    std::string pkg_name;
    WeldPackageCandidate candidate;
    std::string local_path;
    bool success = false;
    std::string error_msg;
};

bool download_weld_packages(std::vector<PendingWeldDownload>& pending_weld_downloads,
                            std::vector<InstallDecision>& decisions, bool quiet) {
    if (pending_weld_downloads.empty()) return true;

    std::size_t num_threads = std::min<std::size_t>(4, pending_weld_downloads.size());
    std::vector<std::thread> workers;
    std::atomic<std::size_t> current_index(0);

    for (std::size_t t = 0; t < num_threads; ++t) {
        workers.emplace_back([&]() {
            while (true) {
                std::size_t idx = current_index.fetch_add(1);
                if (idx >= pending_weld_downloads.size()) break;
                auto& pending = pending_weld_downloads[idx];
                if (!quiet) safe_log("Downloading Weld package: ", pending.pkg_name, "...\n");
                auto start_time = std::chrono::steady_clock::now();
                if (!cache_weld_package(pending.candidate, pending.local_path)) {
                    pending.error_msg = std::format("E: Failed to download {} from the Weld repository.\n",
                        pending.pkg_name);
                    continue;
                }
                auto end_time = std::chrono::steady_clock::now();
                double elapsed_sec = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();

                if (pending.candidate.sha256.empty()) {
                    pending.error_msg = std::format(
                        "E: SHA256 checksum is missing in metadata for package {}.\n"
                        "E: Refusing to install unverified package.\n", pending.pkg_name);
                    exec_argv_devnull_out({"rm", "-f", pending.local_path});
                    continue;
                }

                std::string local_hash = calculate_sha256(pending.local_path);
                if (local_hash != pending.candidate.sha256) {
                    pending.error_msg = std::format(
                        "E: SHA256 checksum mismatch for {}.\n"
                        "E: Expected: {}\n"
                        "E: Got:      {}\n"
                        "E: Aborting installation of this package.\n",
                        pending.pkg_name, pending.candidate.sha256, local_hash);
                    exec_argv_devnull_out({"rm", "-f", pending.local_path});
                    continue;
                }

                std::error_code ec;
                std::uint64_t file_sz = fs::file_size(pending.local_path, ec);
                std::string sz_str = (!ec && file_sz > 0) ? format_bytes(file_sz) : "";
                std::string speed_str;
                if (!ec && file_sz > 0 && elapsed_sec > 0.005) {
                    double bytes_per_sec = static_cast<double>(file_sz) / elapsed_sec;
                    speed_str = format_bytes(static_cast<std::uint64_t>(bytes_per_sec)) + "/s";
                }

                if (!quiet) {
                    constexpr std::string_view kCyan = "\033[1;36m";
                    constexpr std::string_view kGray = "\033[38;2;148;163;184m";
                    constexpr std::string_view kReset = "\033[0m";
                    std::string details;
                    if (!sz_str.empty()) details += sz_str;
                    if (!speed_str.empty()) details += (details.empty() ? "" : " | ") + speed_str;
                    safe_log(" * ", kCyan, pending.pkg_name, kReset,
                             (!details.empty() ? " " + std::string(kGray) + "(" + details + ")" + std::string(kReset) : ""),
                             "\n");
                }
                pending.success = true;
            }
        });
    }
    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    bool ok = true;
    for (const auto& pending : pending_weld_downloads) {
        if (!pending.success) {
            if (!quiet) safe_log(pending.error_msg, "\n");
            ok = false;
        } else {
            InstallDecision decision;
            decision.package_name = pending.candidate.actual_pkg_name.empty()
                ? pending.pkg_name
                : pending.candidate.actual_pkg_name;
            decision.apt_argument = pending.local_path;
            decision.selected_version = pending.candidate.version;
            decision.from_weld = true;
            decisions.push_back(decision);
        }
    }
    return ok;
}

bool resolve_install_decisions(const std::vector<std::string>& pkgs, std::vector<InstallDecision>& decisions,
                                bool quiet, bool is_upgrade) pre(!pkgs.empty()) {
    if (pkgs.empty()) {
        if (!quiet) log_error("no packages were specified.");
        return false;
    }
    pkgCacheFile cache_file;
    std::vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    bool had_error = false;
    std::vector<PendingWeldDownload> pending_weld_downloads;

    for (const auto& pkg_name : pkgs) {
        if (ends_with(pkg_name, ".deb")) {
            if (pkg_name.find("..") != std::string::npos || pkg_name.find('\0') != std::string::npos) {
                if (!quiet) log_error(std::format("suspicious path traversal in: {}", pkg_name));
                had_error = true;
                continue;
            }
            int probe_fd = open_no_follow(pkg_name, O_RDONLY);
            if (probe_fd < 0) {
                if (!quiet) log_error(std::format("unable to locate local package file: {}", pkg_name));
                had_error = true;
                continue;
            }
            struct stat st{};
            bool is_regular = (fstat(probe_fd, &st) == 0 && S_ISREG(st.st_mode));
            close(probe_fd);
            if (!is_regular) {
                if (!quiet) log_error(std::format("local package is not a regular file: {}", pkg_name));
                had_error = true;
                continue;
            }
            std::error_code ec;
            fs::path abs_path = fs::absolute(pkg_name, ec);
            if (!ec) abs_path = fs::weakly_canonical(abs_path, ec);
            std::string resolved_path = ec ? pkg_name : abs_path.string();

            InstallDecision decision;
            decision.package_name = resolved_path;
            decision.apt_argument = resolved_path;
            decision.selected_version = "";
            decision.from_weld = false;
            decisions.push_back(decision);
            continue;
        }

        AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
        WeldPackageCandidate weld_candidate = find_best_weld_candidate(repos, pkg_name);

        if (!apt_state.found && !weld_candidate.found) {
            if (!quiet) log_error(std::format("unable to locate package {}", pkg_name));
            had_error = true;
            continue;
        }

        bool use_weld = false;
        if (weld_candidate.found) {
            if (weld_candidate.is_replacement) use_weld = true;
            else if (!apt_state.found || apt_state.candidate_version.empty()) use_weld = true;
            else if (compare_versions(weld_candidate.version, apt_state.candidate_version) > 0) use_weld = true;
        }

        if (use_weld) {
            AptPackageState target_apt_state = (weld_candidate.is_replacement)
                ? get_apt_package_state(cache_file, weld_candidate.actual_pkg_name)
                : apt_state;
            if (target_apt_state.installed && !g_force_reinstall.load()
                && compare_versions(target_apt_state.installed_version, weld_candidate.version) >= 0) {
                if (!quiet) print_install_already_present_message(weld_candidate.actual_pkg_name, is_upgrade);
                continue;
            }
            pending_weld_downloads.push_back({pkg_name, weld_candidate, "", false, ""});
            continue;
        }

        if (!apt_state.found || apt_state.candidate_version.empty()) {
            if (!quiet) log_error(std::format("unable to locate package {}", pkg_name));
            had_error = true;
            continue;
        }

        if (apt_state.installed && !g_force_reinstall.load()
            && compare_versions(apt_state.installed_version, apt_state.candidate_version) >= 0) {
            if (!quiet) print_install_already_present_message(pkg_name, is_upgrade);
            continue;
        }

        InstallDecision decision;
        decision.package_name = pkg_name;
        decision.apt_argument = pkg_name;
        decision.selected_version = apt_state.candidate_version;
        decision.from_weld = false;
        decisions.push_back(decision);
    }

    if (!download_weld_packages(pending_weld_downloads, decisions, quiet)) {
        had_error = true;
    }
    return !had_error;
}

std::string parse_arvor_ua_version(const std::string& page) {
    if (page.empty()) return "";
    static constexpr std::string_view kNeedle = "ArvorLinux/";
    auto pos = page.find(kNeedle);
    if (pos == std::string::npos) return "";
    pos += kNeedle.size();
    std::string ver;
    while (pos < page.size()) {
        char c = page[pos];
        if (std::isdigit(static_cast<unsigned char>(c)) || c == '.') {
            ver += c;
            ++pos;
        } else {
            break;
        }
    }
    while (!ver.empty() && ver.back() == '.') ver.pop_back();
    return ver;
}

int compare_arvor_versions(const std::string& a, const std::string& b) {
    auto parse = [](std::string_view s) -> std::pair<int, int> {
        int major = 0, minor = 0;
        auto dot = s.find('.');
        if (dot == std::string_view::npos) {
            try { major = std::stoi(std::string{s}); } catch (...) {}
        } else {
            try { major = std::stoi(std::string{s.substr(0, dot)}); } catch (...) {}
            try { minor = std::stoi(std::string{s.substr(dot + 1)}); } catch (...) {}
        }
        return {major, minor};
    };
    auto pa = parse(a);
    auto pb = parse(b);
    if (pa.first != pb.first) return pa.first < pb.first ? -1 : 1;
    if (pa.second != pb.second) return pa.second < pb.second ? -1 : 1;
    return 0;
}

std::string strip_maintainer_email(const std::string& maintainer) {
    if (maintainer.empty()) return "";
    auto pos = maintainer.find(" <");
    if (pos != std::string::npos) return maintainer.substr(0, pos);
    return maintainer;
}

void print_successful_install(const std::string& action, const std::vector<std::string>& targets) {
    constexpr std::string_view kGreen = "\033[38;5;114m";
    constexpr std::string_view kReset = "\033[0m";
    if (action != "install" && action != "upgrade" && action != "dist-upgrade") {
        std::print("{}Transaction completed successfully.{}\n", kGreen, kReset);
        return;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) {
        std::print("{}Transaction completed successfully.{}\n", kGreen, kReset);
        return;
    }
    pkgRecords records(*cache);
    bool printed_any = false;
    for (const auto& t : targets) {
        if (ends_with(t, ".deb")) continue;
        pkgCache::PkgIterator pkg = cache->FindPkg(t);
        if (pkg.end() || pkg->CurrentVer == 0) continue;
        pkgCache::VerIterator ver = pkg.CurrentVer();
        std::string version = ver.VerStr();
        std::string maintainer;
        pkgCache::VerFileIterator vf = ver.FileList();
        if (!vf.end()) {
            pkgRecords::Parser& parser = records.Lookup(vf);
            maintainer = parser.Maintainer();
        }
        std::string maint_name = strip_maintainer_email(maintainer);
        std::print("{}Successfully Installed {}", kGreen, t);
        if (!version.empty()) std::print(", Version {}", version);
        if (!maint_name.empty()) std::print(" by {}", maint_name);
        std::print("{}\n", kReset);
        printed_any = true;
    }
    if (!printed_any) {
        std::print("{}Transaction completed successfully.{}\n", kGreen, kReset);
    }
}

std::string read_arvor_version_from_os_release() post(r: !r.empty()) {
    std::string content;
    if (!read_text_file("/etc/os-release", content)) {
        return ARVOR_VERSION;
    }
    std::istringstream ss(content);
    std::string line;
    while (std::getline(ss, line)) {
        if (!starts_with(line, "VERSION_ID")) continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) break;
        std::string value = line.substr(eq + 1);
        value = strip_quotes(trim_copy(value));
        if (value.empty()) break;
        return value;
    }
    return ARVOR_VERSION;
}

void do_nflinux_upgrade(bool apply_host, const std::string& arv_version) {
    std::string user_agent = "ArvorLinux/" + arv_version;
    std::string ua_page = curl_fetch_string("https://nextferret.github.io/ua", user_agent);
    std::string remote_version = parse_arvor_ua_version(ua_page);

    if (!remote_version.empty()) {
        int cmp = compare_arvor_versions(arv_version, remote_version);
        if (cmp > 0) {
            std::print("You are running a development build of Arvor Linux, or the remote release server may be outdated.\n");
            std::print("Local version: {} | Remote version: {}\n", arv_version, remote_version);
            std::print("No upgradeable release was found for your channel.\n");
            return;
        }
        if (cmp == 0) {
            std::print("Arvor Linux is already up to date (version {}).\n", arv_version);
            return;
        }
        std::print("Arvor Linux local version: {}\n", arv_version);
        std::print("A newer release ({}) is available. Proceed with upgrade? [Y/n] ", remote_version);
        std::cout.flush();
        if (!g_assume_yes.load()) {
            std::string answer;
            std::getline(std::cin, answer);
            if (answer != "y" && answer != "Y") {
                std::print("Upgrade cancelled.\n");
                return;
            }
        }
    }

#ifdef nflinux
    g_config_backup.backup();

    std::string os_release = curl_fetch_string("https://nextferret.github.io/etc/os-release", user_agent);
    std::string codenames = curl_fetch_string("https://nextferret.github.io/version_codename", user_agent);
    std::string repo_number_str = trim_copy(curl_fetch_string("https://nextferret.github.io/repo-number", user_agent));
    std::string weld_sources;
    std::string apt_sources;

    if (!codenames.empty() && !repo_number_str.empty()) {
        auto comma = codenames.find(',');
        if (comma != std::string::npos) {
            std::string weld_code = trim_copy(codenames.substr(0, comma));
            std::string debian_code = trim_copy(codenames.substr(comma + 1));
            std::string base_repo_url = "https://thearvorindex.github.io/repo-arvorlinux--" + repo_number_str;
            std::string meta_url = base_repo_url + "/releases/" + weld_code + "/repo-metadata";
            std::string sig_url  = meta_url + ".minisig";
            std::string meta = curl_fetch_string(meta_url);
            std::string sig  = curl_fetch_string(sig_url);
            if (!meta.empty() && !sig.empty()) {
                std::string tc;
                std::string err;
                if (verify_repo_metadata_signature(meta, sig, tc, err)) {
                    weld_sources = "deb " + base_repo_url + " " + weld_code + "\n";
                    apt_sources = "deb http://deb.debian.org/debian " + debian_code + " main contrib non-free non-free-firmware\n";
                    apt_sources += "deb http://deb.debian.org/debian-security " + debian_code + "-security main contrib non-free non-free-firmware\n";
                    apt_sources += "deb http://deb.debian.org/debian " + debian_code + "-updates main contrib non-free non-free-firmware\n";
                } else {
                    log_error(std::format("refusing to switch to release {} because its signature could not be verified: {}",
                        weld_code, err));
                }
            }
        }
    }

    if (!os_release.empty() || !apt_sources.empty() || !weld_sources.empty()) {
        g_config_backup.set_new(os_release, apt_sources, weld_sources);
        g_config_backup.apply_new();
    }

    std::vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    std::vector<std::string> pkgs_to_install;
    for (const auto& repo : repos) {
        for (const auto& req : repo.required_packages)
            pkgs_to_install.push_back(req);
    }

    if (!pkgs_to_install.empty()) {
        std::ranges::sort(pkgs_to_install);
        auto last = std::ranges::unique(pkgs_to_install);
        pkgs_to_install.erase(last.begin(), pkgs_to_install.end());
        std::print("Installing required packages from repositories...\n");
        perform_install_transaction(pkgs_to_install, apply_host);
    }
#else
    (void)apply_host;
#endif
}

std::vector<std::string> bind_mount_local_deb_dirs(const std::vector<std::string>& targets) {
    std::set<std::string> parents;
    for (const auto& t : targets) {
        if (!ends_with(t, ".deb")) continue;
        fs::path parent = fs::path(t).parent_path();
        if (!parent.empty()) parents.insert(parent.string());
    }
    std::vector<std::string> mounted;
    for (const auto& parent : parents) {
        std::string target = g_tree_root + parent;
        std::error_code ec;
        fs::create_directories(target, ec);
        if (ec) continue;
        exec_argv_devnull_out({"mount", "--bind", parent, target});
        mounted.push_back(target);
    }
    return mounted;
}

void unbind_local_deb_dirs(const std::vector<std::string>& mounted) {
    for (auto it = mounted.rbegin(); it != mounted.rend(); ++it)
        exec_argv_devnull_out({"umount", "-l", *it});
}

void perform_transaction_argv(const std::string& action, const std::vector<std::string>& targets, bool apply_host) {
    if (!check_system_memory(kWeldMinMemMb)) return;

    if (!apply_host) {
        if (!manage_sandbox("create")) {
            log_error("aborting transaction: sandbox could not be created.");
            return;
        }
        mount_fs();
        std::vector<std::string> local_deb_mounts = bind_mount_local_deb_dirs(targets);

        int apt_pipe[2]  = {-1, -1};
        bool have_pipe   = (pipe(apt_pipe) == 0);
        int err_pipe[2]  = {-1, -1};
        bool have_err    = (pipe2(err_pipe, O_CLOEXEC) == 0);

        std::cout.flush();
        std::cerr.flush();
        pid_t pid = fork();
        if (pid == 0) {
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                if (have_err) {
                    static constexpr std::string_view kMsg = "prctl NO_NEW_PRIVS failed\n";
                    ssize_t written = write(err_pipe[1], kMsg.data(), kMsg.size());
                    (void)written;
                }
                _exit(1);
            }
            if (unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC) != 0) {
                if (have_err) {
                    static constexpr std::string_view kMsg = "unshare namespace failed\n";
                    ssize_t written = write(err_pipe[1], kMsg.data(), kMsg.size());
                    (void)written;
                }
                _exit(1);
            }

            std::string put_old_path = std::string(g_tree_root) + "/.old_root";
            bool pivoted = false;
            if (mkdir(put_old_path.c_str(), 0755) == 0) {
                int verify_fd = open_no_follow(put_old_path, O_RDONLY | O_DIRECTORY);
                if (verify_fd >= 0) {
                    if (mount("", g_tree_root.c_str(), "", MS_PRIVATE | MS_REC, nullptr) == 0) {
                        if (do_pivot_root(g_tree_root.c_str(), put_old_path.c_str()) == 0) {
                            pivoted = true;
                        }
                    }
                    close(verify_fd);
                }
            }

            if (pivoted) {
                if (chdir("/") != 0) {
                    if (have_err) {
                        static constexpr std::string_view kMsg = "chdir(\"/\") failed after pivot_root\n";
                        ssize_t written = write(err_pipe[1], kMsg.data(), kMsg.size());
                        (void)written;
                    }
                    _exit(1);
                }
                umount2("/.old_root", MNT_DETACH);
                rmdir("/.old_root");
            } else {
                rmdir(put_old_path.c_str());
                if (chroot(g_tree_root.c_str()) != 0 || chdir("/") != 0) {
                    if (have_err) {
                        static constexpr std::string_view kMsg = "pivot_root and chroot fallback both failed\n";
                        ssize_t written = write(err_pipe[1], kMsg.data(), kMsg.size());
                        (void)written;
                    }
                    _exit(1);
                }
            }

            apply_strict_resource_limits();
            restrict_capabilities();

            {
                std::string seccomp_err;
                if (!ChrootSeccompManager::apply_filter(seccomp_err)) {
                    if (have_err && !seccomp_err.empty()) {
                        std::string msg = std::format("W: SECCOMP filter notice: {}\n", seccomp_err);
                        ssize_t written = write(err_pipe[1], msg.c_str(), msg.size());
                        (void)written;
                    }
                }
            }

            int devnull_r = open("/dev/null", O_RDONLY);
            if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }

            if (have_err) {
                close(err_pipe[0]);
                if (err_pipe[1] != STDERR_FILENO) {
                    dup2(err_pipe[1], STDERR_FILENO);
                    close(err_pipe[1]);
                }
            } else {
                int dn2 = open("/dev/null", O_WRONLY);
                if (dn2 >= 0) { dup2(dn2, STDERR_FILENO); close(dn2); }
            }

            int status_fd = -1;
            if (have_pipe) {
                close(apt_pipe[0]);
                if (apt_pipe[1] != 3) { dup2(apt_pipe[1], 3); close(apt_pipe[1]); }
                fcntl(3, F_SETFD, 0);
                status_fd = 3;
            }

            for (int fd = 4; fd < 1024; ++fd) close(fd);

            pkgInitConfig(*_config);
            pkgInitSystem(*_config, _system);

            sanitize_child_environment();
            setenv("DEBIAN_FRONTEND", "noninteractive", 1);
            bool ok = run_libapt_transaction(action, targets, status_fd, true);
            std::cout.flush();
            std::cerr.flush();
            _exit(ok ? 0 : 1);

        } else if (pid > 0) {
            if (have_pipe) close(apt_pipe[1]);
            if (have_err)  close(err_pipe[1]);

            std::cout << render_weld_progress(0, "Verifying Transaction") << std::flush;

            std::atomic<int> apt_percent(-1);
            std::string child_stderr_output;

            std::thread stderr_reader([&]() {
                if (!have_err) return;
                char buf[256];
                ssize_t n;
                while ((n = read(err_pipe[0], buf, sizeof(buf) - 1)) > 0) {
                    buf[n] = '\0';
                    child_stderr_output += buf;
                }
                close(err_pipe[0]);
            });

            std::thread reader_thread([&]() {
                if (!have_pipe) return;
                FILE* f = fdopen(apt_pipe[0], "r");
                if (!f) { close(apt_pipe[0]); return; }
                char line[512];
                int last_shown = -1;
                while (fgets(line, sizeof(line), f) != nullptr) {
                    std::string s(line);
                    bool is_pm = (s.size() > 9 && s.substr(0, 9) == "pmstatus:");
                    bool is_dl = (!is_pm && s.size() > 9 && s.substr(0, 9) == "dlstatus:");
                    if (!is_pm && !is_dl) continue;
                    auto c1 = s.find(':');
                    if (c1 == std::string::npos) continue;
                    auto c2 = s.find(':', c1 + 1);
                    if (c2 == std::string::npos) continue;
                    auto c3 = s.find(':', c2 + 1);
                    if (c3 == std::string::npos) continue;
                    std::string pct_str = s.substr(c2 + 1, c3 - c2 - 1);
                    try {
                        int pct = static_cast<int>(std::stod(pct_str));
                        if (pct > apt_percent.load()) apt_percent.store(pct);
                        int current = apt_percent.load();
                        if (current != last_shown) {
                            std::cout << render_weld_progress(current, "Verifying Transaction") << std::flush;
                            last_shown = current;
                        }
                    } catch (...) {}
                }
                fclose(f);
            });

            int status = 0;
            bool waited = wait_for_child(pid, status);

            reader_thread.join();
            stderr_reader.join();

            unbind_local_deb_dirs(local_deb_mounts);
            umount_fs();
            manage_sandbox("delete");

            if (!waited) {
                g_config_backup.restore_orig();
                std::print("\n\033[1;31mE:\033[0m Sandbox verification interrupted.\n");
                return;
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                g_config_backup.restore_orig();
                std::print("\n\033[1;31mE:\033[0m Sandbox verification failed.\n");
                if (!child_stderr_output.empty()) {
                    std::print("---- sandbox error output ----\n{}", child_stderr_output);
                    if (child_stderr_output.back() != '\n') std::print("\n");
                    std::print("------------------------------\n");
                }
                return;
            }

            std::cout << render_weld_progress(100, "Verifying Transaction") << "\n\n";

            if (!g_assume_yes.load()) {
                std::print("Sandbox verification passed without errors.\n");
                std::print("The transaction is now ready to be applied to the host system.\n");
                std::print("Do you wish to continue? [Y/n] ");
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm != "y" && confirm != "Y") {
                    g_config_backup.restore_orig();
                    std::print("Transaction aborted by user.\n");
                    return;
                }
            }
        } else {
            if (have_pipe) { close(apt_pipe[0]); close(apt_pipe[1]); }
            if (have_err)  { close(err_pipe[0]); close(err_pipe[1]); }
            std::print("\033[1;31mE:\033[0m Unable to fork process for sandbox verification.\n");
            return;
        }
    }

    g_config_backup.restore_orig();
    bool snapshot_created = create_snapshot("apt-pre");
    g_config_backup.apply_new();

    std::string kver = trim_copy(exec_argv_capture({"uname", "-r"}));
    if (!kver.empty()) {
        std::string src = "/lib/modules/" + kver;
        std::string dst = "/var/tmp/.arvor_kmodules_" + kver;
        std::error_code ec;
        if (fs::exists(src, ec) && !fs::exists(dst, ec)) {
            exec_argv_devnull_out({"cp", "-a", src, dst});
        }
    }

    std::cout.flush();
    std::cerr.flush();

    std::cout << render_weld_progress(0, "Applying Transaction") << std::flush;

    int host_pipe[2];
    bool have_host_pipe = (pipe(host_pipe) == 0);

    pid_t host_pid = fork();
    if (host_pid == 0) {
        int devnull_r = open("/dev/null", O_RDONLY);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }
        int devnull_w = open("/dev/null", O_WRONLY);
        if (devnull_w >= 0) {
            dup2(devnull_w, STDOUT_FILENO);
            dup2(devnull_w, STDERR_FILENO);
            close(devnull_w);
        }

        int status_fd = -1;
        if (have_host_pipe) {
            close(host_pipe[0]);
            if (host_pipe[1] != 3) { dup2(host_pipe[1], 3); close(host_pipe[1]); }
            fcntl(3, F_SETFD, 0);
            status_fd = 3;
        }

        for (int fd = 4; fd < 1024; ++fd) close(fd);
        sanitize_child_environment();
        setenv("DEBIAN_FRONTEND", "noninteractive", 1);
        bool ok = run_libapt_transaction(action, targets, status_fd, true);
        std::cout.flush();
        std::cerr.flush();
        _exit(ok ? 0 : 1);
    }

    int host_status = 0;
    bool host_ok = false;
    if (host_pid > 0) {
        if (have_host_pipe) close(host_pipe[1]);

        std::atomic<int> host_percent(-1);

        std::thread host_reader([&]() {
            if (!have_host_pipe) return;
            FILE* f = fdopen(host_pipe[0], "r");
            if (!f) { close(host_pipe[0]); return; }
            char line[512];
            int last_shown = -1;
            while (fgets(line, sizeof(line), f) != nullptr) {
                std::string s(line);
                bool is_pm = (s.size() > 9 && s.substr(0, 9) == "pmstatus:");
                bool is_dl = (!is_pm && s.size() > 9 && s.substr(0, 9) == "dlstatus:");
                if (!is_pm && !is_dl) continue;
                auto c1 = s.find(':');
                if (c1 == std::string::npos) continue;
                auto c2 = s.find(':', c1 + 1);
                if (c2 == std::string::npos) continue;
                auto c3 = s.find(':', c2 + 1);
                if (c3 == std::string::npos) continue;
                std::string pct_str = s.substr(c2 + 1, c3 - c2 - 1);
                try {
                    int pct = static_cast<int>(std::stod(pct_str));
                    if (pct > host_percent.load()) host_percent.store(pct);
                    int current = host_percent.load();
                    if (current != last_shown) {
                        std::cout << render_weld_progress(current, "Applying Transaction") << std::flush;
                        last_shown = current;
                    }
                } catch (...) {}
            }
            fclose(f);
        });

        wait_for_child(host_pid, host_status);
        host_reader.join();
        host_ok = WIFEXITED(host_status) && WEXITSTATUS(host_status) == 0;
    }

    if (host_ok) {
        std::cout << render_weld_progress(100, "Applying Transaction") << "\n\n";
        create_snapshot("apt-post");
        print_successful_install(action, targets);
    } else {
        std::print("\n\033[1;31mE:\033[0m Host transaction failed. Rolling back to previous snapshot...\n");
        g_config_backup.restore_orig();
        if (snapshot_created) do_rollback("apt-pre");
    }
}

void perform_transaction(const std::string& action, const std::vector<std::string>& pkgs, bool apply_host) {
    PrecheckResult precheck = precheck_transaction(action, pkgs, false);
    if (precheck == PrecheckResult::Failed || precheck == PrecheckResult::NoChanges) return;
    perform_transaction_argv(action, pkgs, apply_host);
}

void perform_install_transaction(const std::vector<std::string>& pkgs, bool apply_host, bool is_upgrade) {
    std::vector<InstallDecision> decisions;
    if (!resolve_install_decisions(pkgs, decisions, false, is_upgrade)) return;
    if (decisions.empty()) return;
    std::vector<std::string> args;
    args.reserve(decisions.size());
    for (const auto& decision : decisions) args.push_back(decision.apt_argument);
    perform_transaction_argv("install", args, apply_host);
}

void perform_global_upgrade(bool apply_host) {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return;

    std::vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    std::vector<std::string> weld_upgrade_args;

    auto get_installed_version = [&](const std::string& pkg_name) -> std::string {
        AptPackageState s = get_apt_package_state(cache_file, pkg_name);
        return s.installed ? s.installed_version : "";
    };

    auto try_queue_weld_upgrade = [&](const std::string& pkg_name, const std::string& installed_version) {
        WeldPackageCandidate candidate = find_best_weld_candidate(repos, pkg_name);
        if (!candidate.found) return;
        if (!installed_version.empty() && compare_versions(candidate.version, installed_version) <= 0) return;
        std::string local_path;
        if (!cache_weld_package(candidate, local_path)) return;
        if (candidate.sha256.empty()) {
            exec_argv_devnull_out({"rm", "-f", local_path});
            std::print("W: No SHA256 checksum found in metadata for {}, skipping.\n", pkg_name);
            return;
        } else {
            std::string h = calculate_sha256(local_path);
            if (h != candidate.sha256) {
                exec_argv_devnull_out({"rm", "-f", local_path});
                std::print("E: Checksum mismatch for {}, skipping.\n", pkg_name);
                return;
            }
        }
        std::print("Queuing weld upgrade: {}", pkg_name);
        if (!installed_version.empty()) std::print(" ({} -> {})", installed_version, candidate.version);
        else std::print(" ({})", candidate.version);
        std::print("\n");
        weld_upgrade_args.push_back(local_path);
    };

    std::set<std::string> handled_pkgs;
    for (const auto& repo : repos) {
        if (repo.required_packages.empty()) continue;
        std::string already_installed_req;
        for (const auto& req : repo.required_packages) {
            if (!get_installed_version(req).empty()) { already_installed_req = req; break; }
        }
        if (!already_installed_req.empty()) {
            std::string iv = get_installed_version(already_installed_req);
            try_queue_weld_upgrade(already_installed_req, iv);
            handled_pkgs.insert(already_installed_req);
        } else {
            for (const auto& req : repo.required_packages) {
                std::string iv = get_installed_version(req);
                WeldPackageCandidate c = find_best_weld_candidate(repos, req);
                if (!iv.empty()) {
                    if (c.found && compare_versions(c.version, iv) > 0) {
                        std::print("Upgrading required package: {} ({} -> {})\n", req, iv, c.version);
                        try_queue_weld_upgrade(req, iv);
                        handled_pkgs.insert(req);
                    }
                    continue;
                }
                if (c.found) {
                    std::print("Installing required package: {}\n", req);
                    perform_install_transaction({req}, apply_host);
                    handled_pkgs.insert(req);
                } else {
                    AptPackageState apt_state = get_apt_package_state(cache_file, req);
                    if (apt_state.found) {
                        std::print("Installing required package: {}\n", req);
                        perform_install_transaction({req}, apply_host);
                        handled_pkgs.insert(req);
                    } else {
                        log_warning(std::format("required package {} not found in any repo, skipping.", req));
                    }
                }
            }
        }
    }

    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        if (pkg->CurrentVer == 0) continue;
        std::string pkg_name = pkg.Name();
        if (handled_pkgs.count(pkg_name)) continue;
        AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
        try_queue_weld_upgrade(pkg_name, apt_state.installed_version);
    }

    if (!weld_upgrade_args.empty()) {
        std::print("Upgrading Weld packages first...\n");
        perform_transaction_argv("install", weld_upgrade_args, apply_host);
    }

    std::print("Proceeding with standard apt upgrade...\n");
    perform_transaction("upgrade", std::vector<std::string>(), apply_host);
}

void perform_upgrade_transaction(const std::vector<std::string>& pkgs, bool apply_host) {
    if (pkgs.empty()) { perform_global_upgrade(apply_host); return; }
    perform_install_transaction(pkgs, apply_host, true);
}

PrecheckResult precheck_transaction(const std::string& action, const std::vector<std::string>& pkgs, bool quiet) {
    if (action == "upgrade" || action == "dist-upgrade") {
        pkgCacheFile probe_cache_file;
        pkgCache* probe_cache = probe_cache_file.GetPkgCache();
        pkgDepCache* probe_dep_cache = probe_cache_file.GetDepCache();
        if (probe_cache == nullptr || probe_dep_cache == nullptr)
            return PrecheckResult::Proceed;

        bool upgrade_ok = (action == "upgrade")
            ? APT::Upgrade::Upgrade(*probe_dep_cache,
                  APT::Upgrade::FORBID_REMOVE_PACKAGES | APT::Upgrade::FORBID_INSTALL_NEW_PACKAGES)
            : APT::Upgrade::Upgrade(*probe_dep_cache, APT::Upgrade::ALLOW_EVERYTHING);

        if (!upgrade_ok) {
            _error->DumpErrors();
            return PrecheckResult::Proceed;
        }

        if (probe_dep_cache->InstCount() == 0 && probe_dep_cache->DelCount() == 0) {
            if (!quiet) std::print("No packages to upgrade. Your system is up to date.\n");
            return PrecheckResult::NoChanges;
        }
        return PrecheckResult::Proceed;
    }

    if (action != "install" && action != "remove" && action != "purge")
        return PrecheckResult::Proceed;

    if (pkgs.empty()) {
        if (!quiet) log_error("no packages were specified.");
        return PrecheckResult::Failed;
    }

    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();

    if (cache == nullptr || dep_cache == nullptr)
        return PrecheckResult::Proceed;

    bool has_changes = false;

    for (const auto& pkg_name : pkgs) {
        pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
        if (pkg.end()) {
            if (!quiet) log_error(std::format("package {} not found", pkg_name));
            return PrecheckResult::Failed;
        }

        if (action == "install") {
            pkgCache::VerIterator cand = dep_cache->GetCandidateVersion(pkg);
            if (pkg->CurrentVer != 0 && (cand.end() || cand == pkg.CurrentVer())) {
                if (!quiet) std::print("{} is already the newest version.\n", pkg_name);
                continue;
            }
            has_changes = true;
            continue;
        }

        if (pkg->CurrentVer == 0) {
            if (!quiet) std::print("W: package {} is not installed.\n", pkg_name);
            continue;
        }
        has_changes = true;
    }

    return has_changes ? PrecheckResult::Proceed : PrecheckResult::NoChanges;
}

int run_search(const std::vector<std::string>& terms, int page) {
    if (terms.empty()) { std::print("Usage: weld search <term> [-p <page>]\n"); return 1; }
    if (page < 1) page = 1;
    std::string term = to_lower_copy(terms[0]);
    const int page_size = 30;
    const int offset = (page - 1) * page_size;

    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) { _error->DumpErrors(); return 1; }

    int matches = 0;
    int shown = 0;
    std::set<std::string> seen_names;

    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        std::string name = pkg.Name();
        if (to_lower_copy(name).find(term) == std::string::npos) continue;
        if (!seen_names.insert(name).second) continue;
        int index = matches;
        ++matches;
        if (index < offset || shown >= page_size) continue;
        pkgCache::VerIterator ver = pkg.VersionList();
        std::string version = ver.end() ? "" : ver.VerStr();
        std::print("{}", name);
        if (!version.empty()) std::print(" ({})", version);
        std::print("\n");
        ++shown;
    }

    std::vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    for (const auto& repo : repos) {
        for (const auto& entry : repo.packages) {
            const std::string& pkg_name = entry.first;
            if (to_lower_copy(pkg_name).find(term) == std::string::npos) continue;
            int index = matches;
            ++matches;
            if (index < offset || shown >= page_size) continue;
            std::string version = extract_weld_version(pkg_name, entry.second.first);
            std::print("{} - Provided by Weld repository {}", pkg_name, repo.base_url);
            if (!version.empty()) std::print(", version {}", version);
            std::print(".\n");
            ++shown;
        }
    }

    if (matches == 0) {
        std::print("No packages found matching \"{}\".\n", terms[0]);
        return 0;
    }
    if (shown == 0) {
        std::print("Page {} is empty. This search has {} results.\n", page, matches);
        return 0;
    }
    int total_pages = (matches + page_size - 1) / page_size;
    std::print("Page {} of {} ({} total results).", page, total_pages, matches);
    if (page < total_pages) std::print(" Use -p {} to see more.", page + 1);
    std::print("\n");
    return 0;
}

int show_package_info(const std::string& pkg_name) {
    if (pkg_name.empty()) {
        std::print("Usage: weld info <package_name>\n");
        return 1;
    }

    pkgCacheFile cache_file;
    std::vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
    WeldPackageCandidate weld_cand = find_best_weld_candidate(repos, pkg_name);

    if (!apt_state.found && !weld_cand.found) {
        log_error(std::format("package '{}' not found in any configured repository.", pkg_name));
        return 1;
    }

    constexpr std::string_view kCyanBold = "\033[1;36m";
    constexpr std::string_view kGreen = "\033[1;32m";
    constexpr std::string_view kDim = "\033[2m";
    constexpr std::string_view kReset = "\033[0m";

    std::print("{}Package Information: {}{}\n", kCyanBold, pkg_name, kReset);
    std::print("----------------------------------------\n");

    if (apt_state.installed) {
        std::print("Installed:    {}yes ({}){}\n", kGreen, apt_state.installed_version, kReset);
    } else {
        std::print("Installed:    no\n");
    }

    if (weld_cand.found) {
        std::print("Source:       {} ({})\n", weld_cand.base_url, weld_cand.release);
        std::print("Version:      {}\n", weld_cand.version);
        std::print("SHA256:       {}\n", weld_cand.sha256.empty() ? "None" : weld_cand.sha256);
        if (!weld_cand.description.empty()) {
            std::print("Description: {}\n", weld_cand.description);
        }
        for (const auto& repo : repos) {
            if (repo.base_url == weld_cand.base_url && repo.release == weld_cand.release) {
                if (!repo.name.empty()) std::print("Repo Name:   {}\n", repo.name);
                if (!repo.maintainer.empty()) std::print("Maintainer:  {}\n", repo.maintainer);
                if (!repo.trusted_comment.empty())
                    std::print("Signature:   {}verified{} ({})\n", kDim, kReset, repo.trusted_comment);
                break;
            }
        }
    } else if (apt_state.found && !apt_state.candidate_version.empty()) {
        std::print("Version:      {}\n", apt_state.candidate_version);
    }
    return 0;
}

int list_installed_packages() {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    int count = 0;
    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        if (pkg->CurrentVer != 0) {
            std::print("{} ({})\n", pkg.Name(), pkg.CurrentVer().VerStr());
            ++count;
        }
    }
    std::print("\nTotal installed packages: {}\n", count);
    return 0;
}

bool check_system_locks(bool quiet = false) {
    int fd = open("/var/lib/dpkg/lock-frontend", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (fd < 0) {
        if (!quiet) log_error("cannot open /var/lib/dpkg/lock-frontend");
        return false;
    }
    struct flock fl{};
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    if (fcntl(fd, F_SETLK, &fl) == -1) {
        close(fd);
        if (!quiet) {
            log_error("dpkg lock (/var/lib/dpkg/lock-frontend) is currently held by another process.");
            std::print(stderr, "Please wait for the background package operation to complete.\n");
        }
        return false;
    }
    int old_fd = g_dpkg_lock_fd.exchange(fd);
    if (old_fd >= 0) close(old_fd);
    return true;
}

void release_system_locks() {
    int fd = g_dpkg_lock_fd.exchange(-1);
    if (fd >= 0) {
        struct flock fl{};
        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
    }
}

int show_package_why(const std::string& pkg_name) {
    if (pkg_name.empty()) {
        std::print("Usage: weld why <package_name>\n");
        return 1;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    pkgCache::PkgIterator target_pkg = cache->FindPkg(pkg_name);
    if (target_pkg.end()) {
        log_error(std::format("package '{}' not found.", pkg_name));
        return 1;
    }

    if (target_pkg->CurrentVer == 0) {
        std::print("W: package '{}' is not currently installed.\n", pkg_name);
    }

    constexpr std::string_view kCyanBold = "\033[1;36m";
    constexpr std::string_view kGreen = "\033[1;32m";
    constexpr std::string_view kGray = "\033[38;2;148;163;184m";
    constexpr std::string_view kReset = "\033[0m";

    std::print("{}Dependency Tree (Why is '{}' required?):{}\n", kCyanBold, pkg_name, kReset);
    std::print("--------------------------------------------------------\n");

    int rev_count = 0;
    std::set<std::string> seen_parents;

    for (pkgCache::DepIterator dep = target_pkg.RevDependsList(); !dep.end(); ++dep) {
        if (dep->Type != pkgCache::Dep::Depends && dep->Type != pkgCache::Dep::PreDepends) continue;
        pkgCache::PkgIterator parent = dep.ParentPkg();
        if (parent->CurrentVer != 0) {
            std::string pname = parent.Name();
            if (seen_parents.insert(pname).second) {
                std::cout << "  " << kGreen << "- " << pname << kReset
                          << " (" << parent.CurrentVer().VerStr() << ")"
                          << kGray << " [requires " << dep.DepType() << ": " << pkg_name << "]"
                          << kReset << "\n";
                ++rev_count;
            }
        }
    }

    if (rev_count == 0) {
        std::print("  {}No installed packages depend on '{}'. It was likely installed manually or as a top-level requirement.{}\n",
            kGray, pkg_name, kReset);
    } else if (rev_count == 1) {
        std::print("\nRequired by 1 currently installed package.\n");
    } else {
        std::print("\nRequired by {} currently installed packages.\n", rev_count);
    }
    return 0;
}

int show_package_depends(const std::string& pkg_name) {
    if (pkg_name.empty()) {
        std::print("Usage: weld depends <package_name>\n");
        return 1;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    pkgCache::PkgIterator target_pkg = cache->FindPkg(pkg_name);
    if (target_pkg.end()) {
        log_error(std::format("package '{}' not found.", pkg_name));
        return 1;
    }

    pkgCache::VerIterator ver = target_pkg.CurrentVer() != 0 ? target_pkg.CurrentVer() : target_pkg.VersionList();
    if (ver.end()) {
        log_error(std::format("no versions available for package '{}'.", pkg_name));
        return 1;
    }

    constexpr std::string_view kCyanBold = "\033[1;36m";
    constexpr std::string_view kGreen = "\033[1;32m";
    constexpr std::string_view kYellow = "\033[1;33m";
    constexpr std::string_view kReset = "\033[0m";

    std::print("{}Direct Dependencies for '{}' ({}){}\n", kCyanBold, pkg_name, ver.VerStr(), kReset);
    std::print("--------------------------------------------------------\n");

    for (pkgCache::DepIterator dep = ver.DependsList(); !dep.end(); ++dep) {
        std::string type_name = dep.DepType();
        std::string target_name = dep.TargetPkg().Name();
        std::string_view color = (type_name == "Depends" || type_name == "PreDepends") ? kGreen : kYellow;
        std::print("  {}{}: {}{}", color, type_name, kReset, target_name);
        if (dep.TargetVer() != nullptr) std::print(" ({} {})", dep.CompType(), dep.TargetVer());
        std::print("\n");
    }
    return 0;
}

void do_transaction_rollback() {
    std::print("Querying available recovery snapshots for rollback...\n");
    std::string latest_snap = get_latest_snapshot("apt-pre");
    if (latest_snap.empty()) {
        latest_snap = get_latest_snapshot("root-auto");
    }
    if (latest_snap.empty()) {
        log_error(std::format("no automatic pre-transaction snapshots found in {}.", g_auto_snap_dir));
        std::print("Hint: You can use 'arvorctl rollback b' to restore to the last boot snapshot.\n");
        return;
    }
    std::print("Found latest pre-transaction snapshot: \033[1;32m{}\033[0m\n", latest_snap);
    std::print("Are you sure you want to rollback to this snapshot? [Y/n] ");
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm == "y" || confirm == "Y") {
        do_rollback("apt-pre");
    } else {
        std::print("Rollback cancelled.\n");
    }
}

void report_upgradeable_packages() {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();
    if (cache == nullptr || dep_cache == nullptr) return;

    long count = 0;
    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        if (pkg->CurrentVer == 0) continue;
        pkgCache::VerIterator cand = dep_cache->GetCandidateVersion(pkg);
        if (cand.end() || cand == pkg.CurrentVer()) continue;
        ++count;
    }
    if (count <= 0) return;
    if (count == 1) std::print("W: 1 package can be upgraded. Run 'weld upgrade' to upgrade it.\n");
    else std::print("W: {} packages can be upgraded. Run 'weld upgrade' to upgrade them.\n", count);
}

void simulate_transaction(const std::string& action, const std::vector<std::string>& pkgs) {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();
    if (cache == nullptr || dep_cache == nullptr) {
        _error->DumpErrors();
        log_error("unable to open package cache.");
        return;
    }

    std::vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    std::vector<std::string> extra_lines;
    bool had_error = false;

    if (action == "upgrade" || action == "dist-upgrade") {
        bool ok = (action == "upgrade")
            ? APT::Upgrade::Upgrade(*dep_cache, APT::Upgrade::FORBID_REMOVE_PACKAGES | APT::Upgrade::FORBID_INSTALL_NEW_PACKAGES)
            : APT::Upgrade::Upgrade(*dep_cache, APT::Upgrade::ALLOW_EVERYTHING);
        if (!ok) {
            _error->DumpErrors();
            log_error("unable to resolve upgrade.");
            had_error = true;
        }
    } else if (action == "install") {
        pkgProblemResolver fixer(dep_cache);
        for (const auto& pkg_name : pkgs) {
            if (ends_with(pkg_name, ".deb")) {
                if (!path_is_regular_file(pkg_name)) {
                    log_error(std::format("unable to locate local package file: {}", pkg_name));
                    had_error = true;
                    continue;
                }
                extra_lines.push_back("Inst " + pkg_name + " (local .deb file)");
                continue;
            }

            AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
            WeldPackageCandidate weld_candidate = find_best_weld_candidate(repos, pkg_name);

            if (!apt_state.found && !weld_candidate.found) {
                log_error(std::format("unable to locate package {}", pkg_name));
                had_error = true;
                continue;
            }

            bool use_weld = false;
            if (weld_candidate.found) {
                if (weld_candidate.is_replacement) use_weld = true;
                else if (!apt_state.found || apt_state.candidate_version.empty()) use_weld = true;
                else if (compare_versions(weld_candidate.version, apt_state.candidate_version) > 0) use_weld = true;
            }

            if (use_weld) {
                AptPackageState target_apt_state = (weld_candidate.is_replacement)
                    ? get_apt_package_state(cache_file, weld_candidate.actual_pkg_name)
                    : apt_state;
                if (target_apt_state.installed && !g_force_reinstall.load()
                    && compare_versions(target_apt_state.installed_version, weld_candidate.version) >= 0) {
                    extra_lines.push_back(weld_candidate.actual_pkg_name + " is already up to date ("
                        + weld_candidate.version + ") via Weld.");
                    continue;
                }
                std::string line = "Inst " + weld_candidate.actual_pkg_name + " (";
                if (target_apt_state.installed) line += target_apt_state.installed_version + " => ";
                line += weld_candidate.version + ") from Weld repository " + weld_candidate.base_url;
                extra_lines.push_back(line);
                continue;
            }

            if (!apt_state.found || apt_state.candidate_version.empty()) {
                log_error(std::format("unable to locate package {}", pkg_name));
                had_error = true;
                continue;
            }

            if (apt_state.installed && !g_force_reinstall.load()
                && compare_versions(apt_state.installed_version, apt_state.candidate_version) >= 0) {
                extra_lines.push_back(pkg_name + " is already the newest version ("
                    + apt_state.installed_version + ").");
                continue;
            }

            pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
            fixer.Clear(pkg);
            fixer.Protect(pkg);
            if (g_force_reinstall.load()) dep_cache->SetReInstall(pkg, true);
            dep_cache->MarkInstall(pkg, true);
        }
        if (!fixer.Resolve(true) || _error->PendingError()) {
            log_error("unable to resolve dependencies for this simulation.");
            _error->DumpErrors();
            had_error = true;
        }
    } else if (action == "remove" || action == "purge") {
        bool purge = (action == "purge");
        pkgProblemResolver fixer(dep_cache);
        for (const auto& pkg_name : pkgs) {
            pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
            if (pkg.end()) {
                log_error(std::format("unable to locate package {}", pkg_name));
                had_error = true;
                continue;
            }
            fixer.Clear(pkg);
            fixer.Protect(pkg);
            dep_cache->MarkDelete(pkg, purge);
        }
        if (!fixer.Resolve(true) || _error->PendingError()) {
            log_error("unable to resolve dependencies for this simulation.");
            _error->DumpErrors();
            had_error = true;
        }
    }

    for (const auto& l : extra_lines) std::print("{}\n", l);

    bool any = !extra_lines.empty();
    for (pkgCache::PkgIterator p = cache->PkgBegin(); !p.end(); ++p) {
        pkgDepCache::StateCache& state = (*dep_cache)[p];
        if (state.NewInstall() || state.Upgrade() || state.Downgrade() || (state.Install() && state.ReInstall())) {
            std::string old_ver = (p->CurrentVer != 0) ? p.CurrentVer().VerStr() : "";
            pkgCache::VerIterator cand = dep_cache->GetCandidateVersion(p);
            std::string new_ver = cand.end() ? "" : cand.VerStr();
            std::print("Inst {}", p.Name());
            if (!old_ver.empty()) std::print(" ({} => {})", old_ver, new_ver);
            else if (!new_ver.empty()) std::print(" ({})", new_ver);
            std::print("\n");
            any = true;
        } else if (state.Delete()) {
            std::print("Remv {}\n", p.Name());
            any = true;
        }
    }

    if (!any && !had_error) std::print("No changes would be made.\n");
    std::print("Simulation only - no packages were actually changed, downloaded, or installed.\n");
}

int main(int argc, char** argv) {
    setup_safety_handlers();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();
    pkgInitConfig(*_config);
    pkgInitSystem(*_config, _system);

    std::string command;
    std::vector<std::string> pkgs;
    bool apply_host = false;
    int search_page = 1;
    std::string arv_version = read_arvor_version_from_os_release();

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { show_help(); return 0; }
        else if (arg == "--v" || arg == "-v" || arg == "--version") {
            std::print("{}\n", weld_version_str());
            return 0;
        }
        else if (arg == "--vb") { _config->Set("Debug::pkgAcquire", "true"); }
        else if (arg == "--apply-host") { apply_host = true; }
        else if (arg == "-y" || arg == "--yes" || arg == "--assume-yes") { g_assume_yes.store(true); }
        else if (arg == "--reinstall") { g_force_reinstall.store(true); }
        else if (arg == "-s" || arg == "--simulate" || arg == "--dry-run" || arg == "--just-print") {
            g_simulate_mode.store(true);
        }
        else if (arg == "-p" && i + 1 < argc) {
            try { search_page = std::stoi(argv[++i]); } catch (...) { search_page = 1; }
        }
        else if (command.empty() && !arg.empty() && arg[0] != '-') { command = arg; }
        else if (!arg.empty() && arg[0] != '-') {
            if (!is_valid_package_name(arg) && !ends_with(arg, ".deb")) {
                log_error(std::format("invalid package name: {}", arg));
                return 1;
            }
            pkgs.push_back(arg);
        }
    }

    if (command.empty()) { show_help(); return 0; }

    if (command == "why") {
        if (pkgs.empty()) { std::print("Usage: weld why <package_name>\n"); return 1; }
        return show_package_why(pkgs[0]);
    }
    if (command == "depends" || command == "deps") {
        if (pkgs.empty()) { std::print("Usage: weld depends <package_name>\n"); return 1; }
        return show_package_depends(pkgs[0]);
    }
    if (command == "info" || command == "show") {
        if (pkgs.empty()) { std::print("Usage: weld info <package_name>\n"); return 1; }
        return show_package_info(pkgs[0]);
    }
    if (command == "list" || command == "list-installed") {
        return list_installed_packages();
    }
    if (command == "search") {
        return run_search(pkgs, search_page);
    }

    if (g_simulate_mode.load()) {
        if (command == "install") { simulate_transaction("install", pkgs); return 0; }
        if (command == "upgrade") {
            if (pkgs.empty()) simulate_transaction("upgrade", pkgs);
            else simulate_transaction("install", pkgs);
            return 0;
        }
        if (command == "dist-upgrade") { simulate_transaction("dist-upgrade", pkgs); return 0; }
        if (command == "remove" || command == "purge") { simulate_transaction(command, pkgs); return 0; }
    }

    if (geteuid() != 0) { log_error("root privileges required."); return 1; }

    if (!check_system_locks()) return 1;

    if (command == "sync") {
        bool apt_ok = false;
        {
            pkgCacheFile cache_file;
            pkgSourceList* src_list = cache_file.GetSourceList();
            if (src_list != nullptr) {
                WeldSyncStatus status("Syncing Debian Repositories");
                apt_ok = ListUpdate(status, *src_list);
                if (!apt_ok) _error->DumpErrors();
            } else {
                _error->DumpErrors();
            }
        }
        bool weld_ok = sync_weld_metadata();
        if (apt_ok && weld_ok) {
            report_upgradeable_packages();
            return 0;
        }
        return 1;
    } else if (command == "clean") {
        return clean_weld_cache() ? 0 : 1;
    } else if (command == "autoclean") {
        return autoclean_weld_cache() ? 0 : 1;
    } else if (command == "rollback") {
        do_transaction_rollback();
    } else if (command == "dist-upgrade") {
#ifdef nflinux
        do_nflinux_upgrade(apply_host, arv_version);
#else
        (void)arv_version;
        perform_transaction("dist-upgrade", pkgs, apply_host);
#endif
    } else if (command == "install") {
        (void)arv_version;
        perform_install_transaction(pkgs, apply_host);
    } else if (command == "upgrade") {
        (void)arv_version;
        perform_upgrade_transaction(pkgs, apply_host);
    } else if (command == "remove" || command == "purge") {
        (void)arv_version;
        perform_transaction(command, pkgs, apply_host);
    } else {
        log_error(std::format("unknown command: {}", command));
        show_help();
        return 1;
    }

    curl_global_cleanup();
    EVP_cleanup();
    ERR_free_strings();
    release_system_locks();
    return 0;
}
