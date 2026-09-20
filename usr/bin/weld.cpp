#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cerrno>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <utility>
#include <set>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sched.h>
#include <dirent.h>
#include <fcntl.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <csignal>
#include <mutex>
#include <future>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <apt-pkg/init.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/acquire.h>
#include <apt-pkg/acquire-item.h>
#include <apt-pkg/algorithms.h>
#include <apt-pkg/packagemanager.h>
#include <apt-pkg/pkgrecords.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/policy.h>
#include <apt-pkg/upgrade.h>
#include <apt-pkg/error.h>
#include <apt-pkg/version.h>
#include <apt-pkg/install-progress.h>
#include <apt-pkg/debfile.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/tagfile.h>
#include <apt-pkg/update.h>
#include <apt-pkg/clean.h>
#include <memory>
#include <cstdint>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x05000000U
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

#ifdef arvor_version
#define ARVOR_VERSION arvor_version
#else
#define ARVOR_VERSION "arvor linux 0.0"
#endif

using namespace std;
namespace fs = std::filesystem;

const string TREE_ROOT = "/nsm/weld/root";
const string NF_TREE_BIN = "/usr/bin/nsm";
const string AUTO_SNAP_DIR = "/nsm/snapshots/auto";

const string WELD_ETC_DIR             = "/etc/weld";
const string WELD_SOURCES_FILE        = "/etc/weld/sources.list";
const string WELD_SOURCES_DIR         = "/etc/weld/sources.list.d";
const string WELD_CACHE_DIR           = "/etc/weld/cache";
const string WELD_TRUSTED_KEYS_DIR     = "/etc/weld/trusted_keys";

static const size_t WELD_MIN_MEM_MB = 256;

static bool assume_yes = false;
static std::atomic<bool> sandbox_created_and_mounted(false);

static string get_root_device();
static string get_root_fstype();
static string get_vg_name(const string& lv_path);
static bool is_lv_thin(const string& lv_path);
static double get_vg_free_gb(const string& vg_name);
static long do_pivot_root(const char* new_root, const char* put_old);

namespace {

vector<unsigned char> base64_decode_buf(const string& s) {
    if (s.empty()) return {};
    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) return {};
    BIO* mem = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
    if (!mem) { BIO_free_all(b64); return {}; }
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    vector<unsigned char> out(s.size());
    int n = BIO_read(b64, out.data(), static_cast<int>(s.size()));
    BIO_free_all(b64);
    if (n <= 0) return {};
    out.resize(static_cast<size_t>(n));
    return out;
}

bool compute_blake2b512(const unsigned char* data, size_t len, unsigned char out[64]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    const EVP_MD* md = EVP_blake2b512();
    if (!md) { EVP_MD_CTX_free(ctx); return false; }
    if (EVP_DigestInit_ex(ctx, md, NULL) == 1) {
        if (EVP_DigestUpdate(ctx, data, len) == 1) {
            unsigned int out_len = 0;
            if (EVP_DigestFinal_ex(ctx, out, &out_len) == 1 && out_len == 64) ok = true;
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool verify_ed25519(const unsigned char* msg, size_t msg_len,
                   const unsigned char sig[64], const unsigned char pubkey[32]) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, 32);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1) {
        int rc = EVP_DigestVerify(ctx, sig, 64, msg, msg_len);
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
    string trusted_comment;
    unsigned char global_sig[64];
};

bool parse_minisign_pub_blob(const vector<unsigned char>& blob, MinisignPublicKey& key) {
    if (blob.size() != 42) return false;
    if (blob[0] != 'E' || blob[1] != 'd') return false;
    memcpy(key.key_id, blob.data() + 2, 8);
    memcpy(key.pubkey, blob.data() + 10, 32);
    return true;
}

bool parse_minisign_sig_blob(const vector<unsigned char>& blob, MinisignSignature& sig) {
    if (blob.size() != 74) return false;
    memcpy(sig.sig_alg, blob.data(), 2);
    bool prehashed = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'D');
    bool raw_ed    = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'd');
    if (!prehashed && !raw_ed) return false;
    memcpy(sig.key_id, blob.data() + 2, 8);
    memcpy(sig.sig,    blob.data() + 10, 64);
    return true;
}

string hex_encode(const unsigned char* data, size_t len) {
    static const char* hexchars = "0123456789abcdef";
    string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hexchars[(data[i] >> 4) & 0xF]);
        out.push_back(hexchars[data[i] & 0xF]);
    }
    return out;
}

}

bool read_text_file(const string& path, string& content);
bool write_text_file(const string& path, const string& content);

class ChrootSeccompManager {
public:
    static bool apply_filter(string& err_out) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            err_out = "Failed to set PR_SET_NO_NEW_PRIVS: " + string(strerror(errno));
            return false;
        }

        vector<sock_filter> filter;

        filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)));

#if SECCOMP_TARGET_ARCH != 0
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_TARGET_ARCH, 1, 0));
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
#else
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#endif

        filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)));

        vector<int> blocked_syscalls;

        const int syscalls_to_block[] = {
#ifdef __NR_reboot
            __NR_reboot,
#endif
#ifdef __NR_init_module
            __NR_init_module,
#endif
#ifdef __NR_delete_module
            __NR_delete_module,
#endif
#ifdef __NR_finit_module
            __NR_finit_module,
#endif
#ifdef __NR_create_module
            __NR_create_module,
#endif
#ifdef __NR_get_kernel_syms
            __NR_get_kernel_syms,
#endif
#ifdef __NR_query_module
            __NR_query_module,
#endif
#ifdef __NR_kexec_load
            __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
            __NR_kexec_file_load,
#endif
#ifdef __NR_swapon
            __NR_swapon,
#endif
#ifdef __NR_swapoff
            __NR_swapoff,
#endif
#ifdef __NR_acct
            __NR_acct,
#endif
#ifdef __NR_ptrace
            __NR_ptrace,
#endif
#ifdef __NR_bpf
            __NR_bpf,
#endif
#ifdef __NR_userfaultfd
            __NR_userfaultfd,
#endif
#ifdef __NR_syslog
            __NR_syslog,
#endif
#ifdef __NR_iopl
            __NR_iopl,
#endif
#ifdef __NR_ioperm
            __NR_ioperm,
#endif
#ifdef __NR_vmsplice
            __NR_vmsplice,
#endif
#ifdef __NR_add_key
            __NR_add_key,
#endif
#ifdef __NR_request_key
            __NR_request_key,
#endif
#ifdef __NR_keyctl
            __NR_keyctl,
#endif
#ifdef __NR_pivot_root
            __NR_pivot_root,
#endif
#ifdef __NR_chroot
            __NR_chroot,
#endif
#ifdef __NR_mount
            __NR_mount,
#endif
#ifdef __NR_umount
            __NR_umount,
#endif
#ifdef __NR_umount2
            __NR_umount2,
#endif
#ifdef __NR_move_mount
            __NR_move_mount,
#endif
#ifdef __NR_open_tree
            __NR_open_tree,
#endif
#ifdef __NR_fsopen
            __NR_fsopen,
#endif
#ifdef __NR_fspick
            __NR_fspick,
#endif
#ifdef __NR_fsconfig
            __NR_fsconfig,
#endif
#ifdef __NR_fsmount
            __NR_fsmount,
#endif
#ifdef __NR_mount_setattr
            __NR_mount_setattr,
#endif
#ifdef __NR_clock_settime
            __NR_clock_settime,
#endif
#ifdef __NR_settimeofday
            __NR_settimeofday,
#endif
#ifdef __NR_stime
            __NR_stime,
#endif
#ifdef __NR_sethostname
            __NR_sethostname,
#endif
#ifdef __NR_setdomainname
            __NR_setdomainname,
#endif
#ifdef __NR_unshare
            __NR_unshare,
#endif
#ifdef __NR_setns
            __NR_setns,
#endif
#ifdef __NR_personality
            __NR_personality,
#endif
#ifdef __NR_process_vm_readv
            __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
            __NR_process_vm_writev,
#endif
#ifdef __NR_lookup_dcookie
            __NR_lookup_dcookie,
#endif
#ifdef __NR_perf_event_open
            __NR_perf_event_open,
#endif
#ifdef __NR_open_by_handle_at
            __NR_open_by_handle_at,
#endif
#ifdef __NR_fanotify_init
            __NR_fanotify_init,
#endif
#ifdef __NR_quotactl
            __NR_quotactl,
#endif
#ifdef __NR_nfsservctl
            __NR_nfsservctl,
#endif
#ifdef __NR_ioprio_set
            __NR_ioprio_set,
#endif
        };

        for (int sys_nr : syscalls_to_block) {
            if (sys_nr <= 0) continue;
            blocked_syscalls.push_back(sys_nr);
        }

        for (int sys_nr : blocked_syscalls) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)sys_nr, 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
        }

        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

        struct sock_fprog prog;
        prog.len = (unsigned short)filter.size();
        prog.filter = filter.data();

        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            err_out = "Failed to load SECCOMP filter: " + string(strerror(errno));
            return false;
        }

        return true;
    }
};

bool parse_minisign_pub_file(const string& content, MinisignPublicKey& key) {
    stringstream ss(content);
    string line;
    int line_num = 0;
    while (getline(ss, line)) {
        ++line_num;
        if (line_num != 2) continue;
        string b64 = line;
        while (!b64.empty() && (b64.back() == '\r' || b64.back() == '\n')) b64.pop_back();
        auto blob = base64_decode_buf(b64);
        return parse_minisign_pub_blob(blob, key);
    }
    return false;
}

bool parse_minisign_sig_file(const string& content, MinisignSignature& sig) {
    stringstream ss(content);
    string line;
    vector<string> lines;
    while (getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        lines.push_back(line);
    }
    if (lines.size() < 4) return false;
    auto sig_blob = base64_decode_buf(lines[1]);
    if (!parse_minisign_sig_blob(sig_blob, sig)) return false;
    static const string trusted_prefix = "trusted comment: ";
    if (lines[2].rfind(trusted_prefix, 0) != 0) return false;
    sig.trusted_comment = lines[2].substr(trusted_prefix.size());
    auto global_blob = base64_decode_buf(lines[3]);
    if (global_blob.size() != 64) return false;
    memcpy(sig.global_sig, global_blob.data(), 64);
    return true;
}

bool verify_minisign_signature(const string& content, const MinisignSignature& sig, const MinisignPublicKey& key) {
    if (memcmp(sig.key_id, key.key_id, 8) != 0) return false;

    bool prehashed = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'D');
    bool raw_ed    = (sig.sig_alg[0] == 'E' && sig.sig_alg[1] == 'd');
    if (!prehashed && !raw_ed) return false;

    if (raw_ed) {
        if (!verify_ed25519(reinterpret_cast<const unsigned char*>(content.data()),
                            content.size(), sig.sig, key.pubkey)) {
            return false;
        }
    } else {
        unsigned char hash[64];
        if (!compute_blake2b512(reinterpret_cast<const unsigned char*>(content.data()),
                               content.size(), hash)) {
            return false;
        }
        if (!verify_ed25519(hash, 64, sig.sig, key.pubkey)) {
            return false;
        }
    }

    vector<unsigned char> signed_comment;
    signed_comment.reserve(64 + sig.trusted_comment.size());
    signed_comment.insert(signed_comment.end(), sig.sig, sig.sig + 64);
    signed_comment.insert(signed_comment.end(),
                          sig.trusted_comment.begin(),
                          sig.trusted_comment.end());

    return verify_ed25519(signed_comment.data(), signed_comment.size(),
                          sig.global_sig, key.pubkey);
}

vector<MinisignPublicKey> load_trusted_minisign_keys() {
    vector<MinisignPublicKey> keys;
    DIR* dir = opendir(WELD_TRUSTED_KEYS_DIR.c_str());
    if (!dir) return keys;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        string name = entry->d_name;
        if (name.size() < 5) continue;
        if (name.substr(name.size() - 4) != ".pub") continue;
        string path = WELD_TRUSTED_KEYS_DIR + "/" + name;
        ifstream in(path);
        if (!in) continue;
        stringstream buf;
        buf << in.rdbuf();
        MinisignPublicKey key;
        if (parse_minisign_pub_file(buf.str(), key)) keys.push_back(key);
    }
    closedir(dir);
    return keys;
}

bool verify_repo_metadata_signature(const string& metadata, const string& sig_content,
                                     string& trusted_comment_out, string& error_out) {
    MinisignSignature sig;
    if (!parse_minisign_sig_file(sig_content, sig)) {
        error_out = "minisign signature is malformed";
        return false;
    }

    vector<MinisignPublicKey> keys = load_trusted_minisign_keys();
    if (keys.empty()) {
        error_out = "no trusted minisign keys installed in " + WELD_TRUSTED_KEYS_DIR;
        return false;
    }

    bool key_seen = false;
    for (const auto& key : keys) {
        if (memcmp(key.key_id, sig.key_id, 8) != 0) continue;
        key_seen = true;
        if (verify_minisign_signature(metadata, sig, key)) {
            trusted_comment_out = sig.trusted_comment;
            return true;
        }
    }

    if (!key_seen) {
        error_out = "no trusted key matches the signature key id " + hex_encode(sig.key_id, 8);
    } else {
        error_out = "signature verification failed for matched trusted key";
    }
    return false;
}


struct ConfigBackup {
    string os_release_orig;
    string apt_sources_orig;
    string weld_sources_orig;

    string os_release_new;
    string apt_sources_new;
    string weld_sources_new;

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

    void set_new(const string& os, const string& apt, const string& weld) {
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

static ConfigBackup global_config_backup;

struct WeldSource {
    string base_url;
    string release;
};

struct WeldRepoMetadata {
    string base_url;
    string release;
    string name;
    string maintainer;
    string trusted_comment;
    map<string, pair<string, string>> packages;
    map<string, string> descriptions;
    vector<string> required_packages;
    map<string, string> replaces;
};

struct WeldPackageCandidate {
    bool found = false;
    string base_url;
    string release;
    string file_name;
    string version;
    string sha256;
    string actual_pkg_name;
    string original_query_name;
    string description;
    bool is_replacement = false;
};

struct AptPackageState {
    bool found = false;
    bool installed = false;
    string installed_version;
    string candidate_version;
};

struct InstallDecision {
    string package_name;
    string apt_argument;
    string selected_version;
    bool from_weld = false;
};

void perform_install_transaction(const vector<string>& pkgs, bool apply_host, bool is_upgrade = false);
bool run_libapt_transaction(const string& action, const vector<string>& targets, int status_fd, bool quiet);

bool nf_tree_available() {
    return access(NF_TREE_BIN.c_str(), X_OK) == 0;
}

static string weld_arch() {
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

static string weld_version_str() {
    return string("Weld 4.2 (") + weld_arch() + ")";
}

void show_help() {
    string title = "\033[1;36m";
    string hdr = "\033[1;97m";
    string tx = "\033[38;5;114m";
    string qx = "\033[38;5;179m";
    string dim = "\033[2m";
    string reset = "\033[0m";

    cout << title << weld_version_str() << reset << "\n";
    cout << "Usage: weld <command> [packages] [options]\n\n";

    cout << hdr << "Transaction Commands:" << reset << "\n";
    cout << "  " << tx << "install" << reset << "       <pkgs...>   Install packages or local .deb archives\n";
    cout << "  " << tx << "remove" << reset << "        <pkgs...>   Remove packages from the system\n";
    cout << "  " << tx << "purge" << reset << "         <pkgs...>   Remove packages along with their configuration files\n";
    cout << "  " << tx << "upgrade" << reset << "       [pkgs...]   Upgrade all packages, or only those specified\n";
    cout << "  " << tx << "dist-upgrade" << reset << "               Perform a full system release upgrade\n";
    cout << "  " << tx << "rollback" << reset << "                   Revert the last transaction using its pre-transaction snapshot\n\n";

    cout << hdr << "Query Commands:" << reset << "\n";
    cout << "  " << qx << "search" << reset << "        <term>      Search the package index (supports -p <page>)\n";
    cout << "  " << qx << "info" << reset << "          <pkg>       Show package origin, version and SHA256\n";
    cout << "  " << qx << "why" << reset << "           <pkg>       Show why a package is installed (reverse dependencies)\n";
    cout << "  " << qx << "depends" << reset << "       <pkg>       List a package's direct dependencies\n";
    cout << "  " << qx << "list" << reset << "                      List all installed packages\n\n";

    cout << hdr << "Maintenance Commands:" << reset << "\n";
#ifdef allow_weld_repositories
    cout << "  sync                      Refresh repository metadata (APT + Weld)\n";
    cout << "  clean                     Clear the APT and Weld package caches\n";
    cout << "  autoclean                 Remove obsolete packages from the APT and Weld caches\n\n";

    cout << hdr << "Security:" << reset << "\n";
    cout << "  Weld repositories are never trusted by default. Every repository\n";
    cout << "  metadata must be accompanied by a minisign signature and verified\n";
    cout << "  against the trusted keyring at " << WELD_TRUSTED_KEYS_DIR << ".\n\n";
#else
    cout << "  sync                      Refresh APT repository metadata\n";
    cout << "  clean                     Clear the APT package cache\n";
    cout << "  autoclean                 Remove obsolete packages from the APT cache\n\n";

    cout << hdr << "Security:" << reset << "\n";
    cout << "  Weld repository support is not compiled in.\n";
    cout << "  Rebuild with -Dallow_weld_repositories to enable Weld repos.\n\n";
#endif

    cout << hdr << "Options:" << reset << "\n";
    cout << "  " << dim << "--apply-host" << reset << "              Skip sandbox verification and apply directly to the host\n";
    cout << "  " << dim << "-y, --yes" << reset << "                 Assume yes to all confirmation prompts\n";
    cout << "  " << dim << "--vb" << reset << "                      Enable verbose transaction logging\n";
    cout << "  " << dim << "-h, --help" << reset << "                Show this help message\n";
    cout << "  " << dim << "-v, --version" << reset << "             Show the Weld version\n";
}

static bool wait_for_child(pid_t pid, int& status) {
    status = 0;
    while (true) {
        pid_t ret = waitpid(pid, &status, 0);
        if (ret == pid) return true;
        if (ret == -1 && errno == EINTR) continue;
        return false;
    }
}

static bool is_safe_argument(const string& arg) {
    if (arg.empty()) return false;
    if (arg.find('\0') != string::npos) return false;
    if (arg.find('\n') != string::npos) return false;
    if (arg.find('\r') != string::npos) return false;
    return true;
}

static bool is_safe_device_path(const string& path) {
    if (path.empty()) return false;
    if (path[0] != '/') return false;
    if (path.find("..") != string::npos) return false;
    if (path.find('\0') != string::npos) return false;
    if (path.find('\n') != string::npos) return false;
    if (path.size() > 4096) return false;
    if (path.find(" ") != string::npos) return false;
    if (path.find(";") != string::npos) return false;
    if (path.find("|") != string::npos) return false;
    if (path.find("&") != string::npos) return false;
    if (path.find("$") != string::npos) return false;
    if (path.find("`") != string::npos) return false;
    if (path.find("()") != string::npos) return false;
    if (path.find("<") != string::npos) return false;
    if (path.find(">") != string::npos) return false;
    if (path.find("\\") != string::npos) return false;
    return true;
}

static void exec_abs_argv(const vector<char*>& argv_ptrs) {
    if (argv_ptrs.empty() || argv_ptrs[0] == nullptr) _exit(127);
    const char* binary = argv_ptrs[0];
    if (strchr(binary, '/')) {
        execv(binary, const_cast<char* const*>(argv_ptrs.data()));
    } else {
        const char* paths[] = {"/usr/bin", "/bin", "/usr/sbin", "/sbin"};
        char fullpath[4096];
        for (size_t i = 0; i < 4; ++i) {
            snprintf(fullpath, sizeof(fullpath), "%s/%s", paths[i], binary);
            execv(fullpath, const_cast<char* const*>(argv_ptrs.data()));
        }
    }
    _exit(127);
}

static int exec_argv(const vector<string>& args, int stdout_fd = -1, int stderr_fd = -1, int extra_fd = -1) {
    if (args.empty()) return 1;

    pid_t pid = fork();
    if (pid < 0) return 1;

    if (pid == 0) {
        int devnull_r = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }

        if (stdout_fd >= 0 && stdout_fd != STDOUT_FILENO)
            dup2(stdout_fd, STDOUT_FILENO);
        if (stderr_fd >= 0 && stderr_fd != STDERR_FILENO)
            dup2(stderr_fd, STDERR_FILENO);
        if (extra_fd >= 0) {
            if (extra_fd != 3) dup2(extra_fd, 3);
            fcntl(3, F_SETFD, 0);
        }

        if (stdout_fd >= 0 && stdout_fd != STDOUT_FILENO &&
            stdout_fd != STDERR_FILENO && stdout_fd != 3)
            close(stdout_fd);
        if (stderr_fd >= 0 && stderr_fd != STDERR_FILENO &&
            stderr_fd != STDOUT_FILENO && stderr_fd != 3 &&
            stderr_fd != stdout_fd)
            close(stderr_fd);
        if (extra_fd >= 0 && extra_fd != 3 &&
            extra_fd != STDOUT_FILENO && extra_fd != STDERR_FILENO)
            close(extra_fd);

        DIR* dir = opendir("/proc/self/fd");
        if (dir) {
            int dir_fd = dirfd(dir);
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                int fd = atoi(entry->d_name);
                if (fd > 2 && fd != extra_fd && fd != dir_fd) {
                    close(fd);
                }
            }
            closedir(dir);
        } else {
            int max_fd = static_cast<int>(sysconf(_SC_OPEN_MAX));
            if (max_fd < 0 || max_fd > 4096) max_fd = 1024;
            for (int fd = 4; fd < max_fd; ++fd) close(fd);
        }

        vector<char*> argv_ptrs;
        argv_ptrs.reserve(args.size() + 1);
        for (const auto& a : args) argv_ptrs.push_back(const_cast<char*>(a.c_str()));
        argv_ptrs.push_back(nullptr);

        exec_abs_argv(argv_ptrs);
    }

    int status = 0;
    wait_for_child(pid, status);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

static int exec_argv_devnull_out(const vector<string>& args) {
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int rc = exec_argv(args, devnull, devnull);
    if (devnull >= 0) close(devnull);
    return rc;
}

static int exec_argv_devnull_out_checked(const vector<string>& args) {
    if (args.empty()) return 1;
    for (const auto& a : args) {
        if (!is_safe_argument(a)) return 1;
    }
    return exec_argv_devnull_out(args);
}

static string exec_argv_capture(const vector<string>& args) {
    if (args.empty()) return "";

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return "";

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return ""; }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        int devnull_r = open("/dev/null", O_RDONLY);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }
        for (int fd = 3; fd < 1024; ++fd) close(fd);

        vector<char*> argv_ptrs;
        argv_ptrs.reserve(args.size() + 1);
        for (const auto& a : args) argv_ptrs.push_back(const_cast<char*>(a.c_str()));
        argv_ptrs.push_back(nullptr);
        exec_abs_argv(argv_ptrs);
    }

    close(pipefd[1]);
    char buf[512];
    string result;
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        result.append(buf, n);
    close(pipefd[0]);

    int status = 0;
    wait_for_child(pid, status);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return result;
    return "";
}

bool create_snapshot(const string& name) {
    if (name.empty() || name.find('/') != string::npos) return false;
    if (nf_tree_available()) {
        if (exec_argv_devnull_out_checked({NF_TREE_BIN, "create", name}) == 0) return true;
    }
    string root_dev = get_root_device();
    string vg_name = get_vg_name(root_dev);
    if (!root_dev.empty() && !vg_name.empty() && is_safe_device_path(root_dev)) {
        string snap_name = name + "_" + to_string(time(nullptr));
        if (is_lv_thin(root_dev)) {
            return exec_argv_devnull_out_checked({"lvcreate", "-s", "-k", "n", "--name", snap_name, root_dev}) == 0;
        }
        return exec_argv_devnull_out_checked({"lvcreate", "-s", "--name", snap_name, "-k", "n", root_dev}) == 0;
    }
    return false;
}

enum class PrecheckResult { Proceed, NoChanges, Failed };

PrecheckResult precheck_transaction(const string& action, const vector<string>& pkgs, bool quiet) {
    if (action != "install" && action != "remove" && action != "purge")
        return PrecheckResult::Proceed;

    if (pkgs.empty()) {
        if (!quiet) cout << "No packages were specified.\n";
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
            if (!quiet) cout << "Package " << pkg_name << " not found.\n";
            return PrecheckResult::Failed;
        }

        if (action == "install") {
            pkgCache::VerIterator cand = dep_cache->GetCandidateVersion(pkg);
            if (pkg->CurrentVer != 0 && (cand.end() || cand == pkg.CurrentVer())) {
                if (!quiet) cout << pkg_name << " is already the newest version.\n";
                continue;
            }
            has_changes = true;
            continue;
        }

        if (pkg->CurrentVer == 0) {
            if (!quiet) cout << "Package " << pkg_name << " is not installed.\n";
            continue;
        }

        has_changes = true;
    }

    return has_changes ? PrecheckResult::Proceed : PrecheckResult::NoChanges;
}

static void bind_safe_dev_node(const string& host_path, const string& chroot_path, mode_t mode) {
    error_code ec;
    if (!fs::exists(host_path, ec)) return;
    if (!fs::exists(chroot_path, ec)) {
        if (!fs::create_directories(fs::path(chroot_path).parent_path(), ec)) return;
        mknod(chroot_path.c_str(), mode | 0, 0);
    }
    exec_argv_devnull_out({"mount", "--bind", host_path, chroot_path});
}

void mount_fs() {
    error_code ec;
    fs::create_directories(TREE_ROOT + "/dev", ec);
    fs::create_directories(TREE_ROOT + "/dev/pts", ec);

    exec_argv_devnull_out({"mount", "-t", "devtmpfs", "-o", "nosuid,noexec,mode=755", "devtmpfs", TREE_ROOT + "/dev"});

    bind_safe_dev_node("/dev/null",   TREE_ROOT + "/dev/null",   S_IFCHR | 0666);
    bind_safe_dev_node("/dev/zero",   TREE_ROOT + "/dev/zero",   S_IFCHR | 0666);
    bind_safe_dev_node("/dev/random",  TREE_ROOT + "/dev/random", S_IFCHR | 0666);
    bind_safe_dev_node("/dev/urandom", TREE_ROOT + "/dev/urandom", S_IFCHR | 0666);
    bind_safe_dev_node("/dev/full",   TREE_ROOT + "/dev/full",   S_IFCHR | 0666);
    bind_safe_dev_node("/dev/tty",    TREE_ROOT + "/dev/tty",    S_IFCHR | 0666);

    exec_argv_devnull_out({"mount", "-t", "devpts", "-o", "nosuid,noexec,mode=620,ptmxmode=666",
                            "devpts", TREE_ROOT + "/dev/pts"});

    exec_argv_devnull_out({"mount", "-t", "tmpfs", "-o", "nosuid,noexec,mode=755,size=512M",
                            "tmpfs", TREE_ROOT + "/dev/shm"});

    if (fs::exists("/dev/ptmx", ec)) {
        if (!fs::exists(TREE_ROOT + "/dev/ptmx", ec)) mknod((TREE_ROOT + "/dev/ptmx").c_str(), S_IFCHR | 0666, 0);
        exec_argv_devnull_out({"mount", "--bind", "/dev/ptmx", TREE_ROOT + "/dev/ptmx"});
    }

    exec_argv_devnull_out({"mount", "--bind", "/proc",     TREE_ROOT + "/proc"});
    exec_argv_devnull_out({"mount", "-o", "remount,nosuid,nodev,hidepid=2", TREE_ROOT + "/proc"});
    exec_argv_devnull_out({"mount", "--bind", "/sys",      TREE_ROOT + "/sys"});
    exec_argv_devnull_out({"mount", "-o", "remount,ro,nosuid,nodev,noexec", TREE_ROOT + "/sys"});

    exec_argv_devnull_out({"mount", "-t", "tmpfs", "tmpfs", TREE_ROOT + "/tmp",
                            "-o", "mode=1777,nosuid,nodev,noexec,size=2G"});
    exec_argv_devnull_out({"mount", "-t", "tmpfs", "tmpfs", TREE_ROOT + "/run",
                            "-o", "mode=755,nosuid,nodev,noexec,size=512M"});

    string resolv_target = TREE_ROOT + "/etc/resolv.conf";
    if (!fs::exists("/etc/resolv.conf")) return;
    if (!fs::exists(resolv_target, ec)) {
        ofstream touch(resolv_target);
    }
    exec_argv_devnull_out({"mount", "--bind", "/etc/resolv.conf", resolv_target});
}

void umount_fs() {
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/run"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/tmp"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/etc/resolv.conf"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/shm"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/pts"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/ptmx"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/null"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/zero"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/random"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/urandom"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/full"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/tty"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/proc"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/sys"});
}

static string trim_str(const string& s) {
    size_t start = s.find_first_not_of(" \n\r\t<>");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \n\r\t<>");
    return s.substr(start, end - start + 1);
}

static string get_root_device() {
    string out = exec_argv_capture({"findmnt", "-n", "-o", "SOURCE", "/"});
    out = trim_str(out);
    size_t bracket = out.find('[');
    if (bracket != string::npos) out = out.substr(0, bracket);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' '))
        out.pop_back();
    if (out.empty()) return "";
    if (!is_safe_device_path(out)) return "";
    if (out.find("/dev/") != 0) return "";
    return out;
}

static string get_root_fstype() {
    string out = exec_argv_capture({"findmnt", "-n", "-o", "FSTYPE", "/"});
    return trim_str(out);
}

static string get_vg_name(const string& lv_path) {
    string out = exec_argv_capture({"lvs", "--noheadings", "-o", "vg_name", lv_path});
    return trim_str(out);
}

static bool is_lv_thin(const string& lv_path) {
    string out = exec_argv_capture({"lvs", "--noheadings", "-o", "segtype", lv_path});
    out = trim_str(out);
    return out.find("thin") != string::npos;
}

static double get_vg_free_gb(const string& vg_name) {
    string out = exec_argv_capture({"vgs", "--noheadings", "-o", "vg_free", "--units", "g", vg_name});
    out = trim_str(out);
    size_t g = out.find_first_of("gG");
    if (g != string::npos) out = out.substr(0, g);
    try { return stod(out); } catch (...) { return 0.0; }
}

static string g_cached_root_dev;
static string g_cached_vg_name;

#ifndef _LINUX_CAPABILITY_VERSION_3
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#endif

struct weld_cap_header {
    uint32_t version;
    int pid;
};

struct weld_cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static void drop_all_capabilities() {
    struct weld_cap_header hdr;
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    struct weld_cap_data data[2];
    memset(&data, 0, sizeof(data));
    syscall(__NR_capset, &hdr, data);
}

static long do_pivot_root(const char* new_root, const char* put_old) {
    return syscall(__NR_pivot_root, new_root, put_old);
}

static bool check_system_memory(size_t min_mb) {
    ifstream f("/proc/meminfo");
    if (!f) return true;
    string line;
    while (getline(f, line)) {
        if (line.rfind("MemAvailable:", 0) != 0) continue;
        istringstream iss(line.substr(13));
        unsigned long kb = 0;
        iss >> kb;
        unsigned long mb = kb / 1024;
        if (mb < min_mb) {
            cout << "W: Insufficient system memory. Available: " << mb
                 << " MB, minimum required: " << min_mb << " MB.\n";
            cout << "W: Transaction aborted to prevent system instability.\n";
            return false;
        }
        return true;
    }
    return true;
}

static void apply_strict_resource_limits() {
    struct rlimit rl;

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

bool manage_sandbox(const string& action) {
    string root_dev = get_root_device();
    string vg_name = get_vg_name(root_dev);
    g_cached_root_dev = root_dev;
    g_cached_vg_name = vg_name;
    string snap_lv_name = "weld_sandbox_snap";
    string snap_dev = "/dev/" + vg_name + "/" + snap_lv_name;

    if (action == "create") {
        umount_fs();
        exec_argv_devnull_out_checked({"umount", "-l", TREE_ROOT});
        if (!snap_dev.empty() && is_safe_device_path(snap_dev))
            exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev});
        exec_argv_devnull_out_checked({"mkdir", "-p", "/nsm/weld"});

        if (root_dev.empty() || vg_name.empty() || !is_safe_device_path(root_dev)) {
            cout << "E: Unable to determine the root LVM device or volume group.\n";
            return false;
        }

        bool thin = is_lv_thin(root_dev);
        int rc;
        if (thin) {
            rc = exec_argv_devnull_out_checked({"lvcreate", "-s", "-k", "n", "--name", snap_lv_name, root_dev});
        } else {
            cout << "W: Root logical volume is not thin-provisioned.\n";
            cout << "W: Falling back to thick snapshot. Free VG space will be consumed.\n";
            double free_gb = get_vg_free_gb(vg_name);
            if (free_gb < 1.0) {
                cout << "E: Insufficient free space in volume group: 1 GB required, "
                     << free_gb << " GB available.\n";
                return false;
            }
            string snap_size = "1G";
            if (free_gb >= 10.0) snap_size = "5G";
            else if (free_gb >= 5.0) snap_size = "3G";
            else if (free_gb >= 2.0) snap_size = "1.5G";

            rc = exec_argv_devnull_out_checked({"lvcreate", "-L", snap_size, "-s", "--name", snap_lv_name, root_dev});
        }

        if (rc != 0) {
            cout << "E: LVM snapshot of " << root_dev << " failed (exit code " << rc << ").\n";
            return false;
        }

        exec_argv_devnull_out_checked({"lvchange", "-ay", "--ignoreactivationskip", snap_dev});
        exec_argv_devnull_out_checked({"udevadm", "settle"});

        struct stat dev_st;
        bool dev_ready = false;
        for (int attempt = 0; attempt < 50; ++attempt) {
            if (stat(snap_dev.c_str(), &dev_st) == 0 && S_ISBLK(dev_st.st_mode)) { dev_ready = true; break; }
            usleep(100000);
        }

        if (!dev_ready) {
            cout << "E: Snapshot device " << snap_dev << " did not become available in time.\n";
            exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev});
            return false;
        }

        exec_argv_devnull_out_checked({"mkdir", "-p", TREE_ROOT});

        string fstype = get_root_fstype();
        int mount_rc;
        if (fstype == "xfs") {
            mount_rc = exec_argv_devnull_out_checked({"mount", "-t", "xfs", "-o", "nouuid", snap_dev, TREE_ROOT});
        } else if (!fstype.empty() && fstype.find(',') == string::npos) {
            mount_rc = exec_argv_devnull_out_checked({"mount", "-t", fstype, snap_dev, TREE_ROOT});
        } else {
            mount_rc = exec_argv_devnull_out_checked({"mount", snap_dev, TREE_ROOT});
        }

        if (mount_rc != 0) {
            cout << "E: Unable to mount snapshot at " << TREE_ROOT << " (exit code " << mount_rc << ").\n";
            exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev});
            return false;
        }

        struct stat st;
        if (stat(TREE_ROOT.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            cout << "E: Sandbox root " << TREE_ROOT << " was not created.\n";
            return false;
        }

        exec_argv_devnull_out_checked({"mkdir", "-p", TREE_ROOT + "/tmp"});
        exec_argv_devnull_out_checked({"chmod", "1777", TREE_ROOT + "/tmp"});
        sandbox_created_and_mounted.store(true);
        return true;

    } else if (action == "delete") {
        umount_fs();
        exec_argv_devnull_out_checked({"umount", "-l", TREE_ROOT});
        if (!snap_dev.empty() && is_safe_device_path(snap_dev))
            exec_argv_devnull_out_checked({"lvremove", "-f", snap_dev});
        sandbox_created_and_mounted.store(false);
        return true;
    }

    return false;
}

void cleanup_sandbox_on_exit() {
    if (sandbox_created_and_mounted.load()) {
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/run"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/tmp"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/etc/resolv.conf"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/shm"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/pts"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/ptmx"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/null"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/zero"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/random"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/urandom"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/full"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/tty"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/proc"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/sys"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT});

        string vg_name = !g_cached_vg_name.empty() ? g_cached_vg_name : get_vg_name(get_root_device());
        if (!vg_name.empty()) {
            string snap_dev = "/dev/" + vg_name + "/weld_sandbox_snap";
            exec_argv_devnull_out({"lvremove", "-f", snap_dev});
        }
        sandbox_created_and_mounted.store(false);
    }
    global_config_backup.restore_orig();
}

void handle_termination_signal(int sig) {
    (void)sig;
    cleanup_sandbox_on_exit();
    _exit(128 + sig);
}

void setup_safety_handlers() {
    atexit(cleanup_sandbox_on_exit);
    struct sigaction sa;
    sa.sa_handler = handle_termination_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
}


string get_latest_snapshot(const string& prefix) {
    DIR* dir = opendir(AUTO_SNAP_DIR.c_str());
    if (!dir) return "";
    struct dirent* entry;
    vector<string> matches;
    while ((entry = readdir(dir)) != NULL) {
        string name = entry->d_name;
        if (name.find(prefix) == 0) matches.push_back(name);
    }
    closedir(dir);
    if (matches.empty()) return "";
    sort(matches.begin(), matches.end());
    return matches.back();
}

void do_rollback(const string& prefix) {
    if (!nf_tree_available()) return;
    string root_snap = get_latest_snapshot("root-auto-" + prefix);
    if (!root_snap.empty()) {
        cout << "Rolling back to snapshot: " << root_snap << "\n";
        exec_argv_devnull_out({NF_TREE_BIN, "rollback", root_snap});
    }
}

static std::mutex g_cout_mutex;

string format_bytes(uint64_t bytes);

template<typename... Args>
void safe_log(Args&&... args) {
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    (std::cout << ... << std::forward<Args>(args));
    std::cout << std::flush;
}

string sanitize_filename(const string& raw) {
    size_t pos_slash = raw.find_last_of('/');
    string base = (pos_slash == string::npos) ? raw : raw.substr(pos_slash + 1);
    size_t start = base.find_first_not_of(" \n\r\t");
    string cleaned = (start == string::npos) ? "" : base.substr(start, base.find_last_not_of(" \n\r\t") - start + 1);

    string safe;
    safe.reserve(cleaned.size());
    for (char c : cleaned) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-') {
            safe.push_back(c);
        }
    }
    while (!safe.empty() && (safe.front() == '-' || safe.front() == '.')) {
        safe.erase(safe.begin());
    }
    if (safe == "." || safe == "..") safe = "safe_file";
    return safe.empty() ? "safe_file" : safe;
}

string trim_copy(const string& s) {
    size_t start = s.find_first_not_of(" \n\r\t");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \n\r\t");
    return s.substr(start, end - start + 1);
}

bool starts_with(const string& value, const string& prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const string& value, const string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

string render_sync_progress(int percentage, const string& label) {
    if (percentage < 0) percentage = 0;
    if (percentage > 100) percentage = 100;
    const int total_width = 60;
    string prefix = label + " ";
    string pct = to_string(percentage) + "%";
    while (pct.size() < 4) pct = " " + pct;
    int bar_width = total_width - static_cast<int>(prefix.size()) - static_cast<int>(pct.size()) - 1;
    if (bar_width < 1) bar_width = 1;
    int filled = (percentage * bar_width) / 100;
    string bar;
    bar.reserve(bar_width);
    for (int i = 0; i < filled; ++i) bar += '-';
    for (int i = filled; i < bar_width; ++i) bar += ' ';
    ostringstream oss;
    oss << "\r" << prefix << bar << " " << pct;
    return oss.str();
}

class WeldAcquireStatus final : public pkgAcquireStatus {
    int fd;
    bool show_host;
    string label;
    int last_shown = -1;
public:
    WeldAcquireStatus(int fd_, bool show_host_, string label_ = "packages")
        : fd(fd_), show_host(show_host_), label(std::move(label_)) {}
    bool MediaChange(string, string) override { return false; }
    bool Pulse(pkgAcquire* owner) override {
        pkgAcquireStatus::Pulse(owner);
        int pct = static_cast<int>(Percent);
        if (fd >= 0) {
            string line = "dlstatus:0:" + to_string(Percent) + ":Downloading\n";
            ssize_t written = write(fd, line.c_str(), line.size());
            (void)written;
        } else if (show_host && pct != last_shown) {
            cout << render_sync_progress(pct, label) << flush;
            last_shown = pct;
        }
        return true;
    }
    void Stop() override {
        pkgAcquireStatus::Stop();
        if (fd < 0 && show_host) cout << "\n";
    }
};

class WeldSyncStatus final : public pkgAcquireStatus {
    string label;
    int last_pct = -1;
public:
    explicit WeldSyncStatus(string label_) : label(std::move(label_)) {}
    bool MediaChange(string, string) override { return false; }
    bool Pulse(pkgAcquire* owner) override {
        pkgAcquireStatus::Pulse(owner);
        int pct = static_cast<int>(Percent);
        if (pct != last_pct) {
            cout << render_sync_progress(pct, label) << flush;
            last_pct = pct;
        }
        return true;
    }
    void Stop() override {
        pkgAcquireStatus::Stop();
        cout << render_sync_progress(100, label) << "\n";
    }
};

static string local_deb_package_name(const string& path) {
    FileFd fd;
    if (!fd.Open(path, FileFd::ReadOnly)) return "";
    debDebFile deb(fd);
    debDebFile::MemControlExtract extract;
    if (!extract.Read(deb)) return "";
    return extract.Section.FindS("Package");
}

static bool register_local_debs(pkgSourceList* src_list, const vector<string>& targets,
                                 map<string, string>& local_pkg_names, bool quiet) {
    for (const auto& t : targets) {
        if (!ends_with(t, ".deb")) continue;
        string pkg_name = local_deb_package_name(t);
        if (pkg_name.empty()) {
            if (!quiet) cout << "Could not determine package name for " << t << ".\n";
            _error->DumpErrors();
            return false;
        }
        if (!src_list->AddVolatileFile(t)) {
            if (!quiet) cout << "Failed to register local package " << t << ".\n";
            _error->DumpErrors();
            return false;
        }
        local_pkg_names[t] = pkg_name;
    }
    return true;
}

bool run_libapt_transaction(const string& action, const vector<string>& targets,
                             int status_fd, bool quiet) {
    if (status_fd >= 0) _config->Set("APT::Status-Fd", status_fd);
    _config->Set("Dpkg::Use-Pty", "false");
    _config->Set("APT::Sandbox::User", "root");

    pkgCacheFile cache_file;
    pkgSourceList* src_list = cache_file.GetSourceList();
    if (src_list == nullptr) { _error->DumpErrors(); return false; }

    map<string, string> local_pkg_names;
    if (!register_local_debs(src_list, targets, local_pkg_names, quiet)) return false;

    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();
    if (cache == nullptr || dep_cache == nullptr) { _error->DumpErrors(); return false; }

    pkgProblemResolver fixer(dep_cache);

    if (action == "install") {
        for (const auto& t : targets) {
            string pkg_name = ends_with(t, ".deb") ? local_pkg_names[t] : t;
            pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
            if (pkg.end()) {
                if (!quiet) cout << "Package " << pkg_name << " not found.\n";
                return false;
            }
            fixer.Clear(pkg);
            fixer.Protect(pkg);
            dep_cache->MarkInstall(pkg, true);
            if (!(*dep_cache)[pkg].Install()) {
                if (!quiet) cout << "Unable to mark " << pkg_name << " for installation.\n";
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
        if (!quiet) cout << "Unknown transaction: " << action << ".\n";
        return false;
    }

    if (!fixer.Resolve(true) || _error->PendingError()) {
        if (!quiet) cout << "Unable to resolve dependencies for this transaction.\n";
        _error->DumpErrors();
        return false;
    }

    unique_ptr<pkgPackageManager> pm(_system->CreatePM(dep_cache));
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
            if (need < 1024 * 1024)
                cout << "Downloading packages (" << (need / 1024) << " KB)...\n";
            else
                cout << "Downloading packages (" << (need / 1024 / 1024) << " MB)...\n";
        }
    }

    WeldAcquireStatus acquire_status(status_fd, !quiet && status_fd < 0);
    fetcher.SetLog(&acquire_status);
    if (fetcher.Run() != pkgAcquire::Continue) {
        _error->DumpErrors();
        return false;
    }

    unique_ptr<APT::Progress::PackageManager> pm_progress;
    if (status_fd >= 0)
        pm_progress = make_unique<APT::Progress::PackageManagerProgressFd>(status_fd);
    else
        pm_progress = make_unique<APT::Progress::PackageManager>();

    pkgPackageManager::OrderResult result = pm->DoInstall(pm_progress.get());
    if (result != pkgPackageManager::Completed) {
        _error->DumpErrors();
        return false;
    }

    return true;
}

bool path_is_directory(const string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool path_is_regular_file(const string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

string path_basename(const string& path) {
    size_t pos = path.find_last_of('/');
    if (pos == string::npos) return path;
    return path.substr(pos + 1);
}

#ifdef allow_weld_repositories
string normalize_weld_base_url(const string& raw_url) {
    string url = trim_copy(raw_url);
    if (url.find("http://") != 0 && url.find("https://") != 0)
        url = "https://" + url;
    while (!url.empty() && url.back() == '/') url.pop_back();
    return url;
}

bool parse_weld_source_line(const string& raw_line, WeldSource& source) {
    string line = trim_copy(raw_line);
    if (line.empty() || line[0] == '#') return false;
    istringstream iss(line);
    string type, base_url, release;
    if (!(iss >> type >> base_url >> release)) return false;
    if (type != "deb") return false;
    base_url = normalize_weld_base_url(base_url);
    release = trim_copy(release);
    if (base_url.empty() || release.empty()) return false;
    source.base_url = base_url;
    source.release = release;
    return true;
}

void load_weld_sources_from_file(const string& path, vector<WeldSource>& sources) {
    ifstream in(path);
    if (!in) return;
    string line;
    while (getline(in, line)) {
        WeldSource source;
        if (parse_weld_source_line(line, source)) sources.push_back(source);
    }
}
#endif

vector<WeldSource> load_weld_sources() {
#ifndef allow_weld_repositories
    return {};
#else
    vector<WeldSource> sources;

    if (path_is_regular_file(WELD_SOURCES_FILE))
        load_weld_sources_from_file(WELD_SOURCES_FILE, sources);

    if (path_is_directory(WELD_SOURCES_DIR)) {
        DIR* dir = opendir(WELD_SOURCES_DIR.c_str());
        if (dir != nullptr) {
            vector<string> files;
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                string name = entry->d_name;
                if (name == "." || name == "..") continue;
                string path = WELD_SOURCES_DIR + "/" + name;
                if (path_is_regular_file(path)) files.push_back(path);
            }
            closedir(dir);
            sort(files.begin(), files.end());
            for (const auto& path : files) load_weld_sources_from_file(path, sources);
        }
    }

    return sources;
#endif
}

bool write_text_file(const string& path, const string& content) {
    string dir = path;
    size_t slash = dir.find_last_of('/');
    if (slash != string::npos) dir = dir.substr(0, slash);
    else dir = ".";

    char tmpl[4096];
    int n = snprintf(tmpl, sizeof(tmpl), "%s/.weld_XXXXXX", dir.c_str());
    if (n < 0 || static_cast<size_t>(n) >= sizeof(tmpl)) return false;

    sigset_t old_mask, block_mask;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGINT);
    sigaddset(&block_mask, SIGTERM);
    sigaddset(&block_mask, SIGQUIT);
    sigaddset(&block_mask, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &block_mask, &old_mask);

    int fd = mkstemp(tmpl);
    if (fd < 0) {
        pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        return false;
    }

    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(tmpl);
        pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        return false;
    }

    bool write_ok = true;
    if (!content.empty()) {
        const char* data = content.data();
        size_t remaining = content.size();
        while (remaining > 0) {
            ssize_t written = write(fd, data, remaining);
            if (written < 0) {
                if (errno == EINTR) continue;
                write_ok = false;
                break;
            }
            data += written;
            remaining -= static_cast<size_t>(written);
        }
    }

    if (fsync(fd) != 0) write_ok = false;

    if (close(fd) != 0) write_ok = false;

    if (!write_ok) {
        unlink(tmpl);
        pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        return false;
    }

    bool renamed = (rename(tmpl, path.c_str()) == 0);
    if (!renamed) {
        unlink(tmpl);
    }
    pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
    return renamed;
}

bool read_text_file(const string& path, string& content) {
    ifstream in(path);
    if (!in) return false;
    stringstream buffer;
    buffer << in.rdbuf();
    content = buffer.str();
    return true;
}

string strip_inline_comment(const string& line) {
    string result;
    result.reserve(line.size());
    bool in_string = false;
    char string_quote = '\0';
    char prev = ' ';
    for (size_t i = 0; i < line.size(); ++i) {
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

string strip_quotes(const string& value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return value.substr(1, value.size() - 2);
    }
    if (value.size() >= 2 && value.front() == '\'' && value.back() == '\'') {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

bool parse_weld_repo_metadata_v2(const string& text, WeldRepoMetadata& metadata, string& error_out) {
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
        string name;
        string description;
        string sha256;
        string deb;
    };
    struct TempReplaces {
        string name;
        string replaces;
    };
    struct TempRequired {
        string name;
    };

    TempPkg pending_pkg;
    bool has_pending_pkg = false;
    TempReplaces pending_rep;
    bool has_pending_rep = false;
    TempRequired pending_req;
    bool has_pending_req = false;

    string cur_repo_name;
    string cur_repo_maintainer;
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
            error_out = "package record for '" + pending_pkg.name + "' missing required field: sha256";
            return false;
        }
        if (pending_pkg.deb.empty()) {
            error_out = "package record for '" + pending_pkg.name + "' missing required field: deb";
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
            error_out = "replaces record for '" + pending_rep.name + "' missing required field: replaces";
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

    stringstream ss(text);
    string raw_line;
    while (getline(ss, raw_line)) {
        string line = strip_inline_comment(raw_line);
        string trimmed = trim_copy(line);
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

        size_t colon = trimmed.find(':');
        if (colon == string::npos) continue;

        string key = trim_copy(trimmed.substr(0, colon));
        string value = strip_quotes(trim_copy(trimmed.substr(colon + 1)));

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

constexpr size_t WELD_MAX_METADATA_SIZE = 8 * 1024 * 1024;
constexpr size_t WELD_MAX_DOWNLOAD_SIZE = 1024ULL * 1024 * 1024;

struct CurlStringCtx {
    string* dest;
    size_t max_size;
    bool overflow = false;
};

size_t curl_string_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t total = size * nmemb;
    CurlStringCtx* ctx = static_cast<CurlStringCtx*>(userdata);
    if (ctx->dest->size() + total > ctx->max_size) {
        ctx->overflow = true;
        return 0;
    }
    ctx->dest->append(ptr, total);
    return total;
}

string curl_fetch_string(const string& url, const string& user_agent = "", long timeout_sec = 30,
                          size_t max_size = WELD_MAX_METADATA_SIZE) {
    if (url.empty()) return "";
    size_t start = url.find_first_not_of(" \n\r\t");
    string norm_url = (start == string::npos) ? "" : url.substr(start, url.find_last_not_of(" \n\r\t") - start + 1);
    if (norm_url.empty() || norm_url.front() == '-') return "";
    if (norm_url.find("https://") != 0) return "";
    if (norm_url.size() > 4096) return "";

    CURL* curl = curl_easy_init();
    if (!curl) return "";

    string response;
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
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Weld/4.2");
    }

    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || response_code != 200) return "";
    if (ctx.overflow) return "";
    return response;
}

size_t curl_file_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    FILE* fp = static_cast<FILE*>(userdata);
    return fwrite(ptr, size, nmemb, fp);
}

bool curl_download_file(const string& url, const string& dest_path, const string& user_agent = "") {
    if (url.empty() || dest_path.empty()) return false;
    if (url.find("https://") != 0) return false;

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
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Weld/4.2");
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

string fetch_url(const string& url) {
    return curl_fetch_string(url);
}

string fetch_url_with_ua(const string& url, const string& user_agent) {
    return curl_fetch_string(url, user_agent);
}

bool sync_weld_metadata() {
#ifndef allow_weld_repositories
    return true;
#else
    vector<WeldSource> sources = load_weld_sources();
    if (sources.empty()) return true;

    exec_argv_devnull_out({"mkdir", "-p", WELD_ETC_DIR});
    exec_argv_devnull_out({"mkdir", "-p", WELD_TRUSTED_KEYS_DIR});

    vector<MinisignPublicKey> trusted_keys = load_trusted_minisign_keys();
    if (trusted_keys.empty()) {
        cout << "E: No trusted minisign keys found in " << WELD_TRUSTED_KEYS_DIR << ".\n";
        cout << "E: To enable Weld repositories, install a valid '*.pub' keyring and run 'weld sync' again.\n";
        return false;
    }

    atomic<int> completed(0);
    int total = static_cast<int>(sources.size());
    safe_log(render_sync_progress(0, "Syncing Weld Repositories"));

    vector<future<bool>> futures;
    futures.reserve(sources.size());

    for (const auto& source : sources) {
        futures.push_back(std::async(std::launch::async, [source, &completed, total]() -> bool {
            string meta_url = source.base_url + "/releases/" + source.release + "/repo-metadata";
            string sig_url  = meta_url + ".minisig";

            string metadata = curl_fetch_string(meta_url);
            if (metadata.empty()) {
                safe_log("\nE: Failed to fetch repository metadata from ", meta_url, "\n");
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }

            string signature = curl_fetch_string(sig_url);
            if (signature.empty()) {
                safe_log("\nE: Repository ", source.base_url, " is missing its minisign signature.\n");
                safe_log("E: Expected signature file: ", sig_url, "\n");
                safe_log("E: Weld refuses to trust unsigned repository metadata.\n");
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }

            string trusted_comment;
            string verify_err;
            if (!verify_repo_metadata_signature(metadata, signature, trusted_comment, verify_err)) {
                safe_log("\nE: Signature verification failed for ", source.base_url, ": ", verify_err, "\n");
                safe_log("E: Weld refuses to use this repository.\n");
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }

            string safe_release = sanitize_filename(source.release);
            string release_dir = WELD_ETC_DIR + "/" + safe_release;
            if (exec_argv_devnull_out({"mkdir", "-p", release_dir}) != 0) {
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }
            string output_path = release_dir + "/repo-metadata";
            if (!write_text_file(output_path, metadata)) {
                int done = completed.fetch_add(1) + 1;
                int pct = (done * 100) / total;
                safe_log(render_sync_progress(pct, "Syncing Weld Repositories"));
                return false;
            }
            string sig_output_path = release_dir + "/repo-metadata.minisig";
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
    string archives = _config->FindDir("Dir::Cache::archives");
    if (archives.empty()) archives = "/var/cache/apt/archives/";
    if (!archives.empty() && archives.back() != '/') archives += "/";

    error_code ec;
    if (!fs::exists(archives, ec)) {
        cout << "APT archives directory does not exist: " << archives << "\n";
        return true;
    }

    bool removed_any = false;
    uint64_t bytes_freed = 0;

    for (const auto& entry : fs::directory_iterator(archives, ec)) {
        if (ec) {
            cout << "Failed to read APT archives directory: " << archives << "\n";
            return false;
        }
        string name = entry.path().filename().string();
        if (name == "partial" || name == "lock") continue;

        error_code fec;
        if (!entry.is_regular_file(fec)) continue;

        uint64_t sz = entry.file_size(fec);
        error_code rm_ec;
        fs::remove(entry.path(), rm_ec);
        if (!rm_ec) {
            bytes_freed += sz;
            removed_any = true;
        }
    }

    if (removed_any)
        cout << "APT archives cleaned: " << archives << "(" << format_bytes(bytes_freed) << " freed)\n";
    else
        cout << "APT archives already clean: " << archives << "\n";

    return true;
}

bool clean_weld_cache_only() {
#ifndef allow_weld_repositories
    return true;
#else
    error_code ec;
    string cache_dir = WELD_CACHE_DIR;
    if (!fs::exists(cache_dir, ec)) {
        if (!fs::create_directories(cache_dir, ec)) {
            cout << "Failed to create Weld cache directory: " << cache_dir << "\n";
            return false;
        }
        cout << "Weld cache is already clean.\n";
        return true;
    }

    bool removed_any = false;
    for (const auto& entry : fs::directory_iterator(cache_dir, ec)) {
        if (ec) {
            cout << "Failed to read Weld cache directory: " << cache_dir << "\n";
            return false;
        }
        fs::remove_all(entry.path(), ec);
        if (ec) {
            cout << "Failed to remove: " << entry.path().string() << "\n";
            return false;
        }
        removed_any = true;
    }

    if (!fs::exists(cache_dir, ec) && !fs::create_directories(cache_dir, ec)) {
        cout << "Failed to recreate Weld cache directory: " << cache_dir << "\n";
        return false;
    }

    if (removed_any)
        cout << "Weld cache cleaned: " << cache_dir << "\n";
    else
        cout << "Weld cache is already clean.\n";

    return true;
#endif
}

bool clean_weld_cache() {
    bool apt_ok = clean_apt_archives_cache();
    bool weld_ok = clean_weld_cache_only();
    return apt_ok && weld_ok;
}

string format_bytes(uint64_t bytes) {
    if (bytes < 1024) return to_string(bytes) + " B";
    if (bytes < 1024 * 1024) {
        double kb = static_cast<double>(bytes) / 1024.0;
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f KB", kb);
        return string(buf);
    }
    if (bytes < 1024 * 1024 * 1024) {
        double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f MB", mb);
        return string(buf);
    }
    double gb = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f GB", gb);
    return string(buf);
}

vector<WeldRepoMetadata> load_cached_weld_metadata();

class WeldArchiveCleaner final : public pkgArchiveCleaner {
public:
    size_t   removed_count = 0;
    uint64_t bytes_freed   = 0;
protected:
    void Erase(int const dirfd, char const * const File,
               string const &Pkg, string const &Ver,
               struct stat const &St) override {
        (void)Pkg; (void)Ver;
        bytes_freed += static_cast<uint64_t>(St.st_size);
        if (unlinkat(dirfd, File, 0) == 0) {
            ++removed_count;
        }
    }
};

bool autoclean_apt_archives_cache() {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) {
        _error->DumpErrors();
        cout << "Unable to open APT package cache for autoclean.\n";
        return false;
    }

    string archives = _config->FindDir("Dir::Cache::archives");
    if (archives.empty()) archives = "/var/cache/apt/archives/";
    if (!archives.empty() && archives.back() != '/') archives += "/";

    error_code ec;
    if (!fs::exists(archives, ec)) {
        cout << "APT archives directory does not exist: " << archives << "\n";
        return true;
    }
    if (!fs::exists(archives + "partial", ec)) {
        cout << "APT archives partial directory missing, skipping APT autoclean: "
             << archives << "partial/\n";
        return true;
    }

    WeldArchiveCleaner cleaner;
    if (!cleaner.Go(archives, *cache)) {
        _error->DumpErrors();
        cout << "APT autoclean encountered errors while cleaning: " << archives << "\n";
        return false;
    }
    _error->DumpErrors();

    if (cleaner.removed_count > 0) {
        cout << "APT autoclean removed " << cleaner.removed_count
             << " obsolete .deb file(s) (" << format_bytes(cleaner.bytes_freed) << " freed)\n";
    } else {
        cout << "APT archives: no obsolete packages found.\n";
    }
    return true;
}

bool autoclean_weld_cache_only() {
#ifndef allow_weld_repositories
    return true;
#else
    error_code ec;
    string cache_dir = WELD_CACHE_DIR;
    if (!fs::exists(cache_dir, ec)) {
        cout << "Weld cache directory does not exist: " << cache_dir << "\n";
        return true;
    }

    vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    set<string> valid_filenames;
    for (const auto& repo : repos) {
        for (const auto& entry : repo.packages) {
            valid_filenames.insert(path_basename(entry.second.first));
        }
    }

    bool removed_any = false;
    uint64_t bytes_freed = 0;

    for (const auto& rel_entry : fs::directory_iterator(cache_dir, ec)) {
        if (!rel_entry.is_directory()) continue;
        for (const auto& file_entry : fs::directory_iterator(rel_entry.path(), ec)) {
            if (!file_entry.is_regular_file()) continue;
            string filename = file_entry.path().filename().string();
            if (valid_filenames.find(filename) == valid_filenames.end()) {
                uint64_t sz = file_entry.file_size(ec);
                if (!ec) bytes_freed += sz;
                fs::remove(file_entry.path(), ec);
                if (!ec) {
                    cout << "Weld autoclean removed stale package: " << filename << "\n";
                    removed_any = true;
                }
            }
        }
    }

    if (removed_any) {
        cout << "Weld autoclean finished. Space freed: " << format_bytes(bytes_freed) << "\n";
    } else {
        cout << "Weld cache is already clean. No obsolete packages found.\n";
    }
    return true;
#endif
}

bool autoclean_weld_cache() {
    bool apt_ok = autoclean_apt_archives_cache();
    bool weld_ok = autoclean_weld_cache_only();
    return apt_ok && weld_ok;
}

void print_install_already_present_message(const string& pkg_name, bool is_upgrade) {
    if (is_upgrade) {
        cout << pkg_name << " is already up to date.\n";
        return;
    }
    cout << pkg_name << " is already installed. To upgrade it, run weld upgrade "
         << pkg_name << ", or weld upgrade with no arguments to upgrade all packages.\n"
         << "For large transactions, --apply-host skips the chroot verification step.\n";
}

vector<WeldRepoMetadata> load_cached_weld_metadata() {
#ifndef allow_weld_repositories
    return {};
#else
    vector<WeldRepoMetadata> repos;
    vector<WeldSource> sources = load_weld_sources();
    vector<MinisignPublicKey> trusted_keys = load_trusted_minisign_keys();
    if (trusted_keys.empty()) return repos;

    for (const auto& source : sources) {
        string path = WELD_ETC_DIR + "/" + sanitize_filename(source.release) + "/repo-metadata";
        string content;
        if (!read_text_file(path, content)) continue;

        string sig_path = WELD_ETC_DIR + "/" + sanitize_filename(source.release) + "/repo-metadata.minisig";
        string sig_content;
        if (!read_text_file(sig_path, sig_content)) {
            cout << "E: Repository " << source.base_url
                 << " is missing its minisign signature file. Refusing to load.\n";
            continue;
        }

        string trusted_comment;
        string verify_err;
        if (!verify_repo_metadata_signature(content, sig_content, trusted_comment, verify_err)) {
            cout << "E: Cached signature for " << source.base_url
                 << " is invalid: " << verify_err << ". Refusing to load.\n";
            continue;
        }

        WeldRepoMetadata metadata;
        metadata.base_url = source.base_url;
        metadata.release = source.release;
        metadata.trusted_comment = trusted_comment;
        string parse_err;
        if (!parse_weld_repo_metadata_v2(content, metadata, parse_err)) {
            cout << "E: Metadata for " << source.base_url
                 << " is malformed: " << parse_err << ". Refusing to load.\n";
            continue;
        }
        if (metadata.release.empty()) metadata.release = source.release;
        repos.push_back(metadata);
    }
    return repos;
#endif
}

int compare_versions(const string& a, const string& b) {
    if (a.empty() && b.empty()) return 0;
    if (a.empty()) return -1;
    if (b.empty()) return 1;
    if (_system != nullptr && _system->VS != nullptr)
        return _system->VS->CmpVersion(a.c_str(), b.c_str());
    if (a == b) return 0;
    return a < b ? -1 : 1;
}

string extract_weld_version(const string& pkg_name, const string& file_name) {
    string base = path_basename(trim_copy(file_name));
    if (!ends_with(base, ".deb")) return "";
    string stem = base.substr(0, base.size() - 4);
    string rest;
    if (starts_with(stem, pkg_name + "_"))
        rest = stem.substr(pkg_name.size() + 1);
    else if (starts_with(stem, pkg_name + "-"))
        rest = stem.substr(pkg_name.size() + 1);
    else
        return "";
    size_t split = rest.find_last_of('_');
    if (split != string::npos && split > 0) return rest.substr(0, split);
    split = rest.find_last_of('-');
    if (split != string::npos && split > 0) return rest.substr(0, split);
    return rest;
}

AptPackageState get_apt_package_state(pkgCacheFile& cache_file, const string& pkg_name) {
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

WeldPackageCandidate find_best_weld_candidate(const vector<WeldRepoMetadata>& repos, const string& pkg_name) {
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

        string target_weld_pkg = rep_it->second;
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

string build_weld_download_url(const WeldPackageCandidate& candidate) {
    string file_name = trim_copy(candidate.file_name);
    while (!file_name.empty() && file_name.front() == '/') file_name.erase(file_name.begin());
    size_t pos = 0;
    while ((pos = file_name.find("..", pos)) != string::npos) {
        file_name.erase(pos, 2);
    }
    while (!file_name.empty() && file_name.front() == '/') file_name.erase(file_name.begin());
    return candidate.base_url + "/releases/" + candidate.release + "/" + file_name;
}

bool cache_weld_package(const WeldPackageCandidate& candidate, string& local_path) {
#ifndef allow_weld_repositories
    (void)candidate;
    (void)local_path;
    return false;
#else
    string safe_release = sanitize_filename(candidate.release);
    string safe_file = sanitize_filename(candidate.file_name);
    if (safe_release.empty() || safe_file.empty()) return false;
    string release_dir = WELD_CACHE_DIR + "/" + safe_release;
    if (exec_argv_devnull_out({"mkdir", "-p", release_dir}) != 0) return false;
    local_path = release_dir + "/" + safe_file;
    string url = build_weld_download_url(candidate);
    if (url.empty() || url.front() == '-') return false;
    if (url.find("https://") != 0) return false;
    return curl_download_file(url, local_path);
#endif
}

string calculate_sha256(const string& file_path) {
    ifstream in(file_path, ios::binary);
    if (!in) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    char buf[65536];
    bool failed = false;
    while (in) {
        in.read(buf, sizeof(buf));
        streamsize got = in.gcount();
        if (got > 0) {
            if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(got)) != 1) {
                failed = true;
                break;
            }
        }
    }

    string result;
    if (!failed) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) == 1 && hash_len > 0) {
            result = hex_encode(hash, hash_len);
        }
    }
    EVP_MD_CTX_free(ctx);
    return result;
}

struct PendingWeldDownload {
    string pkg_name;
    WeldPackageCandidate candidate;
    string local_path;
    bool success = false;
    string error_msg;
};

static bool download_weld_packages(vector<PendingWeldDownload>& pending_weld_downloads, vector<InstallDecision>& decisions, bool quiet) {
    if (pending_weld_downloads.empty()) return true;

    size_t num_threads = std::min<size_t>(4, pending_weld_downloads.size());
    vector<thread> workers;
    std::atomic<size_t> current_index(0);

    for (size_t t = 0; t < num_threads; ++t) {
        workers.emplace_back([&]() {
            while (true) {
                size_t idx = current_index.fetch_add(1);
                if (idx >= pending_weld_downloads.size()) break;

                auto& pending = pending_weld_downloads[idx];
                if (!quiet) safe_log("Downloading Weld package: ", pending.pkg_name, "...\n");
                auto start_time = chrono::steady_clock::now();
                if (!cache_weld_package(pending.candidate, pending.local_path)) {
                    pending.error_msg = "E: Failed to download " + pending.pkg_name + " from the Weld repository.";
                    continue;
                }
                auto end_time = chrono::steady_clock::now();
                double elapsed_sec = chrono::duration_cast<chrono::duration<double>>(end_time - start_time).count();

                if (pending.candidate.sha256.empty()) {
                    pending.error_msg = "E: SHA256 checksum is missing in metadata for package " + pending.pkg_name + ".\nE: Refusing to install unverified package.";
                    exec_argv_devnull_out({"rm", "-f", pending.local_path});
                    continue;
                }

                string local_hash = calculate_sha256(pending.local_path);
                if (local_hash != pending.candidate.sha256) {
                    pending.error_msg = "E: SHA256 checksum mismatch for " + pending.pkg_name + ".\nE: Expected: " + pending.candidate.sha256 + "\nE: Got:      " + local_hash + "\nE: Aborting installation of this package.";
                    exec_argv_devnull_out({"rm", "-f", pending.local_path});
                    continue;
                }

                error_code ec;
                uint64_t file_sz = fs::file_size(pending.local_path, ec);
                string sz_str = (!ec && file_sz > 0) ? format_bytes(file_sz) : "";
                string speed_str = "";
                if (!ec && file_sz > 0 && elapsed_sec > 0.005) {
                    double bytes_per_sec = static_cast<double>(file_sz) / elapsed_sec;
                    speed_str = format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
                }

                if (!quiet) {
                    string cyan = "\033[1;36m";
                    string gray = "\033[38;2;148;163;184m";
                    string reset = "\033[0m";
                    string details = "";
                    if (!sz_str.empty()) details += sz_str;
                    if (!speed_str.empty()) details += (details.empty() ? "" : " | ") + speed_str;

                    safe_log(" * ", cyan, pending.pkg_name, reset,
                             (!details.empty() ? " " + gray + "(" + details + ")" + reset : ""),
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
            decision.package_name     = pending.candidate.actual_pkg_name.empty() ? pending.pkg_name : pending.candidate.actual_pkg_name;
            decision.apt_argument     = pending.local_path;
            decision.selected_version = pending.candidate.version;
            decision.from_weld        = true;
            decisions.push_back(decision);
        }
    }
    return ok;
}

bool resolve_install_decisions(const vector<string>& pkgs, vector<InstallDecision>& decisions, bool quiet, bool is_upgrade = false) {
    if (pkgs.empty()) {
        if (!quiet) cout << "E: No packages were specified.\n";
        return false;
    }

    pkgCacheFile cache_file;
    vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    bool had_error = false;
    vector<PendingWeldDownload> pending_weld_downloads;

    for (const auto& pkg_name : pkgs) {
        if (ends_with(pkg_name, ".deb")) {
            if (!path_is_regular_file(pkg_name)) {
                if (!quiet) cout << "E: Unable to locate local package file: " << pkg_name << ".\n";
                had_error = true;
                continue;
            }
            error_code ec;
            fs::path abs_path = fs::absolute(pkg_name, ec);
            if (!ec) abs_path = fs::weakly_canonical(abs_path, ec);
            string resolved_path = ec ? pkg_name : abs_path.string();

            InstallDecision decision;
            decision.package_name     = resolved_path;
            decision.apt_argument     = resolved_path;
            decision.selected_version = "";
            decision.from_weld        = false;
            decisions.push_back(decision);
            continue;
        }

        AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
        WeldPackageCandidate weld_candidate = find_best_weld_candidate(repos, pkg_name);

        if (!apt_state.found && !weld_candidate.found) {
            if (!quiet) cout << "E: Unable to locate package " << pkg_name << ".\n";
            had_error = true;
            continue;
        }

        bool use_weld = false;
        if (weld_candidate.found) {
            if (weld_candidate.is_replacement) {
                use_weld = true;
            } else if (!apt_state.found || apt_state.candidate_version.empty()) {
                use_weld = true;
            } else if (compare_versions(weld_candidate.version, apt_state.candidate_version) > 0) {
                use_weld = true;
            }
        }

        if (use_weld) {
            AptPackageState target_apt_state = (weld_candidate.is_replacement)
                ? get_apt_package_state(cache_file, weld_candidate.actual_pkg_name)
                : apt_state;

            if (target_apt_state.installed && compare_versions(target_apt_state.installed_version, weld_candidate.version) >= 0) {
                if (!quiet) print_install_already_present_message(weld_candidate.actual_pkg_name, is_upgrade);
                continue;
            }
            pending_weld_downloads.push_back({pkg_name, weld_candidate, "", false, ""});
            continue;
        }

        if (!apt_state.found || apt_state.candidate_version.empty()) {
            if (!quiet) cout << "E: Unable to locate package " << pkg_name << ".\n";
            had_error = true;
            continue;
        }

        if (apt_state.installed && compare_versions(apt_state.installed_version, apt_state.candidate_version) >= 0) {
            if (!quiet) print_install_already_present_message(pkg_name, is_upgrade);
            continue;
        }

        InstallDecision decision;
        decision.package_name     = pkg_name;
        decision.apt_argument     = pkg_name;
        decision.selected_version = apt_state.candidate_version;
        decision.from_weld        = false;
        decisions.push_back(decision);
    }

    if (!download_weld_packages(pending_weld_downloads, decisions, quiet)) {
        had_error = true;
    }

    return !had_error;
}

string parse_arvor_ua_version(const string& page) {
    if (page.empty()) return "";
    const string needle = "ArvorLinux/";
    size_t pos = page.find(needle);
    if (pos == string::npos) return "";
    pos += needle.size();
    string ver;
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

int compare_arvor_versions(const string& a, const string& b) {
    auto parse = [](const string& s) -> pair<int, int> {
        int major = 0, minor = 0;
        size_t dot = s.find('.');
        if (dot == string::npos) {
            try { major = std::stoi(s); } catch (...) {}
        } else {
            try { major = std::stoi(s.substr(0, dot)); } catch (...) {}
            try { minor = std::stoi(s.substr(dot + 1)); } catch (...) {}
        }
        return {major, minor};
    };
    auto pa = parse(a);
    auto pb = parse(b);
    if (pa.first != pb.first) return pa.first < pb.first ? -1 : 1;
    if (pa.second != pb.second) return pa.second < pb.second ? -1 : 1;
    return 0;
}

string render_weld_progress(int percentage, const string& label) {
    if (percentage < 0) percentage = 0;
    if (percentage > 100) percentage = 100;
    const int bar_width = 32;
    int filled = (percentage * bar_width) / 100;
    string bar;
    bar.reserve(bar_width);
    for (int i = 0; i < filled; ++i) bar += '-';
    for (int i = filled; i < bar_width; ++i) bar += ' ';
    char pct_buf[16];
    snprintf(pct_buf, sizeof(pct_buf), "%3d%%", percentage);
    string dim = "\033[38;5;250m";
    string accent = "\033[38;5;117m";
    string reset = "\033[0m";
    ostringstream oss;
    oss << "\r" << accent << label << reset << " " << dim << bar << reset << " " << pct_buf;
    return oss.str();
}

string strip_maintainer_email(const string& maintainer) {
    if (maintainer.empty()) return "";
    size_t pos = maintainer.find(" <");
    if (pos != string::npos) return maintainer.substr(0, pos);
    return maintainer;
}

void print_successful_install(const string& action, const vector<string>& targets) {
    string green = "\033[38;5;114m";
    string reset = "\033[0m";
    if (action != "install" && action != "upgrade" && action != "dist-upgrade") {
        cout << green << "Transaction completed successfully." << reset << "\n";
        return;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) {
        cout << green << "Transaction completed successfully." << reset << "\n";
        return;
    }
    pkgRecords records(*cache);
    bool printed_any = false;
    for (const auto& t : targets) {
        if (ends_with(t, ".deb")) continue;
        pkgCache::PkgIterator pkg = cache->FindPkg(t);
        if (pkg.end() || pkg->CurrentVer == 0) continue;
        pkgCache::VerIterator ver = pkg.CurrentVer();
        string version = ver.VerStr();
        string maintainer;
        pkgCache::VerFileIterator vf = ver.FileList();
        if (!vf.end()) {
            pkgRecords::Parser& parser = records.Lookup(vf);
            maintainer = parser.Maintainer();
        }
        string maint_name = strip_maintainer_email(maintainer);
        cout << green << "Successfully Installed " << t;
        if (!version.empty()) cout << ", Version " << version;
        if (!maint_name.empty()) cout << " by " << maint_name;
        cout << reset << "\n";
        printed_any = true;
    }
    if (!printed_any) {
        cout << green << "Transaction completed successfully." << reset << "\n";
    }
}

void do_nflinux_upgrade(bool apply_host, const string& arv_version) {
    string user_agent = "ArvorLinux/" + arv_version;
    string ua_page = curl_fetch_string("https://nextferret.github.io/ua", user_agent);
    string remote_version = parse_arvor_ua_version(ua_page);

    if (!remote_version.empty()) {
        int cmp = compare_arvor_versions(arv_version, remote_version);
        if (cmp > 0) {
            cout << "You are running a development build of Arvor Linux, or the remote release server may be outdated.\n";
            cout << "Local version: " << arv_version << " | Remote version: " << remote_version << "\n";
            cout << "No upgradeable release was found for your channel.\n";
            return;
        }
        if (cmp == 0) {
            cout << "Arvor Linux is already up to date (version " << arv_version << ").\n";
            return;
        }
        cout << "Arvor Linux local version: " << arv_version << "\n";
        cout << "A newer release (" << remote_version << ") is available. Proceed with upgrade? [Y/n] ";
        cout.flush();
        if (!assume_yes) {
            string answer;
            getline(cin, answer);
            if (answer != "y" && answer != "Y") {
                cout << "Upgrade cancelled.\n";
                return;
            }
        }
    }

#ifdef nflinux
    global_config_backup.backup();

    string os_release = curl_fetch_string("https://nextferret.github.io/etc/os-release", user_agent);
    string codenames = curl_fetch_string("https://nextferret.github.io/version_codename", user_agent);
    string repo_number_str = trim_copy(curl_fetch_string("https://nextferret.github.io/repo-number", user_agent));
    string weld_sources = "";
    string apt_sources = "";

    if (!codenames.empty() && !repo_number_str.empty()) {
        size_t comma = codenames.find(',');
        if (comma != string::npos) {
            string weld_code = trim_copy(codenames.substr(0, comma));
            string debian_code = trim_copy(codenames.substr(comma + 1));
            string base_repo_url = "https://thearvorindex.github.io/repo-arvorlinux--" + repo_number_str;
            string meta_url = base_repo_url + "/releases/" + weld_code + "/repo-metadata";
            string sig_url  = meta_url + ".minisig";
            string meta = curl_fetch_string(meta_url);
            string sig  = curl_fetch_string(sig_url);
            if (!meta.empty() && !sig.empty()) {
                string tc;
                string err;
                if (verify_repo_metadata_signature(meta, sig, tc, err)) {
                    weld_sources = "deb " + base_repo_url + " " + weld_code + "\n";
                    apt_sources = "deb http://deb.debian.org/debian " + debian_code + " main contrib non-free non-free-firmware\n";
                    apt_sources += "deb http://deb.debian.org/debian-security " + debian_code + "-security main contrib non-free non-free-firmware\n";
                    apt_sources += "deb http://deb.debian.org/debian " + debian_code + "-updates main contrib non-free non-free-firmware\n";
                } else {
                    cout << "E: Refusing to switch to release " << weld_code
                         << " because its signature could not be verified: " << err << "\n";
                }
            }
        }
    }

    if (!os_release.empty() || !apt_sources.empty() || !weld_sources.empty()) {
        global_config_backup.set_new(os_release, apt_sources, weld_sources);
        global_config_backup.apply_new();
    }

    vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    vector<string> pkgs_to_install;
    for (const auto& repo : repos) {
        for (const auto& req : repo.required_packages)
            pkgs_to_install.push_back(req);
    }

    if (!pkgs_to_install.empty()) {
        sort(pkgs_to_install.begin(), pkgs_to_install.end());
        pkgs_to_install.erase(unique(pkgs_to_install.begin(), pkgs_to_install.end()), pkgs_to_install.end());
        cout << "Installing required packages from repositories...\n";
        perform_install_transaction(pkgs_to_install, apply_host);
    }
#else
    (void)apply_host;
#endif
}

vector<string> bind_mount_local_deb_dirs(const vector<string>& targets) {
    set<string> parents;
    for (const auto& t : targets) {
        if (!ends_with(t, ".deb")) continue;
        fs::path parent = fs::path(t).parent_path();
        if (!parent.empty()) parents.insert(parent.string());
    }

    vector<string> mounted;
    for (const auto& parent : parents) {
        string target = TREE_ROOT + parent;
        error_code ec;
        fs::create_directories(target, ec);
        if (ec) continue;
        exec_argv_devnull_out({"mount", "--bind", parent, target});
        mounted.push_back(target);
    }
    return mounted;
}

void unbind_local_deb_dirs(const vector<string>& mounted) {
    for (auto it = mounted.rbegin(); it != mounted.rend(); ++it)
        exec_argv_devnull_out({"umount", "-l", *it});
}

void perform_transaction_argv(const string& action, const vector<string>& targets, bool apply_host) {
    if (!check_system_memory(WELD_MIN_MEM_MB)) return;

    if (!apply_host) {
        if (!manage_sandbox("create")) {
            cout << "Aborting transaction: sandbox could not be created.\n";
            return;
        }
        mount_fs();
        vector<string> local_deb_mounts = bind_mount_local_deb_dirs(targets);

        int apt_pipe[2]  = {-1, -1};
        bool have_pipe   = (pipe(apt_pipe) == 0);
        int err_pipe[2]  = {-1, -1};
        bool have_err    = (pipe2(err_pipe, O_CLOEXEC) == 0);

        cout.flush();
        cerr.flush();
        pid_t pid = fork();
        if (pid == 0) {
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                if (have_err) {
                    const char* msg = "prctl NO_NEW_PRIVS failed\n";
                    ssize_t written = write(err_pipe[1], msg, strlen(msg));
                    (void)written;
                }
                _exit(1);
            }

            if (unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC) != 0) {
                if (have_err) {
                    const char* msg = "unshare namespace failed\n";
                    ssize_t written = write(err_pipe[1], msg, strlen(msg));
                    (void)written;
                }
                _exit(1);
            }

            string put_old_path = string(TREE_ROOT) + "/.old_root";
            bool pivoted = false;
            if (mkdir(put_old_path.c_str(), 0755) == 0) {
                if (mount("", TREE_ROOT.c_str(), "", MS_PRIVATE | MS_REC, nullptr) == 0) {
                    if (do_pivot_root(TREE_ROOT.c_str(), put_old_path.c_str()) == 0) {
                        pivoted = true;
                    }
                }
            }

            if (pivoted) {
                chdir("/");
                umount2("/.old_root", MNT_DETACH);
                rmdir("/.old_root");
            } else {
                rmdir(put_old_path.c_str());
                if (chroot(TREE_ROOT.c_str()) != 0 || chdir("/") != 0) {
                    if (have_err) {
                        const char* msg = "pivot_root and chroot fallback both failed\n";
                        ssize_t written = write(err_pipe[1], msg, strlen(msg));
                        (void)written;
                    }
                    _exit(1);
                }
            }

            apply_strict_resource_limits();

            {
                string seccomp_err;
                if (!ChrootSeccompManager::apply_filter(seccomp_err)) {
                    if (have_err && !seccomp_err.empty()) {
                        string msg = "W: SECCOMP filter notice: " + seccomp_err + "\n";
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

            setenv("DEBIAN_FRONTEND", "noninteractive", 1);
            bool ok = run_libapt_transaction(action, targets, status_fd, true);
            cout.flush();
            cerr.flush();
            _exit(ok ? 0 : 1);

        } else if (pid > 0) {
            if (have_pipe) close(apt_pipe[1]);
            if (have_err)  close(err_pipe[1]);

            cout << render_weld_progress(0, "Verifying Transaction") << flush;

            std::atomic<int> apt_percent(-1);
            string child_stderr_output;

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
                while (fgets(line, sizeof(line), f) != NULL) {
                    string s(line);
                    bool is_pm = (s.size() > 9 && s.substr(0, 9) == "pmstatus:");
                    bool is_dl = (!is_pm && s.size() > 9 && s.substr(0, 9) == "dlstatus:");
                    if (!is_pm && !is_dl) continue;
                    size_t c1 = s.find(':');
                    if (c1 == string::npos) continue;
                    size_t c2 = s.find(':', c1 + 1);
                    if (c2 == string::npos) continue;
                    size_t c3 = s.find(':', c2 + 1);
                    if (c3 == string::npos) continue;
                    string pct_str = s.substr(c2 + 1, c3 - c2 - 1);
                    try {
                        int pct = static_cast<int>(stod(pct_str));
                        if (pct > apt_percent.load()) apt_percent.store(pct);
                        int current = apt_percent.load();
                        if (current != last_shown) {
                            cout << render_weld_progress(current, "Verifying Transaction") << flush;
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
                global_config_backup.restore_orig();
                cout << "\n\033[1;31mE:\033[0m Sandbox verification interrupted.\n";
                return;
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                global_config_backup.restore_orig();
                cout << "\n\033[1;31mE:\033[0m Sandbox verification failed.\n";
                if (!child_stderr_output.empty()) {
                    cout << "---- sandbox error output ----\n" << child_stderr_output;
                    if (child_stderr_output.back() != '\n') cout << '\n';
                    cout << "------------------------------\n";
                }
                return;
            }

            cout << render_weld_progress(100, "Verifying Transaction") << "\n\n";

            if (!assume_yes) {
                cout << "Sandbox verification passed without errors.\n";
                cout << "The transaction is now ready to be applied to the host system.\n";
                cout << "Do you wish to continue? [Y/n] ";
                string confirm;
                getline(cin, confirm);
                if (confirm != "y" && confirm != "Y") {
                    global_config_backup.restore_orig();
                    cout << "Transaction aborted by user.\n";
                    return;
                }
            }
        } else {
            if (have_pipe) { close(apt_pipe[0]); close(apt_pipe[1]); }
            if (have_err)  { close(err_pipe[0]); close(err_pipe[1]); }
            cout << "\033[1;31mE:\033[0m Unable to fork process for sandbox verification.\n";
            return;
        }
    }

    global_config_backup.restore_orig();
    bool snapshot_created = create_snapshot("apt-pre");
    global_config_backup.apply_new();

    string kver = trim_copy(exec_argv_capture({"uname", "-r"}));
    if (!kver.empty()) {
        string src = "/lib/modules/" + kver;
        string dst = "/var/tmp/.arvor_kmodules_" + kver;
        error_code ec;
        if (fs::exists(src, ec) && !fs::exists(dst, ec)) {
            exec_argv_devnull_out({"cp", "-a", src, dst});
        }
    }

    cout.flush();
    cerr.flush();

    cout << render_weld_progress(0, "Applying Transaction") << flush;

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
        setenv("DEBIAN_FRONTEND", "noninteractive", 1);
        bool ok = run_libapt_transaction(action, targets, status_fd, true);
        cout.flush();
        cerr.flush();
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
            while (fgets(line, sizeof(line), f) != NULL) {
                string s(line);
                bool is_pm = (s.size() > 9 && s.substr(0, 9) == "pmstatus:");
                bool is_dl = (!is_pm && s.size() > 9 && s.substr(0, 9) == "dlstatus:");
                if (!is_pm && !is_dl) continue;
                size_t c1 = s.find(':');
                if (c1 == string::npos) continue;
                size_t c2 = s.find(':', c1 + 1);
                if (c2 == string::npos) continue;
                size_t c3 = s.find(':', c2 + 1);
                if (c3 == string::npos) continue;
                string pct_str = s.substr(c2 + 1, c3 - c2 - 1);
                try {
                    int pct = static_cast<int>(stod(pct_str));
                    if (pct > host_percent.load()) host_percent.store(pct);
                    int current = host_percent.load();
                    if (current != last_shown) {
                        cout << render_weld_progress(current, "Applying Transaction") << flush;
                        last_shown = current;
                    }
                } catch (...) {}
            }
            fclose(f);
        });

        wait_for_child(host_pid, host_status);
        if (have_host_pipe) host_reader.join();
        host_ok = WIFEXITED(host_status) && WEXITSTATUS(host_status) == 0;
    }

    if (host_ok) {
        cout << render_weld_progress(100, "Applying Transaction") << "\n\n";
        create_snapshot("apt-post");
        print_successful_install(action, targets);
    } else {
        cout << "\n\033[1;31mE:\033[0m Host transaction failed. Rolling back to previous snapshot...\n";
        global_config_backup.restore_orig();
        if (snapshot_created) do_rollback("apt-pre");
    }
}

void perform_transaction(const string& action, const vector<string>& pkgs, bool apply_host) {
    PrecheckResult precheck = precheck_transaction(action, pkgs, false);
    if (precheck == PrecheckResult::Failed || precheck == PrecheckResult::NoChanges) return;

    perform_transaction_argv(action, pkgs, apply_host);
}

void perform_install_transaction(const vector<string>& pkgs, bool apply_host, bool is_upgrade) {
    vector<InstallDecision> decisions;
    if (!resolve_install_decisions(pkgs, decisions, false, is_upgrade)) return;
    if (decisions.empty()) return;

    vector<string> args;
    for (const auto& decision : decisions) args.push_back(decision.apt_argument);

    perform_transaction_argv("install", args, apply_host);
}

void perform_global_upgrade(bool apply_host) {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return;

    vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    vector<string> weld_upgrade_args;

    auto get_installed_version = [&](const string& pkg_name) -> string {
        AptPackageState s = get_apt_package_state(cache_file, pkg_name);
        return s.installed ? s.installed_version : "";
    };

    auto try_queue_weld_upgrade = [&](const string& pkg_name, const string& installed_version) {
        WeldPackageCandidate candidate = find_best_weld_candidate(repos, pkg_name);
        if (!candidate.found) return;
        if (!installed_version.empty() && compare_versions(candidate.version, installed_version) <= 0) return;
        string local_path;
        if (!cache_weld_package(candidate, local_path)) return;
        if (candidate.sha256.empty()) {
            exec_argv_devnull_out({"rm", "-f", local_path});
            cout << "No SHA256 checksum found in metadata for " << pkg_name << ", skipping.\n";
            return;
        } else {
            string h = calculate_sha256(local_path);
            if (h != candidate.sha256) {
                exec_argv_devnull_out({"rm", "-f", local_path});
                cout << "Checksum mismatch for " << pkg_name << ", skipping.\n";
                return;
            }
        }
        cout << "Queuing weld upgrade: " << pkg_name;
        if (!installed_version.empty()) cout << " (" << installed_version << " -> " << candidate.version << ")";
        else cout << " (" << candidate.version << ")";
        cout << "\n";
        weld_upgrade_args.push_back(local_path);
    };

    set<string> handled_pkgs;
    for (const auto& repo : repos) {
        if (repo.required_packages.empty()) continue;
        string already_installed_req;
        for (const auto& req : repo.required_packages) {
            if (!get_installed_version(req).empty()) { already_installed_req = req; break; }
        }
        if (!already_installed_req.empty()) {
            string iv = get_installed_version(already_installed_req);
            try_queue_weld_upgrade(already_installed_req, iv);
            handled_pkgs.insert(already_installed_req);
        } else {
            for (const auto& req : repo.required_packages) {
                string iv = get_installed_version(req);
                WeldPackageCandidate c = find_best_weld_candidate(repos, req);
                if (!iv.empty()) {
                    if (c.found && compare_versions(c.version, iv) > 0) {
                        cout << "Upgrading required package: " << req << " (" << iv << " -> " << c.version << ")\n";
                        try_queue_weld_upgrade(req, iv);
                        handled_pkgs.insert(req);
                    }
                    continue;
                }
                if (c.found) {
                    cout << "Installing required package: " << req << "\n";
                    perform_install_transaction({req}, apply_host);
                    handled_pkgs.insert(req);
                } else {
                    AptPackageState apt_state = get_apt_package_state(cache_file, req);
                    if (apt_state.found) {
                        cout << "Installing required package: " << req << "\n";
                        perform_install_transaction({req}, apply_host);
                        handled_pkgs.insert(req);
                    } else {
                        cout << "Warning: required package " << req << " not found in any repo, skipping.\n";
                    }
                }
            }
        }
    }

    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        if (pkg->CurrentVer == 0) continue;
        string pkg_name = pkg.Name();
        if (handled_pkgs.count(pkg_name)) continue;
        AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
        try_queue_weld_upgrade(pkg_name, apt_state.installed_version);
    }

    if (!weld_upgrade_args.empty()) {
        cout << "Upgrading Weld packages first...\n";
        perform_transaction_argv("install", weld_upgrade_args, apply_host);
    }

    cout << "Proceeding with standard apt upgrade...\n";
    perform_transaction("upgrade", vector<string>(), apply_host);
}

void perform_upgrade_transaction(const vector<string>& pkgs, bool apply_host) {
    if (pkgs.empty()) { perform_global_upgrade(apply_host); return; }
    perform_install_transaction(pkgs, apply_host, true);
}

static string to_lower_copy(const string& s) {
    string r = s;
    transform(r.begin(), r.end(), r.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return r;
}

int run_search(const vector<string>& terms, int page) {
    if (terms.empty()) { cout << "Usage: weld search <term> [-p <page>]\n"; return 1; }
    if (page < 1) page = 1;
    string term = to_lower_copy(terms[0]);
    const int page_size = 30;
    const int offset = (page - 1) * page_size;

    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) { _error->DumpErrors(); return 1; }

    int matches = 0;
    int shown = 0;
    set<string> seen_names;

    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        string name = pkg.Name();
        if (to_lower_copy(name).find(term) == string::npos) continue;
        if (!seen_names.insert(name).second) continue;

        int index = matches;
        ++matches;
        if (index < offset || shown >= page_size) continue;

        pkgCache::VerIterator ver = pkg.VersionList();
        string version = ver.end() ? "" : ver.VerStr();

        cout << name;
        if (!version.empty()) cout << " (" << version << ")";
        cout << "\n";
        ++shown;
    }

    vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    for (const auto& repo : repos) {
        for (const auto& entry : repo.packages) {
            const string& pkg_name = entry.first;
            if (to_lower_copy(pkg_name).find(term) == string::npos) continue;

            int index = matches;
            ++matches;
            if (index < offset || shown >= page_size) continue;

            string version = extract_weld_version(pkg_name, entry.second.first);
            cout << pkg_name << " - Provided by Weld repository " << repo.base_url;
            if (!version.empty()) cout << ", version " << version;
            cout << ".\n";
            ++shown;
        }
    }

    if (matches == 0) {
        cout << "No packages found matching \"" << terms[0] << "\".\n";
        return 0;
    }

    if (shown == 0) {
        cout << "Page " << page << " is empty. This search has " << matches << " results.\n";
        return 0;
    }

    int total_pages = (matches + page_size - 1) / page_size;
    cout << "Page " << page << " of " << total_pages << " (" << matches << " total results).";
    if (page < total_pages) cout << " Use -p " << (page + 1) << " to see more.";
    cout << "\n";
    return 0;
}

int show_package_info(const string& pkg_name) {
    if (pkg_name.empty()) {
        cout << "Usage: weld info <package_name>\n";
        return 1;
    }

    pkgCacheFile cache_file;
    vector<WeldRepoMetadata> repos = load_cached_weld_metadata();
    AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
    WeldPackageCandidate weld_cand = find_best_weld_candidate(repos, pkg_name);

    if (!apt_state.found && !weld_cand.found) {
        cout << "Package '" << pkg_name << "' not found in any configured repository.\n";
        return 1;
    }

    string cyan_bold = "\033[1;36m";
    string green = "\033[1;32m";
    string dim = "\033[2m";
    string reset = "\033[0m";

    cout << cyan_bold << "Package Information: " << pkg_name << reset << "\n";
    cout << "----------------------------------------\n";

    if (apt_state.installed) {
        cout << "Installed:    " << green << "yes (" << apt_state.installed_version << ")" << reset << "\n";
    } else {
        cout << "Installed:    no\n";
    }

    if (weld_cand.found) {
        cout << "Source:       " << weld_cand.base_url << " (" << weld_cand.release << ")\n";
        cout << "Version:      " << weld_cand.version << "\n";
        cout << "SHA256:       " << (weld_cand.sha256.empty() ? "None" : weld_cand.sha256) << "\n";
        if (!weld_cand.description.empty()) {
            cout << "Description: " << weld_cand.description << "\n";
        }
        for (const auto& repo : repos) {
            if (repo.base_url == weld_cand.base_url && repo.release == weld_cand.release) {
                if (!repo.name.empty()) cout << "Repo Name:   " << repo.name << "\n";
                if (!repo.maintainer.empty()) cout << "Maintainer:  " << repo.maintainer << "\n";
                if (!repo.trusted_comment.empty()) cout << "Signature:   " << dim << "verified" << reset << " (" << repo.trusted_comment << ")\n";
                break;
            }
        }
    } else if (apt_state.found && !apt_state.candidate_version.empty()) {
        cout << "Version:      " << apt_state.candidate_version << "\n";
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
            cout << pkg.Name() << " (" << pkg.CurrentVer().VerStr() << ")\n";
            count++;
        }
    }
    cout << "\nTotal installed packages: " << count << "\n";
    return 0;
}

bool check_system_locks(bool quiet = false) {
    int fd = open("/var/lib/dpkg/lock-frontend", O_RDWR | O_CREAT | O_CLOEXEC, 0640);
    if (fd >= 0) {
        struct flock fl;
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(fd, F_SETLK, &fl) == -1) {
            close(fd);
            if (!quiet) {
                cout << "\033[1;31mE:\033[0m dpkg lock (/var/lib/dpkg/lock-frontend) is currently held by another process.\n";
                cout << "Please wait for the background package operation to complete.\n";
            }
            return false;
        }
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
    }
    return true;
}

int show_package_why(const string& pkg_name) {
    if (pkg_name.empty()) {
        cout << "Usage: weld why <package_name>\n";
        return 1;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    pkgCache::PkgIterator target_pkg = cache->FindPkg(pkg_name);
    if (target_pkg.end()) {
        cout << "Package '" << pkg_name << "' not found.\n";
        return 1;
    }

    if (target_pkg->CurrentVer == 0) {
        cout << "Package '" << pkg_name << "' is not currently installed.\n";
    }

    string cyan_bold = "\033[1;36m";
    string green = "\033[1;32m";
    string gray = "\033[38;2;148;163;184m";
    string reset = "\033[0m";

    cout << cyan_bold << "Dependency Tree (Why is '" << pkg_name << "' required?):" << reset << "\n";
    cout << "--------------------------------------------------------\n";

    int rev_count = 0;
    set<string> seen_parents;

    for (pkgCache::DepIterator dep = target_pkg.RevDependsList(); !dep.end(); ++dep) {
        if (dep->Type != pkgCache::Dep::Depends && dep->Type != pkgCache::Dep::PreDepends) continue;
        pkgCache::PkgIterator parent = dep.ParentPkg();
        if (parent->CurrentVer != 0) {
            string pname = parent.Name();
            if (seen_parents.insert(pname).second) {
                cout << "  " << green << "- " << pname << reset << " (" << parent.CurrentVer().VerStr() << ")"
                     << gray << " [requires " << dep.DepType() << ": " << pkg_name << "]" << reset << "\n";
                rev_count++;
            }
        }
    }

    if (rev_count == 0) {
        cout << "  " << gray << "No installed packages depend on '" << pkg_name << "'. It was likely installed manually or as a top-level requirement." << reset << "\n";
    } else if (rev_count == 1) {
        cout << "\nRequired by 1 currently installed package.\n";
    } else {
        cout << "\nRequired by " << rev_count << " currently installed packages.\n";
    }
    return 0;
}

int show_package_depends(const string& pkg_name) {
    if (pkg_name.empty()) {
        cout << "Usage: weld depends <package_name>\n";
        return 1;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    pkgCache::PkgIterator target_pkg = cache->FindPkg(pkg_name);
    if (target_pkg.end()) {
        cout << "Package '" << pkg_name << "' not found.\n";
        return 1;
    }

    pkgCache::VerIterator ver = target_pkg.CurrentVer() != 0 ? target_pkg.CurrentVer() : target_pkg.VersionList();
    if (ver.end()) {
        cout << "No versions available for package '" << pkg_name << "'.\n";
        return 1;
    }

    string cyan_bold = "\033[1;36m";
    string green = "\033[1;32m";
    string yellow = "\033[1;33m";
    string reset = "\033[0m";

    cout << cyan_bold << "Direct Dependencies for '" << pkg_name << "' (" << ver.VerStr() << "):" << reset << "\n";
    cout << "--------------------------------------------------------\n";

    for (pkgCache::DepIterator dep = ver.DependsList(); !dep.end(); ++dep) {
        string type_name = dep.DepType();
        string target_name = dep.TargetPkg().Name();
        string color = (type_name == "Depends" || type_name == "PreDepends") ? green : yellow;
        cout << "  " << color << type_name << ": " << reset << target_name;
        if (dep.TargetVer() != nullptr) cout << " (" << dep.CompType() << " " << dep.TargetVer() << ")";
        cout << "\n";
    }
    return 0;
}

void do_transaction_rollback() {
    cout << "Querying available recovery snapshots for rollback...\n";
    string latest_snap = get_latest_snapshot("apt-pre");
    if (latest_snap.empty()) {
        latest_snap = get_latest_snapshot("root-auto");
    }

    if (latest_snap.empty()) {
        cout << "\033[1;31mE:\033[0m No automatic pre-transaction snapshots found in " << AUTO_SNAP_DIR << ".\n";
        cout << "Hint: You can use 'arvorctl rollback b' to restore to the last boot snapshot.\n";
        return;
    }

    cout << "Found latest pre-transaction snapshot: \033[1;32m" << latest_snap << "\033[0m\n";
    cout << "Are you sure you want to rollback to this snapshot? [Y/n] ";
    string confirm;
    getline(cin, confirm);
    if (confirm == "y" || confirm == "Y") {
        do_rollback("apt-pre");
    } else {
        cout << "Rollback cancelled.\n";
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

    if (count == 1) {
        cout << "W: 1 package can be upgraded. Run 'weld upgrade' to upgrade it.\n";
    } else {
        cout << "W: " << count << " packages can be upgraded. Run 'weld upgrade' to upgrade them.\n";
    }
}

int main(int argc, char** argv) {
    setup_safety_handlers();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();
    pkgInitConfig(*_config);
    pkgInitSystem(*_config, _system);
    string command;
    vector<string> pkgs;
    bool apply_host = false;
    int search_page = 1;
    string arv_version = ARVOR_VERSION;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-h" || arg == "--help") { show_help(); return 0; }
        else if (arg == "--v" || arg == "-v" || arg == "--version") { cout << weld_version_str() << "\n"; return 0; }
        else if (arg == "--vb") { _config->Set("Debug::pkgAcquire", "true"); }
        else if (arg == "--apply-host") { apply_host = true; }
        else if (arg == "-y" || arg == "--yes" || arg == "--assume-yes") { assume_yes = true; }
        else if (arg == "-p" && i + 1 < argc) { search_page = atoi(argv[++i]); }
        else if (command.empty() && arg[0] != '-') { command = arg; }
        else if (arg[0] != '-') { pkgs.push_back(arg); }
    }

    if (command.empty()) { show_help(); return 0; }

    if (command == "why") {
        if (pkgs.empty()) { cout << "Usage: weld why <package_name>\n"; return 1; }
        return show_package_why(pkgs[0]);
    } else if (command == "depends" || command == "deps") {
        if (pkgs.empty()) { cout << "Usage: weld depends <package_name>\n"; return 1; }
        return show_package_depends(pkgs[0]);
    } else if (command == "info" || command == "show") {
        if (pkgs.empty()) { cout << "Usage: weld info <package_name>\n"; return 1; }
        return show_package_info(pkgs[0]);
    } else if (command == "list" || command == "list-installed") {
        return list_installed_packages();
    } else if (command == "search") {
        return run_search(pkgs, search_page);
    }

    if (geteuid() != 0) { cout << "Root privileges required.\n"; return 1; }

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
        cout << "Unknown command: " << command << "\n";
        show_help();
        return 1;
    }

    curl_global_cleanup();
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
