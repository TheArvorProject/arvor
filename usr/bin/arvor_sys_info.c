#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#ifndef CODE_NAME
#define CODE_NAME "00000000000000000000000000000000000000000000"
#endif

#define DEFAULT_BUILD_CODE "59FF03AD8C168C3A9F443A95287EF208F3E775F8793BCA549100927F96F42A15"

#ifndef BUILD_CODE
#define BUILD_CODE DEFAULT_BUILD_CODE
#endif

#define BUILD_CODE_LEN 64

static const char k_build_code[] = BUILD_CODE;
static const char k_default_code[] = DEFAULT_BUILD_CODE;

static void die(void) {
    _exit(111);
}

static int ct_equal(const char *a, const char *b, size_t n) {
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

static char *trim(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

static void strip_quotes(char *s) {
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static int read_first_line(const char *path, char *out, size_t outsz) {
    if (outsz == 0) return -1;
    FILE *f = fopen(path, "r");
    if (!f) {
        out[0] = '\0';
        return -1;
    }
    char line[512];
    int ok = 0;
    if (fgets(line, sizeof(line), f)) {
        char *t = trim(line);
        size_t tlen = strlen(t);
        if (tlen >= outsz) tlen = outsz - 1;
        memmove(out, t, tlen);
        out[tlen] = '\0';
        ok = 1;
    }
    fclose(f);
    if (!ok) out[0] = '\0';
    return ok ? 0 : -1;
}

static int has_tracer(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 1;
    char line[256];
    int traced = 0;
    while (fgets(line, sizeof(line), f)) {
        long pid;
        if (sscanf(line, "TracerPid: %ld", &pid) == 1) {
            traced = (pid != 0);
            break;
        }
    }
    fclose(f);
    return traced;
}

static int has_rwx_mapping(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 1;
    char line[1024];
    int bad = 0;
    while (fgets(line, sizeof(line), f)) {
        char perms[8];
        if (sscanf(line, "%*s %7s", perms) == 1) {
            if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                bad = 1;
                break;
            }
        }
    }
    fclose(f);
    return bad;
}

static void harden_process(void) {
    struct rlimit rl = {0, 0};
    if (setrlimit(RLIMIT_CORE, &rl) != 0) die();
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) die();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die();
    if (getenv("LD_PRELOAD") || getenv("LD_AUDIT") ||
        getenv("LD_LIBRARY_PATH") || getenv("LD_DEBUG")) die();
    if (has_tracer()) die();
    if (has_rwx_mapping()) die();
}

static int get_os_name(char *out, size_t outsz) {
    if (outsz == 0) return -1;
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) {
        snprintf(out, outsz, "Unknown");
        return -1;
    }
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "NAME=", 5) == 0) {
            char *val = line + 5;
            size_t len = strlen(val);
            if (len > 0 && val[len - 1] == '\n') val[len - 1] = '\0';
            char *t = trim(val);
            strip_quotes(t);
            size_t tlen = strlen(t);
            if (tlen >= outsz) tlen = outsz - 1;
            memmove(out, t, tlen);
            out[tlen] = '\0';
            found = 1;
            break;
        }
    }
    fclose(f);
    if (!found) snprintf(out, outsz, "Unknown");
    return found ? 0 : -1;
}

static int get_kernel(char *out, size_t outsz) {
    struct utsname u;
    if (uname(&u) != 0) {
        snprintf(out, outsz, "Unknown");
        return -1;
    }
    snprintf(out, outsz, "%s", u.release);
    return 0;
}

static int get_root_fs(char *out, size_t outsz) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) {
        snprintf(out, outsz, "unknown");
        return -1;
    }
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char dev[256], mnt[256], type[64];
        if (sscanf(line, "%255s %255s %63s", dev, mnt, type) == 3) {
            if (strcmp(mnt, "/") == 0) {
                snprintf(out, outsz, "%s", type);
                found = 1;
            }
        }
    }
    fclose(f);
    if (!found) snprintf(out, outsz, "unknown");
    return found ? 0 : -1;
}

static int get_manufacturer(char *out, size_t outsz) {
    if (read_first_line("/sys/class/dmi/id/sys_vendor", out, outsz) != 0) {
        snprintf(out, outsz, "Unknown");
        return -1;
    }
    return 0;
}

static int get_cpu(char *out, size_t outsz) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        snprintf(out, outsz, "Unknown");
        return -1;
    }
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                colon++;
                char *t = trim(colon);
                size_t tlen = strlen(t);
                if (tlen >= outsz) tlen = outsz - 1;
                memmove(out, t, tlen);
                out[tlen] = '\0';
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    if (!found) snprintf(out, outsz, "Unknown");
    return found ? 0 : -1;
}

static int get_meminfo_kb(unsigned long long *memtotal_kb, unsigned long long *swaptotal_kb) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[256];
    *memtotal_kb = 0;
    *swaptotal_kb = 0;
    int got_mem = 0, got_swap = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long val;
        if (!got_mem && sscanf(line, "MemTotal: %llu kB", &val) == 1) {
            *memtotal_kb = val;
            got_mem = 1;
        } else if (!got_swap && sscanf(line, "SwapTotal: %llu kB", &val) == 1) {
            *swaptotal_kb = val;
            got_swap = 1;
        }
        if (got_mem && got_swap) break;
    }
    fclose(f);
    return got_mem ? 0 : -1;
}

static int is_plain_card_name(const char *name) {
    if (strncmp(name, "card", 4) != 0) return 0;
    const char *p = name + 4;
    if (*p == '\0') return 0;
    while (*p) {
        if (!isdigit((unsigned char)*p)) return 0;
        p++;
    }
    return 1;
}

static int get_vram_mb(unsigned long long *vram_mb) {
    DIR *d = opendir("/sys/class/drm");
    if (!d) return -1;
    struct dirent *entry;
    unsigned long long vram_bytes = 0;
    unsigned long long gtt_bytes = 0;
    int found = 0;
    while ((entry = readdir(d)) != NULL) {
        if (!is_plain_card_name(entry->d_name)) continue;

        char path[512];
        snprintf(path, sizeof(path), "/sys/class/drm/%s/device/mem_info_vram_total", entry->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            unsigned long long val;
            if (fscanf(f, "%llu", &val) == 1) {
                vram_bytes += val;
                found = 1;
            }
            fclose(f);
        }

        snprintf(path, sizeof(path), "/sys/class/drm/%s/device/mem_info_gtt_total", entry->d_name);
        f = fopen(path, "r");
        if (f) {
            unsigned long long val;
            if (fscanf(f, "%llu", &val) == 1) {
                gtt_bytes += val;
            }
            fclose(f);
        }
    }
    closedir(d);
    if (!found) return -1;
    *vram_mb = (vram_bytes + gtt_bytes) / (1024ULL * 1024ULL);
    return 0;
}

static long round_even_gb(double gb) {
    if (gb < 0.0) gb = 0.0;
    long n = (long)((gb + 1.0) / 2.0);
    return n * 2;
}

static int get_secure_boot_status(void) {
    DIR *d = opendir("/sys/firmware/efi/efivars");
    if (!d) return 1;
    struct dirent *entry;
    int status = -1;
    while ((entry = readdir(d)) != NULL) {
        if (strncmp(entry->d_name, "SecureBoot-", 11) == 0) {
            char path[512];
            snprintf(path, sizeof(path), "/sys/firmware/efi/efivars/%s", entry->d_name);
            FILE *f = fopen(path, "rb");
            if (f) {
                unsigned char buf[8];
                size_t n = fread(buf, 1, sizeof(buf), f);
                fclose(f);
                if (n >= 5) status = buf[4];
            }
            break;
        }
    }
    closedir(d);
    if (status < 0) return 1;
    return status ? 0 : 1;
}

static int build_code_valid(void) {
    if (strlen(k_build_code) != BUILD_CODE_LEN) return 0;
    int all_zero = 1;
    for (size_t i = 0; i < BUILD_CODE_LEN; i++) {
        if (!isxdigit((unsigned char)k_build_code[i])) return 0;
        if (k_build_code[i] != '0') all_zero = 0;
    }
    if (all_zero) return 0;
    if (strlen(k_default_code) == BUILD_CODE_LEN &&
        ct_equal(k_build_code, k_default_code, BUILD_CODE_LEN)) return 0;
    return 1;
}

static int name_valid(void) {
    char name[128];
    if (get_os_name(name, sizeof(name)) != 0) return 0;
    return strcmp(name, "Arvor Linux") == 0;
}

static int fs_valid(void) {
    char fs[64];
    if (get_root_fs(fs, sizeof(fs)) != 0) return 0;
    return strcmp(fs, "xfs") == 0 || strcmp(fs, "ext4") == 0;
}

static int support_once(void) {
    int a = build_code_valid();
    int b = name_valid();
    int c = fs_valid();
    return (a & b & c) ? 0x0 : 0x1;
}

static int get_support_type(void) {
    int r1 = support_once();
    int r2 = support_once();
    if (r1 != r2) die();
    return r1;
}

static void print_help(void) {
    static const char *rows[][2] = {
        {"get.sys.codename",       "build codename"},
        {"get.sys.name",           "OS name"},
        {"get.sys.kernel",         "kernel release"},
        {"get.sys.support.type",   "support status (0x0 supported / 0x1 unsupported)"},
        {"get.sys.sbstatus",       "secure boot state (1 disabled / 0 enabled)"},
        {"get.sys.manufacturer",   "hardware manufacturer"},
        {"get.sys.cpu",            "CPU model"},
        {"get.sys.fs",             "root filesystem type"},
        {"get.sys.memory",         "total RAM, includes swap/zram"},
        {"get.sys.vram",           "video memory"},
        {"get.sys.build-code",     "build code"}
    };
    size_t n = sizeof(rows) / sizeof(rows[0]);
    printf("system info commands:\n");
    for (size_t i = 0; i < n; i++) {
        printf(" %-22s %s\n", rows[i][0], rows[i][1]);
    }
    printf("\nrun 'arvor_sys_info <command>' to query a single value\n");
}

int main(int argc, char **argv) {
    harden_process();

    if (argc < 2 ||
        strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0 ||
        strcmp(argv[1], "help") == 0) {
        print_help();
        return 0;
    }

    const char *cmd = argv[1];
    char buf[256];

    if (strcmp(cmd, "get.sys.codename") == 0) {
        printf("%s\n", CODE_NAME);
    } else if (strcmp(cmd, "get.sys.name") == 0) {
        get_os_name(buf, sizeof(buf));
        printf("%s\n", buf);
    } else if (strcmp(cmd, "get.sys.kernel") == 0) {
        get_kernel(buf, sizeof(buf));
        printf("%s\n", buf);
    } else if (strcmp(cmd, "get.sys.support.type") == 0) {
        printf("0x%x\n", get_support_type());
    } else if (strcmp(cmd, "get.sys.sbstatus") == 0) {
        printf("%d\n", get_secure_boot_status());
    } else if (strcmp(cmd, "get.sys.manufacturer") == 0) {
        get_manufacturer(buf, sizeof(buf));
        printf("%s\n", buf);
    } else if (strcmp(cmd, "get.sys.cpu") == 0) {
        get_cpu(buf, sizeof(buf));
        printf("%s\n", buf);
    } else if (strcmp(cmd, "get.sys.fs") == 0) {
        get_root_fs(buf, sizeof(buf));
        printf("%s\n", buf);
    } else if (strcmp(cmd, "get.sys.memory") == 0) {
        unsigned long long memtotal = 0, swaptotal = 0;
        if (get_meminfo_kb(&memtotal, &swaptotal) != 0) {
            printf("Unknown\n");
        } else {
            double gb = (double)(memtotal + swaptotal) / 1024.0 / 1024.0;
            long rounded = (long)(gb + 0.5);
            printf("%ld GB\n", rounded);
        }
    } else if (strcmp(cmd, "get.sys.vram") == 0) {
        unsigned long long vram_mb = 0;
        if (get_vram_mb(&vram_mb) != 0) {
            printf("Unknown\n");
        } else {
            double gb = (double)vram_mb / 1000.0;
            long rounded = round_even_gb(gb);
            printf("%ld GB\n", rounded);
        }
    } else if (strcmp(cmd, "get.sys.build-code") == 0) {
        printf("%s\n", k_build_code);
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        print_help();
        return 1;
    }

    return 0;
}
