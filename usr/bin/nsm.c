#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NSM_BASE         "/nsm"
#define SNAPSHOT_BASE    NSM_BASE "/snapshots"
#define AUTO_DIR         SNAPSHOT_BASE "/auto"
#define DAEMON_AUTO_DIR  AUTO_DIR "/daemon"
#define MANUAL_DIR       SNAPSHOT_BASE "/manual"
#define ROOT_SOURCE      "/"
#define HOME_SOURCE      "/home"
#define META_FILE        "meta"

#define STR_BUF          512
#define PATH_BUF         1024
#define OUT_BUF          8192
#define BIG_OUT_BUF      (1024 * 1024)

#define KEEP_LATEST      6
#define THINPOOL_LIMIT   93.0
#define LV_NAME_MAX      127
#define USER_NAME_MAX    64
#define TS_LEN           19
#define MAX_HOLDERS      4096
#define EVICT_ATTEMPTS   5
#define GIB              1073741824.0

static const char *const SNAPSHOT_DIRS[] = { MANUAL_DIR, AUTO_DIR, DAEMON_AUTO_DIR };
#define N_SNAPSHOT_DIRS  (sizeof(SNAPSHOT_DIRS) / sizeof(SNAPSHOT_DIRS[0]))

static const char *const AUTO_DIRS[] = { AUTO_DIR, DAEMON_AUTO_DIR };
#define N_AUTO_DIRS      (sizeof(AUTO_DIRS) / sizeof(AUTO_DIRS[0]))

typedef struct {
    int  rc;
    bool truncated;
    char out[OUT_BUF];
} CmdResult;

typedef struct {
    char vg[STR_BUF];
    char lv[STR_BUF];
    char lvpath[PATH_BUF];
    char segtype[STR_BUF];
    bool is_thin;
} LvmInfo;

typedef struct {
    char kind[16];
    char type[16];
    char name[STR_BUF];
    char timestamp[64];
    char origin_mount[PATH_BUF];
    char origin_source[PATH_BUF];
    char origin_vg[STR_BUF];
    char origin_lv[STR_BUF];
    char origin_lvpath[PATH_BUF];
    char snapshot_lvpath[PATH_BUF];
} SnapshotMeta;

typedef struct { char **v; size_t n, cap; } StrList;
typedef struct { StrList roots, homes; } SnapNames;

__attribute__((format(printf, 3, 4)))
static bool fmt(char *dst, size_t sz, const char *f, ...)
{
    va_list ap;
    va_start(ap, f);
    int n = vsnprintf(dst, sz, f, ap);
    va_end(ap);
    return n >= 0 && (size_t)n < sz;
}

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
}

static bool valid_name(const char *s, size_t max)
{
    size_t len = strlen(s);
    if (len == 0 || len > max || s[0] == '.') return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '_' && c != '.' && c != '+' && c != '-') return false;
    }
    return true;
}

static const char *ts_part(const char *s)
{
    size_t n = strlen(s);
    return n > TS_LEN ? s + n - TS_LEN : s;
}

static int cmp_by_timestamp(const void *a, const void *b)
{
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    int c = strcmp(ts_part(sa), ts_part(sb));
    return c ? c : strcmp(sa, sb);
}

static bool strlist_push(StrList *l, const char *s)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 16;
        char **nv = realloc(l->v, nc * sizeof(*nv));
        if (!nv) return false;
        l->v = nv;
        l->cap = nc;
    }
    char *d = strdup(s);
    if (!d) return false;
    l->v[l->n++] = d;
    return true;
}

static void strlist_free(StrList *l)
{
    for (size_t i = 0; i < l->n; i++) free(l->v[i]);
    free(l->v);
    *l = (StrList){0};
}

static void strlist_sort(StrList *l)
{
    if (l->n > 1) qsort(l->v, l->n, sizeof(*l->v), cmp_by_timestamp);
}

static bool json_str(const char *json, const char *key, char *out, size_t sz)
{
    char pat[96];
    if (!fmt(pat, sizeof(pat), "\"%s\"", key)) return false;

    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *q = p + strlen(pat);
        p = q;
        while (isspace((unsigned char)*q)) q++;
        if (*q != ':') continue;
        q++;
        while (isspace((unsigned char)*q)) q++;
        if (*q != '"') return false;
        q++;

        size_t n = 0;
        while (*q && *q != '"') {
            if (*q == '\\' && q[1]) q++;
            if (n + 1 >= sz) return false;
            out[n++] = *q++;
        }
        if (*q != '"') return false;
        out[n] = '\0';
        return true;
    }
    return false;
}

static void exec_argv(const char *const argv[]) __attribute__((noreturn));
static void exec_argv(const char *const argv[])
{
    char *const *av = (char *const *)argv;

    if (argv[0][0] == '/') {
        execv(argv[0], av);
    } else {
        static const char *const dirs[] = { "/usr/bin", "/bin", "/usr/sbin", "/sbin" };
        char full[PATH_BUF];
        for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
            if (!fmt(full, sizeof(full), "%s/%s", dirs[i], argv[0])) continue;
            execv(full, av);
            if (errno != ENOENT && errno != ENOTDIR) break;
        }
    }
    _exit(127);
}

static int spawn(const char *const argv[], char *out, size_t sz, bool *truncated, bool merge_err)
{
    int pfd[2] = { -1, -1 };
    if (truncated) *truncated = false;

    if (out && sz > 0) {
        out[0] = '\0';
        if (pipe2(pfd, O_CLOEXEC) != 0) return -1;
    } else {
        out = NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (out) { close(pfd[0]); close(pfd[1]); }
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
        size_t total = 0;
        char sink[512];
        for (;;) {
            bool full = total >= sz - 1;
            ssize_t n = full ? read(pfd[0], sink, sizeof(sink))
                             : read(pfd[0], out + total, sz - 1 - total);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            if (full) { if (truncated) *truncated = true; }
            else total += (size_t)n;
        }
        out[total] = '\0';
        close(pfd[0]);
    }

    int st = 0;
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static CmdResult run_cmd(const char *const argv[], bool merge_err)
{
    CmdResult r = { .rc = -1 };
    r.rc = spawn(argv, r.out, sizeof(r.out), &r.truncated, merge_err);
    return r;
}

#define RUN(...)         run_cmd((const char *const[]){ __VA_ARGS__, NULL }, true)
#define RUN_OUT(...)     run_cmd((const char *const[]){ __VA_ARGS__, NULL }, false)
#define RUN_SILENT(...)  spawn((const char *const[]){ __VA_ARGS__, NULL }, NULL, 0, NULL, false)

static bool ensure_dir(const char *path)
{
    char tmp[PATH_BUF];
    if (!fmt(tmp, sizeof(tmp), "%s", path)) return false;
    size_t len = strlen(tmp);
    if (len == 0) return false;
    if (tmp[len - 1] == '/' && len > 1) tmp[--len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
        *p = '/';
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

static bool read_mount_field(const char *target, const char *field, char *out, size_t sz)
{
    CmdResult r = RUN_OUT("findmnt", "-no", field, "--target", target);
    if (r.rc != 0) return false;
    trim(r.out);
    if (r.out[0] == '\0') return false;
    return fmt(out, sz, "%s", r.out);
}

static bool lvm_report(const char *tool, const char *target, const char *fields, CmdResult *r)
{
    *r = RUN_OUT(tool, "--reportformat", "json", "--units", "b", "--nosuffix",
                 "-o", fields, target);
    return r->rc == 0 && !r->truncated;
}

static bool lvm_field(const char *tool, const char *target, const char *field,
                      char *out, size_t sz)
{
    CmdResult r;
    return lvm_report(tool, target, field, &r) && json_str(r.out, field, out, sz);
}

static bool resolve_lvm_info(const char *source, LvmInfo *info)
{
    CmdResult r;
    char vg[STR_BUF], lv[STR_BUF], seg[STR_BUF];

    if (!lvm_report("lvs", source, "vg_name,lv_name,segtype", &r)) return false;
    if (!json_str(r.out, "vg_name", vg, sizeof(vg)) ||
        !json_str(r.out, "lv_name", lv, sizeof(lv)) ||
        !json_str(r.out, "segtype", seg, sizeof(seg)))
        return false;
    if (!vg[0] || !lv[0] || !seg[0]) return false;

    memset(info, 0, sizeof(*info));
    if (!fmt(info->vg, sizeof(info->vg), "%s", vg) ||
        !fmt(info->lv, sizeof(info->lv), "%s", lv) ||
        !fmt(info->segtype, sizeof(info->segtype), "%s", seg) ||
        !fmt(info->lvpath, sizeof(info->lvpath), "/dev/%s/%s", vg, lv))
        return false;
    info->is_thin = strstr(seg, "thin") != NULL;
    return true;
}

static double get_vg_free_gb(const char *vg)
{
    char val[64];
    if (!lvm_field("vgs", vg, "vg_free", val, sizeof(val))) return 0.0;
    return (double)strtoull(val, NULL, 10) / GIB;
}

static const char *classic_snapshot_size(double free_gb)
{
    if (free_gb >= 10.0) return "5G";
    if (free_gb >= 5.0)  return "3G";
    if (free_gb >= 2.0)  return "1.5G";
    if (free_gb >= 1.0)  return "1G";
    return NULL;
}

static bool fstype_supported(const char *mountpoint)
{
    static const char *const ok[] = { "xfs", "ext4", "ext3", "btrfs" };
    char fstype[64];
    if (!read_mount_field(mountpoint, "FSTYPE", fstype, sizeof(fstype))) return false;
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (strcmp(fstype, ok[i]) == 0) return true;
    return false;
}

static bool freeze_mount(const char *mp)   { return RUN("fsfreeze", "-f", mp).rc == 0; }
static void unfreeze_mount(const char *mp) { RUN("fsfreeze", "-u", mp); }

static bool delete_snapshot_lv(const char *lvpath)
{
    return RUN("lvremove", "-fy", lvpath).rc == 0;
}

static bool lv_exists(const char *lvpath)
{
    return RUN_OUT("lvs", lvpath).rc == 0;
}

typedef struct { const char *key; size_t off; size_t size; } MetaField;

#define MF(f) { #f, offsetof(SnapshotMeta, f), sizeof(((SnapshotMeta *)0)->f) }
static const MetaField META_FIELDS[] = {
    MF(kind), MF(type), MF(name), MF(timestamp),
    MF(origin_mount), MF(origin_source), MF(origin_vg), MF(origin_lv),
    MF(origin_lvpath), MF(snapshot_lvpath),
};
#undef MF
#define N_META_FIELDS (sizeof(META_FIELDS) / sizeof(META_FIELDS[0]))

static bool write_snapshot_meta(const char *dir, const SnapshotMeta *meta)
{
    char path[PATH_BUF], tmp_path[PATH_BUF];
    if (!fmt(path, sizeof(path), "%s/%s", dir, META_FILE) ||
        !fmt(tmp_path, sizeof(tmp_path), "%s/%s.tmp.%d", dir, META_FILE, (int)getpid()))
        return false;

    FILE *f = fopen(tmp_path, "w");
    if (!f) return false;

    for (size_t i = 0; i < N_META_FIELDS; i++)
        fprintf(f, "%s=%s\n", META_FIELDS[i].key,
                (const char *)meta + META_FIELDS[i].off);

    bool ok = fflush(f) == 0 && fsync(fileno(f)) == 0;
    ok = (fclose(f) == 0) && ok;
    if (!ok || rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return false;
    }
    return true;
}

static bool read_snapshot_meta(const char *dir, SnapshotMeta *meta)
{
    memset(meta, 0, sizeof(*meta));
    char path[PATH_BUF];
    if (!fmt(path, sizeof(path), "%s/%s", dir, META_FILE)) return false;

    FILE *f = fopen(path, "r");
    if (!f) return false;

    char line[PATH_BUF * 2];
    bool ok = true;
    while (ok && fgets(line, sizeof(line), f)) {
        trim(line);
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *val = eq + 1;
        for (size_t i = 0; i < N_META_FIELDS; i++) {
            if (strcmp(line, META_FIELDS[i].key) != 0) continue;
            ok = fmt((char *)meta + META_FIELDS[i].off, META_FIELDS[i].size, "%s", val);
            break;
        }
    }
    fclose(f);
    return ok && meta->kind[0] != '\0' && meta->snapshot_lvpath[0] != '\0';
}

static void remove_snapshot_meta(const char *dir)
{
    char path[PATH_BUF];
    if (fmt(path, sizeof(path), "%s/%s", dir, META_FILE)) unlink(path);
    rmdir(dir);
}

static bool remove_snapshot_at(const char *dir)
{
    SnapshotMeta meta;
    if (read_snapshot_meta(dir, &meta) &&
        !delete_snapshot_lv(meta.snapshot_lvpath) &&
        lv_exists(meta.snapshot_lvpath)) {
        fprintf(stderr, "Warning: failed to remove snapshot LV '%s'.\n", meta.snapshot_lvpath);
        return false;
    }
    remove_snapshot_meta(dir);
    return true;
}

static bool find_snapshot(const char *name, char *dir_out, size_t sz)
{
    if (!valid_name(name, STR_BUF - 1)) return false;
    for (size_t i = 0; i < N_SNAPSHOT_DIRS; i++) {
        char dir[PATH_BUF], meta[PATH_BUF];
        if (!fmt(dir, sizeof(dir), "%s/%s", SNAPSHOT_DIRS[i], name) ||
            !fmt(meta, sizeof(meta), "%s/%s", dir, META_FILE))
            continue;
        if (access(meta, F_OK) == 0) return fmt(dir_out, sz, "%s", dir);
    }
    return false;
}

static bool delete_snapshot(const char *name)
{
    char dir[PATH_BUF];
    SnapshotMeta meta;
    if (!find_snapshot(name, dir, sizeof(dir))) return false;
    if (!read_snapshot_meta(dir, &meta)) return false;
    return remove_snapshot_at(dir);
}

static const char *snapshot_base_dir(const char *type, const char *name)
{
    if (strcmp(name, "nsmd") == 0) return DAEMON_AUTO_DIR;
    return strcmp(type, "auto") == 0 ? AUTO_DIR : MANUAL_DIR;
}

static bool create_snapshot(const char *mountpoint, const char *prefix,
                            const char *type, const char *name)
{
    char source[PATH_BUF];
    if (!read_mount_field(mountpoint, "SOURCE", source, sizeof(source))) {
        printf("Error: cannot resolve source for %s.\n", mountpoint);
        return false;
    }
    if (!fstype_supported(mountpoint)) {
        printf("Error: %s filesystem is not supported (xfs/ext4/ext3/btrfs required).\n",
               mountpoint);
        return false;
    }
    LvmInfo info;
    if (!resolve_lvm_info(source, &info)) {
        printf("Error: %s is not an LVM volume or cannot be resolved.\n", mountpoint);
        return false;
    }

    const char *snap_size = NULL;
    if (!info.is_thin) {
        double free_gb = get_vg_free_gb(info.vg);
        snap_size = classic_snapshot_size(free_gb);
        if (!snap_size) {
            printf("Error: Insufficient free space in volume group %s "
                   "(1.0G required, %.2fG available).\n", info.vg, free_gb);
            return false;
        }
    }

    char ts[64];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d_%H-%M-%S", &tm);

    char snapname[STR_BUF], snapdir[PATH_BUF];
    if (!fmt(snapname, sizeof(snapname), "%s-%s-%s-%s", prefix, type, name, ts) ||
        strlen(snapname) > LV_NAME_MAX) {
        printf("Error: snapshot name is too long.\n");
        return false;
    }
    if (!fmt(snapdir, sizeof(snapdir), "%s/%s", snapshot_base_dir(type, name), snapname) ||
        !ensure_dir(snapdir)) {
        printf("Error: cannot create snapshot metadata directory.\n");
        return false;
    }

    bool frozen = strcmp(mountpoint, "/") != 0 && freeze_mount(mountpoint);
    CmdResult r = info.is_thin
        ? RUN("lvcreate", "-s", "-n", snapname, info.lvpath)
        : RUN("lvcreate", "-L", snap_size, "-s", "-n", snapname, info.lvpath);
    if (frozen) unfreeze_mount(mountpoint);

    if (r.rc != 0) {
        printf("%s\n", r.out);
        remove_snapshot_meta(snapdir);
        return false;
    }

    SnapshotMeta meta;
    memset(&meta, 0, sizeof(meta));
    bool ok = fmt(meta.kind, sizeof(meta.kind), "%s", prefix)
           && fmt(meta.type, sizeof(meta.type), "%s", type)
           && fmt(meta.name, sizeof(meta.name), "%s", snapname)
           && fmt(meta.timestamp, sizeof(meta.timestamp), "%s", ts)
           && fmt(meta.origin_mount, sizeof(meta.origin_mount), "%s", mountpoint)
           && fmt(meta.origin_source, sizeof(meta.origin_source), "%s", source)
           && fmt(meta.origin_vg, sizeof(meta.origin_vg), "%s", info.vg)
           && fmt(meta.origin_lv, sizeof(meta.origin_lv), "%s", info.lv)
           && fmt(meta.origin_lvpath, sizeof(meta.origin_lvpath), "%s", info.lvpath)
           && fmt(meta.snapshot_lvpath, sizeof(meta.snapshot_lvpath),
                  "/dev/%s/%s", info.vg, snapname);

    if (!ok || !write_snapshot_meta(snapdir, &meta)) {
        printf("Error: snapshot was created, but metadata could not be written.\n");
        return false;
    }
    printf("Created (%s): %s\n", type, snapname);
    return true;
}

static bool initramfs_has_lvm_hook(void)
{
    struct utsname un;
    char initrd[PATH_BUF];
    if (uname(&un) != 0) return false;
    if (!fmt(initrd, sizeof(initrd), "/boot/initrd.img-%s", un.release)) return false;

    char *buf = malloc(BIG_OUT_BUF);
    if (!buf) return false;

    const char *const argv[] = { "lsinitramfs", initrd, NULL };
    bool found = spawn(argv, buf, BIG_OUT_BUF, NULL, false) == 0 && strstr(buf, "lvm") != NULL;
    free(buf);
    return found;
}

static pid_t parent_of(pid_t pid)
{
    char path[64], line[512];
    if (!fmt(path, sizeof(path), "/proc/%d/stat", (int)pid)) return 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *got = fgets(line, sizeof(line), f);
    fclose(f);
    if (!got) return 0;

    char *p = strrchr(line, ')');
    int ppid = 0;
    if (!p || sscanf(p + 1, " %*c %d", &ppid) != 1) return 0;
    return (pid_t)ppid;
}

static bool in_own_chain(pid_t pid)
{
    for (pid_t p = getpid(); p > 1; p = parent_of(p))
        if (p == pid) return true;
    return false;
}

static size_t home_holders(pid_t *pids, size_t max)
{
    CmdResult r = RUN_OUT("fuser", "-m", HOME_SOURCE);
    size_t n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(r.out, " \t\n", &save); tok && n < max;
         tok = strtok_r(NULL, " \t\n", &save)) {
        char *end;
        long v = strtol(tok, &end, 10);
        if (end == tok || v <= 0) continue;
        pids[n++] = (pid_t)v;
    }
    return n;
}

static void evict_holders(void)
{
    pid_t pids[MAX_HOLDERS];
    for (int attempt = 0; attempt < EVICT_ATTEMPTS; attempt++) {
        size_t n = home_holders(pids, MAX_HOLDERS);
        size_t signalled = 0;
        for (size_t i = 0; i < n; i++) {
            if (pids[i] <= 1 || in_own_chain(pids[i])) continue;
            kill(pids[i], attempt < 2 ? SIGTERM : SIGKILL);
            signalled++;
        }
        if (!signalled) return;
        usleep(500000);
    }
}

static bool rollback_home(const SnapshotMeta *meta, bool force)
{
    sync();
    if (force) evict_holders();

    bool unmounted = umount(HOME_SOURCE) == 0 || errno == EINVAL;
    if (!unmounted) {
        pid_t pids[MAX_HOLDERS];
        size_t n = home_holders(pids, MAX_HOLDERS);
        printf("Warning: /home is busy (%zu process(es) holding it); the merge will be deferred.\n", n);
        if (force)
            printf("Processes of your own session still hold it. Leave /home and run again, or reboot.\n");
        else
            printf("Run again with --force to stop them (your own session is never touched).\n");
    } else {
        RUN("lvchange", "-an", meta->origin_lvpath);
    }

    CmdResult r = RUN("lvconvert", "--merge", meta->snapshot_lvpath);
    bool ok = r.rc == 0;
    if (!ok) printf("Rollback failed: %s\n", r.out);

    if (unmounted) {
        RUN("lvchange", "-ay", meta->origin_lvpath);
        RUN_SILENT("mount", HOME_SOURCE);
    }

    if (!ok) return false;
    if (unmounted)
        printf("SUCCESS: Home rollback complete. REBOOT may be required if the merge is pending.\n");
    else
        printf("SUCCESS: Home rollback scheduled. REBOOT REQUIRED.\n");
    return true;
}

static bool rollback_root(const SnapshotMeta *meta)
{
    if (!initramfs_has_lvm_hook()) {
        printf("Warning: LVM hook not detected in initramfs.\n");
        printf("The merge is scheduled but may not apply on reboot.\n");
        printf("Run: update-initramfs -u   then reboot.\n");
    }
    CmdResult r = RUN("lvconvert", "--merge", meta->snapshot_lvpath);
    if (r.rc != 0) {
        printf("Rollback failed: %s\n", r.out);
        return false;
    }
    printf("SUCCESS: Root rollback scheduled. REBOOT REQUIRED.\n");
    return true;
}

static bool rollback_snapshot(const char *name, bool force)
{
    char dir[PATH_BUF];
    SnapshotMeta meta;
    if (!find_snapshot(name, dir, sizeof(dir))) {
        printf("Error: Snapshot '%s' not found.\n", name);
        return false;
    }
    if (!read_snapshot_meta(dir, &meta)) {
        printf("Error: Snapshot metadata could not be read.\n");
        return false;
    }
    if (strcmp(meta.kind, "root") == 0) return rollback_root(&meta);
    if (strcmp(meta.kind, "home") == 0) return rollback_home(&meta, force);
    printf("Error: invalid snapshot kind.\n");
    return false;
}

static void collect_snapshots(const char *dir, SnapNames *out)
{
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char meta[PATH_BUF];
        if (!fmt(meta, sizeof(meta), "%s/%s/%s", dir, e->d_name, META_FILE)) continue;
        if (access(meta, F_OK) != 0) continue;

        StrList *dst = NULL;
        if (strncmp(e->d_name, "root-", 5) == 0)      dst = &out->roots;
        else if (strncmp(e->d_name, "home-", 5) == 0) dst = &out->homes;
        if (dst && !strlist_push(dst, e->d_name))
            fprintf(stderr, "Warning: out of memory while listing %s\n", dir);
    }
    closedir(d);
    strlist_sort(&out->roots);
    strlist_sort(&out->homes);
}

static void snapnames_free(SnapNames *s)
{
    strlist_free(&s->roots);
    strlist_free(&s->homes);
}

static void list_dir(const char *dir)
{
    SnapNames s = {0};
    collect_snapshots(dir, &s);

    printf("  Snapshots:\n");
    if (!s.roots.n && !s.homes.n) printf("    (none)\n");
    for (size_t i = 0; i < s.roots.n; i++) printf("    %s\n", s.roots.v[i]);
    for (size_t i = 0; i < s.homes.n; i++) printf("    %s\n", s.homes.v[i]);
    snapnames_free(&s);
}

static void list_snapshots(void)
{
    printf("\nManual Snapshots\n");     list_dir(MANUAL_DIR);
    printf("\napt Snapshots\n");        list_dir(AUTO_DIR);
    printf("\nnsm Daemon Snapshots\n"); list_dir(DAEMON_AUTO_DIR);
    printf("\n");
}

static bool user_part(const char *snap, char *out, size_t sz)
{
    const char *p = snap;
    if (strncmp(p, "root-", 5) != 0 && strncmp(p, "home-", 5) != 0) return false;
    p += 5;
    if (strncmp(p, "auto-", 5) == 0) p += 5;
    else if (strncmp(p, "manual-", 7) == 0) p += 7;
    else return false;

    size_t n = strlen(p);
    if (n <= TS_LEN + 1) return false;
    n -= TS_LEN + 1;
    if (p[n] != '-' || n >= sz) return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static void find_by_term(const char *term, StrList *out)
{
    for (int pass = 0; pass < 2 && !out->n; pass++) {
        for (size_t i = 0; i < N_SNAPSHOT_DIRS; i++) {
            SnapNames s = {0};
            StrList *lists[2] = { &s.roots, &s.homes };
            collect_snapshots(SNAPSHOT_DIRS[i], &s);
            for (size_t k = 0; k < 2; k++) {
                for (size_t j = 0; j < lists[k]->n; j++) {
                    const char *name = lists[k]->v[j];
                    char part[STR_BUF], path[PATH_BUF];
                    bool hit = pass == 0
                        ? user_part(name, part, sizeof(part)) && strcmp(part, term) == 0
                        : strstr(name, term) != NULL;
                    if (hit && fmt(path, sizeof(path), "%s/%s", SNAPSHOT_DIRS[i], name))
                        strlist_push(out, path);
                }
            }
            snapnames_free(&s);
        }
    }
    strlist_sort(out);
}

static int cmd_delete(const char *term)
{
    char dir[PATH_BUF];
    SnapshotMeta meta;

    if (find_snapshot(term, dir, sizeof(dir))) {
        if (delete_snapshot(term)) {
            printf("Snapshot deleted successfully.\n");
            return 0;
        }
        fprintf(stderr, "Error: snapshot deletion failed.\n");
        return 1;
    }

    if (!valid_name(term, STR_BUF - 1)) {
        fprintf(stderr, "Error: snapshot '%s' not found.\n", term);
        return 1;
    }

    StrList m = {0};
    find_by_term(term, &m);
    if (!m.n) {
        fprintf(stderr, "Error: no snapshot matches '%s'.\n", term);
        return 1;
    }

    printf("Snapshots called \"%s\":\n", term);
    for (size_t i = 0; i < m.n; i++)
        printf("  %zu - %s\n", i + 1, strrchr(m.v[i], '/') + 1);

    int rc = 1;
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "Not a terminal: run again with the full snapshot name.\n");
    } else {
        printf("Which one to delete? [1-%zu, empty to cancel]: ", m.n);
        fflush(stdout);

        char line[32];
        if (!fgets(line, sizeof(line), stdin)) line[0] = '\0';
        trim(line);

        char *end;
        long k = strtol(line, &end, 10);
        if (!line[0]) {
            printf("Cancelled.\n");
        } else if (*end || k < 1 || (size_t)k > m.n) {
            fprintf(stderr, "Error: invalid choice.\n");
        } else if (read_snapshot_meta(m.v[k - 1], &meta) && remove_snapshot_at(m.v[k - 1])) {
            printf("Snapshot deleted successfully.\n");
            rc = 0;
        } else {
            fprintf(stderr, "Error: snapshot deletion failed.\n");
        }
    }
    strlist_free(&m);
    return rc;
}

static void drop_oldest(const char *dir, const StrList *names)
{
    for (size_t i = 0; names->n - i > KEEP_LATEST; i++) {
        char path[PATH_BUF];
        if (!fmt(path, sizeof(path), "%s/%s", dir, names->v[i])) continue;
        remove_snapshot_at(path);
    }
}

static void cleanup_dir(const char *dir)
{
    SnapNames s = {0};
    collect_snapshots(dir, &s);
    drop_oldest(dir, &s.roots);
    drop_oldest(dir, &s.homes);
    snapnames_free(&s);
}

static void autodel_snapshots(void)
{
    for (size_t i = 0; i < N_AUTO_DIRS; i++) cleanup_dir(AUTO_DIRS[i]);
}

static bool get_lv_pool(const char *lvpath, char *pool, size_t sz)
{
    return lvm_field("lvs", lvpath, "pool_lv", pool, sz) && pool[0] != '\0';
}

static double get_thinpool_usage(const char *vg, const char *pool)
{
    char target[PATH_BUF], val[64];
    if (!fmt(target, sizeof(target), "%s/%s", vg, pool)) return 0.0;
    if (!lvm_field("lvs", target, "data_percent", val, sizeof(val))) return 0.0;
    return atof(val);
}

static void push_paths(StrList *dst, const char *dir, const StrList *names)
{
    for (size_t i = 0; i < names->n; i++) {
        char path[PATH_BUF];
        if (fmt(path, sizeof(path), "%s/%s", dir, names->v[i]))
            strlist_push(dst, path);
    }
}

static void purge_auto_snapshots(const char *vg, const char *pool)
{
    StrList paths = {0};
    for (size_t i = 0; i < N_AUTO_DIRS; i++) {
        SnapNames s = {0};
        collect_snapshots(AUTO_DIRS[i], &s);
        push_paths(&paths, AUTO_DIRS[i], &s.roots);
        push_paths(&paths, AUTO_DIRS[i], &s.homes);
        snapnames_free(&s);
    }
    strlist_sort(&paths);

    double usage = get_thinpool_usage(vg, pool);
    for (size_t i = 0; i < paths.n && usage >= THINPOOL_LIMIT; i++)
        if (remove_snapshot_at(paths.v[i])) usage = get_thinpool_usage(vg, pool);
    strlist_free(&paths);

    if (usage >= THINPOOL_LIMIT)
        printf("Warning: Thin pool %s/%s is still at %.2f%% with no automatic snapshots left. "
               "Manual snapshots are never removed automatically; use 'delete <name>'.\n",
               vg, pool, usage);
}

static void monitor_thinpool(const char *mountpoint)
{
    char source[PATH_BUF], pool[STR_BUF];
    LvmInfo info;
    if (!read_mount_field(mountpoint, "SOURCE", source, sizeof(source))) return;
    if (!resolve_lvm_info(source, &info) || !info.is_thin) return;
    if (!get_lv_pool(info.lvpath, pool, sizeof(pool))) return;

    double usage = get_thinpool_usage(info.vg, pool);
    if (usage < THINPOOL_LIMIT) return;

    printf("Warning: Thin pool %s/%s usage is %.2f%% (threshold %.0f%% passed).\n",
           info.vg, pool, usage, THINPOOL_LIMIT);
    autodel_snapshots();

    if (get_thinpool_usage(info.vg, pool) >= THINPOOL_LIMIT)
        purge_auto_snapshots(info.vg, pool);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s <command> [argument]\n\n", prog);
    printf("Commands:\n");
    printf("  create <name>    Create snapshots on XFS/ext4/LVM volumes\n");
    printf("                   Auto type if name matches 'apt', 'apt-*', or 'nsmd'\n");
    printf("  rollback <name> [--force]\n");
    printf("                   Roll back to named snapshot\n");
    printf("                   --force stops processes holding /home (never your own session)\n");
    printf("  delete <name>    Delete a snapshot by full name, or by the name you gave it\n");
    printf("                   (asks which one when several match)\n");
    printf("  list             List all snapshots\n");
    printf("  autodel          Delete oldest automatic snapshots, keeping the latest %d\n", KEEP_LATEST);
}

static int cmd_create(const char *name)
{
    if (!valid_name(name, USER_NAME_MAX)) {
        fprintf(stderr, "Error: invalid snapshot name (use letters, digits, '_', '.', '+', '-'; "
                        "max %d chars).\n", USER_NAME_MAX);
        return 1;
    }
    if (!ensure_dir(AUTO_DIR) || !ensure_dir(DAEMON_AUTO_DIR) || !ensure_dir(MANUAL_DIR)) {
        fprintf(stderr, "Error: cannot create %s.\n", SNAPSHOT_BASE);
        return 1;
    }

    bool isauto = strcmp(name, "nsmd") == 0 || strncmp(name, "apt", 3) == 0;
    bool ok = create_snapshot(ROOT_SOURCE, "root", isauto ? "auto" : "manual", name);
    if (isauto) autodel_snapshots();
    monitor_thinpool(ROOT_SOURCE);
    monitor_thinpool(HOME_SOURCE);
    return ok ? 0 : 1;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "Error: root privileges required.\n");
        return 1;
    }
    setenv("LC_ALL", "C", 1);

    const char *cmd = argv[1];
    const char *arg = argc > 2 ? argv[2] : NULL;
    bool needs_arg = !strcmp(cmd, "create") || !strcmp(cmd, "rollback") || !strcmp(cmd, "delete");

    if (needs_arg && !arg) {
        print_usage(argv[0]);
        return 1;
    }

    if (!strcmp(cmd, "create")) return cmd_create(arg);

    if (!strcmp(cmd, "rollback")) {
        bool force = false;
        if (argc > 3) {
            if (argc > 4 || strcmp(argv[3], "--force") != 0) {
                print_usage(argv[0]);
                return 1;
            }
            force = true;
        }
        return rollback_snapshot(arg, force) ? 0 : 1;
    }

    if (!strcmp(cmd, "delete")) return cmd_delete(arg);

    if (!strcmp(cmd, "list")) {
        list_snapshots();
        return 0;
    }

    if (!strcmp(cmd, "autodel")) {
        autodel_snapshots();
        monitor_thinpool(ROOT_SOURCE);
        monitor_thinpool(HOME_SOURCE);
        return 0;
    }

    fprintf(stderr, "Error: unknown command '%s'\n\n", cmd);
    print_usage(argv[0]);
    return 1;
}
