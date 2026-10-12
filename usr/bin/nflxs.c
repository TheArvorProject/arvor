#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <termios.h>
#include <time.h>
#include <crypt.h>
#include <net/if.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>

#define NFLXS_VERSION "0.28"
#define NFLXS_ROOT "/nsm/nflxs"
#define NFLXS_SANDBOXES NFLXS_ROOT "/sandboxes"
#define NFLXS_IMAGES NFLXS_ROOT "/images"
#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP_BASE CGROUP_ROOT "/nflxs"
#define MAX_NAME 63
#define MAX_TEXT ((size_t)1 << 20)
#define STACK_SIZE ((size_t)1 << 20)
#define MAX_GROUPS 32

static int g_is_child;
static pid_t g_cleanup_owner;
static char g_cleanup_path[PATH_MAX];
static char g_cleanup_vg[80];

static void die_va(int with_errno, const char *fmt, va_list ap)
{
    int saved = errno;
    fprintf(stderr, "nflxs: error: ");
    vfprintf(stderr, fmt, ap);
    if (with_errno)
        fprintf(stderr, ": %s", strerror(saved));
    fputc('\n', stderr);
    if (g_is_child)
        _exit(1);
    exit(1);
}

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    die_va(0, fmt, ap);
    va_end(ap);
    abort();
}

static void die_errno(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die_errno(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    die_va(1, fmt, ap);
    va_end(ap);
    abort();
}

static void warnx_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void warnx_(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "nflxs: warning: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

#define PROGRESS_WIDTH 36

struct progress {
    char label[160];
    size_t done;
    size_t total;
    bool tty;
};

static void progress_render(const struct progress *p)
{
    unsigned percent = p->total ? (unsigned)((p->done * 100) / p->total) : 100;
    if (percent > 100)
        percent = 100;
    unsigned filled = (percent * PROGRESS_WIDTH) / 100;
    if (p->tty)
        fputc('\r', stdout);
    fprintf(stdout, "%-42.42s \xe2\x94\x81\xe2\x94\x81 ", p->label);
    fputc('[', stdout);
    for (unsigned i = 0; i < PROGRESS_WIDTH; i++) {
        if (i < filled)
            fputs("\xe2\x96\x88", stdout);
        else if (percent > 0 && percent < 100 && i == filled)
            fputs("\xe2\x96\x8c", stdout);
        else
            fputs("\xe2\x96\x91", stdout);
    }
    fputc(']', stdout);
    fprintf(stdout, " %3u%%", percent);
    if (!p->tty || p->done == p->total)
        fputc('\n', stdout);
    fflush(stdout);
}

static void progress_begin(struct progress *p, size_t total, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void progress_begin(struct progress *p, size_t total, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->label, sizeof(p->label), fmt, ap);
    va_end(ap);
    p->done = 0;
    p->total = total ? total : 1;
    p->tty = isatty(STDOUT_FILENO);
    progress_render(p);
}

static void progress_set_label(struct progress *p, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void progress_set_label(struct progress *p, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->label, sizeof(p->label), fmt, ap);
    va_end(ap);
    if (p->tty)
        progress_render(p);
}

static void progress_advance(struct progress *p)
{
    if (p->done < p->total)
        p->done++;
    progress_render(p);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        die("out of memory");
    return p;
}

static void *xcalloc(size_t n, size_t m)
{
    void *p = calloc(n ? n : 1, m ? m : 1);
    if (!p)
        die("out of memory");
    return p;
}

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        die("out of memory");
    return q;
}

static char *xstrndup(const char *s, size_t n)
{
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static char *xstrdup(const char *s)
{
    return xstrndup(s, strlen(s));
}

static char *xvasprintf(const char *fmt, va_list ap)
{
    va_list cp;
    va_copy(cp, ap);
    int n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    if (n < 0)
        die("formatting failure");
    char *p = xmalloc((size_t)n + 1);
    vsnprintf(p, (size_t)n + 1, fmt, ap);
    return p;
}

static char *xasprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static char *xasprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *p = xvasprintf(fmt, ap);
    va_end(ap);
    return p;
}

static void pathf(char *out, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void pathf(char *out, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(out, n, fmt, ap);
    va_end(ap);
    if (r < 0 || (size_t)r >= n)
        die("path too long");
}

struct buf {
    char *d;
    size_t len;
    size_t cap;
};

static void buf_reserve(struct buf *b, size_t extra)
{
    if (extra > SIZE_MAX - b->len - 1)
        die("buffer overflow");
    size_t need = b->len + extra + 1;
    if (b->d && need <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2)
            die("buffer overflow");
        cap *= 2;
    }
    b->d = xrealloc(b->d, cap);
    b->cap = cap;
    b->d[b->len] = '\0';
}

static void buf_add(struct buf *b, const void *p, size_t n)
{
    buf_reserve(b, n);
    if (n)
        memcpy(b->d + b->len, p, n);
    b->len += n;
    b->d[b->len] = '\0';
}

static void buf_free(struct buf *b)
{
    free(b->d);
    memset(b, 0, sizeof(*b));
}

static int write_all(int fd, const void *p, size_t n)
{
    const char *c = p;
    while (n) {
        ssize_t w = write(fd, c, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        c += w;
        n -= (size_t)w;
    }
    return 0;
}

static int read_file(const char *path, struct buf *b, size_t max)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    buf_reserve(b, 0);
    char tmp[4096];
    for (;;) {
        ssize_t r = read(fd, tmp, sizeof(tmp));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        if (r == 0)
            break;
        if (b->len + (size_t)r > max) {
            close(fd);
            errno = EFBIG;
            return -1;
        }
        buf_add(b, tmp, (size_t)r);
    }
    close(fd);
    return 0;
}

static int write_file(const char *path, const void *p, size_t n, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0)
        return -1;
    if (write_all(fd, p, n) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    if (close(fd) < 0)
        return -1;
    return 0;
}

static int write_str_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int r = write_all(fd, s, strlen(s));
    int e = errno;
    close(fd);
    errno = e;
    return r;
}

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static bool path_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static int wait_pid(pid_t pid)
{
    int st;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return -1;
}

static pid_t spawn(char *const argv[], int in_fd, int out_fd)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        signal(SIGPIPE, SIG_DFL);
        if (in_fd >= 0 && dup2(in_fd, 0) < 0)
            _exit(126);
        if (out_fd >= 0 && dup2(out_fd, 1) < 0)
            _exit(126);
        execvp(argv[0], argv);
        dprintf(2, "nflxs: cannot execute %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    return pid;
}

static int run_argv(char *const argv[])
{
    pid_t p = spawn(argv, -1, -1);
    if (p < 0)
        return -1;
    return wait_pid(p);
}

static int run_capture(char *const argv[], struct buf *out, size_t max)
{
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) < 0)
        return -1;
    pid_t p = spawn(argv, -1, pfd[1]);
    close(pfd[1]);
    if (p < 0) {
        close(pfd[0]);
        return -1;
    }
    buf_reserve(out, 0);
    char tmp[4096];
    bool overflow = false;
    for (;;) {
        ssize_t r = read(pfd[0], tmp, sizeof(tmp));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (r == 0)
            break;
        if (out->len + (size_t)r > max) {
            overflow = true;
            kill(p, SIGKILL);
            break;
        }
        buf_add(out, tmp, (size_t)r);
    }
    close(pfd[0]);
    int rc = wait_pid(p);
    if (overflow) {
        errno = EFBIG;
        return -1;
    }
    return rc;
}

static void cleanup_atexit(void)
{
    if (g_cleanup_path[0] == '\0' || getpid() != g_cleanup_owner)
        return;
    if (g_cleanup_vg[0] != '\0') {
        char *vgremove[] = { "vgremove", "-f", "--", g_cleanup_vg, NULL };
        run_argv(vgremove);
        g_cleanup_vg[0] = '\0';
    }
    char *argv[] = { "rm", "-rf", "--one-file-system", "--", g_cleanup_path, NULL };
    run_argv(argv);
    g_cleanup_path[0] = '\0';
}

static void cleanup_set(const char *path)
{
    static bool registered;
    g_cleanup_owner = getpid();
    pathf(g_cleanup_path, sizeof(g_cleanup_path), "%s", path);
    if (!registered) {
        atexit(cleanup_atexit);
        registered = true;
    }
}

static void cleanup_set_vg(const char *vg_name)
{
    pathf(g_cleanup_vg, sizeof(g_cleanup_vg), "%s", vg_name);
}

static void cleanup_clear(void)
{
    g_cleanup_path[0] = '\0';
    g_cleanup_vg[0] = '\0';
}

static bool valid_name(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > MAX_NAME)
        return false;
    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= '0' && s[0] <= '9')))
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool valid_distro(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 128)
        return false;
    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')))
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '/'))
            return false;
        if (c == '/' && (i + 1 == n || s[i + 1] == '/' || s[i + 1] == '.'))
            return false;
        if (c == '.' && i + 1 < n && s[i + 1] == '.')
            return false;
    }
    return s[n - 1] != '/';
}

static bool valid_version(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 128)
        return false;
    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= '0' && s[0] <= '9') || s[0] == '_'))
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool valid_user(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 32)
        return false;
    if (!((s[0] >= 'a' && s[0] <= 'z') || s[0] == '_'))
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static void default_user(const char *distro, char *out, size_t n)
{
    const char *base = strrchr(distro, '/');
    base = base ? base + 1 : distro;
    size_t j = 0;
    for (size_t i = 0; base[i] && j + 1 < n && j < 32; i++) {
        char c = base[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            c = '_';
        if (j == 0 && !((c >= 'a' && c <= 'z') || c == '_'))
            out[j++] = '_';
        if (j + 1 < n && j < 32)
            out[j++] = c;
    }
    if (j == 0)
        out[j++] = 'u';
    out[j] = '\0';
}

static bool parse_u64(const char *s, uint64_t *out)
{
    if (!*s)
        return false;
    uint64_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return false;
        unsigned d = (unsigned)(*s - '0');
        if (v > (UINT64_MAX - d) / 10)
            return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}

static bool parse_size(const char *s, const char *units, uint64_t *out)
{
    size_t n = strlen(s);
    if (n < 2 || n > 32)
        return false;
    char tmp[40];
    memcpy(tmp, s, n + 1);
    if (n >= 2 && (tmp[n - 1] == 'b' || tmp[n - 1] == 'B') && !(tmp[n - 2] >= '0' && tmp[n - 2] <= '9'))
        tmp[--n] = '\0';
    char u = (char)toupper((unsigned char)tmp[n - 1]);
    if (!strchr(units, u))
        return false;
    tmp[n - 1] = '\0';
    uint64_t v;
    if (!parse_u64(tmp, &v) || v == 0)
        return false;
    unsigned shift = u == 'K' ? 10 : u == 'M' ? 20 : u == 'G' ? 30 : 40;
    if (v > (UINT64_MAX >> shift))
        return false;
    *out = v << shift;
    return true;
}

static bool parse_cpu(const char *s, uint32_t *milli)
{
    uint64_t whole = 0, frac = 0;
    size_t i = 0, digits = 0;
    for (; s[i] >= '0' && s[i] <= '9'; i++, digits++) {
        whole = whole * 10 + (uint64_t)(s[i] - '0');
        if (whole > 65536)
            return false;
    }
    if (digits == 0)
        return false;
    size_t fd = 0;
    if (s[i] == '.') {
        i++;
        for (; s[i] >= '0' && s[i] <= '9'; i++, fd++) {
            if (fd >= 3)
                return false;
            frac = frac * 10 + (uint64_t)(s[i] - '0');
        }
        if (fd == 0)
            return false;
    }
    if (s[i] != '\0')
        return false;
    for (size_t k = fd; k < 3; k++)
        frac *= 10;
    uint64_t m = whole * 1000 + frac;
    if (m < 10 || m > 65536000)
        return false;
    *milli = (uint32_t)m;
    return true;
}

struct sha256 {
    uint32_t h[8];
    uint64_t total;
    uint8_t buf[64];
    size_t blen;
};

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(struct sha256 *s)
{
    static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(s->h, iv, sizeof(iv));
    s->total = 0;
    s->blen = 0;
}

static void sha256_block(struct sha256 *s, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_update(struct sha256 *s, const void *data, size_t n)
{
    const uint8_t *p = data;
    s->total += n;
    while (n) {
        size_t c = 64 - s->blen;
        if (c > n)
            c = n;
        memcpy(s->buf + s->blen, p, c);
        s->blen += c;
        p += c;
        n -= c;
        if (s->blen == 64) {
            sha256_block(s, s->buf);
            s->blen = 0;
        }
    }
}

static void sha256_final(struct sha256 *s, char hex[65])
{
    uint64_t bits = s->total * 8;
    uint8_t pad = 0x80;
    sha256_update(s, &pad, 1);
    uint8_t z = 0;
    while (s->blen != 56)
        sha256_update(s, &z, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(s, len, 8);
    for (int i = 0; i < 8; i++)
        snprintf(hex + 8 * i, 9, "%08x", s->h[i]);
}

static int sha256_file(const char *path, char hex[65], uint64_t *size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct sha256 s;
    sha256_init(&s);
    uint8_t *buf = xmalloc(1 << 16);
    uint64_t total = 0;
    for (;;) {
        ssize_t r = read(fd, buf, 1 << 16);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            free(buf);
            close(fd);
            errno = e;
            return -1;
        }
        if (r == 0)
            break;
        sha256_update(&s, buf, (size_t)r);
        total += (uint64_t)r;
    }
    free(buf);
    close(fd);
    sha256_final(&s, hex);
    *size = total;
    return 0;
}

enum jtype { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };

struct json {
    enum jtype type;
    char *str;
    char **keys;
    struct json **vals;
    size_t n;
};

struct jparser {
    const char *p;
    const char *end;
};

static void json_free(struct json *j)
{
    if (!j)
        return;
    for (size_t i = 0; i < j->n; i++) {
        if (j->keys)
            free(j->keys[i]);
        json_free(j->vals[i]);
    }
    free(j->keys);
    free(j->vals);
    free(j->str);
    free(j);
}

static void jskip(struct jparser *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int jhex4(struct jparser *ps, uint32_t *out)
{
    if (ps->end - ps->p < 4)
        return -1;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval((unsigned char)ps->p[i]);
        if (h < 0)
            return -1;
        v = (v << 4) | (uint32_t)h;
    }
    ps->p += 4;
    *out = v;
    return 0;
}

static void utf8_put(struct buf *b, uint32_t cp)
{
    char t[4];
    if (cp < 0x80) {
        t[0] = (char)cp;
        buf_add(b, t, 1);
    } else if (cp < 0x800) {
        t[0] = (char)(0xc0 | (cp >> 6));
        t[1] = (char)(0x80 | (cp & 0x3f));
        buf_add(b, t, 2);
    } else if (cp < 0x10000) {
        t[0] = (char)(0xe0 | (cp >> 12));
        t[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        t[2] = (char)(0x80 | (cp & 0x3f));
        buf_add(b, t, 3);
    } else {
        t[0] = (char)(0xf0 | (cp >> 18));
        t[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
        t[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
        t[3] = (char)(0x80 | (cp & 0x3f));
        buf_add(b, t, 4);
    }
}

static char *jstring(struct jparser *ps)
{
    if (ps->p >= ps->end || *ps->p != '"')
        return NULL;
    ps->p++;
    struct buf b = { 0 };
    buf_reserve(&b, 0);
    while (ps->p < ps->end && *ps->p != '"') {
        unsigned char c = (unsigned char)*ps->p++;
        if (c < 0x20)
            goto fail;
        if (c != '\\') {
            buf_add(&b, &c, 1);
            continue;
        }
        if (ps->p >= ps->end)
            goto fail;
        char e = *ps->p++;
        switch (e) {
        case '"': case '\\': case '/': buf_add(&b, &e, 1); break;
        case 'b': buf_add(&b, "\b", 1); break;
        case 'f': buf_add(&b, "\f", 1); break;
        case 'n': buf_add(&b, "\n", 1); break;
        case 'r': buf_add(&b, "\r", 1); break;
        case 't': buf_add(&b, "\t", 1); break;
        case 'u': {
            uint32_t cp;
            if (jhex4(ps, &cp) < 0)
                goto fail;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                uint32_t lo;
                if (ps->end - ps->p >= 2 && ps->p[0] == '\\' && ps->p[1] == 'u') {
                    ps->p += 2;
                    if (jhex4(ps, &lo) < 0)
                        goto fail;
                    if (lo >= 0xdc00 && lo <= 0xdfff)
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                    else
                        cp = '?';
                } else {
                    cp = '?';
                }
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                cp = '?';
            }
            if (cp == 0)
                cp = '?';
            utf8_put(&b, cp);
            break;
        }
        default:
            goto fail;
        }
    }
    if (ps->p >= ps->end)
        goto fail;
    ps->p++;
    return b.d;
fail:
    buf_free(&b);
    return NULL;
}

static struct json *jvalue(struct jparser *ps, int depth)
{
    if (depth > 48)
        return NULL;
    jskip(ps);
    if (ps->p >= ps->end)
        return NULL;
    struct json *j = xcalloc(1, sizeof(*j));
    char c = *ps->p;
    if (c == '"') {
        j->type = J_STR;
        j->str = jstring(ps);
        if (!j->str)
            goto fail;
        return j;
    }
    if (c == '{' || c == '[') {
        bool obj = c == '{';
        char close = obj ? '}' : ']';
        j->type = obj ? J_OBJ : J_ARR;
        ps->p++;
        jskip(ps);
        if (ps->p < ps->end && *ps->p == close) {
            ps->p++;
            return j;
        }
        for (;;) {
            char *key = NULL;
            jskip(ps);
            if (obj) {
                key = jstring(ps);
                if (!key)
                    goto fail;
                jskip(ps);
                if (ps->p >= ps->end || *ps->p != ':') {
                    free(key);
                    goto fail;
                }
                ps->p++;
            }
            struct json *v = jvalue(ps, depth + 1);
            if (!v) {
                free(key);
                goto fail;
            }
            if (j->n >= 65536) {
                free(key);
                json_free(v);
                goto fail;
            }
            j->vals = xrealloc(j->vals, (j->n + 1) * sizeof(*j->vals));
            if (obj)
                j->keys = xrealloc(j->keys, (j->n + 1) * sizeof(*j->keys));
            j->vals[j->n] = v;
            if (obj)
                j->keys[j->n] = key;
            j->n++;
            jskip(ps);
            if (ps->p >= ps->end)
                goto fail;
            if (*ps->p == ',') {
                ps->p++;
                continue;
            }
            if (*ps->p == close) {
                ps->p++;
                return j;
            }
            goto fail;
        }
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        const char *s = ps->p;
        while (ps->p < ps->end && (strchr("+-.eE", *ps->p) || (*ps->p >= '0' && *ps->p <= '9')))
            ps->p++;
        j->type = J_NUM;
        j->str = xstrndup(s, (size_t)(ps->p - s));
        return j;
    }
    if (ps->end - ps->p >= 4 && !strncmp(ps->p, "true", 4)) {
        ps->p += 4;
        j->type = J_BOOL;
        return j;
    }
    if (ps->end - ps->p >= 5 && !strncmp(ps->p, "false", 5)) {
        ps->p += 5;
        j->type = J_BOOL;
        return j;
    }
    if (ps->end - ps->p >= 4 && !strncmp(ps->p, "null", 4)) {
        ps->p += 4;
        j->type = J_NULL;
        return j;
    }
fail:
    json_free(j);
    return NULL;
}

static struct json *json_parse(const char *s, size_t n)
{
    struct jparser ps = { s, s + n };
    struct json *j = jvalue(&ps, 0);
    if (!j)
        return NULL;
    jskip(&ps);
    if (ps.p != ps.end) {
        json_free(j);
        return NULL;
    }
    return j;
}

static struct json *jget(const struct json *o, const char *key)
{
    if (!o || o->type != J_OBJ)
        return NULL;
    for (size_t i = 0; i < o->n; i++)
        if (!strcmp(o->keys[i], key))
            return o->vals[i];
    return NULL;
}

static const char *jstr(const struct json *v)
{
    return v && v->type == J_STR ? v->str : NULL;
}

static int sys_openat2(int dirfd, const char *path, uint64_t flags, uint64_t mode, uint64_t resolve)
{
    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = flags | O_CLOEXEC;
    how.mode = (flags & O_CREAT) ? mode : 0;
    how.resolve = resolve;
    return (int)syscall(SYS_openat2, dirfd, path, &how, sizeof(how));
}

static int root_open(int rootfd, const char *rel, int flags, mode_t mode)
{
    return sys_openat2(rootfd, rel[0] ? rel : ".", (uint64_t)flags, mode, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS);
}

static int normalize_rel(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    const char *p = in;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *e = p;
        while (*e && *e != '/')
            e++;
        size_t l = (size_t)(e - p);
        if (l == 1 && p[0] == '.') {
            p = e;
            continue;
        }
        if (l == 2 && p[0] == '.' && p[1] == '.')
            return -1;
        if (o + l + 2 > outsz)
            return -1;
        if (o)
            out[o++] = '/';
        memcpy(out + o, p, l);
        o += l;
        p = e;
    }
    out[o] = '\0';
    return 0;
}

static int open_dir_p(int rootfd, const char *dirpath, bool create)
{
    char path[PATH_MAX];
    if (normalize_rel(dirpath, path, sizeof(path)) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (create && path[0]) {
        for (char *e = path;; e++) {
            if (*e != '/' && *e != '\0')
                continue;
            char saved = *e;
            *e = '\0';
            int fd = root_open(rootfd, path, O_PATH | O_DIRECTORY, 0);
            if (fd >= 0) {
                close(fd);
            } else if (errno == ENOENT || errno == ENOTDIR) {
                char *slash = strrchr(path, '/');
                int pfd;
                const char *comp;
                if (slash) {
                    *slash = '\0';
                    pfd = root_open(rootfd, path, O_PATH | O_DIRECTORY, 0);
                    *slash = '/';
                    comp = slash + 1;
                } else {
                    pfd = root_open(rootfd, ".", O_PATH | O_DIRECTORY, 0);
                    comp = path;
                }
                if (pfd < 0)
                    return -1;
                if (mkdirat(pfd, comp, 0755) < 0) {
                    if (errno != EEXIST) {
                        int se = errno;
                        close(pfd);
                        errno = se;
                        return -1;
                    }
                    struct stat st;
                    if (fstatat(pfd, comp, &st, AT_SYMLINK_NOFOLLOW) == 0 && !S_ISDIR(st.st_mode)) {
                        if (unlinkat(pfd, comp, 0) < 0 || mkdirat(pfd, comp, 0755) < 0) {
                            int se = errno;
                            close(pfd);
                            errno = se;
                            return -1;
                        }
                    }
                }
                close(pfd);
            } else {
                return -1;
            }
            *e = saved;
            if (saved == '\0')
                break;
        }
    }
    return root_open(rootfd, path, O_PATH | O_DIRECTORY, 0);
}

static int split_parent(const char *rel, char *dir, size_t dsz, const char **base)
{
    char path[PATH_MAX];
    static char store[PATH_MAX];
    if (normalize_rel(rel, path, sizeof(path)) < 0)
        return -1;
    char *slash = strrchr(path, '/');
    if (slash) {
        *slash = '\0';
        pathf(dir, dsz, "%s", path);
        pathf(store, sizeof(store), "%s", slash + 1);
    } else {
        dir[0] = '\0';
        pathf(store, sizeof(store), "%s", path);
    }
    *base = store;
    return store[0] ? 0 : -1;
}

static int rm_tree_at(int pfd, const char *name, int depth)
{
    if (depth > 512) {
        errno = ELOOP;
        return -1;
    }
    struct stat st;
    if (fstatat(pfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlinkat(pfd, name, 0) < 0 && errno != ENOENT ? -1 : 0;
    int fd = openat(pfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return -1;
    }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (rm_tree_at(dirfd(d), de->d_name, depth + 1) < 0)
            rc = -1;
    }
    closedir(d);
    if (unlinkat(pfd, name, AT_REMOVEDIR) < 0 && errno != ENOENT)
        rc = -1;
    return rc;
}

static int remove_at(int parent, const char *base)
{
    if (unlinkat(parent, base, 0) == 0 || errno == ENOENT)
        return 0;
    if (errno == EISDIR || errno == EPERM)
        return rm_tree_at(parent, base, 0);
    return -1;
}

static int clear_dir_at(int dirfd)
{
    int fd = dup(dirfd);
    if (fd < 0)
        return -1;
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return -1;
    }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (rm_tree_at(dirfd, de->d_name, 0) < 0)
            rc = -1;
    }
    closedir(d);
    return rc;
}

struct stream {
    int fd;
    size_t pos;
    size_t len;
    int eof;
    unsigned char buf[1 << 16];
};

static int s_fill(struct stream *s)
{
    for (;;) {
        ssize_t r = read(s->fd, s->buf, sizeof(s->buf));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0) {
            s->eof = 1;
            return 0;
        }
        s->pos = 0;
        s->len = (size_t)r;
        return 0;
    }
}

static ssize_t s_read(struct stream *s, void *dst, size_t n)
{
    unsigned char *d = dst;
    size_t got = 0;
    while (got < n) {
        if (s->pos == s->len) {
            if (s->eof)
                break;
            if (s_fill(s) < 0)
                return -1;
            if (s->eof)
                break;
        }
        size_t c = s->len - s->pos;
        if (c > n - got)
            c = n - got;
        memcpy(d + got, s->buf + s->pos, c);
        s->pos += c;
        got += c;
    }
    return (ssize_t)got;
}

static int s_skip(struct stream *s, uint64_t n)
{
    while (n) {
        if (s->pos == s->len) {
            if (s->eof)
                return -1;
            if (s_fill(s) < 0)
                return -1;
            if (s->eof)
                return -1;
        }
        size_t c = s->len - s->pos;
        if ((uint64_t)c > n)
            c = (size_t)n;
        s->pos += c;
        n -= c;
    }
    return 0;
}

static int s_drain(struct stream *s)
{
    for (;;) {
        s->pos = s->len = 0;
        if (s->eof)
            return 0;
        if (s_fill(s) < 0)
            return -1;
    }
}

static int tar_num(const unsigned char *f, size_t n, uint64_t *out)
{
    if (f[0] & 0x80) {
        if (f[0] == 0xff)
            return -1;
        uint64_t v = f[0] & 0x7f;
        for (size_t i = 1; i < n; i++) {
            if (v >> 56)
                return -1;
            v = (v << 8) | f[i];
        }
        *out = v;
        return 0;
    }
    size_t i = 0;
    while (i < n && f[i] == ' ')
        i++;
    uint64_t v = 0;
    for (; i < n && f[i] >= '0' && f[i] <= '7'; i++) {
        if (v >> 60)
            return -1;
        v = (v << 3) | (uint64_t)(f[i] - '0');
    }
    for (; i < n; i++)
        if (f[i] != 0 && f[i] != ' ')
            return -1;
    *out = v;
    return 0;
}

struct pax {
    char *path;
    char *linkpath;
    bool has_size, has_uid, has_gid, has_mtime;
    uint64_t size, uid, gid;
    int64_t mtime;
};

static void pax_clear(struct pax *px)
{
    free(px->path);
    free(px->linkpath);
    memset(px, 0, sizeof(*px));
}

static void pax_parse(struct pax *px, const char *d, size_t n)
{
    size_t i = 0;
    while (i < n) {
        size_t len = 0, j = i;
        while (j < n && d[j] >= '0' && d[j] <= '9' && len < (1u << 24))
            len = len * 10 + (size_t)(d[j++] - '0');
        if (j == i || j >= n || d[j] != ' ' || len < (j - i) + 2 || len > n - i)
            return;
        const char *rec = d + j + 1;
        size_t rl = len - (j - i) - 1;
        if (rl == 0 || rec[rl - 1] != '\n')
            return;
        rl--;
        const char *eq = memchr(rec, '=', rl);
        if (eq) {
            size_t kl = (size_t)(eq - rec);
            const char *val = eq + 1;
            size_t vl = rl - kl - 1;
            char *v = xstrndup(val, vl);
            if (kl == 4 && !memcmp(rec, "path", 4)) {
                free(px->path);
                px->path = v;
                v = NULL;
            } else if (kl == 8 && !memcmp(rec, "linkpath", 8)) {
                free(px->linkpath);
                px->linkpath = v;
                v = NULL;
            } else if (kl == 4 && !memcmp(rec, "size", 4)) {
                px->has_size = parse_u64(v, &px->size);
            } else if (kl == 3 && !memcmp(rec, "uid", 3)) {
                px->has_uid = parse_u64(v, &px->uid);
            } else if (kl == 3 && !memcmp(rec, "gid", 3)) {
                px->has_gid = parse_u64(v, &px->gid);
            } else if (kl == 5 && !memcmp(rec, "mtime", 5)) {
                char *dot = strchr(v, '.');
                if (dot)
                    *dot = '\0';
                uint64_t m;
                if (parse_u64(v, &m) && m < (uint64_t)INT64_MAX) {
                    px->has_mtime = true;
                    px->mtime = (int64_t)m;
                }
            }
            free(v);
        }
        i += len;
    }
}

static int read_blob(struct stream *s, uint64_t size, size_t max, char **out)
{
    if (size > max)
        return -1;
    char *p = xmalloc((size_t)size + 1);
    ssize_t r = s_read(s, p, (size_t)size);
    if (r < 0 || (uint64_t)r != size) {
        free(p);
        return -1;
    }
    p[size] = '\0';
    uint64_t pad = (512 - (size % 512)) % 512;
    if (s_skip(s, pad) < 0) {
        free(p);
        return -1;
    }
    *out = p;
    return 0;
}

struct tar_entry {
    char *path;
    char *link;
    char type;
    uint64_t size;
    uint32_t mode, uid, gid;
    int64_t mtime;
    bool has_mtime;
};

static int extract_file_data(struct stream *s, int fd, uint64_t size)
{
    unsigned char *tmp = xmalloc(1 << 16);
    uint64_t left = size;
    int rc = 0;
    while (left) {
        size_t want = left > (1 << 16) ? (1 << 16) : (size_t)left;
        ssize_t r = s_read(s, tmp, want);
        if (r < 0 || (size_t)r != want) {
            rc = -1;
            break;
        }
        if (write_all(fd, tmp, want) < 0) {
            rc = -1;
            break;
        }
        left -= want;
    }
    free(tmp);
    return rc;
}

static int apply_entry(struct stream *s, int rootfd, struct tar_entry *e, bool *skipped_dev)
{
    char rel[PATH_MAX], dir[PATH_MAX];
    const char *base;
    if (normalize_rel(e->path, rel, sizeof(rel)) < 0) {
        warnx_("rejecting unsafe path in archive: %s", e->path);
        return -1;
    }
    if (rel[0] == '\0')
        return 0;
    if (split_parent(rel, dir, sizeof(dir), &base) < 0)
        return -1;
    char name[NAME_MAX + 1];
    if (strlen(base) > NAME_MAX)
        return -1;
    memcpy(name, base, strlen(base) + 1);
    int parent = open_dir_p(rootfd, dir, true);
    if (parent < 0) {
        warnx_("cannot open parent of %s: %s", rel, strerror(errno));
        return -1;
    }
    int rc = -1;
    mode_t perm = e->mode & 07777;
    struct timespec ts[2] = { { 0, UTIME_OMIT }, { 0, UTIME_OMIT } };
    if (e->has_mtime) {
        ts[1].tv_sec = (time_t)e->mtime;
        ts[1].tv_nsec = 0;
    }
    switch (e->type) {
    case '5': {
        struct stat st;
        if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) < 0 || !S_ISDIR(st.st_mode)) {
            if (remove_at(parent, name) < 0 || mkdirat(parent, name, 0700) < 0)
                goto out;
        }
        int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            goto out;
        if (fchown(fd, e->uid, e->gid) < 0 || fchmod(fd, perm) < 0) {
            close(fd);
            goto out;
        }
        close(fd);
        rc = 0;
        break;
    }
    case '0': case '\0': case '7': {
        if (remove_at(parent, name) < 0)
            goto out;
        int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0)
            goto out;
        if (extract_file_data(s, fd, e->size) < 0 || fchown(fd, e->uid, e->gid) < 0 || fchmod(fd, perm) < 0 || futimens(fd, ts) < 0) {
            close(fd);
            goto out;
        }
        if (close(fd) < 0)
            goto out;
        rc = 0;
        break;
    }
    case '2': {
        if (!e->link || strlen(e->link) >= PATH_MAX || remove_at(parent, name) < 0)
            goto out;
        if (symlinkat(e->link, parent, name) < 0)
            goto out;
        if (fchownat(parent, name, e->uid, e->gid, AT_SYMLINK_NOFOLLOW) < 0)
            goto out;
        rc = 0;
        break;
    }
    case '1': {
        char trel[PATH_MAX], tdir[PATH_MAX];
        const char *tbase;
        if (!e->link || normalize_rel(e->link, trel, sizeof(trel)) < 0 || split_parent(trel, tdir, sizeof(tdir), &tbase) < 0)
            goto out;
        char tname[NAME_MAX + 1];
        if (strlen(tbase) > NAME_MAX)
            goto out;
        memcpy(tname, tbase, strlen(tbase) + 1);
        int tp = open_dir_p(rootfd, tdir, false);
        if (tp < 0)
            goto out;
        if (remove_at(parent, name) < 0 || linkat(tp, tname, parent, name, 0) < 0) {
            close(tp);
            goto out;
        }
        close(tp);
        rc = 0;
        break;
    }
    case '6': {
        if (remove_at(parent, name) < 0 || mknodat(parent, name, S_IFIFO | 0600, 0) < 0)
            goto out;
        if (fchownat(parent, name, e->uid, e->gid, AT_SYMLINK_NOFOLLOW) < 0)
            goto out;
        int fd = openat(parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            fchmod(fd, perm);
            close(fd);
        }
        rc = 0;
        break;
    }
    case '3': case '4':
        *skipped_dev = true;
        rc = 0;
        break;
    default:
        rc = 0;
        break;
    }
out:
    if (rc < 0)
        warnx_("failed to extract %s: %s", rel, strerror(errno));
    close(parent);
    return rc;
}

static int apply_whiteout(int rootfd, const char *path)
{
    char rel[PATH_MAX], dir[PATH_MAX];
    const char *base;
    if (normalize_rel(path, rel, sizeof(rel)) < 0)
        return -1;
    if (split_parent(rel, dir, sizeof(dir), &base) < 0)
        return -1;
    char name[NAME_MAX + 1];
    if (strlen(base) > NAME_MAX)
        return -1;
    memcpy(name, base, strlen(base) + 1);
    int parent = open_dir_p(rootfd, dir, false);
    if (parent < 0)
        return errno == ENOENT || errno == ENOTDIR ? 0 : -1;
    int rc = 0;
    if (!strcmp(name, ".wh..wh..opq")) {
        int fd = root_open(rootfd, dir, O_RDONLY | O_DIRECTORY, 0);
        if (fd >= 0) {
            rc = clear_dir_at(fd);
            close(fd);
        }
    } else {
        rc = remove_at(parent, name + 4);
    }
    close(parent);
    return rc;
}

static bool is_whiteout_path(const char *path)
{
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    return strncmp(b, ".wh.", 4) == 0;
}

static int tar_walk(struct stream *s, int rootfd, bool whiteout_pass)
{
    unsigned char h[512];
    int zeros = 0, rc = -1;
    char *lname = NULL, *llink = NULL;
    struct pax px;
    memset(&px, 0, sizeof(px));
    bool skipped_dev = false;
    for (;;) {
        ssize_t r = s_read(s, h, sizeof(h));
        if (r < 0) {
            warnx_("read error in archive: %s", strerror(errno));
            goto out;
        }
        if (r == 0) {
            rc = 0;
            break;
        }
        if (r != (ssize_t)sizeof(h)) {
            warnx_("truncated archive");
            goto out;
        }
        bool zero = true;
        for (size_t i = 0; i < sizeof(h); i++)
            if (h[i]) {
                zero = false;
                break;
            }
        if (zero) {
            if (++zeros >= 2) {
                rc = 0;
                break;
            }
            continue;
        }
        zeros = 0;
        uint64_t stored;
        if (tar_num(h + 148, 8, &stored) < 0) {
            warnx_("corrupt archive header");
            goto out;
        }
        uint64_t sum = 0;
        for (size_t i = 0; i < sizeof(h); i++)
            sum += (i >= 148 && i < 156) ? ' ' : h[i];
        if (sum != stored) {
            warnx_("archive header checksum mismatch");
            goto out;
        }
        uint64_t size, mode, uid, gid, mtime;
        if (tar_num(h + 124, 12, &size) < 0 || tar_num(h + 100, 8, &mode) < 0 || tar_num(h + 108, 8, &uid) < 0 ||
            tar_num(h + 116, 8, &gid) < 0 || tar_num(h + 136, 12, &mtime) < 0 || uid > UINT32_MAX || gid > UINT32_MAX) {
            warnx_("corrupt archive header fields");
            goto out;
        }
        char type = (char)h[156];
        if (type == 'x' || type == 'L' || type == 'K' || type == 'g') {
            char *data = NULL;
            if (read_blob(s, size, MAX_TEXT, &data) < 0) {
                warnx_("corrupt extended header");
                goto out;
            }
            if (type == 'x') {
                pax_parse(&px, data, (size_t)size);
                free(data);
            } else if (type == 'L') {
                free(lname);
                lname = data;
            } else if (type == 'K') {
                free(llink);
                llink = data;
            } else {
                free(data);
            }
            continue;
        }
        struct tar_entry e;
        memset(&e, 0, sizeof(e));
        e.type = type;
        e.mode = (uint32_t)mode;
        e.uid = (uint32_t)uid;
        e.gid = (uint32_t)gid;
        e.size = size;
        e.mtime = (int64_t)(mtime < (uint64_t)INT64_MAX ? mtime : 0);
        e.has_mtime = true;
        if (px.has_size)
            e.size = px.size;
        if (px.has_uid && px.uid <= UINT32_MAX)
            e.uid = (uint32_t)px.uid;
        if (px.has_gid && px.gid <= UINT32_MAX)
            e.gid = (uint32_t)px.gid;
        if (px.has_mtime)
            e.mtime = px.mtime;
        if (px.path) {
            e.path = px.path;
            px.path = NULL;
        } else if (lname) {
            e.path = lname;
            lname = NULL;
        } else {
            size_t nl = strnlen((char *)h, 100);
            if (!memcmp(h + 257, "ustar", 5) && h[345]) {
                size_t pl = strnlen((char *)h + 345, 155);
                e.path = xasprintf("%.*s/%.*s", (int)pl, (char *)h + 345, (int)nl, (char *)h);
            } else {
                e.path = xstrndup((char *)h, nl);
            }
        }
        if (px.linkpath) {
            e.link = px.linkpath;
            px.linkpath = NULL;
        } else if (llink) {
            e.link = llink;
            llink = NULL;
        } else {
            e.link = xstrndup((char *)h + 157, strnlen((char *)h + 157, 100));
        }
        pax_clear(&px);
        bool carries = !(type == '1' || type == '2' || type == '3' || type == '4' || type == '5' || type == '6');
        bool wh = is_whiteout_path(e.path);
        int er = 0;
        if (whiteout_pass) {
            if (wh)
                er = apply_whiteout(rootfd, e.path);
            if (carries && s_skip(s, (e.size + 511) / 512 * 512) < 0)
                er = -1;
        } else if (wh) {
            if (carries && s_skip(s, (e.size + 511) / 512 * 512) < 0)
                er = -1;
        } else {
            bool regular = type == '0' || type == '\0' || type == '7';
            er = apply_entry(s, rootfd, &e, &skipped_dev);
            if (er == 0 && carries) {
                uint64_t pad = (512 - (e.size % 512)) % 512;
                if (!regular) {
                    if (s_skip(s, e.size) < 0)
                        er = -1;
                }
                if (er == 0 && s_skip(s, pad) < 0)
                    er = -1;
            }
        }
        free(e.path);
        free(e.link);
        if (er < 0)
            goto out;
    }
out:
    free(lname);
    free(llink);
    pax_clear(&px);
    return rc;
}

static int open_layer(const char *path, pid_t *pid)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    unsigned char m[6] = { 0 };
    ssize_t r = pread(fd, m, sizeof(m), 0);
    if (r < 0) {
        close(fd);
        return -1;
    }
    char *argv[3] = { NULL, "-dc", NULL };
    if (r >= 2 && m[0] == 0x1f && m[1] == 0x8b)
        argv[0] = "gzip";
    else if (r >= 4 && m[0] == 0x28 && m[1] == 0xb5 && m[2] == 0x2f && m[3] == 0xfd)
        argv[0] = "zstd";
    else if (r >= 6 && m[0] == 0xfd && !memcmp(m + 1, "7zXZ", 4))
        argv[0] = "xz";
    else if (r >= 3 && m[0] == 'B' && m[1] == 'Z' && m[2] == 'h')
        argv[0] = "bzip2";
    if (!argv[0]) {
        *pid = -1;
        return fd;
    }
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) < 0) {
        close(fd);
        return -1;
    }
    pid_t p = spawn(argv, fd, pfd[1]);
    close(fd);
    close(pfd[1]);
    if (p < 0) {
        close(pfd[0]);
        return -1;
    }
    *pid = p;
    return pfd[0];
}

static int extract_layer(const char *blob, const char *dest)
{
    int rootfd = open(dest, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0)
        return -1;
    int rc = 0;
    for (int pass = 0; pass < 2 && rc == 0; pass++) {
        pid_t pid;
        int fd = open_layer(blob, &pid);
        if (fd < 0) {
            rc = -1;
            break;
        }
        struct stream *s = xcalloc(1, sizeof(*s));
        s->fd = fd;
        if (tar_walk(s, rootfd, pass == 0) < 0)
            rc = -1;
        if (s_drain(s) < 0 && rc == 0)
            rc = -1;
        free(s);
        close(fd);
        if (pid > 0) {
            int w = wait_pid(pid);
            if (w != 0 && rc == 0) {
                warnx_("decompressor failed");
                rc = -1;
            }
        }
    }
    close(rootfd);
    return rc;
}

static const char *host_arch(void)
{
    struct utsname u;
    if (uname(&u) < 0)
        die_errno("uname");
    const char *m = u.machine;
    if (!strcmp(m, "x86_64") || !strcmp(m, "amd64"))
        return "amd64";
    if (!strcmp(m, "aarch64") || !strcmp(m, "arm64"))
        return "arm64";
    if (!strcmp(m, "riscv64"))
        return "riscv64";
    if (!strcmp(m, "ppc64le"))
        return "ppc64le";
    if (!strcmp(m, "s390x"))
        return "s390x";
    if (!strncmp(m, "armv7", 5))
        return "arm";
    if (m[0] == 'i' && m[2] == '8' && m[3] == '6')
        return "386";
    die("unsupported architecture: %s", m);
}

static int http_get(const char *url, const char *token, const char *accept, const char *outfile, struct buf *out, size_t max)
{
    char *argv[24];
    int n = 0;
    char *auth = NULL, *acc = NULL;
    argv[n++] = "curl";
    argv[n++] = "-fsSL";
    argv[n++] = "--proto";
    argv[n++] = "=https";
    argv[n++] = "--proto-redir";
    argv[n++] = "=https";
    argv[n++] = "--tlsv1.2";
    argv[n++] = "--connect-timeout";
    argv[n++] = "20";
    argv[n++] = "--retry";
    argv[n++] = "3";
    argv[n++] = "--retry-delay";
    argv[n++] = "2";
    if (token) {
        auth = xasprintf("Authorization: Bearer %s", token);
        argv[n++] = "-H";
        argv[n++] = auth;
    }
    if (accept) {
        acc = xasprintf("Accept: %s", accept);
        argv[n++] = "-H";
        argv[n++] = acc;
    }
    if (outfile) {
        argv[n++] = "-o";
        argv[n++] = (char *)outfile;
    }
    argv[n++] = "--url";
    argv[n++] = (char *)url;
    argv[n] = NULL;
    int rc;
    if (outfile)
        rc = run_argv(argv);
    else
        rc = run_capture(argv, out, max);
    free(auth);
    free(acc);
    return rc;
}

static bool valid_digest(const char *d)
{
    if (strncmp(d, "sha256:", 7) != 0 || strlen(d) != 71)
        return false;
    for (size_t i = 7; i < 71; i++)
        if (!((d[i] >= '0' && d[i] <= '9') || (d[i] >= 'a' && d[i] <= 'f')))
            return false;
    return true;
}

static char *registry_token(const char *repo)
{
    char *url = xasprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repo);
    struct buf b = { 0 };
    if (http_get(url, NULL, NULL, NULL, &b, MAX_TEXT) != 0)
        die("failed to obtain registry token for %s", repo);
    free(url);
    struct json *j = json_parse(b.d, b.len);
    buf_free(&b);
    const char *t = jstr(jget(j, "token"));
    if (!t)
        t = jstr(jget(j, "access_token"));
    if (!t || !*t || strpbrk(t, "\r\n"))
        die("registry returned an invalid token");
    char *tok = xstrdup(t);
    json_free(j);
    return tok;
}

static struct json *fetch_manifest(const char *repo, const char *ref, const char *token, bool verify)
{
    static const char *accept =
        "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
        "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
    char *url = xasprintf("https://registry-1.docker.io/v2/%s/manifests/%s", repo, ref);
    struct buf b = { 0 };
    if (http_get(url, token, accept, NULL, &b, 8 * MAX_TEXT) != 0)
        die("failed to fetch manifest %s:%s (image not found?)", repo, ref);
    free(url);
    if (verify) {
        struct sha256 s;
        char hex[65];
        sha256_init(&s);
        sha256_update(&s, b.d, b.len);
        sha256_final(&s, hex);
        if (strcmp(hex, ref + 7) != 0)
            die("manifest digest mismatch for %s", ref);
    }
    struct json *j = json_parse(b.d, b.len);
    buf_free(&b);
    if (!j || j->type != J_OBJ)
        die("registry returned an invalid manifest");
    return j;
}

static bool uses_zstd_or_unknown_media(const char *mt)
{
    return mt && strstr(mt, "foreign") != NULL;
}

static void pull_image(const char *distro, const char *version, const char *dest, const char *tmpdir)
{
    char *repo = strchr(distro, '/') ? xstrdup(distro) : xasprintf("library/%s", distro);
    const char *arch = host_arch();
    char *token = registry_token(repo);
    struct json *m = fetch_manifest(repo, version, token, false);
    for (int hop = 0; hop < 2 && jget(m, "manifests"); hop++) {
        struct json *list = jget(m, "manifests");
        const char *pick = NULL;
        if (list->type != J_ARR)
            die("invalid manifest list");
        for (size_t i = 0; i < list->n; i++) {
            struct json *pl = jget(list->vals[i], "platform");
            const char *os = jstr(jget(pl, "os"));
            const char *ar = jstr(jget(pl, "architecture"));
            const char *dg = jstr(jget(list->vals[i], "digest"));
            if (!os || !ar || !dg || strcmp(os, "linux") || strcmp(ar, arch))
                continue;
            if (!valid_digest(dg))
                continue;
            pick = dg;
            break;
        }
        if (!pick)
            die("image %s:%s has no linux/%s variant", distro, version, arch);
        char *dg = xstrdup(pick);
        json_free(m);
        m = fetch_manifest(repo, dg, token, true);
        free(dg);
    }
    struct json *layers = jget(m, "layers");
    if (!layers || layers->type != J_ARR || layers->n == 0 || layers->n > 256)
        die("manifest has no usable layers");
    if (mkdir(tmpdir, 0700) < 0 && errno != EEXIST)
        die_errno("mkdir %s", tmpdir);
    struct progress progress;
    progress_begin(&progress, layers->n * 3, "Preparing %s:%s (%s)", distro, version, arch);
    for (size_t i = 0; i < layers->n; i++) {
        struct json *l = layers->vals[i];
        const char *dg = jstr(jget(l, "digest"));
        const char *mt = jstr(jget(l, "mediaType"));
        struct json *sz = jget(l, "size");
        uint64_t want = 0;
        if (!dg || !valid_digest(dg) || !sz || sz->type != J_NUM || !parse_u64(sz->str, &want))
            die("layer %zu has an invalid descriptor", i);
        if (want > ((uint64_t)64 << 30))
            die("layer %zu is too large", i);
        if (uses_zstd_or_unknown_media(mt))
            die("layer %zu uses an unsupported media type: %s", i, mt);
        char blob[PATH_MAX];
        pathf(blob, sizeof(blob), "%s/layer-%zu", tmpdir, i);
        char *url = xasprintf("https://registry-1.docker.io/v2/%s/blobs/%s", repo, dg);
        progress_set_label(&progress, "Downloading layer %zu/%zu", i + 1, layers->n);
        if (http_get(url, token, NULL, blob, NULL, 0) != 0)
            die("failed to download layer %s", dg);
        free(url);
        progress_advance(&progress);
        char hex[65];
        uint64_t got;
        progress_set_label(&progress, "Verifying layer %zu/%zu", i + 1, layers->n);
        if (sha256_file(blob, hex, &got) < 0)
            die_errno("hash %s", blob);
        if (got != want || strcmp(hex, dg + 7) != 0)
            die("layer %s failed integrity verification", dg);
        progress_advance(&progress);
        progress_set_label(&progress, "Extracting layer %zu/%zu", i + 1, layers->n);
        if (extract_layer(blob, dest) < 0)
            die("failed to extract layer %s", dg);
        progress_advance(&progress);
        unlink(blob);
    }
    json_free(m);
    free(token);
    free(repo);
    if (chmod(dest, 0755) < 0)
        die_errno("chmod %s", dest);
}

static void image_cache_path(char *out, size_t n, const char *distro, const char *version)
{
    char d[160];
    size_t j = 0;
    for (size_t i = 0; distro[i] && j + 1 < sizeof(d); i++)
        d[j++] = distro[i] == '/' ? '_' : distro[i];
    d[j] = '\0';
    pathf(out, n, "%s/rootfs-%s%s", NFLXS_IMAGES, d, version);
}

static void ensure_image(const char *distro, const char *version, char *cache, size_t csz)
{
    image_cache_path(cache, csz, distro, version);
    if (mkdir_p(NFLXS_IMAGES, 0755) < 0)
        die_errno("mkdir %s", NFLXS_IMAGES);
    if (path_exists(cache)) {
        printf("Using cached image %s\n", cache);
        return;
    }
    char lockp[PATH_MAX];
    pathf(lockp, sizeof(lockp), "%s/.lock", NFLXS_IMAGES);
    int lfd = open(lockp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd < 0)
        die_errno("open %s", lockp);
    if (flock(lfd, LOCK_EX) < 0)
        die_errno("flock %s", lockp);
    if (path_exists(cache)) {
        close(lfd);
        return;
    }
    char tmp[PATH_MAX], stage[PATH_MAX], blobs[PATH_MAX];
    pathf(tmp, sizeof(tmp), "%s/.pull-%ld", NFLXS_IMAGES, (long)getpid());
    pathf(stage, sizeof(stage), "%s/rootfs", tmp);
    pathf(blobs, sizeof(blobs), "%s/blobs", tmp);
    char *rm0[] = { "rm", "-rf", "--one-file-system", "--", tmp, NULL };
    run_argv(rm0);
    if (mkdir(tmp, 0700) < 0 || mkdir(stage, 0755) < 0)
        die_errno("mkdir %s", tmp);
    cleanup_set(tmp);
    pull_image(distro, version, stage, blobs);
    if (rename(stage, cache) < 0)
        die_errno("rename %s", cache);
    run_argv(rm0);
    cleanup_clear();
    close(lfd);
    printf("Image cached at %s\n", cache);
}

struct sandbox {
    char name[MAX_NAME + 1];
    char dir[PATH_MAX];
    char rootfs[PATH_MAX];
    char img[PATH_MAX];
    char meta[PATH_MAX];
    char distro[160];
    char version[160];
    char fs[16];
    char user[40];
    uint64_t size;
    bool lvm;          /* true when an LVM PV/VG/LV sits underneath sb->fs */
    int lockfd;
};

static void sandbox_paths(struct sandbox *sb, const char *name)
{
    if (!valid_name(name))
        die("invalid sandbox name '%s' (use letters, digits, '.', '_' and '-', max %d chars)", name, MAX_NAME);
    memset(sb, 0, sizeof(*sb));
    sb->lockfd = -1;
    pathf(sb->name, sizeof(sb->name), "%s", name);
    pathf(sb->dir, sizeof(sb->dir), "%s/%s", NFLXS_SANDBOXES, name);
    pathf(sb->rootfs, sizeof(sb->rootfs), "%s/rootfs", sb->dir);
    pathf(sb->img, sizeof(sb->img), "%s/disk.img", sb->dir);
    pathf(sb->meta, sizeof(sb->meta), "%s/meta", sb->dir);
}

static bool valid_fs(const char *fs)
{
    return !strcmp(fs, "ext4") || !strcmp(fs, "xfs") || !strcmp(fs, "btrfs");
}

/* Backward-compat helper: meta files written by older nflxs builds stored
 * fs=lvm when the sandbox was built on top of an LVM volume.  The current
 * build never writes "lvm" as the fs; instead it stores the real fs (ext4,
 * xfs or btrfs) plus an `lvm=1` flag.  We still accept "lvm" on load so that
 * pre-existing sandboxes keep working; the loader converts them to the new
 * representation (fs=xfs, lvm=1) because the old LVM branch always formatted
 * the LV with XFS. */
static bool valid_fs_compat(const char *fs)
{
    return valid_fs(fs) || !strcmp(fs, "lvm");
}

static bool env_lvm_enabled(void)
{
    const char *v = getenv("NFLXS_DM_USE_LVM");
    return v && strcmp(v, "1") == 0;
}

static bool env_lvm_thin(void)
{
    const char *v = getenv("NFLXS_DM_USE_LVM_THIN");
    return v && strcmp(v, "1") == 0;
}

static void sandbox_save(const struct sandbox *sb)
{
    char *text = xasprintf("distro=%s\nversion=%s\nfs=%s\nsize=%llu\nuser=%s\nlvm=%s\n",
                           sb->distro, sb->version, sb->fs,
                           (unsigned long long)sb->size, sb->user,
                           sb->lvm ? "1" : "0");
    if (write_file(sb->meta, text, strlen(text), 0600) < 0)
        die_errno("write %s", sb->meta);
    free(text);
}

static int sandbox_try_load(struct sandbox *sb, const char *name)
{
    sandbox_paths(sb, name);
    struct buf b = { 0 };
    if (read_file(sb->meta, &b, 4096) < 0) {
        buf_free(&b);
        return errno == ENOENT ? -2 : -1;
    }
    char *save = NULL;
    for (char *line = strtok_r(b.d, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        const char *k = line, *v = eq + 1;
        if (!strcmp(k, "distro") && valid_distro(v))
            pathf(sb->distro, sizeof(sb->distro), "%s", v);
        else if (!strcmp(k, "version") && valid_version(v))
            pathf(sb->version, sizeof(sb->version), "%s", v);
        else if (!strcmp(k, "fs") && (v[0] == '\0' || valid_fs_compat(v))) {
            /* Migrate legacy "fs=lvm" to the new representation: the old
             * LVM branch always formatted the LV with XFS, so we restore
             * fs=xfs and turn the lvm flag on. */
            if (!strcmp(v, "lvm")) {
                pathf(sb->fs, sizeof(sb->fs), "%s", "xfs");
                sb->lvm = true;
            } else {
                pathf(sb->fs, sizeof(sb->fs), "%s", v);
            }
        } else if (!strcmp(k, "size")) {
            parse_u64(v, &sb->size);
        } else if (!strcmp(k, "user") && valid_user(v))
            pathf(sb->user, sizeof(sb->user), "%s", v);
        else if (!strcmp(k, "lvm"))
            sb->lvm = !strcmp(v, "1");
    }
    buf_free(&b);
    if (!sb->distro[0] || !sb->version[0] || !sb->user[0])
        return -3;
    if (sb->fs[0] && !path_exists(sb->img))
        return -4;
    return 0;
}

static void sandbox_load(struct sandbox *sb, const char *name)
{
    int r = sandbox_try_load(sb, name);
    if (r == -2)
        die("sandbox '%s' does not exist", name);
    if (r == -3)
        die("metadata of sandbox '%s' is corrupt", name);
    if (r == -4)
        die("disk image of sandbox '%s' is missing", name);
    if (r < 0)
        die_errno("read %s", sb->meta);
}

static void sandbox_lock(struct sandbox *sb)
{
    char p[PATH_MAX];
    pathf(p, sizeof(p), "%s/lock", sb->dir);
    sb->lockfd = open(p, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (sb->lockfd < 0)
        die_errno("open %s", p);
    if (flock(sb->lockfd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK)
            die("sandbox '%s' is in use", sb->name);
        die_errno("flock %s", p);
    }
}

static int loop_attach(const char *img, char *dev, size_t dsz)
{
    int ffd = open(img, O_RDWR | O_CLOEXEC);
    if (ffd < 0)
        return -1;
    int ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
    if (ctl < 0) {
        int e = errno;
        close(ffd);
        errno = e;
        return -1;
    }
    int rc = -1;
    int result_fd = -1;
    for (int attempt = 0; attempt < 16; attempt++) {
        int idx = ioctl(ctl, LOOP_CTL_GET_FREE);
        if (idx < 0)
            break;
        pathf(dev, dsz, "/dev/loop%d", idx);
        int lfd = open(dev, O_RDWR | O_CLOEXEC);
        if (lfd < 0)
            break;
        struct loop_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.fd = (uint32_t)ffd;
        cfg.info.lo_flags = LO_FLAGS_AUTOCLEAR;
        memcpy(cfg.info.lo_file_name, img, strnlen(img, LO_NAME_SIZE - 1));
        if (ioctl(lfd, LOOP_CONFIGURE, &cfg) == 0) {
            rc = 0;
            result_fd = lfd;
            break;
        }
        if (errno == EBUSY) {
            close(lfd);
            continue;
        }
        if (errno == EINVAL || errno == ENOTTY) {
            if (ioctl(lfd, LOOP_SET_FD, ffd) == 0) {
                struct loop_info64 li;
                memset(&li, 0, sizeof(li));
                li.lo_flags = LO_FLAGS_AUTOCLEAR;
                memcpy(li.lo_file_name, img, strnlen(img, LO_NAME_SIZE - 1));
                if (ioctl(lfd, LOOP_SET_STATUS64, &li) == 0) {
                    rc = 0;
                    result_fd = lfd;
                    break;
                }
                int e = errno;
                ioctl(lfd, LOOP_CLR_FD, 0);
                errno = e;
            } else if (errno == EBUSY) {
                close(lfd);
                continue;
            }
        }
        int e = errno;
        close(lfd);
        errno = e;
        break;
    }
    int e = errno;
    close(ctl);
    close(ffd);
    errno = e;
    return rc == 0 ? result_fd : -1;
}

static void make_mounts_private(void)
{
    if (unshare(CLONE_NEWNS) < 0)
        die_errno("unshare(CLONE_NEWNS)");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        die_errno("make mounts private");
}

static void lvm_vg_name(char *out, size_t n, const char *sandbox_name)
{
    /* VG names mirror the sandbox name, which is already restricted to
     * [A-Za-z0-9._-] by valid_name().  LVM also allows those characters,
     * but rejects names that start with '-'; valid_name() already
     * requires the first character to be alnum, so we are safe. */
    pathf(out, n, "nflxs_%s", sandbox_name);
}

static void sandbox_mount_image(const struct sandbox *sb)
{
    if (sb->lvm) {
        char dev[64];
        int lfd = loop_attach(sb->img, dev, sizeof(dev));
        if (lfd < 0)
            die_errno("attach loop device for %s", sb->img);

        char vg_name[80];
        lvm_vg_name(vg_name, sizeof(vg_name), sb->name);

        /* LVM keeps the loop device alive via its own PV reference, but the
         * kernel still drops the loop binding as soon as the last open fd
         * on /dev/loopN is closed *and* there is no consumer holding it.
         * pvscan/vgchange below reopen the block device, so in theory the
         * binding survives, but to remove the race window we keep lfd
         * open until the LV is mounted. */
        char *pvscan[] = { "pvscan", "--cache", dev, NULL };
        run_argv(pvscan);

        char *vgchange[] = { "vgchange", "-a", "y", vg_name, NULL };
        if (run_argv(vgchange) != 0) {
            int e = errno;
            close(lfd);
            errno = e;
            die("vgchange -a y failed for %s", vg_name);
        }

        char lv_dev[96];
        snprintf(lv_dev, sizeof(lv_dev), "/dev/%s/root", vg_name);
        if (mount(lv_dev, sb->rootfs, sb->fs, MS_NODEV, NULL) < 0) {
            int e = errno;
            close(lfd);
            errno = e;
            die_errno("mount %s (%s) on %s", lv_dev, sb->fs, sb->rootfs);
        }
        /* mount() took a reference to the LV; the underlying loop device
         * stays bound for the lifetime of the mount, so we can finally
         * release our fd.  LO_FLAGS_AUTOCLEAR will only fire when the
         * mount is torn down. */
        close(lfd);
    } else {
        char dev[64];
        int lfd = loop_attach(sb->img, dev, sizeof(dev));
        if (lfd < 0)
            die_errno("attach loop device for %s", sb->img);
        if (mount(dev, sb->rootfs, sb->fs, MS_NODEV, NULL) < 0) {
            int e = errno;
            close(lfd);
            errno = e;
            die_errno("mount %s (%s) on %s", dev, sb->fs, sb->rootfs);
        }
        close(lfd);
    }
}

static bool path_has_mounts(const char *dir)
{
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f)
        return false;
    char *line = NULL;
    size_t cap = 0;
    size_t dl = strlen(dir);
    bool found = false;
    while (getline(&line, &cap, f) > 0) {
        char *save = NULL;
        char *tok = strtok_r(line, " ", &save);
        for (int i = 1; tok && i < 5; i++)
            tok = strtok_r(NULL, " ", &save);
        if (tok && !strncmp(tok, dir, dl) && (tok[dl] == '\0' || tok[dl] == '/')) {
            found = true;
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

static int edit_db(int rootfd, const char *rel, const char *key, const char *newline, mode_t defmode, bool replace_only_existing)
{
    char dir[PATH_MAX], tmpname[NAME_MAX + 8];
    const char *base;
    if (split_parent(rel, dir, sizeof(dir), &base) < 0)
        return -1;
    char name[NAME_MAX + 1];
    if (strlen(base) + 8 > NAME_MAX)
        return -1;
    memcpy(name, base, strlen(base) + 1);
    snprintf(tmpname, sizeof(tmpname), "%s.nflxs", name);
    int parent = open_dir_p(rootfd, dir, true);
    if (parent < 0)
        return -1;
    struct buf in = { 0 };
    buf_reserve(&in, 0);
    mode_t mode = defmode;
    uid_t uid = 0;
    gid_t gid = 0;
    int ofd = root_open(rootfd, rel, O_RDONLY, 0);
    if (ofd >= 0) {
        struct stat st;
        if (fstat(ofd, &st) == 0) {
            mode = st.st_mode & 07777;
            uid = st.st_uid;
            gid = st.st_gid;
        }
        char tmp[4096];
        for (;;) {
            ssize_t r = read(ofd, tmp, sizeof(tmp));
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                break;
            if (in.len + (size_t)r > MAX_TEXT) {
                close(ofd);
                close(parent);
                buf_free(&in);
                errno = EFBIG;
                return -1;
            }
            buf_add(&in, tmp, (size_t)r);
        }
        close(ofd);
    } else if (errno != ENOENT) {
        close(parent);
        buf_free(&in);
        return -1;
    }
    struct buf out = { 0 };
    buf_reserve(&out, 0);
    size_t klen = strlen(key);
    bool done = false;
    char *p = in.d;
    while (p && *p) {
        char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        if (ll > klen && !strncmp(p, key, klen) && p[klen] == ':') {
            if (!done) {
                buf_add(&out, newline, strlen(newline));
                buf_add(&out, "\n", 1);
                done = true;
            }
        } else {
            buf_add(&out, p, ll);
            buf_add(&out, "\n", 1);
        }
        p += ll + (nl ? 1 : 0);
    }
    if (!done) {
        if (replace_only_existing) {
            buf_free(&in);
            buf_free(&out);
            close(parent);
            return 0;
        }
        buf_add(&out, newline, strlen(newline));
        buf_add(&out, "\n", 1);
    }
    unlinkat(parent, tmpname, 0);
    int nfd = openat(parent, tmpname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int rc = -1;
    if (nfd >= 0) {
        if (write_all(nfd, out.d, out.len) == 0 && fchown(nfd, uid, gid) == 0 && fchmod(nfd, mode) == 0 && fsync(nfd) == 0) {
            if (renameat(parent, tmpname, parent, name) == 0)
                rc = 0;
        }
        close(nfd);
        if (rc < 0) {
            int e = errno;
            unlinkat(parent, tmpname, 0);
            errno = e;
        }
    }
    close(parent);
    buf_free(&in);
    buf_free(&out);
    return rc;
}

static bool db_has_key(int rootfd, const char *rel, const char *key, char **line_out)
{
    int fd = root_open(rootfd, rel, O_RDONLY, 0);
    if (fd < 0)
        return false;
    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return false;
    }
    char *line = NULL;
    size_t cap = 0, klen = strlen(key);
    bool found = false;
    ssize_t r;
    while ((r = getline(&line, &cap, f)) > 0) {
        if ((size_t)r > klen && !strncmp(line, key, klen) && line[klen] == ':') {
            found = true;
            if (line_out) {
                if (line[r - 1] == '\n')
                    line[r - 1] = '\0';
                *line_out = xstrdup(line);
            }
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

static bool db_id_used(int rootfd, const char *rel, uint64_t id)
{
    int fd = root_open(rootfd, rel, O_RDONLY, 0);
    if (fd < 0)
        return false;
    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return false;
    }
    char *line = NULL;
    size_t cap = 0;
    bool used = false;
    while (getline(&line, &cap, f) > 0) {
        char *c1 = strchr(line, ':');
        if (!c1)
            continue;
        char *c2 = strchr(c1 + 1, ':');
        if (!c2)
            continue;
        char *c3 = strchr(c2 + 1, ':');
        if (!c3)
            continue;
        *c3 = '\0';
        uint64_t v;
        if (parse_u64(c2 + 1, &v) && v == id) {
            used = true;
            break;
        }
    }
    free(line);
    fclose(f);
    return used;
}

static void random_salt(char *out, size_t n)
{
    static const char al[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    unsigned char r[32];
    if (n > sizeof(r) || getrandom(r, n, 0) != (ssize_t)n)
        die_errno("getrandom");
    for (size_t i = 0; i < n; i++)
        out[i] = al[r[i] % 64];
    out[n] = '\0';
}

static void provision_user(const char *rootfs, const char *user)
{
    int rootfd = open(rootfs, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0)
        die_errno("open %s", rootfs);
    char *existing = NULL;
    uint64_t uid = 1000, gid = 1000;
    char home[PATH_MAX];
    pathf(home, sizeof(home), "/home/%s", user);
    char shell[64] = "/bin/sh";
    int sfd = root_open(rootfd, "bin/bash", O_PATH, 0);
    if (sfd >= 0) {
        pathf(shell, sizeof(shell), "/bin/bash");
        close(sfd);
    }
    if (db_has_key(rootfd, "etc/passwd", user, &existing)) {
        char *f[7] = { 0 };
        char *save = existing;
        for (int i = 0; i < 7; i++) {
            f[i] = save;
            char *c = save ? strchr(save, ':') : NULL;
            if (c) {
                *c = '\0';
                save = c + 1;
            } else {
                save = NULL;
            }
        }
        if (!f[2] || !f[3] || !f[5] || !parse_u64(f[2], &uid) || !parse_u64(f[3], &gid))
            die("existing user '%s' has a malformed passwd entry", user);
        pathf(home, sizeof(home), "%s", f[5]);
        free(existing);
    } else {
        while (db_id_used(rootfd, "etc/passwd", uid))
            uid++;
        char *gl = NULL;
        if (db_has_key(rootfd, "etc/group", user, &gl)) {
            char *c = strchr(gl, ':');
            c = c ? strchr(c + 1, ':') : NULL;
            char *e = c ? strchr(c + 1, ':') : NULL;
            uint64_t g;
            if (e) {
                *e = '\0';
                if (parse_u64(c + 1, &g))
                    gid = g;
            }
            free(gl);
        } else {
            gid = uid;
            while (db_id_used(rootfd, "etc/group", gid))
                gid++;
            char *gline = xasprintf("%s:x:%llu:", user, (unsigned long long)gid);
            if (edit_db(rootfd, "etc/group", user, gline, 0644, false) < 0)
                die_errno("update /etc/group");
            free(gline);
        }
        char *pline = xasprintf("%s:x:%llu:%llu:%s:%s:%s", user, (unsigned long long)uid, (unsigned long long)gid, user, home, shell);
        if (edit_db(rootfd, "etc/passwd", user, pline, 0644, false) < 0)
            die_errno("update /etc/passwd");
        free(pline);
    }
    char salt[17], setting[32];
    random_salt(salt, 16);
    pathf(setting, sizeof(setting), "$6$%s$", salt);
    struct crypt_data *cd = xcalloc(1, sizeof(*cd));
    char *hash = crypt_r(user, setting, cd);
    if (!hash || hash[0] == '*')
        die("password hashing failed");
    char *sline = xasprintf("%s:%s:%ld:0:99999:7:::", user, hash, (long)(time(NULL) / 86400));
    free(cd);
    if (edit_db(rootfd, "etc/shadow", user, sline, 0640, false) < 0)
        die_errno("update /etc/shadow");
    free(sline);
    char hdir[PATH_MAX];
    pathf(hdir, sizeof(hdir), "%s", home);
    int hfd = open_dir_p(rootfd, hdir, true);
    if (hfd < 0)
        die_errno("create home %s", home);
    char dir[PATH_MAX];
    const char *base;
    if (split_parent(hdir, dir, sizeof(dir), &base) == 0) {
        char name[NAME_MAX + 1];
        pathf(name, sizeof(name), "%s", base);
        int pfd = open_dir_p(rootfd, dir, false);
        if (pfd >= 0) {
            if (fchownat(pfd, name, (uid_t)uid, (gid_t)gid, AT_SYMLINK_NOFOLLOW) < 0)
                die_errno("chown home");
            close(pfd);
        }
    }
    close(hfd);
    close(rootfd);
}

static bool cgroup2_available(void)
{
    struct statfs sf;
    return statfs(CGROUP_ROOT, &sf) == 0 && (unsigned long)sf.f_type == (unsigned long)CGROUP2_SUPER_MAGIC;
}

static int cg_write(const char *dir, const char *file, const char *val)
{
    char p[PATH_MAX];
    pathf(p, sizeof(p), "%s/%s", dir, file);
    return write_str_file(p, val);
}

static bool cg_has_controller(const char *dir, const char *c)
{
    char p[PATH_MAX];
    pathf(p, sizeof(p), "%s/cgroup.controllers", dir);
    struct buf b = { 0 };
    if (read_file(p, &b, 4096) < 0)
        return false;
    bool found = false;
    char *save = NULL;
    for (char *t = strtok_r(b.d, " \n", &save); t; t = strtok_r(NULL, " \n", &save))
        if (!strcmp(t, c))
            found = true;
    buf_free(&b);
    return found;
}

static char *cg_setup(const char *name, uint32_t cpu_milli, uint64_t mem, bool required)
{
    if (!cgroup2_available()) {
        if (required)
            die("cgroup v2 is not mounted on %s; resource limits are unavailable", CGROUP_ROOT);
        return NULL;
    }
    if (mkdir(CGROUP_BASE, 0755) < 0 && errno != EEXIST) {
        if (required)
            die_errno("mkdir %s", CGROUP_BASE);
        return NULL;
    }
    char wanted[32] = "";
    if (cpu_milli)
        strcat(wanted, "+cpu ");
    if (mem)
        strcat(wanted, "+memory");
    if (wanted[0]) {
        if (cpu_milli && !cg_has_controller(CGROUP_ROOT, "cpu"))
            die("the cgroup 'cpu' controller is not available");
        if (mem && !cg_has_controller(CGROUP_ROOT, "memory"))
            die("the cgroup 'memory' controller is not available");
        cg_write(CGROUP_ROOT, "cgroup.subtree_control", wanted);
        if (cg_write(CGROUP_BASE, "cgroup.subtree_control", wanted) < 0)
            die_errno("enable cgroup controllers");
    }
    char *path = xasprintf("%s/%s", CGROUP_BASE, name);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        if (required)
            die_errno("mkdir %s", path);
        free(path);
        return NULL;
    }
    if (cpu_milli) {
        uint64_t quota = (uint64_t)cpu_milli * 100;
        if (quota < 1000)
            quota = 1000;
        char v[64];
        snprintf(v, sizeof(v), "%llu 100000", (unsigned long long)quota);
        if (cg_write(path, "cpu.max", v) < 0)
            die_errno("set cpu.max");
    }
    if (mem) {
        char v[32];
        snprintf(v, sizeof(v), "%llu", (unsigned long long)mem);
        if (cg_write(path, "memory.max", v) < 0)
            die_errno("set memory.max");
        cg_write(path, "memory.swap.max", "0");
        cg_write(path, "memory.oom.group", "1");
    }
    return path;
}

static void cg_cleanup(char *path)
{
    if (!path)
        return;
    for (int i = 0; i < 50; i++) {
        if (rmdir(path) == 0 || errno == ENOENT)
            break;
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    free(path);
}

#ifndef __NR_open
#define __NR_open (-1)
#endif
#ifndef __NR_stat
#define __NR_stat (-1)
#endif
#ifndef __NR_fstat
#define __NR_fstat (-1)
#endif
#ifndef __NR_lstat
#define __NR_lstat (-1)
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat (-1)
#endif
#ifndef __NR_poll
#define __NR_poll (-1)
#endif
#ifndef __NR_select
#define __NR_select (-1)
#endif
#ifndef __NR_access
#define __NR_access (-1)
#endif
#ifndef __NR_pipe
#define __NR_pipe (-1)
#endif
#ifndef __NR_dup2
#define __NR_dup2 (-1)
#endif
#ifndef __NR_pause
#define __NR_pause (-1)
#endif
#ifndef __NR_alarm
#define __NR_alarm (-1)
#endif
#ifndef __NR_fork
#define __NR_fork (-1)
#endif
#ifndef __NR_vfork
#define __NR_vfork (-1)
#endif
#ifndef __NR_getdents
#define __NR_getdents (-1)
#endif
#ifndef __NR_rename
#define __NR_rename (-1)
#endif
#ifndef __NR_renameat
#define __NR_renameat (-1)
#endif
#ifndef __NR_mkdir
#define __NR_mkdir (-1)
#endif
#ifndef __NR_rmdir
#define __NR_rmdir (-1)
#endif
#ifndef __NR_creat
#define __NR_creat (-1)
#endif
#ifndef __NR_link
#define __NR_link (-1)
#endif
#ifndef __NR_unlink
#define __NR_unlink (-1)
#endif
#ifndef __NR_symlink
#define __NR_symlink (-1)
#endif
#ifndef __NR_readlink
#define __NR_readlink (-1)
#endif
#ifndef __NR_chmod
#define __NR_chmod (-1)
#endif
#ifndef __NR_chown
#define __NR_chown (-1)
#endif
#ifndef __NR_lchown
#define __NR_lchown (-1)
#endif
#ifndef __NR_getrlimit
#define __NR_getrlimit (-1)
#endif
#ifndef __NR_setrlimit
#define __NR_setrlimit (-1)
#endif
#ifndef __NR_getpgrp
#define __NR_getpgrp (-1)
#endif
#ifndef __NR_utime
#define __NR_utime (-1)
#endif
#ifndef __NR_utimes
#define __NR_utimes (-1)
#endif
#ifndef __NR_futimesat
#define __NR_futimesat (-1)
#endif
#ifndef __NR_mknod
#define __NR_mknod (-1)
#endif
#ifndef __NR_arch_prctl
#define __NR_arch_prctl (-1)
#endif
#ifndef __NR_time
#define __NR_time (-1)
#endif
#ifndef __NR_set_thread_area
#define __NR_set_thread_area (-1)
#endif
#ifndef __NR_get_thread_area
#define __NR_get_thread_area (-1)
#endif
#ifndef __NR_epoll_create
#define __NR_epoll_create (-1)
#endif
#ifndef __NR_epoll_wait
#define __NR_epoll_wait (-1)
#endif
#ifndef __NR_inotify_init
#define __NR_inotify_init (-1)
#endif
#ifndef __NR_eventfd
#define __NR_eventfd (-1)
#endif
#ifndef __NR_signalfd
#define __NR_signalfd (-1)
#endif
#ifndef __NR_modify_ldt
#define __NR_modify_ldt (-1)
#endif
#ifndef __NR_kexec_load
#define __NR_kexec_load (-1)
#endif
#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load (-1)
#endif
#ifndef __NR_init_module
#define __NR_init_module (-1)
#endif
#ifndef __NR_finit_module
#define __NR_finit_module (-1)
#endif
#ifndef __NR_delete_module
#define __NR_delete_module (-1)
#endif
#ifndef __NR_iopl
#define __NR_iopl (-1)
#endif
#ifndef __NR_ioperm
#define __NR_ioperm (-1)
#endif
#ifndef __NR_bpf
#define __NR_bpf (-1)
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open (-1)
#endif
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv (-1)
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev (-1)
#endif
#ifndef __NR_kcmp
#define __NR_kcmp (-1)
#endif
#ifndef __NR_open_by_handle_at
#define __NR_open_by_handle_at (-1)
#endif
#ifndef __NR_swapon
#define __NR_swapon (-1)
#endif
#ifndef __NR_swapoff
#define __NR_swapoff (-1)
#endif
#ifndef __NR_reboot
#define __NR_reboot (-1)
#endif
#ifndef __NR_acct
#define __NR_acct (-1)
#endif
#ifndef __NR_settimeofday
#define __NR_settimeofday (-1)
#endif
#ifndef __NR_clock_settime
#define __NR_clock_settime (-1)
#endif
#ifndef __NR_syslog
#define __NR_syslog (-1)
#endif
#ifndef __NR_ptrace
#define __NR_ptrace (-1)
#endif

static const int allowed_syscalls[] = {
    __NR_read, __NR_write, __NR_open, __NR_openat, __NR_close, __NR_stat, __NR_fstat, __NR_lstat,
    __NR_newfstatat, __NR_statx, __NR_poll, __NR_ppoll, __NR_select, __NR_pselect6, __NR_lseek, __NR_mmap,
    __NR_mprotect, __NR_munmap, __NR_brk, __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn,
    __NR_rt_sigpending, __NR_rt_sigtimedwait, __NR_rt_sigqueueinfo, __NR_rt_tgsigqueueinfo, __NR_rt_sigsuspend,
    __NR_sigaltstack, __NR_pread64, __NR_pwrite64, __NR_readv, __NR_writev, __NR_preadv, __NR_pwritev,
    __NR_preadv2, __NR_pwritev2, __NR_access, __NR_faccessat, __NR_faccessat2, __NR_pipe, __NR_pipe2,
    __NR_sched_yield, __NR_mremap, __NR_msync, __NR_mincore, __NR_madvise, __NR_shmget, __NR_shmat, __NR_shmctl,
    __NR_shmdt, __NR_dup, __NR_dup2, __NR_dup3, __NR_pause, __NR_nanosleep, __NR_clock_nanosleep,
    __NR_getitimer, __NR_setitimer, __NR_alarm, __NR_getpid, __NR_sendfile, __NR_connect, __NR_accept,
    __NR_accept4, __NR_sendto, __NR_recvfrom, __NR_sendmsg, __NR_recvmsg, __NR_sendmmsg, __NR_recvmmsg,
    __NR_shutdown, __NR_bind, __NR_listen, __NR_getsockname, __NR_getpeername, __NR_socketpair, __NR_setsockopt,
    __NR_getsockopt, __NR_fork, __NR_vfork, __NR_execve, __NR_execveat, __NR_exit, __NR_exit_group, __NR_wait4,
    __NR_waitid, __NR_kill, __NR_tkill, __NR_tgkill, __NR_uname, __NR_semget, __NR_semop, __NR_semctl,
    __NR_semtimedop, __NR_msgget, __NR_msgsnd, __NR_msgrcv, __NR_msgctl, __NR_fcntl, __NR_flock, __NR_fsync,
    __NR_fdatasync, __NR_truncate, __NR_ftruncate, __NR_getdents, __NR_getdents64, __NR_getcwd, __NR_chdir,
    __NR_fchdir, __NR_rename, __NR_renameat, __NR_renameat2, __NR_mkdir, __NR_mkdirat, __NR_rmdir, __NR_creat,
    __NR_link, __NR_linkat, __NR_unlink, __NR_unlinkat, __NR_symlink, __NR_symlinkat, __NR_readlink,
    __NR_readlinkat, __NR_chmod, __NR_fchmod, __NR_fchmodat, __NR_fchmodat2, __NR_chown, __NR_fchown,
    __NR_lchown, __NR_fchownat, __NR_umask, __NR_gettimeofday, __NR_getrlimit, __NR_setrlimit, __NR_prlimit64,
    __NR_getrusage, __NR_sysinfo, __NR_times, __NR_getuid, __NR_getgid, __NR_setuid, __NR_setgid, __NR_geteuid,
    __NR_getegid, __NR_setpgid, __NR_getppid, __NR_getpgrp, __NR_setsid, __NR_setreuid, __NR_setregid,
    __NR_getgroups, __NR_setgroups, __NR_setresuid, __NR_getresuid, __NR_setresgid, __NR_getresgid,
    __NR_getpgid, __NR_setfsuid, __NR_setfsgid, __NR_getsid, __NR_capget, __NR_capset, __NR_utime, __NR_utimes,
    __NR_futimesat, __NR_utimensat, __NR_mknod, __NR_mknodat, __NR_statfs, __NR_fstatfs, __NR_sched_setparam,
    __NR_sched_getparam, __NR_sched_setscheduler, __NR_sched_getscheduler, __NR_sched_get_priority_max,
    __NR_sched_get_priority_min, __NR_sched_rr_get_interval, __NR_sched_setaffinity, __NR_sched_getaffinity,
    __NR_sched_setattr, __NR_sched_getattr, __NR_getpriority, __NR_setpriority, __NR_ioprio_set,
    __NR_ioprio_get, __NR_mlock, __NR_munlock, __NR_mlockall, __NR_munlockall, __NR_mlock2, __NR_prctl,
    __NR_arch_prctl, __NR_chroot, __NR_sync, __NR_syncfs, __NR_gettid, __NR_readahead, __NR_setxattr,
    __NR_lsetxattr, __NR_fsetxattr, __NR_getxattr, __NR_lgetxattr, __NR_fgetxattr, __NR_listxattr,
    __NR_llistxattr, __NR_flistxattr, __NR_removexattr, __NR_lremovexattr, __NR_fremovexattr, __NR_time,
    __NR_futex, __NR_futex_waitv, __NR_set_thread_area, __NR_get_thread_area, __NR_set_tid_address,
    __NR_restart_syscall, __NR_fadvise64, __NR_timer_create, __NR_timer_settime, __NR_timer_gettime,
    __NR_timer_getoverrun, __NR_timer_delete, __NR_clock_gettime, __NR_clock_getres, __NR_epoll_create,
    __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_wait, __NR_epoll_pwait, __NR_epoll_pwait2, __NR_inotify_init,
    __NR_inotify_init1, __NR_inotify_add_watch, __NR_inotify_rm_watch, __NR_eventfd, __NR_eventfd2,
    __NR_signalfd, __NR_signalfd4, __NR_timerfd_create, __NR_timerfd_settime, __NR_timerfd_gettime,
    __NR_fallocate, __NR_splice, __NR_tee, __NR_vmsplice, __NR_sync_file_range, __NR_get_robust_list,
    __NR_set_robust_list, __NR_getcpu, __NR_getrandom, __NR_memfd_create, __NR_copy_file_range, __NR_membarrier,
    __NR_rseq, __NR_pidfd_open, __NR_pidfd_send_signal, __NR_close_range, __NR_openat2,
    __NR_landlock_create_ruleset, __NR_landlock_add_rule, __NR_landlock_restrict_self, __NR_cachestat,
    __NR_seccomp, __NR_remap_file_pages, __NR_pkey_alloc, __NR_pkey_free, __NR_pkey_mprotect,
    __NR_mq_open, __NR_mq_unlink, __NR_mq_timedsend, __NR_mq_timedreceive, __NR_mq_notify, __NR_mq_getsetattr,
    __NR_set_mempolicy, __NR_get_mempolicy, __NR_mbind, __NR_modify_ldt,
};

static const int kill_syscalls[] = {
    __NR_kexec_load, __NR_kexec_file_load, __NR_init_module, __NR_finit_module,
    __NR_delete_module, __NR_iopl, __NR_ioperm, __NR_bpf, __NR_perf_event_open,
    __NR_process_vm_readv, __NR_process_vm_writev, __NR_kcmp,
    __NR_open_by_handle_at, __NR_swapon, __NR_swapoff, __NR_reboot,
    __NR_acct, __NR_settimeofday, __NR_clock_settime, __NR_syslog,
    __NR_ptrace,
};

#if defined(__x86_64__)
#define NFLXS_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NFLXS_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "unsupported architecture"
#endif

#define SC_NR ((uint32_t)offsetof(struct seccomp_data, nr))
#define SC_ARCH ((uint32_t)offsetof(struct seccomp_data, arch))
#define SC_ARG(i) ((uint32_t)(offsetof(struct seccomp_data, args) + (i) * 8))
#define RET_EPERM (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
#define RET_ENOSYS (SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA))
#define MAX_FILTER 2048

struct filter {
    struct sock_filter ins[MAX_FILTER];
    size_t n;
};

static void f_emit(struct filter *f, struct sock_filter i)
{
    if (f->n >= MAX_FILTER)
        die("seccomp filter too large");
    f->ins[f->n++] = i;
}

static void f_block_begin(struct filter *f, int nr, size_t body)
{
    f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)nr, 0, (uint8_t)body));
}

static void build_filter(struct filter *f)
{
    static const uint32_t clone_ns_mask = 0x7e020080u;
    static const uint32_t socket_domains[] = { AF_UNIX, AF_INET, AF_INET6, AF_NETLINK };
    static const uint32_t personalities[] = { 0x0, 0x8, 0x20000, 0x20008, 0xffffffffu };
    f->n = 0;
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARCH));
    f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NFLXS_AUDIT_ARCH, 1, 0));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_NR));

    f_block_begin(f, __NR_clone, 4);
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARG(0)));
    f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, clone_ns_mask, 0, 1));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, RET_EPERM));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    f_block_begin(f, __NR_clone3, 1);
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, RET_ENOSYS));

    size_t nd = sizeof(socket_domains) / sizeof(socket_domains[0]);
    f_block_begin(f, __NR_socket, nd + 3);
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARG(0)));
    for (size_t i = 0; i < nd; i++)
        f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, socket_domains[i], (uint8_t)(nd - i), 0));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, RET_EPERM));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    size_t np = sizeof(personalities) / sizeof(personalities[0]);
    f_block_begin(f, __NR_personality, np + 3);
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARG(0)));
    for (size_t i = 0; i < np; i++)
        f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, personalities[i], (uint8_t)(np - i), 0));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, RET_EPERM));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    f_block_begin(f, __NR_ioctl, 6);
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SC_ARG(1)));
    f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5412, 3, 0));
    f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x541c, 2, 0));
    f_emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x541d, 1, 0));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, RET_EPERM));

    for (size_t i = 0; i < sizeof(kill_syscalls) / sizeof(kill_syscalls[0]); i++) {
        if (kill_syscalls[i] < 0)
            continue;
        f_block_begin(f, kill_syscalls[i], 1);
        f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    for (size_t i = 0; i < sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]); i++) {
        if (allowed_syscalls[i] < 0)
            continue;
        f_block_begin(f, allowed_syscalls[i], 1);
        f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
    f_emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, RET_EPERM));
}

static void apply_seccomp(void)
{
    struct filter *f = xcalloc(1, sizeof(*f));
    build_filter(f);
    struct sock_fprog prog = { .len = (unsigned short)f->n, .filter = f->ins };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die_errno("PR_SET_NO_NEW_PRIVS");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
        die_errno("install seccomp filter");
    free(f);
}

static void drop_capabilities(void)
{
    static const int keep[] = { CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID,
                    CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_CHROOT, CAP_SETFCAP, CAP_AUDIT_WRITE };
    uint64_t keepmask = 0;
    for (size_t i = 0; i < sizeof(keep) / sizeof(keep[0]); i++)
        keepmask |= (uint64_t)1 << keep[i];
    int last = 40;
    struct buf b = { 0 };
    if (read_file("/proc/sys/kernel/cap_last_cap", &b, 64) == 0 && b.d) {
        uint64_t v;
        b.d[strcspn(b.d, "\n")] = '\0';
        if (parse_u64(b.d, &v) && v < 64)
            last = (int)v;
    }
    buf_free(&b);
    for (int c = 0; c <= last; c++) {
        if (keepmask & ((uint64_t)1 << c))
            continue;
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL)
            die_errno("drop capability %d", c);
    }
    struct __user_cap_header_struct h;
    struct __user_cap_data_struct d[2];
    memset(&h, 0, sizeof(h));
    memset(d, 0, sizeof(d));
    h.version = _LINUX_CAPABILITY_VERSION_3;
    d[0].effective = d[0].permitted = (uint32_t)keepmask;
    d[1].effective = d[1].permitted = (uint32_t)(keepmask >> 32);
    if (syscall(SYS_capset, &h, d) < 0)
        die_errno("capset");
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        warnx_("cannot disable core dumps");
}

struct gfx {
    char *display;
    bool x11;
    char *xauth;
    size_t xauth_len;
    char *wl_name;
    char *wl_sock;
};

struct run_opts {
    bool as_root;
    bool no_net;
    bool interactive;
    uint32_t cpu_milli;
    uint64_t mem;
    char **argv;
};

struct uinfo {
    char name[40];
    uid_t uid;
    gid_t gid;
    char home[PATH_MAX];
    char shell[PATH_MAX];
    gid_t groups[MAX_GROUPS];
    int ngroups;
};

struct cctx {
    const struct sandbox *sb;
    const struct run_opts *o;
    struct gfx gfx;
    int sync_fd;
    bool use_pty;
    bool use_cgroup;
    char slave[PATH_MAX];
    struct uinfo u;
    gid_t extra[MAX_GROUPS];
    int nextra;
    int rootfd;
    char term[64];
    char lang[64];
};

static volatile sig_atomic_t g_winch, g_chld, g_sig, g_nsig;
static volatile pid_t g_init_child;
static struct termios g_saved_tty;
static bool g_tty_saved;

static void restore_tty(void)
{
    if (g_tty_saved && !g_is_child) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_tty);
        g_tty_saved = false;
    }
}

static void host_signal(int s)
{
    if (s == SIGWINCH)
        g_winch = 1;
    else if (s == SIGCHLD)
        g_chld = 1;
    else {
        g_sig = s;
        g_nsig++;
    }
}

static void init_forward(int s)
{
    if (g_init_child > 0)
        kill(g_init_child, s);
}

static void add_extra_gid(struct cctx *c, gid_t g)
{
    for (int i = 0; i < c->nextra; i++)
        if (c->extra[i] == g)
            return;
    if (c->nextra < MAX_GROUPS)
        c->extra[c->nextra++] = g;
}

static int mnt_target(int rootfd, const char *rel, bool isdir)
{
    if (isdir)
        return open_dir_p(rootfd, rel, true);
    char dir[PATH_MAX];
    const char *base;
    if (split_parent(rel, dir, sizeof(dir), &base) < 0)
        return -1;
    char name[NAME_MAX + 1];
    if (strlen(base) > NAME_MAX)
        return -1;
    memcpy(name, base, strlen(base) + 1);
    int parent = open_dir_p(rootfd, dir, true);
    if (parent < 0)
        return -1;
    struct stat st;
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISLNK(st.st_mode))
            unlinkat(parent, name, 0);
    }
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) {
            int e = errno;
            close(parent);
            errno = e;
            return -1;
        }
        close(fd);
    }
    close(parent);
    return root_open(rootfd, rel, O_PATH, 0);
}

static int do_mount(int rootfd, const char *rel, bool isdir, const char *src, const char *type, unsigned long flags,
            const char *data, unsigned long ro_flags)
{
    int fd = mnt_target(rootfd, rel, isdir);
    if (fd < 0)
        return -1;
    char tp[64];
    snprintf(tp, sizeof(tp), "/proc/self/fd/%d", fd);
    int r = mount(src, tp, type, flags, data);
    int e = errno;
    close(fd);
    if (r < 0) {
        errno = e;
        return -1;
    }
    if (ro_flags) {
        fd = root_open(rootfd, rel, O_PATH, 0);
        if (fd < 0)
            return -1;
        snprintf(tp, sizeof(tp), "/proc/self/fd/%d", fd);
        r = mount(NULL, tp, NULL, MS_REMOUNT | MS_BIND | ro_flags, NULL);
        e = errno;
        close(fd);
        if (r < 0) {
            errno = e;
            return -1;
        }
    }
    return 0;
}

static int bind_existing(int rootfd, const char *rel, const char *src, unsigned long ro_flags)
{
    int fd = root_open(rootfd, rel, O_PATH, 0);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    char tp[64];
    snprintf(tp, sizeof(tp), "/proc/self/fd/%d", fd);
    int r = mount(src ? src : tp, tp, NULL, MS_BIND, NULL);
    int e = errno;
    close(fd);
    if (r < 0) {
        errno = e;
        return -1;
    }
    if (ro_flags) {
        fd = root_open(rootfd, rel, O_PATH, 0);
        if (fd < 0)
            return -1;
        snprintf(tp, sizeof(tp), "/proc/self/fd/%d", fd);
        r = mount(NULL, tp, NULL, MS_REMOUNT | MS_BIND | ro_flags, NULL);
        e = errno;
        close(fd);
        if (r < 0) {
            errno = e;
            return -1;
        }
    }
    return 0;
}

static int make_dir_owned(int rootfd, const char *rel, mode_t mode, uid_t uid, gid_t gid)
{
    char dir[PATH_MAX];
    const char *base;
    if (split_parent(rel, dir, sizeof(dir), &base) < 0)
        return -1;
    char name[NAME_MAX + 1];
    if (strlen(base) > NAME_MAX)
        return -1;
    memcpy(name, base, strlen(base) + 1);
    int parent = open_dir_p(rootfd, dir, true);
    if (parent < 0)
        return -1;
    int rc = -1;
    if ((mkdirat(parent, name, mode) == 0 || errno == EEXIST) && fchownat(parent, name, uid, gid, AT_SYMLINK_NOFOLLOW) == 0)
        rc = 0;
    int e = errno;
    close(parent);
    errno = e;
    return rc;
}

static int write_owned_file(int rootfd, const char *rel, const void *data, size_t len, mode_t mode, uid_t uid, gid_t gid)
{
    char dir[PATH_MAX];
    const char *base;
    if (split_parent(rel, dir, sizeof(dir), &base) < 0)
        return -1;
    char name[NAME_MAX + 1];
    if (strlen(base) > NAME_MAX)
        return -1;
    memcpy(name, base, strlen(base) + 1);
    int parent = open_dir_p(rootfd, dir, true);
    if (parent < 0)
        return -1;
    unlinkat(parent, name, 0);
    int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int rc = -1;
    if (fd >= 0) {
        if (write_all(fd, data, len) == 0 && fchown(fd, uid, gid) == 0 && fchmod(fd, mode) == 0)
            rc = 0;
        int e = errno;
        close(fd);
        errno = e;
    }
    int e = errno;
    close(parent);
    errno = e;
    return rc;
}

static void lookup_user(int rootfd, const char *name, struct uinfo *u)
{
    memset(u, 0, sizeof(*u));
    pathf(u->name, sizeof(u->name), "%s", name);
    int fd = root_open(rootfd, "etc/passwd", O_RDONLY, 0);
    if (fd < 0)
        die_errno("open /etc/passwd of the sandbox");
    FILE *f = fdopen(fd, "r");
    if (!f)
        die_errno("fdopen");
    char *line = NULL;
    size_t cap = 0;
    bool found = false;
    while (getline(&line, &cap, f) > 0) {
        line[strcspn(line, "\n")] = '\0';
        char *fl[7] = { 0 };
        char *p = line;
        for (int i = 0; i < 7; i++) {
            fl[i] = p;
            char *cn = p ? strchr(p, ':') : NULL;
            if (cn) {
                *cn = '\0';
                p = cn + 1;
            } else {
                p = NULL;
            }
        }
        if (!fl[0] || strcmp(fl[0], name) != 0 || !fl[2] || !fl[3] || !fl[5] || !fl[6])
            continue;
        uint64_t uid, gid;
        if (!parse_u64(fl[2], &uid) || !parse_u64(fl[3], &gid) || uid > UINT32_MAX || gid > UINT32_MAX)
            continue;
        u->uid = (uid_t)uid;
        u->gid = (gid_t)gid;
        pathf(u->home, sizeof(u->home), "%s", fl[5][0] ? fl[5] : "/");
        pathf(u->shell, sizeof(u->shell), "%s", fl[6][0] ? fl[6] : "/bin/sh");
        found = true;
        break;
    }
    free(line);
    fclose(f);
    if (!found)
        die("user '%s' was not found in the sandbox /etc/passwd", name);
    fd = root_open(rootfd, "etc/group", O_RDONLY, 0);
    if (fd < 0)
        return;
    f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        return;
    }
    line = NULL;
    cap = 0;
    size_t nl = strlen(name);
    while (getline(&line, &cap, f) > 0) {
        line[strcspn(line, "\n")] = '\0';
        char *c1 = strchr(line, ':');
        char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
        char *c3 = c2 ? strchr(c2 + 1, ':') : NULL;
        if (!c3)
            continue;
        *c3 = '\0';
        uint64_t gid;
        if (!parse_u64(c2 + 1, &gid) || gid > UINT32_MAX)
            continue;
        bool member = false;
        for (char *m = c3 + 1; *m;) {
            char *e = strchr(m, ',');
            size_t l = e ? (size_t)(e - m) : strlen(m);
            if (l == nl && !strncmp(m, name, nl))
                member = true;
            if (!e)
                break;
            m = e + 1;
        }
        if (member && u->ngroups < MAX_GROUPS)
            u->groups[u->ngroups++] = (gid_t)gid;
    }
    free(line);
    fclose(f);
}

static void gfx_collect(struct gfx *g)
{
    memset(g, 0, sizeof(*g));
    struct stat st;
    const char *sudo_uid = getenv("SUDO_UID");
    const char *disp = getenv("DISPLAY");
    if (stat("/tmp/.X11-unix", &st) == 0 && S_ISDIR(st.st_mode)) {
        if (disp && *disp) {
            g->display = xstrdup(disp);
        } else {
            DIR *d = opendir("/tmp/.X11-unix");
            struct dirent *de;
            while (d && (de = readdir(d)) != NULL) {
                if (de->d_name[0] == 'X' && de->d_name[1] >= '0' && de->d_name[1] <= '9') {
                    g->display = xasprintf(":%s", de->d_name + 1);
                    break;
                }
            }
            if (d)
                closedir(d);
        }
        g->x11 = g->display != NULL;
    }
    if (g->x11) {
        char xa[PATH_MAX] = "";
        const char *e = getenv("XAUTHORITY");
        if (e && *e) {
            pathf(xa, sizeof(xa), "%s", e);
        } else if (sudo_uid) {
            uint64_t su;
            struct passwd *pw = parse_u64(sudo_uid, &su) ? getpwuid((uid_t)su) : NULL;
            if (pw && pw->pw_dir)
                pathf(xa, sizeof(xa), "%s/.Xauthority", pw->pw_dir);
        }
        if (xa[0]) {
            struct buf b = { 0 };
            if (read_file(xa, &b, MAX_TEXT) == 0 && b.len > 0) {
                g->xauth = b.d;
                g->xauth_len = b.len;
            } else {
                buf_free(&b);
            }
        }
    }
    char rt[PATH_MAX] = "";
    const char *xr = getenv("XDG_RUNTIME_DIR");
    if (xr && *xr)
        pathf(rt, sizeof(rt), "%s", xr);
    else if (sudo_uid)
        pathf(rt, sizeof(rt), "/run/user/%s", sudo_uid);
    if (rt[0]) {
        const char *wl = getenv("WAYLAND_DISPLAY");
        if (!wl || !*wl)
            wl = "wayland-0";
        if (!strchr(wl, '/') && wl[0] != '.' && strlen(wl) < 64) {
            char sock[PATH_MAX];
            pathf(sock, sizeof(sock), "%s/%s", rt, wl);
            if (stat(sock, &st) == 0 && S_ISSOCK(st.st_mode)) {
                g->wl_name = xstrdup(wl);
                g->wl_sock = xstrdup(sock);
            }
        }
    }
}

static void gfx_free(struct gfx *g)
{
    free(g->display);
    free(g->xauth);
    free(g->wl_name);
    free(g->wl_sock);
    memset(g, 0, sizeof(*g));
}

static void bind_gpu(struct cctx *c)
{
    int rfd = c->rootfd;
    struct stat st;
    if (stat("/dev/dri", &st) == 0 && S_ISDIR(st.st_mode)) {
        if (do_mount(rfd, "dev/dri", true, "/dev/dri", NULL, MS_BIND | MS_REC, NULL, 0) < 0)
            warnx_("cannot expose /dev/dri: %s", strerror(errno));
        DIR *d = opendir("/dev/dri");
        struct dirent *de;
        while (d && (de = readdir(d)) != NULL) {
            char p[PATH_MAX];
            if (de->d_name[0] == '.')
                continue;
            pathf(p, sizeof(p), "/dev/dri/%s", de->d_name);
            if (stat(p, &st) == 0 && S_ISCHR(st.st_mode))
                add_extra_gid(c, st.st_gid);
        }
        if (d)
            closedir(d);
    }
    DIR *d = opendir("/dev");
    struct dirent *de;
    while (d && (de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "nvidia", 6) != 0 && strcmp(de->d_name, "kfd") != 0)
            continue;
        char p[PATH_MAX], rel[PATH_MAX];
        pathf(p, sizeof(p), "/dev/%s", de->d_name);
        pathf(rel, sizeof(rel), "dev/%s", de->d_name);
        if (stat(p, &st) != 0 || !S_ISCHR(st.st_mode))
            continue;
        if (do_mount(rfd, rel, false, p, NULL, MS_BIND, NULL, 0) < 0)
            warnx_("cannot expose %s: %s", p, strerror(errno));
        else
            add_extra_gid(c, st.st_gid);
    }
    if (d)
        closedir(d);
}

static void setup_mounts(struct cctx *c)
{
    int rfd = c->rootfd;
    const unsigned long hard = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    if (do_mount(rfd, "proc", true, "proc", "proc", hard, NULL, 0) < 0)
        die_errno("mount /proc");
    static const char *ro_proc[] = { "proc/bus", "proc/fs", "proc/irq", "proc/sys", "proc/sysrq-trigger" };
    for (size_t i = 0; i < sizeof(ro_proc) / sizeof(ro_proc[0]); i++)
        if (bind_existing(rfd, ro_proc[i], NULL, MS_RDONLY | hard) < 0)
            die_errno("protect %s", ro_proc[i]);
    static const char *mask_proc[] = {
        "proc/kcore", "proc/keys", "proc/timer_list", "proc/sched_debug",
        "proc/latency_stats", "proc/kallsyms", "proc/modules", "proc/config.gz",
        "proc/self/mem", "proc/asound", "proc/timer_stats", "proc/version_signature"
    };
    for (size_t i = 0; i < sizeof(mask_proc) / sizeof(mask_proc[0]); i++) {
        if (bind_existing(rfd, mask_proc[i], "/dev/null", 0) < 0) {
            if (errno == ENOTDIR) {
                if (do_mount(rfd, mask_proc[i], true, "tmpfs", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0000,size=1", 0) < 0)
                    warnx_("cannot mask %s: %s", mask_proc[i], strerror(errno));
            } else if (errno != ENOENT) {
                warnx_("cannot mask %s: %s", mask_proc[i], strerror(errno));
            }
        }
    }
    if (do_mount(rfd, "sys", true, "sysfs", "sysfs", hard | MS_RDONLY, NULL, 0) < 0)
        die_errno("mount /sys");
    if (bind_existing(rfd, "sys/firmware", NULL, MS_RDONLY | hard) < 0)
        warnx_("cannot protect sys/firmware");
    if (bind_existing(rfd, "sys/kernel", NULL, MS_RDONLY | hard) < 0)
        warnx_("cannot protect sys/kernel");
    if (do_mount(rfd, "dev", true, "tmpfs", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755,size=65536", 0) < 0)
        die_errno("mount /dev");
    static const char *devs[] = { "null", "zero", "full", "random", "urandom", "tty" };
    for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
        char src[64], rel[64];
        pathf(src, sizeof(src), "/dev/%s", devs[i]);
        pathf(rel, sizeof(rel), "dev/%s", devs[i]);
        if (access(src, F_OK) == 0 && do_mount(rfd, rel, false, src, NULL, MS_BIND, NULL, 0) < 0)
            die_errno("bind %s", src);
    }
    if (do_mount(rfd, "dev/pts", true, "devpts", "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620", 0) < 0)
        die_errno("mount /dev/pts");
    if (do_mount(rfd, "dev/shm", true, "tmpfs", "tmpfs", hard, "mode=1777,size=268435456", 0) < 0)
        die_errno("mount /dev/shm");
    int devfd = open_dir_p(rfd, "dev", false);
    if (devfd < 0)
        die_errno("open /dev");
    static const char *links[][2] = { { "pts/ptmx", "ptmx" }, { "/proc/self/fd", "fd" }, { "/proc/self/fd/0", "stdin" },
                      { "/proc/self/fd/1", "stdout" }, { "/proc/self/fd/2", "stderr" } };
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++)
        if (symlinkat(links[i][0], devfd, links[i][1]) < 0 && errno != EEXIST)
            die_errno("symlink /dev/%s", links[i][1]);
    close(devfd);
    if (c->use_pty && do_mount(rfd, "dev/console", false, c->slave, NULL, MS_BIND, NULL, 0) < 0)
        die_errno("bind console");
    if (do_mount(rfd, "run", true, "tmpfs", "tmpfs", MS_NOSUID | MS_NODEV, "mode=755,size=67108864", 0) < 0)
        die_errno("mount /run");
    if (access("/etc/resolv.conf", F_OK) == 0 &&
        do_mount(rfd, "etc/resolv.conf", false, "/etc/resolv.conf", NULL, MS_BIND, NULL, MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC) < 0)
        warnx_("cannot provide resolv.conf: %s", strerror(errno));
    bind_gpu(c);
    if (c->gfx.x11) {
        if (do_mount(rfd, "tmp/.X11-unix", true, "/tmp/.X11-unix", NULL, MS_BIND, NULL, MS_RDONLY | hard) < 0)
            warnx_("cannot expose the X11 socket: %s", strerror(errno));
        if (c->gfx.xauth) {
            if (make_dir_owned(rfd, "run/nflxs", 0755, 0, 0) < 0 ||
                write_owned_file(rfd, "run/nflxs/Xauthority", c->gfx.xauth, c->gfx.xauth_len, 0600, c->u.uid, c->u.gid) < 0)
                warnx_("cannot provide Xauthority: %s", strerror(errno));
        }
    }
    if (c->gfx.wl_sock) {
        char rel[PATH_MAX];
        pathf(rel, sizeof(rel), "run/user/%u", (unsigned)c->u.uid);
        if (make_dir_owned(rfd, "run/user", 0755, 0, 0) < 0 || make_dir_owned(rfd, rel, 0700, c->u.uid, c->u.gid) < 0) {
            warnx_("cannot prepare the runtime directory: %s", strerror(errno));
        } else {
            pathf(rel, sizeof(rel), "run/user/%u/%s", (unsigned)c->u.uid, c->gfx.wl_name);
            if (do_mount(rfd, rel, false, c->gfx.wl_sock, NULL, MS_BIND, NULL, 0) < 0)
                warnx_("cannot expose the Wayland socket: %s", strerror(errno));
        }
    }
}

static void set_environment(const struct cctx *c)
{
    clearenv();
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", c->u.home, 1);
    setenv("USER", c->u.name, 1);
    setenv("LOGNAME", c->u.name, 1);
    setenv("SHELL", c->u.shell, 1);
    setenv("TERM", "xterm", 1);
    setenv("HOSTNAME", c->sb->name, 1);
    setenv("container", "nflxs", 1);
    if (c->lang[0])
        setenv("LANG", c->lang, 1);
    if (c->gfx.x11) {
        setenv("DISPLAY", c->gfx.display, 1);
        setenv("QT_X11_NO_MITSHM", "1", 1);
        if (c->gfx.xauth)
            setenv("XAUTHORITY", "/run/nflxs/Xauthority", 1);
    }
    if (c->gfx.wl_sock) {
        char rt[64];
        snprintf(rt, sizeof(rt), "/run/user/%u", (unsigned)c->u.uid);
        setenv("XDG_RUNTIME_DIR", rt, 1);
        setenv("WAYLAND_DISPLAY", c->gfx.wl_name, 1);
    }
}

static void loopback_up(void)
{
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0)
        return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP;
        ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
}

static void workload(struct cctx *c)
{
    for (int s = 1; s < 32; s++)
        if (s != SIGKILL && s != SIGSTOP)
            signal(s, SIG_DFL);
    sigset_t all;
    sigemptyset(&all);
    sigprocmask(SIG_SETMASK, &all, NULL);
    if (c->use_pty) {
        if (setsid() < 0)
            die_errno("setsid");
        int fd = open("/dev/console", O_RDWR);
        if (fd < 0)
            die_errno("open /dev/console");
        if (ioctl(fd, TIOCSCTTY, 0) < 0)
            die_errno("TIOCSCTTY");
        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
            die_errno("dup2");
        if (fd > 2)
            close(fd);
    } else if (!c->o->interactive) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) {
            dup2(fd, 0);
            if (fd > 2)
                close(fd);
        }
    }
    gid_t groups[2 * MAX_GROUPS];
    int ng = 0;
    if (!c->o->as_root)
        for (int i = 0; i < c->u.ngroups; i++)
            groups[ng++] = c->u.groups[i];
    for (int i = 0; i < c->nextra; i++)
        groups[ng++] = c->extra[i];
    if (setgroups((size_t)ng, groups) < 0)
        die_errno("setgroups");
    if (setgid(c->u.gid) < 0)
        die_errno("setgid");
    if (setuid(c->u.uid) < 0)
        die_errno("setuid");
    if (chdir(c->u.home) < 0 && chdir("/") < 0)
        die_errno("chdir");
    umask(077);
    syscall(SYS_close_range, 3u, ~0u, 0);
    if (c->o->argv && c->o->argv[0]) {
        execvp(c->o->argv[0], c->o->argv);
        dprintf(2, "nflxs: cannot execute %s: %s\n", c->o->argv[0], strerror(errno));
        _exit(127);
    }
    const char *sh = access(c->u.shell, X_OK) == 0 ? c->u.shell : "/bin/sh";
    const char *bn = strrchr(sh, '/');
    char a0[80];
    snprintf(a0, sizeof(a0), "-%.70s", bn ? bn + 1 : sh);
    char *args[2] = { a0, NULL };
    execv(sh, args);
    dprintf(2, "nflxs: cannot execute %s: %s\n", sh, strerror(errno));
    _exit(127);
}

static int container_main(void *arg)
{
    struct cctx *c = arg;
    g_is_child = 1;
    char b;
    if (read(c->sync_fd, &b, 1) != 1)
        _exit(1);
    close(c->sync_fd);
    if (c->use_cgroup && unshare(CLONE_NEWCGROUP) < 0)
        die_errno("unshare(CLONE_NEWCGROUP)");
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    umask(077);
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        die_errno("make mounts private");
    if (sethostname(c->sb->name, strlen(c->sb->name)) < 0)
        die_errno("sethostname");
    const char *R = c->sb->rootfs;
    if (mount(R, R, NULL, MS_BIND | MS_REC, NULL) < 0)
        die_errno("bind %s", R);
    c->rootfd = open(R, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (c->rootfd < 0)
        die_errno("open %s", R);
    lookup_user(c->rootfd, c->o->as_root ? "root" : c->sb->user, &c->u);
    setup_mounts(c);
    close(c->rootfd);
    if (chdir(R) < 0)
        die_errno("chdir %s", R);
    if (syscall(SYS_pivot_root, ".", ".") < 0)
        die_errno("pivot_root");
    if (umount2(".", MNT_DETACH) < 0)
        die_errno("detach old root");
    if (chdir("/") < 0)
        die_errno("chdir /");
    if (c->o->no_net)
        loopback_up();
    set_environment(c);
    drop_capabilities();
    apply_seccomp();
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = init_forward;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    pid_t cp = fork();
    if (cp < 0)
        die_errno("fork");
    if (cp == 0)
        workload(c);
    g_init_child = cp;
    int status = 0;
    for (;;) {
        int st;
        pid_t w = waitpid(-1, &st, 0);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (w == cp) {
            status = st;
            break;
        }
    }
    if (WIFEXITED(status))
        _exit(WEXITSTATUS(status));
    if (WIFSIGNALED(status))
        _exit(128 + WTERMSIG(status));
    _exit(1);
}

static void write_winsize(int master)
{
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
        ioctl(master, TIOCSWINSZ, &ws);
}

static void drain_master(int master)
{
    char buf[4096];
    for (;;) {
        struct pollfd pf = { master, POLLIN, 0 };
        int n = poll(&pf, 1, 50);
        if (n <= 0)
            return;
        ssize_t r = read(master, buf, sizeof(buf));
        if (r <= 0)
            return;
        write_all(STDOUT_FILENO, buf, (size_t)r);
    }
}

static int status_code(int st)
{
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return 1;
}

static int relay_pty(int master, pid_t child)
{
    struct termios raw;
    if (tcgetattr(STDIN_FILENO, &g_saved_tty) == 0) {
        g_tty_saved = true;
        raw = g_saved_tty;
        cfmakeraw(&raw);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    }
    sigset_t blk, old;
    sigemptyset(&blk);
    sigaddset(&blk, SIGCHLD);
    sigaddset(&blk, SIGWINCH);
    sigaddset(&blk, SIGTERM);
    sigaddset(&blk, SIGHUP);
    sigaddset(&blk, SIGINT);
    sigprocmask(SIG_BLOCK, &blk, &old);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = host_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGWINCH, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    struct pollfd pf[2] = { { STDIN_FILENO, POLLIN, 0 }, { master, POLLIN, 0 } };
    int status = 0;
    bool stdin_open = true;
    char *buf = xmalloc(4096);
    for (;;) {
        if (g_winch) {
            g_winch = 0;
            write_winsize(master);
        }
        if (g_sig) {
            g_sig = 0;
            kill(child, g_nsig > 1 ? SIGKILL : SIGTERM);
        }
        if (g_chld) {
            g_chld = 0;
            if (waitpid(child, &status, WNOHANG) == child) {
                drain_master(master);
                break;
            }
        }
        pf[0].fd = stdin_open ? STDIN_FILENO : -1;
        int n = ppoll(pf, 2, NULL, &old);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pf[0].revents & (POLLIN | POLLHUP)) {
            ssize_t r = read(STDIN_FILENO, buf, 4096);
            if (r > 0)
                write_all(master, buf, (size_t)r);
            else if (r == 0 || (errno != EINTR && errno != EAGAIN))
                stdin_open = false;
        }
        if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = read(master, buf, 4096);
            if (r > 0) {
                write_all(STDOUT_FILENO, buf, (size_t)r);
            } else if (r == 0 || errno == EIO) {
                while (waitpid(child, &status, 0) < 0 && errno == EINTR)
                    ;
                break;
            }
        }
    }
    free(buf);
    restore_tty();
    return status_code(status);
}

static int wait_plain(pid_t child)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = host_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    int st = 0;
    for (;;) {
        pid_t w = waitpid(child, &st, 0);
        if (w == child)
            break;
        if (w < 0 && errno == EINTR) {
            if (g_sig) {
                g_sig = 0;
                kill(child, g_nsig > 1 ? SIGKILL : SIGTERM);
            }
            continue;
        }
        if (w < 0)
            return 1;
    }
    return status_code(st);
}

static int container_run(const struct sandbox *sb, const struct run_opts *o)
{
    struct cctx *c = xcalloc(1, sizeof(*c));
    c->sb = sb;
    c->o = o;
    gfx_collect(&c->gfx);
    const char *t = getenv("TERM");
    if (t)
        pathf(c->term, sizeof(c->term), "%s", t);
    const char *l = getenv("LANG");
    if (l)
        pathf(c->lang, sizeof(c->lang), "%s", l);
    char *cg = cg_setup(sb->name, o->cpu_milli, o->mem, o->cpu_milli || o->mem);
    c->use_cgroup = cg != NULL;
    int master = -1;
    c->use_pty = o->interactive && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    if (c->use_pty) {
        master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 || ptsname_r(master, c->slave, sizeof(c->slave)) != 0)
            die_errno("allocate pseudo-terminal");
        struct termios tio;
        if (tcgetattr(STDIN_FILENO, &tio) == 0)
            tcsetattr(master, TCSANOW, &tio);
        write_winsize(master);
    }
    int sp[2];
    if (pipe2(sp, O_CLOEXEC) < 0)
        die_errno("pipe2");
    c->sync_fd = sp[0];
    void *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED)
        die_errno("mmap stack");
    int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | SIGCHLD;
    if (o->no_net)
        flags |= CLONE_NEWNET;
    pid_t pid = clone(container_main, (char *)stack + STACK_SIZE, flags, c);
    if (pid < 0)
        die_errno("clone");
    close(sp[0]);
    if (cg) {
        char p[PATH_MAX], v[32];
        pathf(p, sizeof(p), "%s/cgroup.procs", cg);
        snprintf(v, sizeof(v), "%ld", (long)pid);
        if (write_str_file(p, v) < 0) {
            int e = errno;
            kill(pid, SIGKILL);
            wait_pid(pid);
            errno = e;
            die_errno("join cgroup");
        }
    }
    if (write_all(sp[1], "x", 1) < 0)
        die_errno("synchronise with container");
    close(sp[1]);
    int rc = c->use_pty ? relay_pty(master, pid) : wait_plain(pid);
    if (master >= 0)
        close(master);
    munmap(stack, STACK_SIZE);
    cg_cleanup(cg);
    gfx_free(&c->gfx);
    free(c);
    return rc;
}

struct ztsl_step {
    bool shell;
    char **argv;
    char *text;
};

struct ztsl {
    char *name;
    char *distro;
    char *size;
    char *fs;
    struct ztsl_step *steps;
    size_t n;
};

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r')
        s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
        s[--n] = '\0';
    return s;
}

static char **tokenize(const char *line, int lineno)
{
    size_t cap = 8, n = 0;
    char **v = xmalloc(cap * sizeof(*v));
    const char *p = line;
    for (;;) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        struct buf b = { 0 };
        buf_reserve(&b, 0);
        while (*p && *p != ' ' && *p != '\t') {
            if (*p == '\'') {
                const char *e = strchr(p + 1, '\'');
                if (!e)
                    die("ztsl line %d: unterminated quote", lineno);
                buf_add(&b, p + 1, (size_t)(e - p - 1));
                p = e + 1;
            } else if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && (p[1] == '"' || p[1] == '\\'))
                        p++;
                    buf_add(&b, p, 1);
                    p++;
                }
                if (*p != '"')
                    die("ztsl line %d: unterminated quote", lineno);
                p++;
            } else {
                buf_add(&b, p, 1);
                p++;
            }
        }
        if (n + 2 > cap) {
            cap *= 2;
            v = xrealloc(v, cap * sizeof(*v));
        }
        v[n++] = b.d;
    }
    v[n] = NULL;
    return v;
}

static void ztsl_push(struct ztsl *z, struct ztsl_step st)
{
    z->steps = xrealloc(z->steps, (z->n + 1) * sizeof(*z->steps));
    z->steps[z->n++] = st;
}

static void ztsl_free(struct ztsl *z)
{
    free(z->name);
    free(z->distro);
    free(z->size);
    free(z->fs);
    for (size_t i = 0; i < z->n; i++) {
        if (z->steps[i].argv) {
            for (char **a = z->steps[i].argv; *a; a++)
                free(*a);
            free(z->steps[i].argv);
        }
        free(z->steps[i].text);
    }
    free(z->steps);
    memset(z, 0, sizeof(*z));
}

static void ztsl_define(struct ztsl *z, char *line, int lineno)
{
    static const char pre[] = "define variable ";
    if (strncmp(line, pre, sizeof(pre) - 1) != 0)
        die("ztsl line %d: expected 'define variable KEY as \"VALUE\"'", lineno);
    char *key = line + sizeof(pre) - 1;
    char *sp = strchr(key, ' ');
    if (!sp)
        die("ztsl line %d: malformed definition", lineno);
    *sp = '\0';
    char *rest = trim(sp + 1);
    if (strncmp(rest, "as ", 3) != 0)
        die("ztsl line %d: expected 'as' after the variable name", lineno);
    char *val = trim(rest + 3);
    size_t vl = strlen(val);
    if (vl < 2 || val[0] != '"' || val[vl - 1] != '"')
        die("ztsl line %d: the value must be enclosed in double quotes", lineno);
    val[vl - 1] = '\0';
    val++;
    char **slot = NULL;
    if (!strcmp(key, "NAME"))
        slot = &z->name;
    else if (!strcmp(key, "DISTRO"))
        slot = &z->distro;
    else if (!strcmp(key, "SIZE"))
        slot = &z->size;
    else if (!strcmp(key, "FS"))
        slot = &z->fs;
    else
        die("ztsl line %d: unknown variable '%s'", lineno, key);
    if (*slot)
        die("ztsl line %d: variable '%s' defined twice", lineno, key);
    *slot = xstrdup(val);
}

static void ztsl_parse(const char *path, struct ztsl *z)
{
    struct buf b = { 0 };
    if (read_file(path, &b, MAX_TEXT) < 0)
        die_errno("read %s", path);
    enum { S_BEGIN, S_BODY, S_OPTS, S_FUNC, S_FENCE, S_CODE, S_END } st = S_BEGIN;
    bool shell = false;
    struct buf code = { 0 };
    buf_reserve(&code, 0);
    int lineno = 0;
    char *p = b.d;
    while (p && *p && st != S_END) {
        char *nl = strchr(p, '\n');
        char *raw = xstrndup(p, nl ? (size_t)(nl - p) : strlen(p));
        p = nl ? nl + 1 : NULL;
        lineno++;
        char *line = trim(raw);
        if (st == S_CODE) {
            if (!strcmp(line, "```")) {
                if (shell) {
                    struct ztsl_step s = { true, NULL, xstrdup(code.d) };
                    ztsl_push(z, s);
                }
                code.len = 0;
                code.d[0] = '\0';
                st = S_BODY;
            } else if (shell) {
                buf_add(&code, line, strlen(line));
                buf_add(&code, "\n", 1);
            } else if (line[0] && line[0] != '#') {
                char **argv = tokenize(line, lineno);
                if (argv[0]) {
                    struct ztsl_step s = { false, argv, NULL };
                    ztsl_push(z, s);
                } else {
                    free(argv);
                }
            }
            free(raw);
            continue;
        }
        if (line[0] == '\0' || line[0] == '#' || !strcmp(line, "}")) {
            free(raw);
            continue;
        }
        switch (st) {
        case S_BEGIN:
            if (strcmp(line, "ztsl.start") != 0)
                die("ztsl line %d: the file must start with 'ztsl.start'", lineno);
            st = S_BODY;
            break;
        case S_BODY:
            if (!strcmp(line, "ztslo.start"))
                st = S_OPTS;
            else if (!strcmp(line, "func postinst"))
                st = S_FUNC;
            else if (!strcmp(line, "ztsl.end"))
                st = S_END;
            else
                die("ztsl line %d: unexpected '%s'", lineno, line);
            break;
        case S_OPTS:
            if (!strcmp(line, "ztslo.end"))
                st = S_BODY;
            else
                ztsl_define(z, line, lineno);
            break;
        case S_FUNC:
            if (strcmp(line, "sys.exec") != 0)
                die("ztsl line %d: expected 'sys.exec'", lineno);
            st = S_FENCE;
            break;
        case S_FENCE: {
            if (strncmp(line, "```", 3) != 0)
                die("ztsl line %d: expected a ```exec or ```shell block", lineno);
            char *kind = line + 3;
            size_t kl = strcspn(kind, " \t#");
            if (kl == 4 && !strncmp(kind, "exec", 4))
                shell = false;
            else if (kl == 5 && !strncmp(kind, "shell", 5))
                shell = true;
            else
                die("ztsl line %d: block type must be 'exec' or 'shell'", lineno);
            st = S_CODE;
            break;
        }
        default:
            break;
        }
        free(raw);
    }
    if (st != S_END)
        die("ztsl: unexpected end of file (missing 'ztsl.end' or an unterminated block)");
    buf_free(&code);
    buf_free(&b);
    if (!z->name || !z->distro)
        die("ztsl: NAME and DISTRO must be defined");
}

static void split_distro(const char *spec, char *d, size_t dn, char *v, size_t vn)
{
    const char *c = strrchr(spec, ':');
    if (c) {
        if ((size_t)(c - spec) >= dn)
            die("distro name too long");
        memcpy(d, spec, (size_t)(c - spec));
        d[c - spec] = '\0';
        pathf(v, vn, "%s", c + 1);
    } else {
        pathf(d, dn, "%s", spec);
        pathf(v, vn, "latest");
    }
    if (!valid_distro(d))
        die("invalid distro name '%s'", d);
    if (!valid_version(v))
        die("invalid distro version '%s'", v);
}

static void require_root(void)
{
    if (geteuid() != 0)
        die("nflxs must be run as root (rootless operation is not supported)");
}

static void ensure_state_dirs(void)
{
    if (mkdir_p(NFLXS_SANDBOXES, 0711) < 0)
        die_errno("mkdir %s", NFLXS_SANDBOXES);
    if (mkdir_p(NFLXS_IMAGES, 0755) < 0)
        die_errno("mkdir %s", NFLXS_IMAGES);
}

struct create_args {
    const char *name;
    const char *distro;
    const char *fs;
    const char *size;
    const char *file;
};

static void alloc_image(const struct sandbox *sb, uint64_t size)
{
    int fd = open(sb->img, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        die_errno("create %s", sb->img);
    if (fallocate(fd, 0, 0, (off_t)size) < 0) {
        if (errno == EOPNOTSUPP || errno == ENOSYS) {
            warnx_("the filesystem does not support fallocate; creating a sparse image");
            if (ftruncate(fd, (off_t)size) < 0)
                die_errno("ftruncate %s", sb->img);
        } else {
            die_errno("fallocate %llu bytes for %s", (unsigned long long)size, sb->img);
        }
    }
    if (close(fd) < 0)
        die_errno("close %s", sb->img);
}

/* Format a block device (a path like /dev/vg/lv or the disk image itself)
 * with the requested filesystem.  Dies on failure. */
static void format_with_fs(const char *target, const char *fs, const char *what)
{
    if (!strcmp(fs, "ext4")) {
        char *mk[] = { "mkfs.ext4", "-q", "-F", (char *)target, NULL };
        if (run_argv(mk) != 0) die("mkfs.ext4 failed on %s (is it installed?)", what);
    } else if (!strcmp(fs, "xfs")) {
        char *mk[] = { "mkfs.xfs", "-q", "-f", (char *)target, NULL };
        if (run_argv(mk) != 0) die("mkfs.xfs failed on %s (is it installed?)", what);
    } else if (!strcmp(fs, "btrfs")) {
        char *mk[] = { "mkfs.btrfs", "-q", "-f", (char *)target, NULL };
        if (run_argv(mk) != 0) die("mkfs.btrfs failed on %s (is it installed?)", what);
    } else {
        die("internal error: unsupported filesystem '%s'", fs);
    }
}

/* When NFLXS_DM_USE_LVM=1 is set in the environment, build an LVM stack
 * (PV -> VG -> LV) on top of the loop-backed image, then format the LV
 * with the user-chosen filesystem.  Returns the fd of the loop device
 * (kept open for the caller to drop after the LV is mounted) and fills
 * lv_dev with the path of the resulting block device.  On failure the
 * function dies; the registered atexit cleanup tears the VG down. */
static int create_lvm_underneath(struct sandbox *sb, struct progress *progress,
                                 char *lv_dev, size_t lv_dev_sz)
{
    char dev[64];
    int lfd = loop_attach(sb->img, dev, sizeof(dev));
    if (lfd < 0) die_errno("loop attach for LVM");

    char vg_name[80];
    lvm_vg_name(vg_name, sizeof(vg_name), sb->name);
    cleanup_set_vg(vg_name);

    char *pvcreate[] = { "pvcreate", "-ff", "-y", dev, NULL };
    char *vgcreate[] = { "vgcreate", "-y", vg_name, dev, NULL };

    progress_set_label(progress, "Creating LVM PV and VG");
    if (run_argv(pvcreate) != 0) die("pvcreate failed");
    if (run_argv(vgcreate) != 0) die("vgcreate failed");

    if (env_lvm_thin()) {
        char size_arg[32];
        snprintf(size_arg, sizeof(size_arg), "%llub",
                 (unsigned long long)sb->size);
        char thin_pool_arg[128];
        snprintf(thin_pool_arg, sizeof(thin_pool_arg), "%s/pool", vg_name);

        char *pool[] = { "lvcreate", "-y", "-T", thin_pool_arg, "-L", size_arg, NULL };
        progress_set_label(progress, "Creating LVM thin pool");
        if (run_argv(pool) != 0) die("lvcreate thin pool failed");

        char *vol[] = { "lvcreate", "-y", "-T", thin_pool_arg, "-V", size_arg, "-n", "root", NULL };
        progress_set_label(progress, "Creating LVM thin volume");
        if (run_argv(vol) != 0) die("lvcreate thin volume failed");
    } else {
        char *lvcreate[] = { "lvcreate", "-y", "-n", "root", "-l", "100%FREE", vg_name, NULL };
        progress_set_label(progress, "Creating LVM volume");
        if (run_argv(lvcreate) != 0) die("lvcreate failed");
    }

    snprintf(lv_dev, lv_dev_sz, "/dev/%s/root", vg_name);

    progress_set_label(progress, "Formatting %s on LVM", sb->fs);
    format_with_fs(lv_dev, sb->fs, lv_dev);

    return lfd;
}

static void create_worker(struct sandbox *sb, const char *cache, const struct ztsl *z)
{
    make_mounts_private();
    if (mkdir(sb->rootfs, 0755) < 0)
        die_errno("mkdir %s", sb->rootfs);
    struct progress progress;
    progress_begin(&progress, 3 + (sb->fs[0] ? 2 : 0) + z->n, "Creating sandbox %s", sb->name);
    if (sb->fs[0]) {
        /* The chosen fs is one of ext4/xfs/btrfs (already validated by the
         * caller).  When NFLXS_DM_USE_LVM=1, an LVM stack is built between
         * the disk image and the chosen fs; the meta file then records
         * lvm=1 so subsequent mounts/deletes know to talk to LVM. */
        if (sb->lvm && !env_lvm_enabled())
            die("sandbox meta requires LVM but NFLXS_DM_USE_LVM is not 1");
        sb->lvm = env_lvm_enabled();

        progress_set_label(&progress, "Allocating %s disk image%s",
                           sb->fs, sb->lvm ? " (LVM underneath)" : "");
        alloc_image(sb, sb->size);
        progress_advance(&progress);

        if (sb->lvm) {
            char lv_dev[96];
            /* lfd stays open until the LV is mounted (see below). */
            int lfd = create_lvm_underneath(sb, &progress, lv_dev, sizeof(lv_dev));
            /* The mount in sandbox_mount_image would re-attach the loop
             * device a second time.  Instead we mount the LV directly
             * here while we still hold the loop fd, then close it. */
            if (mount(lv_dev, sb->rootfs, sb->fs, MS_NODEV, NULL) < 0) {
                int e = errno;
                close(lfd);
                errno = e;
                die_errno("mount %s (%s) on %s", lv_dev, sb->fs, sb->rootfs);
            }
            close(lfd);
        } else {
            progress_set_label(&progress, "Formatting %s filesystem", sb->fs);
            format_with_fs(sb->img, sb->fs, sb->img);
            sandbox_mount_image(sb);
        }
        progress_advance(&progress);
    }
    char src[PATH_MAX], dst[PATH_MAX];
    pathf(src, sizeof(src), "%s/.", cache);
    pathf(dst, sizeof(dst), "%s/", sb->rootfs);
    char *cp[] = { "cp", "-a", "--reflink=auto", "--", src, dst, NULL };
    progress_set_label(&progress, "Installing root filesystem");
    if (run_argv(cp) != 0)
        die("failed to copy the image into the sandbox");
    progress_advance(&progress);
    if (chmod(sb->rootfs, 0755) < 0)
        die_errno("chmod %s", sb->rootfs);
    progress_set_label(&progress, "Creating default user");
    provision_user(sb->rootfs, sb->user);
    progress_advance(&progress);
    progress_set_label(&progress, "Saving sandbox configuration");
    sandbox_save(sb);
    progress_advance(&progress);
    for (size_t i = 0; i < z->n; i++) {
        struct run_opts o;
        memset(&o, 0, sizeof(o));
        o.as_root = true;
        char *shargv[] = { "/bin/sh", "-c", z->steps[i].text, NULL };
        o.argv = z->steps[i].shell ? shargv : z->steps[i].argv;
        progress_set_label(&progress, "Running post-install step %zu/%zu", i + 1, z->n);
        int rc = container_run(sb, &o);
        if (rc != 0)
            die("postinst step %zu failed with status %d", i + 1, rc);
        progress_advance(&progress);
    }
}

static void cmd_create(const struct create_args *a)
{
    struct ztsl z;
    memset(&z, 0, sizeof(z));
    if (a->file)
        ztsl_parse(a->file, &z);
    const char *name = a->name ? a->name : z.name;
    const char *spec = a->distro ? a->distro : z.distro;
    const char *fs = a->fs ? a->fs : z.fs;
    const char *size_s = a->size ? a->size : z.size;
    if (!name)
        die("missing sandbox name (-n)");
    if (!spec)
        die("missing distribution (-d distro:version)");
    if (size_s && !fs) {
        if (a->size)
            die("-s requires -fs");
        fs = "ext4";
    }
    if (fs && !size_s)
        die("-fs requires -s (size)");
    char distro[160], version[160];
    split_distro(spec, distro, sizeof(distro), version, sizeof(version));
    uint64_t size = 0;
    bool want_lvm = env_lvm_enabled();
    if (fs) {
        /* Reject -fs lvm explicitly: LVM is no longer a top-level filesystem
         * choice.  It is a stack underneath ext4/xfs/btrfs, gated by
         * NFLXS_DM_USE_LVM=1. */
        if (!strcmp(fs, "lvm"))
            die("-fs lvm is not supported; use -fs ext4|xfs|btrfs together with NFLXS_DM_USE_LVM=1");
        if (!valid_fs(fs))
            die("unsupported filesystem '%s' (supported: ext4, xfs, btrfs)", fs);
        if (!parse_size(size_s, "MG", &size))
            die("invalid size '%s' (examples: 512M, 20G)", size_s);
        uint64_t min = ((uint64_t)64 << 20);
        if (!strcmp(fs, "xfs")) min = ((uint64_t)300 << 20);
        else if (!strcmp(fs, "btrfs")) min = ((uint64_t)100 << 20);
        /* When LVM is layered underneath, the chosen fs still has to fit on
         * the LV, so the same per-fs minimum applies; the LVM metadata
         * overhead is small enough that the existing minimums are safe. */
        if (size < min)
            die("the minimum size for %s is %lluM", fs, (unsigned long long)(min >> 20));
        if (size > ((uint64_t)1 << 50))
            die("size too large");
    }
    if (want_lvm && !fs)
        die("NFLXS_DM_USE_LVM=1 requires -fs (one of ext4, xfs, btrfs) and -s");
    require_root();
    struct sandbox sb;
    sandbox_paths(&sb, name);
    if (fs)
        pathf(sb.fs, sizeof(sb.fs), "%s", fs);
    sb.size = size;
    sb.lvm = want_lvm;
    pathf(sb.distro, sizeof(sb.distro), "%s", distro);
    pathf(sb.version, sizeof(sb.version), "%s", version);
    default_user(distro, sb.user, sizeof(sb.user));
    ensure_state_dirs();
    char cache[PATH_MAX];
    ensure_image(distro, version, cache, sizeof(cache));
    if (mkdir(sb.dir, 0700) < 0) {
        if (errno == EEXIST)
            die("sandbox '%s' already exists", name);
        die_errno("mkdir %s", sb.dir);
    }
    cleanup_set(sb.dir);
    fflush(NULL);
    pid_t w = fork();
    if (w < 0)
        die_errno("fork");
    if (w == 0) {
        create_worker(&sb, cache, &z);
        exit(0);
    }
    int rc = wait_pid(w);
    if (rc != 0)
        die("failed to create sandbox '%s'", name);
    cleanup_clear();
    printf("Sandbox '%s' created (%s:%s)\n", name, distro, version);
    if (sb.lvm)
        printf("LVM volume group: nflxs_%s\n", name);
    printf("Default user: %s  Password: %s\n", sb.user, sb.user);
    ztsl_free(&z);
}

static void cmd_delete(const char *name)
{
    require_root();
    struct sandbox sb;
    sandbox_paths(&sb, name);
    struct stat st;
    if (lstat(sb.dir, &st) < 0 || !S_ISDIR(st.st_mode))
        die("sandbox '%s' does not exist", name);
    sandbox_lock(&sb);
    if (path_has_mounts(sb.dir))
        die("sandbox '%s' still has active mounts; refusing to delete", name);

    /* Decide whether the sandbox owns an LVM VG.  We prefer the new
     * `lvm=1` meta key, but also fall back to the legacy `fs=lvm` form
     * so that sandboxes created by older nflxs builds are still torn
     * down correctly. */
    bool has_lvm = false;
    struct buf meta = {0};
    if (read_file(sb.meta, &meta, 4096) == 0) {
        char *save = NULL;
        for (char *line = strtok_r(meta.d, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            if (!strcmp(line, "lvm") && !strcmp(eq + 1, "1")) {
                has_lvm = true;
                break;
            }
            if (!strcmp(line, "fs") && !strcmp(eq + 1, "lvm")) {
                has_lvm = true;
                break;
            }
        }
    }
    buf_free(&meta);

    if (has_lvm) {
        char vg_name[80];
        lvm_vg_name(vg_name, sizeof(vg_name), name);
        /* vgchange -a n first so the loop device is released; then
         * vgremove -ff to drop the VG/PV metadata.  Errors are non-fatal
         * because the sandbox dir is still removed below; we only warn. */
        char *vgchange[] = { "vgchange", "-a", "n", vg_name, NULL };
        run_argv(vgchange);
        char *vgremove[] = { "vgremove", "-ff", "--", vg_name, NULL };
        if (run_argv(vgremove) != 0)
            warnx_("vgremove %s failed; the VG may have to be cleaned up manually", vg_name);
    }

    struct progress progress;
    progress_begin(&progress, 1, "Deleting sandbox %s", name);
    char *rm[] = { "rm", "-rf", "--one-file-system", "--", sb.dir, NULL };
    if (run_argv(rm) != 0 || path_exists(sb.dir))
        die("failed to remove %s", sb.dir);
    progress_advance(&progress);
    printf("Sandbox '%s' deleted\n", name);
}

static int cmd_enter(const char *name, bool as_root, bool no_net, const char *cpu_s, const char *mem_s, char **cmd)
{
    struct run_opts o;
    memset(&o, 0, sizeof(o));
    if (cpu_s && !parse_cpu(cpu_s, &o.cpu_milli))
        die("invalid CPU limit '%s' (examples: 2, 0.5)", cpu_s);
    if (mem_s && !parse_size(mem_s, "KMG", &o.mem))
        die("invalid memory limit '%s' (examples: 512M, 4G)", mem_s);
    if (o.mem && o.mem < ((uint64_t)4 << 20))
        die("the minimum memory limit is 4M");
    require_root();
    struct sandbox sb;
    sandbox_load(&sb, name);
    sandbox_lock(&sb);
    o.as_root = as_root;
    o.no_net = no_net;
    o.interactive = true;
    o.argv = cmd;
    make_mounts_private();
    if (sb.fs[0])
        sandbox_mount_image(&sb);
    return container_run(&sb, &o);
}

static void cmd_export(const char *name, const char *outfile)
{
    require_root();
    struct sandbox sb;
    sandbox_load(&sb, name);
    sandbox_lock(&sb);
    make_mounts_private();
    if (sb.fs[0])
        sandbox_mount_image(&sb);
    struct progress progress;
    progress_begin(&progress, 1, "Exporting sandbox %s to %s", name, outfile ? outfile : "stdout");
    char *tar_argv[10];
    int ti = 0;
    tar_argv[ti++] = "tar";
    tar_argv[ti++] = "--xattrs";
    tar_argv[ti++] = "--acls";
    tar_argv[ti++] = "-cf";
    if (outfile)
        tar_argv[ti++] = (char *)outfile;
    else
        tar_argv[ti++] = "-";
    tar_argv[ti++] = "-C";
    tar_argv[ti++] = sb.rootfs;
    tar_argv[ti++] = ".";
    tar_argv[ti] = NULL;
    if (run_argv(tar_argv) != 0)
        die("failed to export sandbox '%s'", name);
    progress_advance(&progress);
    printf("Sandbox '%s' exported\n", name);
}

static void format_size(uint64_t v, char *out, size_t n)
{
    if (v == 0)
        snprintf(out, n, "-");
    else if (v % ((uint64_t)1 << 30) == 0)
        snprintf(out, n, "%lluG", (unsigned long long)(v >> 30));
    else
        snprintf(out, n, "%lluM", (unsigned long long)(v >> 20));
}

static void cmd_list(void)
{
    require_root();
    DIR *d = opendir(NFLXS_SANDBOXES);
    if (!d) {
        if (errno == ENOENT) {
            puts("no sandboxes");
            return;
        }
        die_errno("open %s", NFLXS_SANDBOXES);
    }
    printf("%-24s %-28s %-10s %-8s %s\n", "NAME", "IMAGE", "FS", "SIZE", "USER");
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' || !valid_name(de->d_name))
            continue;
        struct sandbox sb;
        if (sandbox_try_load(&sb, de->d_name) != 0)
            continue;
        char img[330], sz[24], fsbuf[24];
        snprintf(img, sizeof(img), "%s:%s", sb.distro, sb.version);
        format_size(sb.size, sz, sizeof(sz));
        if (!sb.fs[0])
            snprintf(fsbuf, sizeof(fsbuf), "dir");
        else if (sb.lvm)
            snprintf(fsbuf, sizeof(fsbuf), "%s+lvm", sb.fs);
        else
            snprintf(fsbuf, sizeof(fsbuf), "%s", sb.fs);
        printf("%-24s %-28s %-10s %-8s %s\n", sb.name, img, fsbuf, sz, sb.user);
    }
    closedir(d);
}

static void print_help(void)
{
    printf("\x1b[1m\x1b[36mnflxs %s\x1b[0m \xe2\x80\x94 %s\n", NFLXS_VERSION, host_arch());
    puts("\n"
         "\x1b[1mUsage:\x1b[0m\n"
         "  nflxs <command> [options]\n"
         "  nflxs help | -h | --help\n"
         "  nflxs -v | --version\n"
         "\n"
         "\x1b[1mCommands:\x1b[0m\n"
         "  \x1b[32m-c\x1b[0m    Create a sandbox from a distribution image or ZTSL file\n"
         "  \x1b[32m-e\x1b[0m    Start an interactive session or run a command in a sandbox\n"
         "  \x1b[32m-d\x1b[0m    Permanently delete a sandbox\n"
         "  \x1b[32m-x\x1b[0m    Export a sandbox rootfs as a tar archive\n"
         "  \x1b[32m-l\x1b[0m    List available sandboxes\n"
         "\n"
         "\x1b[1mCreate a sandbox:\x1b[0m\n"
         "  nflxs -c -n NAME -d DISTRO[:VERSION] [-fs FS -s SIZE]\n"
         "  nflxs -c -f FILE.ztsl [-n NAME] [-d DISTRO[:VERSION]] [-fs FS -s SIZE]\n"
         "\n"
         "  \x1b[33m-n\x1b[0m NAME             Sandbox name; up to 63 letters, numbers, '.', '_' or '-'\n"
         "  \x1b[33m-d\x1b[0m DISTRO[:VERSION] Distribution image (for example, debian:trixie)\n"
         "                        VERSION defaults to latest\n"
         "  \x1b[33m-f\x1b[0m FILE              Read the build description from a ZTSL file\n"
         "  \x1b[33m-fs\x1b[0m FS               Use a fixed-size ext4, xfs, or btrfs disk image\n"
         "  \x1b[33m-s\x1b[0m SIZE              Disk image size (for example, 512M or 20G); required with\n"
         "                        -fs. Minimum: 64M for ext4; 300M for xfs; 100M for btrfs\n"
         "\n"
         "\x1b[1mLVM underneath the filesystem:\x1b[0m\n"
         "  When NFLXS_DM_USE_LVM=1 is set in the environment, the chosen filesystem\n"
         "  (ext4, xfs or btrfs) is built on top of an LVM volume: loop -> PV -> VG\n"
         "  'nflxs_<name>' -> LV 'root' -> mkfs.<fs>.  Set NFLXS_DM_USE_LVM_THIN=1 to\n"
         "  use a thin pool instead of a regular LV.  -fs lvm is no longer accepted;\n"
         "  LVM is purely an opt-in storage layer controlled by the environment.\n"
         "\n"
         "\x1b[1mEnter a sandbox:\x1b[0m\n"
         "  nflxs -e -n NAME [-r] [-c CPUS] [-m MEMORY] [--no-net] [-- COMMAND [ARGS...]]\n"
         "\n"
         "  \x1b[33m-n\x1b[0m NAME             Sandbox name\n"
         "  \x1b[33m-r\x1b[0m                  Run as root instead of the default distribution user\n"
         "  \x1b[33m-c\x1b[0m CPUS             CPU limit in cores (for example, 8 or 0.5)\n"
         "  \x1b[33m-m\x1b[0m MEMORY           Memory limit (for example, 512M or 4G); disables swap\n"
         "  \x1b[33m--no-net\x1b[0m            Start with loopback-only networking\n"
         "  -- COMMAND          Run COMMAND instead of a login shell\n"
         "\n"
         "\x1b[1mExport a sandbox:\x1b[0m\n"
         "  nflxs -x -n NAME [-o OUTPUT.tar]\n"
         "\n"
         "  \x1b[33m-n\x1b[0m NAME             Sandbox name to export\n"
         "  \x1b[33m-o\x1b[0m OUTPUT.tar       Output tar file (defaults to stdout)\n"
         "\n"
         "\x1b[1mDelete a sandbox:\x1b[0m\n"
         "  nflxs -d -n NAME\n"
         "\n"
         "\x1b[1mExamples:\x1b[0m\n"
         "  \x1b[34mnflxs -c -n web -d debian:trixie\x1b[0m\n"
         "  \x1b[34mnflxs -c -n dev -d ubuntu:24.04 -fs ext4 -s 20G\x1b[0m\n"
         "  \x1b[34mnflxs -c -f build.ztsl\x1b[0m\n"
         "  \x1b[34mnflxs -e -n dev -c 8 -m 4G\x1b[0m\n"
         "  \x1b[34mnflxs -e -n dev -- uname -a\x1b[0m\n"
         "  \x1b[34mnflxs -x -n dev -o dev-backup.tar\x1b[0m\n"
         "  \x1b[34mnflxs -x -n dev | gzip > dev-backup.tar.gz\x1b[0m\n"
         "\n"
         "\x1b[1mZTSL build files:\x1b[0m\n"
         "  ztsl.start -> ztslo.start -> variable definitions -> ztslo.end -> postinst ->\n"
         "  ztsl.end. NAME and DISTRO are required; SIZE and FS are optional. The postinst\n"
         "  function uses sys.exec with an ```exec or ```shell block. Commands run as root;\n"
         "  a failed step aborts creation and removes the sandbox.\n"
         "\n"
         "\x1b[1mDefault credentials:\x1b[0m\n"
         "  The default username and password match the distribution (for example,\n"
         "  debian/debian). Root has no password; use -r to enter as root.\n"
         "\n"
         "\x1b[1mIsolation:\x1b[0m\n"
         "  nflxs uses mount, PID, UTS and IPC namespaces, cgroup v2 limits, pivot_root,\n"
         "  a default-deny seccomp policy with KILL_PROCESS for kernel-modifying syscalls,\n"
         "  reduced capabilities, no_new_privs, PR_SET_DUMPABLE(0), and hardened umask.\n"
         "  X11, Wayland and /dev/dri are exposed when available. One session per sandbox.\n"
         "\n"
         "\x1b[1mEnvironment:\x1b[0m\n"
         "  TERM is forced to xterm.\n"
         "  NFLXS_DM_USE_LVM=1         Build a PV/VG/LV stack underneath -fs (see above).\n"
         "  NFLXS_DM_USE_LVM_THIN=1    Use a thin pool when NFLXS_DM_USE_LVM=1 is set.\n"
         "\n"
         "\x1b[1mData paths:\x1b[0m\n"
         "  /nsm/nflxs/sandboxes/NAME      Sandbox rootfs, disk image and metadata\n"
         "  /nsm/nflxs/images/rootfs-*     Cached distribution images\n"
         "\n"
         "\x1b[1mRequirements:\x1b[0m\n"
         "  Root, Linux 5.6+, cgroup v2, curl, gzip, and mkfs.ext4, mkfs.xfs or mkfs.btrfs\n"
         "  when using -fs. Some images also require zstd or xz.  When\n"
         "  NFLXS_DM_USE_LVM=1 is set, lvm2 (pvcreate, vgcreate, lvcreate, vgchange,\n"
         "  vgremove) must also be installed.\n"
         "\n"
         "\x1b[1mExit status:\x1b[0m\n"
         "  0 on success; 1 on nflxs errors. With -e, the sandbox command's status is\n"
         "  returned (128+N when terminated by signal N).");
}

static const char *opt_value(int argc, char **argv, int *i, const char *eq, const char *flag)
{
    if (eq)
        return eq;
    if (*i + 1 >= argc)
        die("option %s requires a value", flag);
    return argv[++*i];
}

static void set_once(const char **slot, const char *v, const char *flag)
{
    if (*slot)
        die("option %s given more than once", flag);
    *slot = v;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        print_help();
        return 0;
    }
    if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
        printf("nflxs %s \xe2\x80\x94 %s\n", NFLXS_VERSION, host_arch());
        return 0;
    }
    const char *cmd = argv[1];
    const char *name = NULL, *distro = NULL, *fs = NULL, *size = NULL, *file = NULL, *cpu = NULL, *mem = NULL, *outfile = NULL;
    bool root = false, nonet = false;
    char **run_cmd = NULL;
    bool is_c = !strcmp(cmd, "-c"), is_d = !strcmp(cmd, "-d"), is_e = !strcmp(cmd, "-e"), is_l = !strcmp(cmd, "-l"), is_x = !strcmp(cmd, "-x");
    if (!is_c && !is_d && !is_e && !is_l && !is_x)
        die("unknown command '%s'; run 'nflxs help' for usage", cmd);
    for (int i = 2; i < argc; i++) {
        char *a = argv[i];
        if (!strcmp(a, "--")) {
            if (!is_e)
                die("'--' is only valid with -e");
            if (i + 1 >= argc)
                die("missing command after '--'");
            run_cmd = &argv[i + 1];
            break;
        }
        char key[32];
        char *eq = strchr(a, '=');
        size_t kl = eq ? (size_t)(eq - a) : strlen(a);
        if (kl == 0 || kl >= sizeof(key))
            die("unknown option '%s'", a);
        memcpy(key, a, kl);
        key[kl] = '\0';
        const char *ev = eq ? eq + 1 : NULL;
        if (!strcmp(key, "-n") && !is_l)
            set_once(&name, opt_value(argc, argv, &i, ev, "-n"), "-n");
        else if (!strcmp(key, "-d") && is_c)
            set_once(&distro, opt_value(argc, argv, &i, ev, "-d"), "-d");
        else if (!strcmp(key, "-fs") && is_c)
            set_once(&fs, opt_value(argc, argv, &i, ev, "-fs"), "-fs");
        else if (!strcmp(key, "-s") && is_c)
            set_once(&size, opt_value(argc, argv, &i, ev, "-s"), "-s");
        else if (!strcmp(key, "-f") && is_c)
            set_once(&file, opt_value(argc, argv, &i, ev, "-f"), "-f");
        else if (!strcmp(key, "-r") && is_e && !eq)
            root = true;
        else if (!strcmp(key, "--no-net") && is_e && !eq)
            nonet = true;
        else if (!strcmp(key, "-c") && is_e)
            set_once(&cpu, opt_value(argc, argv, &i, ev, "-c"), "-c");
        else if (!strcmp(key, "-m") && is_e)
            set_once(&mem, opt_value(argc, argv, &i, ev, "-m"), "-m");
        else if (!strcmp(key, "-o") && is_x)
            set_once(&outfile, opt_value(argc, argv, &i, ev, "-o"), "-o");
        else
            die("unknown or misplaced option '%s' for %s; run 'nflxs help' for usage", a, cmd);
    }
    if (is_l) {
        cmd_list();
        return 0;
    }
    if (is_c) {
        struct create_args ca = { name, distro, fs, size, file };
        if (!name && !file)
            die("missing sandbox name (-n)");
        if (!distro && !file)
            die("missing distribution (-d distro:version)");
        cmd_create(&ca);
        return 0;
    }
    if (!name)
        die("missing sandbox name (-n)");
    if (is_d) {
        cmd_delete(name);
        return 0;
    }
    if (is_x) {
        cmd_export(name, outfile);
        return 0;
    }
    return cmd_enter(name, root, nonet, cpu, mem, run_cmd);
}
