#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PACKAGES_FILE "/etc/weld/packages.weld"
#define UNIT_PATH "/etc/systemd/system/arvor-declaration.service"
#define UNIT_NAME "arvor-declaration.service"
#define SAFE_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define NAME_BUF 512
#define SELF_BUF 4096

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} StrList;

static void strlist_free(StrList *l)
{
    size_t i;

    if (l == NULL)
        return;
    for (i = 0; i < l->count; i++)
        free(l->items[i]);
    free(l->items);
    l->items = NULL;
    l->count = 0;
    l->cap = 0;
}

static bool strlist_push_unique(StrList *l, const char *s)
{
    size_t i;
    size_t ncap;
    char **grown;
    char *dup;

    if (l == NULL || s == NULL)
        return false;
    for (i = 0; i < l->count; i++) {
        if (strcmp(l->items[i], s) == 0)
            return true;
    }
    if (l->count == l->cap) {
        ncap = (l->cap == 0) ? 16 : l->cap * 2;
        if (ncap < l->cap)
            return false;
        grown = realloc(l->items, ncap * sizeof(char *));
        if (grown == NULL)
            return false;
        l->items = grown;
        l->cap = ncap;
    }
    dup = strdup(s);
    if (dup == NULL)
        return false;
    l->items[l->count] = dup;
    l->count++;
    return true;
}

static bool strlist_contains(const StrList *l, const char *s)
{
    size_t i;

    if (l == NULL || s == NULL)
        return false;
    for (i = 0; i < l->count; i++) {
        if (strcmp(l->items[i], s) == 0)
            return true;
    }
    return false;
}

static char *trim(char *s)
{
    size_t len;

    if (s == NULL)
        return NULL;
    while (*s != '\0' && isspace((unsigned char)*s))
        s++;
    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
    return s;
}

static void strip_comment(char *s)
{
    bool in_str = false;
    char quote = '\0';
    char prev = ' ';
    size_t i;

    if (s == NULL)
        return;
    for (i = 0; s[i] != '\0'; i++) {
        char c = s[i];

        if (in_str) {
            if (c == quote)
                in_str = false;
        } else if (c == '"' || c == '\'') {
            in_str = true;
            quote = c;
        } else if (c == '#' && (i == 0 || prev == ' ' || prev == '\t')) {
            s[i] = '\0';
            return;
        }
        prev = c;
    }
}

static void strip_quotes(char *s)
{
    size_t len;

    if (s == NULL)
        return;
    len = strlen(s);
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') ||
                     (s[0] == '\'' && s[len - 1] == '\''))) {
        s[len - 1] = '\0';
        memmove(s, s + 1, len - 1);
    }
}

static bool valid_package_name(const char *s)
{
    size_t i;
    size_t len;

    if (s == NULL || s[0] == '\0')
        return false;
    len = strlen(s);
    if (len > 256)
        return false;
    if (!isalnum((unsigned char)s[0]))
        return false;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];

        if (!(islower(c) || isdigit(c) || c == '+' || c == '-' || c == '.'))
            return false;
    }
    return true;
}

static bool is_repo_group(const char *name)
{
    size_t len;
    const char *suffix = ".repositories";
    size_t slen;

    if (name == NULL)
        return true;
    if (strcmp(name, "weld.repositories") == 0 ||
        strcmp(name, "apt.repositories") == 0)
        return true;
    len = strlen(name);
    slen = strlen(suffix);
    if (len > slen && strcmp(name + (len - slen), suffix) == 0)
        return true;
    return false;
}

static void copy_name(char *dst, size_t dstsz, const char *src)
{
    size_t i;

    if (dst == NULL || dstsz == 0)
        return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    for (i = 0; i + 1 < dstsz && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

static int wait_child(pid_t pid)
{
    int status = 0;

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 1;
}

static int run_cmd(const char *prog, char *const argv[])
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp(prog, argv);
        _exit(127);
    }
    return wait_child(pid);
}

static bool parse_weld_packages(const char *path, StrList *out)
{
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    bool in_group = false;
    bool group_is_package = false;
    char group_name[NAME_BUF];
    char pkg_name[NAME_BUF];

    group_name[0] = '\0';
    pkg_name[0] = '\0';
    f = fopen(path, "r");
    if (f == NULL)
        return false;
    while (getline(&line, &cap, f) != -1) {
        char *t;

        strip_comment(line);
        t = trim(line);
        if (t[0] == '\0')
            continue;
        if (!in_group) {
            if (strcmp(t, "Wld.end") == 0)
                break;
            if (strncmp(t, "group", 5) == 0 &&
                (t[5] == ' ' || t[5] == '\t')) {
                char *name = trim(t + 5);

                strip_quotes(name);
                copy_name(group_name, sizeof(group_name), name);
                in_group = true;
                group_is_package = !is_repo_group(group_name);
                if (group_is_package)
                    copy_name(pkg_name, sizeof(pkg_name), group_name);
                else
                    copy_name(pkg_name, sizeof(pkg_name), NULL);
            }
        } else if (strcmp(t, "end") == 0) {
            if (group_is_package && valid_package_name(pkg_name)) {
                if (!strlist_push_unique(out, pkg_name)) {
                    fprintf(stderr, "E: out of memory\n");
                    free(line);
                    fclose(f);
                    return false;
                }
            }
            in_group = false;
            group_is_package = false;
            group_name[0] = '\0';
            pkg_name[0] = '\0';
        } else {
            char *colon = strchr(t, ':');

            if (colon != NULL && group_is_package) {
                char *key;
                char *val;

                *colon = '\0';
                key = trim(t);
                val = trim(colon + 1);
                strip_quotes(val);
                if (strcasecmp(key, "Name") == 0)
                    copy_name(pkg_name, sizeof(pkg_name), val);
            }
        }
    }
    free(line);
    if (ferror(f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    return true;
}

static bool read_dpkg_installed(StrList *out)
{
    int pipefd[2];
    pid_t pid;
    FILE *rp;
    char *line = NULL;
    size_t cap = 0;
    bool ok = true;
    char *const dq_argv[] = {
        (char *)"dpkg-query", (char *)"-W",
        (char *)"-f=${db:Status-Status}\\t${Package}\\n", NULL
    };

    if (pipe(pipefd) != 0)
        return false;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }
    if (pid == 0) {
        int devnull;

        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        if (pipefd[1] != STDOUT_FILENO)
            close(pipefd[1]);
        devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            if (dup2(devnull, STDIN_FILENO) < 0)
                _exit(127);
            close(devnull);
        }
        execvp("dpkg-query", dq_argv);
        _exit(127);
    }
    close(pipefd[1]);
    rp = fdopen(pipefd[0], "r");
    if (rp == NULL) {
        close(pipefd[0]);
        wait_child(pid);
        return false;
    }
    while (getline(&line, &cap, rp) != -1) {
        if (strncmp(line, "installed\t", 10) == 0) {
            char *pkg = trim(line + 10);

            if (valid_package_name(pkg)) {
                if (!strlist_push_unique(out, pkg))
                    ok = false;
            }
        }
    }
    free(line);
    fclose(rp);
    if (wait_child(pid) != 0)
        ok = false;
    return ok;
}

static int run_weld(const char *action, const char *pkg)
{
    char *const w_argv[] = {
        (char *)"weld", (char *)action, (char *)pkg,
        (char *)"--apply-host", NULL
    };
    pid_t pid;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp("weld", w_argv);
        _exit(127);
    }
    return wait_child(pid);
}

static bool get_self_path(char *buf, size_t bufsz)
{
    ssize_t n;

    if (buf == NULL || bufsz < 2)
        return false;
    n = readlink("/proc/self/exe", buf, bufsz - 1);
    if (n < 0)
        return false;
    if ((size_t)n > bufsz - 2) {
        errno = ENAMETOOLONG;
        return false;
    }
    buf[n] = '\0';
    return true;
}

static bool write_unit_file(const char *self_path)
{
    FILE *f;
    int rc;

    f = fopen(UNIT_PATH, "w");
    if (f == NULL)
        return false;
    rc = fprintf(f,
                 "[Unit]\n"
                 "Description=Arvor package declaration sync\n"
                 "Wants=network-online.target\n"
                 "After=network-online.target\n"
                 "ConditionPathExists=" PACKAGES_FILE "\n"
                 "\n"
                 "[Service]\n"
                 "Type=oneshot\n"
                 "ExecStart=%s --daemon\n"
                 "TimeoutStartSec=0\n"
                 "RemainAfterExit=yes\n"
                 "\n"
                 "[Install]\n"
                 "WantedBy=multi-user.target\n",
                 self_path);
    if (rc < 0) {
        fclose(f);
        return false;
    }
    if (fclose(f) != 0)
        return false;
    if (chmod(UNIT_PATH, 0644) != 0)
        return false;
    return true;
}

static int do_enable(void)
{
    char self_path[SELF_BUF];
    char *const reload_argv[] = {
        (char *)"systemctl", (char *)"daemon-reload", NULL
    };
    char *const enable_argv[] = {
        (char *)"systemctl", (char *)"enable", (char *)"--now",
        (char *)UNIT_NAME, NULL
    };

    if (!get_self_path(self_path, sizeof(self_path))) {
        fprintf(stderr, "E: cannot resolve executable path\n");
        return 1;
    }
    if (strpbrk(self_path, " \t\n") != NULL) {
        fprintf(stderr, "E: executable path contains spaces\n");
        return 1;
    }
    if (access(UNIT_PATH, F_OK) != 0) {
        if (!write_unit_file(self_path)) {
            fprintf(stderr, "E: cannot create %s\n", UNIT_PATH);
            return 1;
        }
        printf("I: created %s\n", UNIT_PATH);
    }
    if (run_cmd("systemctl", reload_argv) != 0) {
        fprintf(stderr, "E: systemctl daemon-reload failed\n");
        return 1;
    }
    if (run_cmd("systemctl", enable_argv) != 0) {
        fprintf(stderr, "E: cannot enable %s\n", UNIT_NAME);
        return 1;
    }
    printf("I: %s enabled\n", UNIT_NAME);
    return 0;
}

static int do_disable(void)
{
    char *const disable_argv[] = {
        (char *)"systemctl", (char *)"disable", (char *)"--now",
        (char *)UNIT_NAME, NULL
    };

    if (access(UNIT_PATH, F_OK) != 0) {
        printf("I: %s is not installed\n", UNIT_NAME);
        return 0;
    }
    if (run_cmd("systemctl", disable_argv) != 0) {
        fprintf(stderr, "E: cannot disable %s\n", UNIT_NAME);
        return 1;
    }
    printf("I: %s disabled\n", UNIT_NAME);
    return 0;
}

static int do_sync(void)
{
    StrList weld_pkgs = {NULL, 0, 0};
    StrList dpkg_pkgs = {NULL, 0, 0};
    int exit_code = 0;
    size_t i;
    int rc;

    if (setenv("PATH", SAFE_PATH, 1) != 0) {
        fprintf(stderr, "E: cannot set PATH\n");
        return 1;
    }
    if (!parse_weld_packages(PACKAGES_FILE, &weld_pkgs)) {
        fprintf(stderr, "E: cannot read %s\n", PACKAGES_FILE);
        strlist_free(&weld_pkgs);
        return 1;
    }
    if (weld_pkgs.count == 0) {
        fprintf(stderr, "W: no packages declared in %s\n", PACKAGES_FILE);
        strlist_free(&weld_pkgs);
        return 0;
    }
    if (!read_dpkg_installed(&dpkg_pkgs)) {
        fprintf(stderr, "E: cannot query dpkg database\n");
        strlist_free(&weld_pkgs);
        strlist_free(&dpkg_pkgs);
        return 1;
    }
    for (i = 0; i < dpkg_pkgs.count; i++) {
        if (!strlist_contains(&weld_pkgs, dpkg_pkgs.items[i])) {
            printf("I: removing %s\n", dpkg_pkgs.items[i]);
            rc = run_weld("remove", dpkg_pkgs.items[i]);
            if (rc != 0) {
                fprintf(stderr, "E: weld remove %s failed with code %d\n",
                        dpkg_pkgs.items[i], rc);
                exit_code = 1;
            }
        }
    }
    for (i = 0; i < weld_pkgs.count; i++) {
        if (!strlist_contains(&dpkg_pkgs, weld_pkgs.items[i])) {
            printf("I: installing %s\n", weld_pkgs.items[i]);
            rc = run_weld("install", weld_pkgs.items[i]);
            if (rc != 0) {
                fprintf(stderr, "E: weld install %s failed with code %d\n",
                        weld_pkgs.items[i], rc);
                exit_code = 1;
            }
        }
    }
    strlist_free(&weld_pkgs);
    strlist_free(&dpkg_pkgs);
    return exit_code;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (geteuid() != 0) {
        fprintf(stderr, "E: Root Privileges Required\n");
        return 1;
    }
    if (argc == 2 && strcmp(argv[1], "--daemon") == 0)
        return do_sync();
    if (argc == 2 && strcmp(argv[1], "true") == 0)
        return do_enable();
    if (argc == 2 && strcmp(argv[1], "false") == 0)
        return do_disable();
    fprintf(stderr, "E: invalid argument\n");
    return 1;
}
