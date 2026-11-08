#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

static void run_standard_execve(void) {
    char *argv[] = {"/bin/true", NULL};
    char *envp[] = {NULL};
    execve("/bin/true", argv, envp);
    perror("execve");
    exit(1);
}

static void run_direct_syscall(void) {
    char *argv[] = {"/bin/true", NULL};
    char *envp[] = {NULL};
    syscall(SYS_execve, "/bin/true", argv, envp);
    perror("syscall SYS_execve");
    exit(1);
}

static void run_execveat_relative(void) {
    int dfd = open("/bin", O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        perror("open /bin");
        exit(1);
    }
    char *argv[] = {"true", NULL};
    char *envp[] = {NULL};
    syscall(SYS_execveat, dfd, "true", argv, envp, 0);
    perror("syscall SYS_execveat relative");
    close(dfd);
    exit(1);
}

static void run_execveat_memfd(void) {
    int src_fd = open("/bin/true", O_RDONLY);
    if (src_fd < 0) {
        perror("open /bin/true");
        exit(1);
    }

    int memfd = memfd_create("anon_elf_true", MFD_CLOEXEC);
    if (memfd < 0) {
        perror("memfd_create");
        close(src_fd);
        exit(1);
    }

    char buf[4096];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(memfd, buf, n) != n) {
            perror("write memfd");
            close(src_fd);
            close(memfd);
            exit(1);
        }
    }
    close(src_fd);

    char *argv[] = {"anon_elf_true", NULL};
    char *envp[] = {NULL};
    syscall(SYS_execveat, memfd, "", argv, envp, AT_EMPTY_PATH);
    perror("syscall SYS_execveat memfd AT_EMPTY_PATH");
    close(memfd);
    exit(1);
}

static void run_shebang(void) {
    const char *script_path = "/tmp/cg_test_shebang.sh";
    int fd = open(script_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        perror("open script");
        exit(1);
    }
    const char *content = "#!/bin/sh\nexit 0\n";
    if (write(fd, content, strlen(content)) < 0) {
        perror("write script");
        close(fd);
        exit(1);
    }
    close(fd);

    char *argv[] = {(char *)script_path, NULL};
    char *envp[] = {NULL};
    execve(script_path, argv, envp);
    perror("execve shebang");
    exit(1);
}

static void run_symlink(void) {
    const char *symlink_path = "/tmp/cg_test_symlink_true";
    unlink(symlink_path);
    if (symlink("/bin/true", symlink_path) < 0) {
        perror("symlink");
        exit(1);
    }

    char *argv[] = {(char *)symlink_path, NULL};
    char *envp[] = {NULL};
    execve(symlink_path, argv, envp);
    perror("execve symlink");
    exit(1);
}

static void run_fail_enoent(void) {
    char *argv[] = {"/tmp/nonexistent_binary_xyz_9999", NULL};
    char *envp[] = {NULL};
    execve("/tmp/nonexistent_binary_xyz_9999", argv, envp);
    // Syscall failed with ENOENT (-2)
    exit(errno);
}

static void run_fail_eacces(void) {
    const char *no_exec_path = "/tmp/cg_no_exec.bin";
    int fd = open(no_exec_path, O_WRONLY | O_CREAT | O_TRUNC, 0644); // no +x
    if (fd >= 0) {
        write(fd, "#!/bin/sh\nexit 0\n", 17);
        close(fd);
    }
    char *argv[] = {(char *)no_exec_path, NULL};
    char *envp[] = {NULL};
    execve(no_exec_path, argv, envp);
    // Syscall failed with EACCES (-13)
    exit(errno);
}

static void run_path_truncation(void) {
    // In Linux, individual component max is 255 (NAME_MAX), total PATH_MAX is 4096.
    // We create a nested directory path longer than our 256-byte telemetry buffer (~350 chars)
    const char *p1 = "d1_111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    const char *p2 = "d2_2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

    char deep_dir[1024];
    snprintf(deep_dir, sizeof(deep_dir), "/tmp/%s/%s", p1, p2);

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s && cp /bin/true %s/true", deep_dir, deep_dir);
    int s = system(cmd);
    (void)s;

    char full_path[1200];
    snprintf(full_path, sizeof(full_path), "%s/true", deep_dir);

    char *argv[] = {full_path, NULL};
    char *envp[] = {NULL};
    execve(full_path, argv, envp);
    perror("execve deep path");
    exit(1);
}

static void run_comm_truncation(void) {
    prctl(PR_SET_NAME, "1234567890abcdef", 0, 0, 0); // 16 chars without null
    char *argv[] = {"/bin/true", NULL};
    char *envp[] = {NULL};
    execve("/bin/true", argv, envp);
    perror("execve comm truncation");
    exit(1);
}

static void run_in_fork(const char *name, void (*fn)(void)) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return;
    }
    if (pid == 0) {
        fn();
        exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
}

int main(int argc, char **argv) {
    const char *mode = "all";
    if (argc > 1) {
        mode = argv[1];
    }

    if (strcmp(mode, "standard_execve") == 0) {
        run_standard_execve();
    } else if (strcmp(mode, "direct_syscall") == 0) {
        run_direct_syscall();
    } else if (strcmp(mode, "execveat_relative") == 0) {
        run_execveat_relative();
    } else if (strcmp(mode, "execveat_memfd") == 0) {
        run_execveat_memfd();
    } else if (strcmp(mode, "shebang") == 0) {
        run_shebang();
    } else if (strcmp(mode, "symlink") == 0) {
        run_symlink();
    } else if (strcmp(mode, "fail_enoent") == 0) {
        run_fail_enoent();
    } else if (strcmp(mode, "fail_eacces") == 0) {
        run_fail_eacces();
    } else if (strcmp(mode, "path_truncation") == 0) {
        run_path_truncation();
    } else if (strcmp(mode, "comm_truncation") == 0) {
        run_comm_truncation();
    } else if (strcmp(mode, "all") == 0) {
        printf("[test_exec_paths] Running all execution paths in separate sub-processes...\n");
        run_in_fork("standard_execve", run_standard_execve);
        run_in_fork("direct_syscall", run_direct_syscall);
        run_in_fork("execveat_relative", run_execveat_relative);
        run_in_fork("execveat_memfd", run_execveat_memfd);
        run_in_fork("shebang", run_shebang);
        run_in_fork("symlink", run_symlink);
        run_in_fork("fail_enoent", run_fail_enoent);
        run_in_fork("fail_eacces", run_fail_eacces);
        run_in_fork("path_truncation", run_path_truncation);
        run_in_fork("comm_truncation", run_comm_truncation);
        printf("[test_exec_paths] All test execution paths completed.\n");
    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        return 1;
    }

    return 0;
}
