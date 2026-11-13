#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <errno.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

static void write_manifest_entry(FILE *fp, const char *scenario, const char *path, const char *method) {
    if (fp) {
        fprintf(fp, "  \"%s\": {\"target_path\": \"%s\", \"method\": \"%s\"},\n", scenario, path, method);
        fflush(fp);
    }
}

static int wait_child_exit(pid_t pid, const char *name) {
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror(name);
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <evidence_dir> <run_id>\n", argv[0]);
        return 1;
    }

    const char *evidence_dir = argv[1];
    const char *run_id = argv[2];

    printf("[supervisor] Initialized (Userspace PID: %d, RUN_ID: %s)\n", getpid(), run_id);
    fflush(stdout);

    // 1. Synchronize with runner release barrier:
    // Ensure ContainerGuard captures supervisor's own execution event (establishing anchor G)
    char release_fifo[1024];
    snprintf(release_fifo, sizeof(release_fifo), "%s/supervisor_release.fifo", evidence_dir);
    int rfd = open(release_fifo, O_RDONLY);
    if (rfd >= 0) {
        char sig = 0;
        if (read(rfd, &sig, 1) > 0) {
            printf("[supervisor] Anchor verified in telemetry by runner. Releasing workloads.\n");
        }
        close(rfd);
    }

    char manifest_path[1024];
    snprintf(manifest_path, sizeof(manifest_path), "%s/supervisor_manifest.json", evidence_dir);
    FILE *mfp = fopen(manifest_path, "w");
    if (mfp) {
        fprintf(mfp, "{\n  \"run_id\": \"%s\",\n  \"supervisor_userspace_pid\": %d,\n  \"scenarios\": {\n", run_id, getpid());
    }

    char target[2048];
    pid_t pid;

    // --- Scenario 1: Standard execve ---
    snprintf(target, sizeof(target), "%s/targets/target_std_execve", evidence_dir);
    write_manifest_entry(mfp, "standard_execve", target, "libc_execve");
    printf("[supervisor] Dispatching standard_execve -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        perror("execve standard_execve");
        _exit(1);
    }
    wait_child_exit(pid, "standard_execve");

    // --- Scenario 2: Direct syscall SYS_execve ---
    snprintf(target, sizeof(target), "%s/targets/target_direct_syscall", evidence_dir);
    write_manifest_entry(mfp, "direct_syscall", target, "raw_syscall_SYS_execve");
    printf("[supervisor] Dispatching direct_syscall -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        syscall(SYS_execve, target, args, envp);
        perror("syscall direct_syscall");
        _exit(1);
    }
    wait_child_exit(pid, "direct_syscall");

    // --- Scenario 3: Relative execveat ---
    char rel_dir[1024];
    snprintf(rel_dir, sizeof(rel_dir), "%s/rel_dir", evidence_dir);
    char rel_name[512];
    snprintf(rel_name, sizeof(rel_name), "relative_execveat_%s", run_id);
    snprintf(target, sizeof(target), "%s/%s", rel_dir, rel_name);
    write_manifest_entry(mfp, "execveat_relative", rel_name, "syscall_SYS_execveat_relative");
    printf("[supervisor] Dispatching execveat_relative -> %s (dirfd: %s)\n", rel_name, rel_dir);
    pid = fork();
    if (pid == 0) {
        int dfd = open(rel_dir, O_RDONLY | O_DIRECTORY);
        if (dfd < 0) { perror("open rel_dir"); _exit(1); }
        char *args[] = {rel_name, NULL};
        char *envp[] = {NULL};
        syscall(SYS_execveat, dfd, rel_name, args, envp, 0);
        perror("syscall execveat_relative");
        close(dfd);
        _exit(1);
    }
    wait_child_exit(pid, "execveat_relative");

    // --- Scenario 4: memfd with AT_EMPTY_PATH ---
    snprintf(target, sizeof(target), "anon_elf_%s", run_id);
    write_manifest_entry(mfp, "execveat_memfd", target, "syscall_SYS_execveat_memfd_AT_EMPTY_PATH");
    printf("[supervisor] Dispatching execveat_memfd -> memfd:%s\n", target);
    pid = fork();
    if (pid == 0) {
        char template_path[1024];
        snprintf(template_path, sizeof(template_path), "%s/targets/target_std_execve", evidence_dir);
        int src_fd = open(template_path, O_RDONLY);
        if (src_fd < 0) { perror("open src binary for memfd"); _exit(1); }
        int mfd = memfd_create(target, MFD_CLOEXEC);
        if (mfd < 0) { perror("memfd_create"); close(src_fd); _exit(1); }
        char buf[4096];
        ssize_t n;
        while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
            if (write(mfd, buf, n) != n) { perror("write memfd"); _exit(1); }
        }
        close(src_fd);
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        syscall(SYS_execveat, mfd, "", args, envp, AT_EMPTY_PATH);
        perror("syscall execveat memfd");
        close(mfd);
        _exit(1);
    }
    wait_child_exit(pid, "execveat_memfd");

    // --- Scenario 5: Shebang script ---
    snprintf(target, sizeof(target), "%s/targets/shebang_%s.sh", evidence_dir, run_id);
    write_manifest_entry(mfp, "shebang", target, "shebang_interpreter");
    printf("[supervisor] Dispatching shebang -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        perror("execve shebang");
        _exit(1);
    }
    wait_child_exit(pid, "shebang");

    // --- Scenario 6: Symlink execution ---
    char symlink_link[1024];
    snprintf(symlink_link, sizeof(symlink_link), "%s/targets/symlink_%s", evidence_dir, run_id);
    write_manifest_entry(mfp, "symlink", symlink_link, "symlink_traversal");
    printf("[supervisor] Dispatching symlink -> %s\n", symlink_link);
    pid = fork();
    if (pid == 0) {
        char *args[] = {symlink_link, NULL};
        char *envp[] = {NULL};
        execve(symlink_link, args, envp);
        perror("execve symlink");
        _exit(1);
    }
    wait_child_exit(pid, "symlink");

    // --- Scenario 7: Failed exec ENOENT ---
    snprintf(target, sizeof(target), "%s/targets/nonexistent_%s_xyz", evidence_dir, run_id);
    write_manifest_entry(mfp, "fail_enoent", target, "failed_exec_enoent");
    printf("[supervisor] Dispatching fail_enoent -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        // Expect failure
        _exit(0);
    }
    wait_child_exit(pid, "fail_enoent");

    // --- Scenario 8: Failed exec EACCES ---
    snprintf(target, sizeof(target), "%s/targets/no_exec_%s.bin", evidence_dir, run_id);
    write_manifest_entry(mfp, "fail_eacces", target, "failed_exec_eacces");
    printf("[supervisor] Dispatching fail_eacces -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        // Expect failure
        _exit(0);
    }
    wait_child_exit(pid, "fail_eacces");

    // --- Scenario 9: Pathname truncation ---
    char path_trunc_target[1024];
    // Find created long path binary in evidence_dir
    snprintf(path_trunc_target, sizeof(path_trunc_target), "%s/targets/path_trunc_marker.txt", evidence_dir);
    FILE *ptf = fopen(path_trunc_target, "r");
    char long_path[2048] = {0};
    if (ptf) {
        if (fgets(long_path, sizeof(long_path), ptf)) {
            char *nl = strchr(long_path, '\n');
            if (nl) *nl = 0;
        }
        fclose(ptf);
    }
    if (long_path[0] == 0) {
        snprintf(long_path, sizeof(long_path), "%s/targets/target_std_execve", evidence_dir);
    }
    write_manifest_entry(mfp, "path_truncation", long_path, "path_truncation_over_256B");
    printf("[supervisor] Dispatching path_truncation (len %zu)\n", strlen(long_path));
    pid = fork();
    if (pid == 0) {
        char *args[] = {long_path, NULL};
        char *envp[] = {NULL};
        execve(long_path, args, envp);
        perror("execve path_truncation");
        _exit(1);
    }
    wait_child_exit(pid, "path_truncation");

    // --- Scenario 10: Comm truncation (ISOLATED: 16 chars with PR_SET_NAME on short basename target) ---
    // Target basename is "comm_short" (10 chars <= 15 chars).
    // Pre-exec name is "16_char_comm_xxx" (16 bytes, index 14 non-null).
    // Proves comm_truncated flag is triggered strictly by PR_SET_NAME, not executable basename.
    snprintf(target, sizeof(target), "%s/targets/comm_short", evidence_dir);
    write_manifest_entry(mfp, "comm_truncation", target, "isolated_prctl_16B_short_target");
    printf("[supervisor] Dispatching comm_truncation (isolated) -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        prctl(PR_SET_NAME, "16_char_comm_xxx", 0, 0, 0);
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        perror("execve comm_truncation");
        _exit(1);
    }
    wait_child_exit(pid, "comm_truncation");

    // --- Scenario 11: Static ELF ---
    snprintf(target, sizeof(target), "%s/targets/static_elf_%s", evidence_dir, run_id);
    write_manifest_entry(mfp, "static_elf", target, "static_binary_no_interp");
    printf("[supervisor] Dispatching static_elf -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        perror("execve static_elf");
        _exit(1);
    }
    wait_child_exit(pid, "static_elf");

    // --- Scenario 12: Setuid EUID transition ---
    snprintf(target, sizeof(target), "%s/targets/setuid_runner_%s", evidence_dir, run_id);
    write_manifest_entry(mfp, "setuid_transition", target, "setuid_suid_euid0");
    printf("[supervisor] Dispatching setuid_transition -> %s\n", target);
    pid = fork();
    if (pid == 0) {
        char *args[] = {target, NULL};
        char *envp[] = {NULL};
        execve(target, args, envp);
        perror("execve setuid_transition");
        _exit(1);
    }
    wait_child_exit(pid, "setuid_transition");

    // --- Scenario 13: Cgroup Migration (Fork-Only Bootstrap Architecture) ---
    char mig_phase1_target[1024], mig_phase2_target[1024];
    snprintf(mig_phase1_target, sizeof(mig_phase1_target), "%s/targets/mig_phase1_%s", evidence_dir, run_id);
    snprintf(mig_phase2_target, sizeof(mig_phase2_target), "%s/targets/mig_phase2_%s", evidence_dir, run_id);
    write_manifest_entry(mfp, "cgroup_migration_phase1", mig_phase1_target, "mig_phase1_in_cg1");
    write_manifest_entry(mfp, "cgroup_migration_phase2", mig_phase2_target, "mig_phase2_in_cg2");
    printf("[supervisor] Dispatching cgroup_migration sequence...\n");

    int p2c[2]; // Pipe: parent -> child
    int c2p[2]; // Pipe: child -> parent
    if (pipe(p2c) < 0 || pipe(c2p) < 0) {
        perror("migration pipes");
    }

    // FIFOs for runner communication
    char cmd_fifo[1024], resp_fifo[1024];
    snprintf(cmd_fifo, sizeof(cmd_fifo), "%s/mig_cmd.fifo", evidence_dir);
    snprintf(resp_fifo, sizeof(resp_fifo), "%s/mig_resp.fifo", evidence_dir);

    pid_t mig_child_pid = fork();
    if (mig_child_pid == 0) {
        // --- CHILD BRANCH (FORK-ONLY BOOTSTRAP) ---
        // Child does NOT call execve yet.
        close(p2c[1]);
        close(c2p[0]);

        // Send ready byte to parent
        char b = 'B';
        if (write(c2p[1], &b, 1) != 1) { perror("child write B"); _exit(1); }

        // Block until supervisor places us in CG1 and signals
        char start_sig = 0;
        if (read(p2c[0], &start_sig, 1) != 1) { perror("child read start_sig"); _exit(1); }

        // Child calls in-place execve to mig_phase1, passing inherited FDs
        char rfd_s[16], wfd_s[16];
        snprintf(rfd_s, sizeof(rfd_s), "%d", p2c[0]);
        snprintf(wfd_s, sizeof(wfd_s), "%d", c2p[1]);
        char *m1_args[] = {mig_phase1_target, rfd_s, wfd_s, mig_phase2_target, NULL};
        char *m1_envp[] = {NULL};
        execve(mig_phase1_target, m1_args, m1_envp);
        perror("child execve mig_phase1");
        _exit(1);
    }

    // --- SUPERVISOR BRANCH ---
    close(p2c[0]);
    close(c2p[1]);

    // 1. Wait for bootstrap child to announce itself
    char child_b = 0;
    if (read(c2p[0], &child_b, 1) == 1 && child_b == 'B') {
        printf("[supervisor] Migration child created (PID: %d). Requesting CG1 placement.\n", mig_child_pid);
    }

    // 2. Instruct runner to place child in CG1
    FILE *c_fp = fopen(cmd_fifo, "w");
    if (c_fp) {
        fprintf(c_fp, "PLACE_CG1 %d\n", mig_child_pid);
        fclose(c_fp);
    }
    // Wait for runner confirmation
    FILE *r_fp = fopen(resp_fifo, "r");
    char resp_buf[64] = {0};
    if (r_fp) {
        if (fgets(resp_buf, sizeof(resp_buf), r_fp) == NULL) {
            /* Handled */
        }
        fclose(r_fp);
    }

    // 3. Release child to execute Phase 1
    char go1 = 'G';
    if (write(p2c[1], &go1, 1) != 1) {
        perror("write go1");
    }

    // 4. Wait for Phase 1 binary readiness signal
    char p1_ready = 0;
    if (read(c2p[0], &p1_ready, 1) == 1 && p1_ready == 'R') {
        printf("[supervisor] Phase 1 binary active in CG1. Requesting Barrier A & CG2 migration.\n");
    }

    // 5. Instruct runner: Barrier A & move to CG2
    c_fp = fopen(cmd_fifo, "w");
    if (c_fp) {
        fprintf(c_fp, "MIGRATE_CG2 %d\n", mig_child_pid);
        fclose(c_fp);
    }
    // Wait for runner confirmation
    r_fp = fopen(resp_fifo, "r");
    if (r_fp) {
        if (fgets(resp_buf, sizeof(resp_buf), r_fp) == NULL) {
            /* Handled */
        }
        fclose(r_fp);
    }

    // 6. Release Phase 1 process to in-place exec Phase 2
    char go2 = 'M';
    if (write(p2c[1], &go2, 1) != 1) {
        perror("write go2");
    }

    // 7. Wait for migration child to complete Phase 2
    wait_child_exit(mig_child_pid, "cgroup_migration_child");
    close(p2c[1]);
    close(c2p[0]);
    printf("[supervisor] Migration sequence completed.\n");

    if (mfp) {
        fprintf(mfp, "    \"completed\": true\n  }\n}\n");
        fclose(mfp);
    }

    printf("[supervisor] All workloads dispatched successfully.\n");
    return 0;
}
