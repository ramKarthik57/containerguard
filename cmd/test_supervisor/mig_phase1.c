#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <read_fd> <write_fd> <phase2_path>\n", argv[0]);
        return 1;
    }

    int read_fd = atoi(argv[1]);
    int write_fd = atoi(argv[2]);
    char *phase2_path = argv[3];

    // 1. Report readiness to supervisor
    char ready = 'R';
    if (write(write_fd, &ready, 1) != 1) {
        perror("mig_phase1: write ready signal");
        return 2;
    }

    // 2. Block until supervisor migrates us to cgroup 2 and signals release
    char go = 0;
    if (read(read_fd, &go, 1) != 1) {
        perror("mig_phase1: read go signal");
        return 3;
    }

    // Close descriptors before exec
    close(read_fd);
    close(write_fd);

    // 3. In-place execve to phase 2 binary (same process identity)
    char *phase2_argv[] = {phase2_path, NULL};
    char *phase2_envp[] = {NULL};
    execve(phase2_path, phase2_argv, phase2_envp);

    perror("mig_phase1: execve phase2 failed");
    return 4;
}
