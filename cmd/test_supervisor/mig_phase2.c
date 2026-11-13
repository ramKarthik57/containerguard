#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    printf("mig_phase2: in-place executed successfully in cgroup 2 (PID: %d)\n", getpid());
    return 0;
}
