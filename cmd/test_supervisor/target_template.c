#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    (void)argc;
    printf("target executed: %s (PID: %d)\n", argv[0], getpid());
    return 0;
}
