#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();
    printf("[setuid_test] Real UID: %d, Effective UID: %d\n", (int)ruid, (int)euid);
    return 0;
}
