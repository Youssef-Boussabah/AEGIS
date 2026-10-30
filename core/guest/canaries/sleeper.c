/* V6: the wall clock is enforced even after the process closes its outputs. */
#define _GNU_SOURCE
#include <unistd.h>

int main(void) {
    close(1);
    close(2);
    for (;;) sleep(100);
}
