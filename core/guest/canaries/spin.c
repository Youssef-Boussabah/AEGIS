/* V6: CPU time is limited (cpu_ms below wall_ms). */
static volatile unsigned long counter;

int main(void) {
    for (;;) counter = counter + 1;
}
