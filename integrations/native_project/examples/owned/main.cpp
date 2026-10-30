#include "compute.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static bool number(const char* text, uint32_t& result) {
    if (!*text || *text == '-') return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (errno || *end || value > UINT32_MAX) return false;
    result = static_cast<uint32_t>(value);
    return true;
}

int main(int argc, char** argv) {
    uint32_t seed = 42, count = 4096;
    if (argc > 3 || (argc > 1 && !number(argv[1], seed)) ||
        (argc > 2 && !number(argv[2], count)) || count > 1000000) {
        std::fputs("expected uint32 seed and count <= 1000000\n", stderr);
        return 2;
    }
    uint32_t state = seed, checksum = 0;
    for (uint32_t index = 0; index < count; ++index) {
        state = mix_pair(state, index);
        checksum = step_byte(checksum, fold_word(state, index));
    }
    std::printf("%u %u %u %d\n", count, state, checksum, classify(static_cast<int>(count) - 100));
    return 0;
}
