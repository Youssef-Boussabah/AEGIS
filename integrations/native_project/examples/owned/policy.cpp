#include "compute.h"

// This signed component is deliberately outside the requested protection scope.
int classify(int value) {
    return value < 0 ? -1 : (value > 0 ? 1 : 0);
}
