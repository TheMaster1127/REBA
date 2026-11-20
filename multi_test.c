#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Tier 0: Leaf Function (Zero local dependencies)
static int compute_leaf(int x, int mult) {
    int res = (x ^ 0x5A) * mult;
    if (res < 0) res = -res;
    return (res >> 2) + 7;
}

// Tier 1: Intermediate Function (Calls compute_leaf in a loop)
static long process_record(const char *name, int count, int multiplier) {
    long accumulator = 0;
    int len = (int)strlen(name);
    for (int i = 0; i < count; i++) {
        int char_code = (int)((unsigned char)name[i % len]);
        accumulator += compute_leaf(char_code + i, multiplier);
    }
    return accumulator;
}

// Tier 2: Root Caller (Parses CLI arguments, calls process_record)
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <name> <count:1-100> <multiplier:1-10>\n", argv[0]);
        return 1;
    }

    const char *name = argv[1];
    int count = atoi(argv[2]);
    int mult = atoi(argv[3]);

    if (count < 1 || count > 100) {
        fprintf(stderr, "error: count must be between 1 and 100\n");
        return 2;
    }
    if (mult < 1 || mult > 10) {
        fprintf(stderr, "error: multiplier must be between 1 and 10\n");
        return 3;
    }

    long result = process_record(name, count, mult);
    printf("record='%s' count=%d mult=%d result=%ld\n", name, count, mult, result);
    return 0;
}
