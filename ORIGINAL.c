#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static unsigned int fnv1a(const char *s) {
    unsigned int h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

static long fib(int n) {
    long a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        long t = a + b;
        a = b;
        b = t;
    }
    return a;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <word> [n]\n", argv[0]);
        return 1;
    }
    const char *word = argv[1];
    int n = (argc > 2) ? atoi(argv[2]) : 10;
    n = clamp(n, 0, 30);
    unsigned int h = fnv1a(word);
    long f = fib(n);
    printf("word=%s\n", word);
    printf("hash=%08x\n", h);
    printf("fib(%d)=%ld\n", n, f);
    return 0;
}
