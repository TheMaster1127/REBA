#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned int crc;
    int length;
    int upper_count;
    int digit_count;
} AnalysisResult;

static unsigned int compute_crc32(const unsigned char *data, int len) {
    unsigned int crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
        }
    }
    return ~crc;
}

static void analyze_text(const char *text, AnalysisResult *out) {
    out->length = 0;
    out->upper_count = 0;
    out->digit_count = 0;

    for (const char *p = text; *p; p++) {
        out->length++;
        if (*p >= 'A' && *p <= 'Z') out->upper_count++;
        if (*p >= '0' && *p <= '9') out->digit_count++;
    }
    out->crc = compute_crc32((const unsigned char *)text, out->length);
}

static void transform(char *str, int mode) {
    int len = strlen(str);
    switch (mode) {
        case 1: // Invert case
            for (int i = 0; i < len; i++) {
                if (str[i] >= 'a' && str[i] <= 'z') str[i] -= 32;
                else if (str[i] >= 'A' && str[i] <= 'Z') str[i] += 32;
            }
            break;
        case 2: // ROT-13
            for (int i = 0; i < len; i++) {
                char c = str[i];
                if (c >= 'a' && c <= 'z') str[i] = 'a' + (c - 'a' + 13) % 26;
                else if (c >= 'A' && c <= 'Z') str[i] = 'A' + (c - 'A' + 13) % 26;
            }
            break;
        case 3: // Reverse
            for (int i = 0, j = len - 1; i < j; i++, j--) {
                char tmp = str[i];
                str[i] = str[j];
                str[j] = tmp;
            }
            break;
        case 4: // Leet speak
            for (int i = 0; i < len; i++) {
                if (str[i] == 'e' || str[i] == 'E') str[i] = '3';
                else if (str[i] == 'a' || str[i] == 'A') str[i] = '4';
                else if (str[i] == 'o' || str[i] == 'O') str[i] = '0';
            }
            break;
        default:
            // Mode 0 or unknown: do nothing
            break;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <mode:1-4> <text>\n", argv[0]);
        return 1;
    }

    int mode = atoi(argv[1]);
    if (mode < 1 || mode > 4) {
        fprintf(stderr, "error: mode must be between 1 and 4\n");
        return 2;
    }

    // Allocate writable copy for transformation
    char *buf = strdup(argv[2]);
    if (!buf) return 3;

    AnalysisResult stats;
    analyze_text(buf, &stats);
    transform(buf, mode);

    printf("orig_len=%d, upper=%d, digits=%d, crc=%08x\n",
           stats.length, stats.upper_count, stats.digit_count, stats.crc);
    printf("output=%s\n", buf);

    free(buf);
    return 0;
}
