#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Writes the one output line for the object `raw` (n bytes) into `out`. Bytes are not text:
   the object may hold zero bytes, so never use strlen on it. `out` has room for n + 64 chars. */
static void check(const unsigned char *raw, size_t n, char *out) {
    size_t numSP;
    size_t posSP;
    const unsigned char* pNUL;
    size_t headerLen;
    size_t typeLen;
    size_t sizeStart;
    size_t sizeLen;
    size_t sizeDeclared;
    size_t sizeActual;

    numSP = 0;
    posSP = 0;
    //
    // check for first NUL byte
    //
    pNUL = memchr(raw, '\0', n);
    if (pNUL == NULL) {
        sprintf(out, "ERR missing NUL");
        return;
    }
    //
    // Does raw contain exactly one space before the NULL char?
    //
    headerLen = (size_t)(pNUL - raw);
    for (size_t i = 0; i < headerLen; ++i) {
        if (raw[i] == ' ') {
            ++numSP;
            posSP = i;
        }
    }
    if (numSP != 1) {
        sprintf(out, "ERR bad header");
        return;
    }
    typeLen = posSP;
    //
    // check type
    //
    if (!(((typeLen == 4) && (memcmp(raw, "tree", 4)   == 0))
       || ((typeLen == 4) && (memcmp(raw, "blob", 4)   == 0))
       || ((typeLen == 6) && (memcmp(raw, "commit", 6) == 0))
       || ((typeLen == 3) && (memcmp(raw, "tag", 3)    == 0)))) {    
        memcpy(out, "ERR unknown type ", 17);
        memcpy(out + 17, raw, typeLen);
        out[typeLen + 17] = '\0';
        return;    
    }
    //
    // check size
    //
    sizeStart = posSP + 1;
    sizeLen   = headerLen - sizeStart;
    //
    // if sizeLen >= 2, only char 1-0 are valid as start
    // 
    if (sizeLen >= 2) {
        if ((raw[sizeStart] - '0' < 1) || (raw[sizeStart] - '0' > 9)) {
            sprintf(out, "ERR bad size");
            return;      
        }
    }
    sizeDeclared = 0;
    for (size_t i = 0; i < sizeLen; ++i) {
        if ((raw[sizeStart + i] - '0' < 0) || (raw[sizeStart + i] - '0' > 9)) {
            sprintf(out, "ERR bad size");
            return;      
        }
        sizeDeclared *= 10;
        sizeDeclared += raw[sizeStart + i] - '0';
    }
    //
    // check declared vs actual
    //
    sizeActual = n - headerLen -1;
    if (sizeDeclared != sizeActual) {
        sprintf(out, "ERR size mismatch %zu != %zu", sizeDeclared, sizeActual);
        return;
    }
    memcpy(out, raw, headerLen);
    out[headerLen] = '\0';
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void handle_line(const unsigned char *line, size_t len) {
    size_t i;
    int ok = (len % 2 == 0);
    for (i = 0; ok && i < len; i++) {
        if (hexval(line[i]) < 0) ok = 0;
    }
    if (!ok) {
        printf("ERR bad hex\n");
        return;
    }
    unsigned char *raw = (unsigned char *)malloc(len / 2 + 1);
    char *out = (char *)malloc(len / 2 + 64);
    for (i = 0; i < len / 2; i++) raw[i] = (unsigned char)(hexval(line[2 * i]) * 16 + hexval(line[2 * i + 1]));
    check(raw, len / 2, out);
    printf("%s\n", out);
    free(raw);
    free(out);
}

int main(void) {
    size_t cap = 1 << 16, len = 0, r;
    unsigned char *data = (unsigned char *)malloc(cap);
    if (!data) return 1;
    while ((r = fread(data + len, 1, cap - len, stdin)) > 0) {
        len += r;
        if (len == cap) {
            cap *= 2;
            data = (unsigned char *)realloc(data, cap);
            if (!data) return 1;
        }
    }
    size_t start = 0, i;
    for (i = 0; i < len; i++) {
        if (data[i] == '\n') {
            handle_line(data + start, i - start);
            start = i + 1;
        }
    }
    if (start < len) handle_line(data + start, len - start);
    free(data);
    return 0;
}
