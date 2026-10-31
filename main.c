#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* ── provided ───────────────────────────────────────────────────────────
   sha1_hex(data, len, out): SHA-1 of `len` bytes as 40 lowercase hex chars
   (`out` must hold 41). The grader (and the local runner) compile this one
   file with no external libraries — there is no OpenSSL — so SHA-1
   (RFC 3174) lives here. You never need to change it.
   ─────────────────────────────────────────────────────────────────────── */
static uint32_t sha1_rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static void sha1_digest(const unsigned char* data, size_t len, unsigned char out[20]) {
    uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    size_t total = ((len + 8) / 64 + 1) * 64;
    unsigned char* msg = (unsigned char*)calloc(total, 1);
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) msg[total - 1 - i] = (unsigned char)(bits >> (8 * i));
    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[off + 4 * i] << 24) | ((uint32_t)msg[off + 4 * i + 1] << 16) |
                   ((uint32_t)msg[off + 4 * i + 2] << 8) | (uint32_t)msg[off + 4 * i + 3];
        for (int i = 16; i < 80; i++) w[i] = sha1_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5A827999u; }
            else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1u; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDCu; }
            else             { f = b ^ c ^ d;                    k = 0xCA62C1D6u; }
            uint32_t t = sha1_rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = sha1_rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    free(msg);
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (unsigned char)(h[i] >> 24); out[4 * i + 1] = (unsigned char)(h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(h[i] >> 8); out[4 * i + 3] = (unsigned char)h[i];
    }
}
static void sha1_hex(const unsigned char* data, size_t len, char out[41]) {
    unsigned char d[20];
    sha1_digest(data, len, d);
    for (int i = 0; i < 20; i++) sprintf(out + 2 * i, "%02x", d[i]);
    out[40] = 0;
}

/* Each input line is one file's content. The "\n" that ends the line is NOT part of it. */

static void hash_blob(const unsigned char *content, size_t n, char out[41]) {
    unsigned char* buf;
    size_t bufLen;
    int headerLen;

    headerLen = snprintf(NULL, 0, "blob %zu", n);
    //
    // Check for formatting errors
    //
    if (headerLen < 0) {
        return;
    }
    //
    // Check for integer overflow
    //
    if (n > SIZE_MAX - (size_t)headerLen - 1) {
        return;
    }
    bufLen = headerLen + 1 + n;
    buf = malloc(bufLen);
    if (buf == NULL) {
        return;
    }
    snprintf(buf, headerLen + 1, "blob %zu", n);  // Write at most headerLen + 1 bytes include the \0-byte
    memcpy(buf + headerLen + 1, content, n);
    sha1_hex(buf, bufLen, out);
    free(buf);
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
    size_t start = 0;
    char hex[41];
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') {
            hash_blob(data + start, i - start, hex);
            printf("%s\n", hex);
            start = i + 1;
        }
    }
    if (start < len) {
        hash_blob(data + start, len - start, hex);
        printf("%s\n", hex);
    }
    free(data);
    return 0;
}
