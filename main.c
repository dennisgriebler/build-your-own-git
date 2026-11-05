#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

/* Adler-32 of p[0..n): (b << 16) | a, both sums modulo 65521. */
static uint32_t adler32(const unsigned char *p, size_t n) {
    /* TODO: a starts at 1 and b at 0; for every byte: a += byte, then b += a, both modulo 65521. */
    size_t a;
    size_t b;
    uint32_t sum;

    a = 1;
    b = 0;
    for (size_t i = 0; i < n; ++i) {
        a += (uint8_t)p[i];
        a %= 65521;
        b += (uint8_t)p[i];
        b %= 65521;
    }
    sum = a & 0xFFFF;
    sum |= (b & 0xFFFF) << 16;
    return sum;
}

/* Writes `data` (n bytes) as a zlib stream of stored deflate blocks into out and returns its
   length. out has room for n + 5 * (n / 65535 + 1) + 6 bytes. */
static size_t wrap_stored(const unsigned char *data, size_t n, unsigned char *out) {
    /* TODO: header 78 01, then stored blocks (flag byte, LEN and NLEN little-endian, the data),
             then the Adler-32 of data as 4 big-endian bytes. Even empty data needs one block.
             Return how many bytes you wrote into out. */
    (void)data;
    (void)n;
    (void)out;
    //
    // zlib stream format:
    // 2 bytes   header:   CMF FLG          (usually 78 01, 78 9c or 78 da)
    // n bytes   deflate:  one or more blocks (RFC 1951)
    // 4 bytes   trailer:  Adler-32 of the uncompressed bytes, big-endian
    //
    size_t a;
    size_t b;
    size_t numBlocks;
    size_t outPos;
    size_t numPayload;
    size_t toWrite;
    uint32_t adlerSum32;
    //
    // append the header
    //
    outPos = 0;
    toWrite = n;
    numPayload = n;
    adlerSum32 = adler32(data, n);
    out[0] = 0x78;
    out[1] = 0x01;
    outPos = 2;
    //
    // built the deflate block
    //
    numBlocks = 1;
    if (n > 65535) {
        numBlocks += (n /65535);
    }
    do {
        //
        // Block format:
        // 1 byte    bit 0 = "this is the last block", bits 1-2 = 00 for stored
        // 2 bytes   LEN,  little-endian, number of data bytes (at most 65535)
        // 2 bytes   NLEN, little-endian, the bitwise complement of LEN
        // LEN bytes the data
        //
        out[outPos++] = (numBlocks > 1) ? 0x00 : 0x01;
        numPayload = (toWrite > 65535) ? 65535 : toWrite;
        out[outPos++] = (char)(numPayload & 0x00FF);
        out[outPos++] = (char)((numPayload & 0xFF00) >> 8);
        out[outPos++] = (char)~(numPayload & 0x00FF);
        out[outPos++] = (char)~((numPayload & 0xFF00) >> 8);
        for (size_t i = 0; i < numPayload; ++i) {
            out[outPos++] = *data++;
        }
        toWrite -= numPayload;
        --numBlocks;
    } while (numBlocks > 0);
    //
    // compute and append adler checksum
    //
    out[outPos++] = (uint8_t)((adlerSum32 >> 24) & 0x000000FF);
    out[outPos++] = (uint8_t)((adlerSum32 >> 16) & 0x000000FF);
    out[outPos++] = (uint8_t)((adlerSum32 >>  8) & 0x000000FF);
    out[outPos++] = (uint8_t)((adlerSum32 >>  0) & 0x000000FF);


    return outPos-1;
}

/* Copies the inflated bytes into out (room for n bytes) and sets *outlen. Returns NULL on success,
   otherwise the error text that follows "ERR ". */
static const char *unwrap_stored(const unsigned char *f, size_t n, unsigned char *out, size_t *outlen) {
    /* TODO: check the 2-byte header, then loop over stored blocks until the "last" bit, then the
             4-byte Adler-32 trailer. Report the FIRST problem with the exact messages of the
             exercise (the text after "ERR "). Return NULL on success. */
    (void)f;
    (void)n;
    (void)out;
    *outlen = 0;
    return "truncated";
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes s[0..len) into out; returns 1 when len is even and all digits are hex. */
static int decode_hex(const char *s, size_t len, unsigned char *out) {
    size_t i;
    if (len % 2 != 0) return 0;
    for (i = 0; i < len; i++) {
        if (hexval((unsigned char)s[i]) < 0) return 0;
    }
    for (i = 0; i < len / 2; i++) out[i] = (unsigned char)(hexval((unsigned char)s[2 * i]) * 16 + hexval((unsigned char)s[2 * i + 1]));
    return 1;
}

/* Returns 1 and sets *type / *size for a well-formed object. */
static int parse_object(const unsigned char *raw, size_t n, char *type, unsigned long *size) {
    size_t nul = 0, i, sp = 0, spaces = 0, sizelen;
    unsigned long declared = 0;
    while (nul < n && raw[nul] != 0) nul++;
    if (nul == n) return 0;
    for (i = 0; i < nul; i++) {
        if (raw[i] == ' ') {
            spaces++;
            sp = i;
        }
    }
    if (spaces != 1) return 0;
    if (!((sp == 4 && (memcmp(raw, "blob", 4) == 0 || memcmp(raw, "tree", 4) == 0)) ||
          (sp == 6 && memcmp(raw, "commit", 6) == 0) || (sp == 3 && memcmp(raw, "tag", 3) == 0)))
        return 0;
    sizelen = nul - sp - 1;
    if (sizelen < 1 || sizelen > 9) return 0;
    for (i = 0; i < sizelen; i++) {
        unsigned char c = raw[sp + 1 + i];
        if (c < '0' || c > '9') return 0;
        declared = declared * 10 + (unsigned long)(c - '0');
    }
    if (sizelen > 1 && raw[sp + 1] == '0') return 0;
    if (declared != (unsigned long)(n - nul - 1)) return 0;
    memcpy(type, raw, sp);
    type[sp] = 0;
    *size = declared;
    return 1;
}

static void print_hex(const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static void handle_line(char *line) {
    char *p1 = strchr(line, ' ');
    char *p2 = NULL;
    char *a1 = NULL, *a2 = NULL;
    if (p1) {
        *p1 = 0;
        a1 = p1 + 1;
        p2 = strchr(a1, ' ');
        if (p2) {
            *p2 = 0;
            a2 = p2 + 1;
        }
    }
    if (strcmp(line, "WRITE") == 0 && a1) {
        size_t hlen = a2 ? strlen(a2) : 0;
        unsigned char *payload = (unsigned char *)malloc(hlen / 2 + 1);
        decode_hex(a2 ? a2 : "", hlen, payload);
        size_t plen = hlen / 2;
        char header[64];
        int hn = snprintf(header, sizeof header, "%s %lu", a1, (unsigned long)plen);
        size_t total = (size_t)hn + 1 + plen;
        unsigned char *inflated = (unsigned char *)malloc(total);
        memcpy(inflated, header, (size_t)hn + 1);
        memcpy(inflated + hn + 1, payload, plen);
        char sha[41];
        sha1_hex(inflated, total, sha);
        printf("objects/%.2s/%s\n", sha, sha + 2);
        unsigned char *file = (unsigned char *)malloc(total + 5 * (total / 65535 + 1) + 8);
        size_t flen = wrap_stored(inflated, total, file);
        print_hex(file, flen);
        free(payload);
        free(inflated);
        free(file);
    } else if (strcmp(line, "READ") == 0) {
        const char *arg = a1 ? a1 : "";
        size_t alen = strlen(arg);
        unsigned char *f = (unsigned char *)malloc(alen / 2 + 1);
        if (!decode_hex(arg, alen, f)) {
            printf("ERR bad hex\n");
            free(f);
            return;
        }
        size_t n = alen / 2, m = 0;
        unsigned char *inflated = (unsigned char *)malloc(n + 1);
        const char *err = unwrap_stored(f, n, inflated, &m);
        if (err) {
            printf("ERR %s\n", err);
        } else {
            char type[16];
            unsigned long size = 0;
            if (!parse_object(inflated, m, type, &size)) {
                printf("ERR bad object\n");
            } else {
                char sha[41];
                sha1_hex(inflated, m, sha);
                printf("%s %lu %s\n", type, size, sha);
            }
        }
        free(f);
        free(inflated);
    }
}

int main(void) {
    size_t cap = 1 << 16, len = 0, r;
    char *data = (char *)malloc(cap + 1);
    if (!data) return 1;
    while ((r = fread(data + len, 1, cap - len, stdin)) > 0) {
        len += r;
        if (len == cap) {
            cap *= 2;
            data = (char *)realloc(data, cap + 1);
            if (!data) return 1;
        }
    }
    data[len] = 0;
    size_t start = 0, i;
    for (i = 0; i <= len; i++) {
        if (i == len || data[i] == '\n') {
            if (i > start || i < len) {
                data[i] = 0;
                handle_line(data + start);
            }
            start = i + 1;
        }
    }
    free(data);
    return 0;
}
