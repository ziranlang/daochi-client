#include "record_api.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Independent libsodium reference for the released record profile. */
extern int crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char *,
    unsigned long long *, unsigned char *, const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *);
extern int sodium_base642bin(unsigned char *, size_t, const char *, size_t, const char *,
    size_t *, const char **, int);

#define ACCOUNT "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define APP StringLiteral("photos")
#define COLLECTION StringLiteral("private.photos.v1.records.media")
#define ID StringLiteral("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
#define SCHEMA StringLiteral("photos.media.v1")
#define KEY_ID StringLiteral("main")

static Slice bytes(void *data, size_t size)
{
    return (Slice){.data = data, .length = size};
}

/* Return the JSON string value that follows name, NUL-terminated in place. */
static char *value(char *json, const char *name)
{
    char *start = strstr(json, name);
    assert(start);
    start += strlen(name);
    char *end = strchr(start, '"');
    assert(end);
    *end = 0;
    return start;
}

static char *duplicate(const char *text)
{
    size_t size = strlen(text) + 1;
    char *copy = malloc(size);
    assert(copy);
    memcpy(copy, text, size);
    return copy;
}

static size_t decode(const char *text, unsigned char *output, size_t capacity)
{
    size_t length = 0;
    const char *end = NULL;
    assert(sodium_base642bin(output, capacity, text, strlen(text), NULL, &length, &end, 7) == 0);
    assert(*end == 0);
    return length;
}

int main(void)
{
    char aad[1024];
    const char *expected = "{\"account_id\":\"" ACCOUNT "\",\"app_id\":\"photos\","
        "\"collection\":\"private.photos.v1.records.media\",\"id\":"
        "\"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\","
        "\"schema\":\"photos.media.v1\"}";
    int64_t length = RecordTestAAD(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, bytes(aad, sizeof aad));
    assert(length == (int64_t)strlen(expected) && strcmp(aad, expected) == 0);
    assert(RecordTestAAD(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, bytes(aad, (size_t)length)) == -1);
    /* Uppercase accounts, JSON escapes and empty fields cannot reach the AAD. */
    assert(RecordTestAAD(StringLiteral("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"),
        APP, COLLECTION, ID, SCHEMA, bytes(aad, sizeof aad)) == -1);
    assert(RecordTestAAD(StringLiteral(ACCOUNT), APP, COLLECTION, StringLiteral("a\"b"), SCHEMA,
        bytes(aad, sizeof aad)) == -1);
    assert(RecordTestAAD(StringLiteral(ACCOUNT), StringLiteral(""), COLLECTION, ID, SCHEMA,
        bytes(aad, sizeof aad)) == -1);
    assert(RecordTestAAD(StringLiteral(ACCOUNT), APP, COLLECTION, StringLiteral("a/b"), SCHEMA,
        bytes(aad, sizeof aad)) == -1);

    char text[64];
    unsigned char vector[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, edge[2] = {0xfb, 0xff};
    assert(RecordTestBase64(bytes(vector, 10), bytes(text, sizeof text)) == 14 && strcmp(text, "AAECAwQFBgcICQ") == 0);
    assert(RecordTestBase64(bytes(edge, 2), bytes(text, sizeof text)) == 3 && strcmp(text, "-_8") == 0);
    assert(RecordTestBase64(bytes(vector, 0), bytes(text, sizeof text)) == 0 && text[0] == 0);
    assert(RecordTestBase64(bytes(vector, 10), bytes(text, 14)) == -1);

    unsigned char key[32], nonce[24], first_nonce[24];
    for (size_t i = 0; i < sizeof key; i++) key[i] = (unsigned char)(i * 7 + 1);
    const size_t sizes[] = {0, 1, 2, 3, 47, 48, 4096, 700000};
    for (size_t n = 0; n < sizeof sizes / sizeof *sizes; n++) {
        size_t size = sizes[n];
        unsigned char *plain = malloc(size + 1), *opened = malloc(size + 1);
        assert(plain && opened);
        for (size_t i = 0; i < size; i++) plain[i] = (unsigned char)(i * 31 + n);
        int64_t room = RecordTestEnvelopeBytes(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, KEY_ID, (int64_t)size);
        assert(room > 0);
        char *envelope = malloc((size_t)room);
        assert(envelope);
        int64_t written = RecordTestSeal(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, KEY_ID,
            bytes(key, 32), bytes(plain, size), bytes(nonce, 24), bytes(envelope, (size_t)room));
        assert(written > 0 && written < room && envelope[written] == 0 && (int64_t)strlen(envelope) == written);
        assert(strncmp(envelope, "{\"aad\":", 7) == 0 && strncmp(envelope + 7, expected, strlen(expected)) == 0);
        assert(strstr(envelope, ",\"alg\":\"xchacha20poly1305\",\"ciphertext\":\""));
        assert(strstr(envelope, "\",\"key_id\":\"main\",\"nonce\":\""));
        const char *tail = "\",\"profile\":\"daochi-record-v1\"}";
        assert(strcmp(envelope + written - (int64_t)strlen(tail), tail) == 0);
        unsigned char decoded_nonce[32], *sealed = malloc(size + 32);
        assert(sealed);
        char *copy = duplicate(envelope);
        assert(copy);
        assert(decode(value(copy, "\"nonce\":\""), decoded_nonce, sizeof decoded_nonce) == 24);
        assert(memcmp(decoded_nonce, nonce, 24) == 0);
        free(copy);
        copy = duplicate(envelope);
        size_t sealed_count = decode(value(copy, "\"ciphertext\":\""), sealed, size + 32);
        assert(sealed_count == size + 16);
        unsigned long long opened_count = 0;
        assert(crypto_aead_xchacha20poly1305_ietf_decrypt(opened, &opened_count, NULL, sealed, sealed_count,
            (const unsigned char *)expected, strlen(expected), nonce, key) == 0);
        assert(opened_count == size && memcmp(opened, plain, size) == 0);
        /* The metadata is authenticated: another record identity cannot open it. */
        char moved[1024];
        assert(RecordTestAAD(StringLiteral(ACCOUNT), APP, StringLiteral("private.photos.v1.records.albums"), ID, SCHEMA,
            bytes(moved, sizeof moved)) > 0);
        assert(crypto_aead_xchacha20poly1305_ietf_decrypt(opened, &opened_count, NULL, sealed, sealed_count,
            (const unsigned char *)moved, strlen(moved), nonce, key) != 0);
        sealed[sealed_count - 1] ^= 1;
        assert(crypto_aead_xchacha20poly1305_ietf_decrypt(opened, &opened_count, NULL, sealed, sealed_count,
            (const unsigned char *)expected, strlen(expected), nonce, key) != 0);
        if (n == 0) memcpy(first_nonce, nonce, 24);
        else assert(memcmp(first_nonce, nonce, 24) != 0);
        /* A short destination fails closed and clears what was written. */
        memset(envelope, 'x', (size_t)room);
        assert(RecordTestSeal(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, KEY_ID,
            bytes(key, 32), bytes(plain, size), bytes(nonce, 24), bytes(envelope, (size_t)written)) == -1);
        free(copy); free(sealed); free(envelope); free(plain); free(opened);
    }
    unsigned char plain[4] = {1, 2, 3, 4};
    char envelope[512];
    assert(RecordTestSeal(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, KEY_ID,
        bytes(key, 31), bytes(plain, 4), bytes(nonce, 24), bytes(envelope, sizeof envelope)) == -1);
    assert(RecordTestSeal(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, KEY_ID,
        bytes(key, 32), bytes(plain, 4), bytes(nonce, 23), bytes(envelope, sizeof envelope)) == -1);
    assert(RecordTestSeal(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, StringLiteral("main key"),
        bytes(key, 32), bytes(plain, 4), bytes(nonce, 24), bytes(envelope, sizeof envelope)) == -1);
    assert(RecordTestEnvelopeBytes(StringLiteral(ACCOUNT), APP, COLLECTION, ID, SCHEMA, KEY_ID, 8388609) == -1);
    puts("Daochi record profile v1 seals canonical metadata and opens with the libsodium reference");
    return 0;
}
