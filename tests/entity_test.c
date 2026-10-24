#include "entity_api.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Vectors from Python's hmac/hashlib and cryptography's ChaCha20Poly1305. */
#define RECORD_KEY "d3d54fa5cc5ead0b135a9a1506a3838c86b53b30b99a925cb52e1b18405cadd1"
#define LEVELS_KEY "1401bd0b55397f1bf59de1831dabe6f18290d7a0a1b14cfcd382502d77cd01a0"
#define HASH "88336e7d067932997ff04438c73ae1a9cef78b36f2d10432093f44050ca2a7d1"
#define BLOB_KEY "db16aa31596d70c588ce31caba8ce359bb4ddcdc06054e7243502e836fbb6636"
#define SEALED "26677749bca793ba6a2e4cd576446cd5caeb7f4625cf4b7cba42abc3e6"

static Slice bytes(void *data, size_t size)
{
    return (Slice){.data = data, .length = size};
}

static void hex(const unsigned char *data, size_t size, char *output)
{
    for (size_t i = 0; i < size; i++) sprintf(output + i * 2, "%02x", data[i]);
}

int main(void)
{
    unsigned char private_key[2560];
    for (size_t i = 0; i < sizeof private_key; i++) private_key[i] = (unsigned char)i;
    unsigned char key[32];
    char text[129];
    assert(EntityTestRecordKey(bytes(private_key, sizeof private_key), StringLiteral("photos"), bytes(key, 32)));
    hex(key, 32, text);
    assert(strcmp(text, RECORD_KEY) == 0);
    assert(EntityTestRecordKey(bytes(private_key, sizeof private_key), StringLiteral("levels"), bytes(key, 32)));
    hex(key, 32, text);
    assert(strcmp(text, LEVELS_KEY) == 0);
    assert(!EntityTestRecordKey(bytes(private_key, sizeof private_key), StringLiteral("Photos"), bytes(key, 32)));
    assert(!EntityTestRecordKey(bytes(private_key, sizeof private_key), StringLiteral(""), bytes(key, 32)));
    assert(!EntityTestRecordKey(bytes(private_key, sizeof private_key), StringLiteral("photos"), bytes(key, 31)));
    assert(EntityTestBlobKey(bytes(private_key, sizeof private_key), StringLiteral("photos"), StringLiteral(HASH), bytes(key, 32)));
    hex(key, 32, text);
    assert(strcmp(text, BLOB_KEY) == 0);
    assert(!EntityTestBlobKey(bytes(private_key, sizeof private_key), StringLiteral("photos"), StringLiteral("88336E"), bytes(key, 32)));

    unsigned char plain[] = "\0photo bytes\xff";
    size_t plain_size = sizeof plain - 1;
    unsigned char sealed[64], again[64], opened[64];
    char hash[65];
    int64_t length = EntityTestSeal(bytes(private_key, sizeof private_key), StringLiteral("photos"),
        bytes(plain, plain_size), bytes(hash, sizeof hash), bytes(sealed, sizeof sealed));
    assert(length == (int64_t)plain_size + 16 && strcmp(hash, HASH) == 0);
    hex(sealed, (size_t)length, text);
    assert(strcmp(text, SEALED) == 0);
    /* The same photo seals to the same bytes, so the node keeps one copy. */
    assert(EntityTestSeal(bytes(private_key, sizeof private_key), StringLiteral("photos"),
        bytes(plain, plain_size), bytes(hash, sizeof hash), bytes(again, sizeof again)) == length);
    assert(memcmp(sealed, again, (size_t)length) == 0);
    assert(EntityTestOpen(bytes(private_key, sizeof private_key), StringLiteral("photos"), StringLiteral(HASH),
        bytes(sealed, (size_t)length), bytes(opened, sizeof opened)) == (int64_t)plain_size);
    assert(memcmp(opened, plain, plain_size) == 0);
    /* Another kind, a tampered byte or the wrong content hash never opens. */
    assert(EntityTestOpen(bytes(private_key, sizeof private_key), StringLiteral("levels"), StringLiteral(HASH),
        bytes(sealed, (size_t)length), bytes(opened, sizeof opened)) == -1);
    sealed[3] ^= 1;
    assert(EntityTestOpen(bytes(private_key, sizeof private_key), StringLiteral("photos"), StringLiteral(HASH),
        bytes(sealed, (size_t)length), bytes(opened, sizeof opened)) == -1);
    sealed[3] ^= 1;
    private_key[0] ^= 1;
    assert(EntityTestOpen(bytes(private_key, sizeof private_key), StringLiteral("photos"), StringLiteral(HASH),
        bytes(sealed, (size_t)length), bytes(opened, sizeof opened)) == -1);
    for (size_t i = 0; i < sizeof opened; i++) assert(opened[i] == 0);
    puts("Entity record keys and shared blobs passed");
    return 0;
}
