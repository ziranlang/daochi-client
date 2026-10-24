#include "entity_api.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Vectors from Python's hmac/hashlib and cryptography's ChaCha20Poly1305. */
#define RECORD_KEY "d3d54fa5cc5ead0b135a9a1506a3838c86b53b30b99a925cb52e1b18405cadd1"
#define LEVELS_KEY "1401bd0b55397f1bf59de1831dabe6f18290d7a0a1b14cfcd382502d77cd01a0"
#define SMALL_HASH "88336e7d067932997ff04438c73ae1a9cef78b36f2d10432093f44050ca2a7d1"
#define SMALL_BLOB_KEY "db16aa31596d70c588ce31caba8ce359bb4ddcdc06054e7243502e836fbb6636"
/* A photo of 8 MiB + 5 bytes, byte i = (i * 7 + 3) % 256, in two chunks. */
#define LARGE_HASH "102a8ba0d321f0ac40bf067b1399397dc926919c4d2645a2617e568d3e37cd36"
#define CHUNK0_KEY "8058dd01609b51d123fe04e123877de0a384f0b6169bb3b48dc01f44ebd132f0"
#define CHUNK1_KEY "c9a7eab9a2b79425bd92875ef5e026c7c64db0b819e059a6c5f8006e29abd5a6"
#define CHUNK0_ADDRESS "01679c4afcf6758f046775113d544a72d56dd38d4ce4165c73e26feb63338d83"
#define CHUNK1_ADDRESS "aa3d34eb39c53546a30c18e1415cbe8c749b565a3b60a4709d7fc6ff9efa1471"
#define CHUNK_BYTES 8388608

static Slice bytes(void *data, size_t size)
{
    return (Slice){.data = data, .length = size};
}

static void hex(const unsigned char *data, size_t size, char *output)
{
    for (size_t i = 0; i < size; i++) sprintf(output + i * 2, "%02x", data[i]);
}

/* The SHA-256 hex of data, through the library's own export. */
static void address(const unsigned char *data, size_t size, char *output)
{
    EntityTestSha256Hex(bytes((void *)data, size), bytes(output, 65));
}

int main(void)
{
    unsigned char private_key[2560];
    for (size_t i = 0; i < sizeof private_key; i++) private_key[i] = (unsigned char)i;
    Slice account = bytes(private_key, sizeof private_key);
    unsigned char key[32];
    char text[129];
    assert(EntityTestRecordKey(account, StringLiteral("photos"), bytes(key, 32)));
    hex(key, 32, text);
    assert(strcmp(text, RECORD_KEY) == 0);
    assert(EntityTestRecordKey(account, StringLiteral("levels"), bytes(key, 32)));
    hex(key, 32, text);
    assert(strcmp(text, LEVELS_KEY) == 0);
    assert(!EntityTestRecordKey(account, StringLiteral("Photos"), bytes(key, 32)));
    assert(!EntityTestRecordKey(account, StringLiteral(""), bytes(key, 32)));
    assert(!EntityTestRecordKey(account, StringLiteral("photos"), bytes(key, 31)));
    assert(EntityTestBlobKey(account, StringLiteral("photos"), StringLiteral(SMALL_HASH), bytes(key, 32)));
    hex(key, 32, text);
    assert(strcmp(text, SMALL_BLOB_KEY) == 0);
    assert(!EntityTestBlobKey(account, StringLiteral("photos"), StringLiteral("88336E"), bytes(key, 32)));

    size_t size = CHUNK_BYTES + 5;
    unsigned char *plain = malloc(size), *sealed = malloc(CHUNK_BYTES + 16), *again = malloc(CHUNK_BYTES + 16),
        *opened = malloc(CHUNK_BYTES);
    assert(plain && sealed && again && opened);
    for (size_t i = 0; i < size; i++) plain[i] = (unsigned char)((i * 7 + 3) % 256);
    const char *keys[] = {CHUNK0_KEY, CHUNK1_KEY}, *addresses[] = {CHUNK0_ADDRESS, CHUNK1_ADDRESS};
    for (int64_t index = 0; index < 2; index++) {
        size_t start = (size_t)index * CHUNK_BYTES, count = index == 0 ? CHUNK_BYTES : 5;
        assert(EntityTestChunkKey(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), index, bytes(key, 32)));
        hex(key, 32, text);
        assert(strcmp(text, keys[index]) == 0);
        int64_t length = EntityTestSeal(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), index,
            bytes(plain + start, count), bytes(sealed, CHUNK_BYTES + 16));
        assert(length == (int64_t)count + 16);
        address(sealed, (size_t)length, text);
        assert(strcmp(text, addresses[index]) == 0);
        /* The same photo seals to the same chunks, so the node keeps one copy. */
        assert(EntityTestSeal(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), index,
            bytes(plain + start, count), bytes(again, CHUNK_BYTES + 16)) == length);
        assert(memcmp(sealed, again, (size_t)length) == 0);
        assert(EntityTestOpen(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), index,
            bytes(sealed, (size_t)length), bytes(opened, CHUNK_BYTES)) == (int64_t)count);
        assert(memcmp(opened, plain + start, count) == 0);
        /* Another index, kind, content, key or a tampered byte never opens. */
        assert(EntityTestOpen(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), 1 - index,
            bytes(sealed, (size_t)length), bytes(opened, CHUNK_BYTES)) == -1);
        assert(EntityTestOpen(account, StringLiteral("levels"), StringLiteral(LARGE_HASH), index,
            bytes(sealed, (size_t)length), bytes(opened, CHUNK_BYTES)) == -1);
        assert(EntityTestOpen(account, StringLiteral("photos"), StringLiteral(SMALL_HASH), index,
            bytes(sealed, (size_t)length), bytes(opened, CHUNK_BYTES)) == -1);
        sealed[3] ^= 1;
        assert(EntityTestOpen(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), index,
            bytes(sealed, (size_t)length), bytes(opened, CHUNK_BYTES)) == -1);
        sealed[3] ^= 1;
        private_key[0] ^= 1;
        assert(EntityTestOpen(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), index,
            bytes(sealed, (size_t)length), bytes(opened, CHUNK_BYTES)) == -1);
        private_key[0] ^= 1;
        for (size_t i = 0; i < count; i++) assert(opened[i] == 0);
    }
    /* Chunks are at most 8 MiB, so each sealed blob stays below the node's 16 MiB limit. */
    assert(EntityTestSeal(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), 0,
        bytes(plain, size), bytes(sealed, CHUNK_BYTES + 16)) == -1);
    assert(EntityTestSeal(account, StringLiteral("photos"), StringLiteral(LARGE_HASH), -1,
        bytes(plain, 5), bytes(sealed, CHUNK_BYTES + 16)) == -1);
    free(plain);
    free(sealed);
    free(again);
    free(opened);
    puts("Entity record keys and chunked shared blobs passed");
    return 0;
}
