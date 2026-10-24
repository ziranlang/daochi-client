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
/* A level record sealed by Python with libsodium's XChaCha20-Poly1305:
 * the levels record key, nonce 10..27 and this plain text. */
#define RECORD_ACCOUNT "9af211329b2fc82e5efe906062c730082819b23fe8394bc435e0b1bf0458eb54"
#define RECORD_ID "0123456789abcdef0123456789abcdef"
#define RECORD_PLAIN "{\"format\":\"shovey-levels-1\",\"edition\":\"classic\",\"title\":\"One\",\"levels\":[],\"updated_at\":1792800000}"
#define RECORD_NONCE "EBESExQVFhcYGRobHB0eHyAhIiMkJSYn"
#define RECORD_TEXT "eyJhYWQiOnsiYWNjb3VudF9pZCI6IjlhZjIxMTMyOWIyZmM4MmU1ZWZlOTA2MDYyYzczMDA4MjgxOWIyM2ZlODM5NGJjNDM1ZTBiMWJmMDQ1OGViNTQiLCJhcHBfaWQiOiJlbnRpdHkiLCJjb2xsZWN0aW9uIjoicHJpdmF0ZS5lbnRpdHkudjEubGV2ZWxzIiwiaWQiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsInNjaGVtYSI6ImVudGl0eS5sZXZlbHMudjEifSwiYWxnIjoieGNoYWNoYTIwcG9seTEzMDUiLCJjaXBoZXJ0ZXh0Ijoic3ZCUmJ6TVM5aUItbnlwS05QTUVDQXp1Sng4OExHTkhDazVEWVowalNZYzNCUFpKVFdZSjFVU1JXUHNXYzBKVmx0Z25EOWtFYXQ2ODE5WjZZaWh0eEp4cG5LeF9zMGpLcDctSnBMZWVNRlRjd2hGYzJhZV9UZ3AwSjRYM1hITzhQN0VvNk9hRVRMS0pIa1ZURU5MX3ZQZlIiLCJrZXlfaWQiOiJlbnRpdHktdjEiLCJub25jZSI6IkVCRVNFeFFWRmhjWUdSb2JIQjBlSHlBaElpTWtKU1luIiwicHJvZmlsZSI6ImRhb2NoaS1yZWNvcmQtdjEifQ"

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

    /* Records: the daochi-record-v1 envelope as the sync request carries it. */
    unsigned char nonce[24], scratch[1024], text_out[2048], envelope[2048], record[512], schema[129];
    for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = (unsigned char)(0x10 + i);
    char nonce_text[40] = {0};
    assert(EntityTestNonceText(bytes(nonce, 24), bytes(nonce_text, sizeof nonce_text)) == 32);
    assert(memcmp(nonce_text, RECORD_NONCE, 32) == 0);
    size_t plain_size = strlen(RECORD_PLAIN);
    int64_t text_size = EntityTestSealRecord(account, StringLiteral(RECORD_ACCOUNT), StringLiteral("levels"),
        StringLiteral(RECORD_ID), StringLiteral("entity.levels.v1"), bytes(RECORD_PLAIN, plain_size),
        bytes(nonce, 24), bytes(scratch, sizeof scratch), bytes(text_out, sizeof text_out));
    assert(text_size == (int64_t)strlen(RECORD_TEXT));
    assert(memcmp(text_out, RECORD_TEXT, (size_t)text_size) == 0);
    int64_t envelope_size = EntityTestEnvelope(StringView((const char *)text_out, (size_t)text_size),
        bytes(envelope, sizeof envelope));
    assert(envelope_size > 0);
    String sealed_envelope = StringView((const char *)envelope, (size_t)envelope_size);
    memset(schema, 0x55, sizeof schema);
    int64_t record_size = EntityTestOpenRecord(account, StringLiteral(RECORD_ACCOUNT), StringLiteral("levels"),
        StringLiteral(RECORD_ID), sealed_envelope, bytes(schema, sizeof schema), bytes(record, sizeof record));
    assert(record_size == (int64_t)plain_size && memcmp(record, RECORD_PLAIN, plain_size) == 0);
    assert(strcmp((const char *)schema, "entity.levels.v1") == 0);
    /* Another account, kind, record or key, or a changed byte, never opens. */
    assert(EntityTestOpenRecord(account, StringLiteral(SMALL_HASH), StringLiteral("levels"),
        StringLiteral(RECORD_ID), sealed_envelope, bytes(schema, sizeof schema), bytes(record, sizeof record)) == -1);
    assert(EntityTestOpenRecord(account, StringLiteral(RECORD_ACCOUNT), StringLiteral("photos"),
        StringLiteral(RECORD_ID), sealed_envelope, bytes(schema, sizeof schema), bytes(record, sizeof record)) == -1);
    assert(EntityTestOpenRecord(account, StringLiteral(RECORD_ACCOUNT), StringLiteral("levels"),
        StringLiteral("0123456789abcdef0123456789abcdee"), sealed_envelope, bytes(schema, sizeof schema),
        bytes(record, sizeof record)) == -1);
    private_key[7] ^= 1;
    assert(EntityTestOpenRecord(account, StringLiteral(RECORD_ACCOUNT), StringLiteral("levels"),
        StringLiteral(RECORD_ID), sealed_envelope, bytes(schema, sizeof schema), bytes(record, sizeof record)) == -1);
    private_key[7] ^= 1;
    char *cipher = strstr((char *)envelope, "\"ciphertext\":\"");
    assert(cipher != NULL && (unsigned char *)cipher < envelope + envelope_size);
    cipher[20] = cipher[20] == 'A' ? 'B' : 'A';
    assert(EntityTestOpenRecord(account, StringLiteral(RECORD_ACCOUNT), StringLiteral("levels"),
        StringLiteral(RECORD_ID), sealed_envelope, bytes(schema, sizeof schema), bytes(record, sizeof record)) == -1);
    for (size_t i = 0; i < plain_size; i++) assert(record[i] == 0);
    /* The node keeps at most 256 KiB of ciphertext text per record. */
    assert(EntityTestSealRecord(account, StringLiteral(RECORD_ACCOUNT), StringLiteral("levels"),
        StringLiteral(RECORD_ID), StringLiteral("entity.levels.v1"), bytes(RECORD_PLAIN, plain_size),
        bytes(nonce, 24), bytes(scratch, sizeof scratch), bytes(text_out, 100)) == -1);
    puts("Entity record keys, records and chunked shared blobs passed");
    return 0;
}
