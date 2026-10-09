#include "crypto_native_api.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Independent reference implementation for the released byte format. */
extern int crypto_aead_xchacha20poly1305_ietf_encrypt(unsigned char *,
    unsigned long long *, const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long, const unsigned char *,
    const unsigned char *, const unsigned char *);
extern int crypto_hash_sha256(unsigned char *, const unsigned char *, unsigned long long);
extern int crypto_auth_hmacsha256(unsigned char *, const unsigned char *, unsigned long long, const unsigned char *);
extern int crypto_sign_seed_keypair(unsigned char *, unsigned char *, const unsigned char *);
extern int crypto_sign_detached(unsigned char *, unsigned long long *, const unsigned char *, unsigned long long, const unsigned char *);
extern int crypto_pwhash(unsigned char *, unsigned long long, const char *, unsigned long long, const unsigned char *, unsigned long long, size_t, int);

static Slice bytes(void *data, size_t size)
{
    return (Slice){.data = data, .length = size};
}

int main(void)
{
    unsigned char key[32], nonce[24], aad[19], hash[32], reference_hash[32];
    for (size_t i = 0; i < sizeof key; i++) key[i] = (unsigned char)i;
    for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = (unsigned char)(255 - i);
    for (size_t i = 0; i < sizeof aad; i++) aad[i] = (unsigned char)(i * 17);
    const size_t sizes[] = {0, 1, 15, 16, 17, 63, 64, 65, 4096, 8388608};
    for (size_t n = 0; n < sizeof sizes / sizeof *sizes; n++) {
        size_t size = sizes[n];
        unsigned char *plain = malloc(size + 1), *sealed = malloc(size + 16);
        unsigned char *reference = malloc(size + 16), *opened = malloc(size + 1);
        assert(plain && sealed && reference && opened);
        for (size_t i = 0; i < size; i++) plain[i] = (unsigned char)(i * 13 + n);
        unsigned long long written = 0;
        assert(crypto_aead_xchacha20poly1305_ietf_encrypt(reference, &written,
            plain, size, aad, sizeof aad, NULL, nonce, key) == 0);
        assert(ContentSeal(bytes(plain, size), bytes(aad, sizeof aad), bytes(key, 32),
            bytes(nonce, 24), bytes(sealed, size + 16)) == (int64_t)(size + 16));
        assert(written == size + 16 && memcmp(reference, sealed, size + 16) == 0);
        assert(ContentOpen(bytes(reference, size + 16), bytes(aad, sizeof aad), bytes(key, 32),
            bytes(nonce, 24), bytes(opened, size)) == (int64_t)size);
        assert(memcmp(opened, plain, size) == 0);
        assert(ContentDigest(bytes(plain, size), bytes(hash, 32)));
        assert(crypto_hash_sha256(reference_hash, plain, size) == 0);
        assert(memcmp(hash, reference_hash, 32) == 0);
        assert(ContentHmacSha256(bytes(plain, size), bytes(key, 32), bytes(hash, 32)));
        assert(crypto_auth_hmacsha256(reference_hash, plain, size, key) == 0);
        assert(memcmp(hash, reference_hash, 32) == 0);
        unsigned char *state = malloc(ContentDigestStateBytes());
        assert(state && ContentDigestStart(bytes(state, ContentDigestStateBytes())));
        size_t middle = size / 2;
        assert(ContentDigestUpdate(bytes(state, ContentDigestStateBytes()), bytes(plain, middle)));
        assert(ContentDigestUpdate(bytes(state, ContentDigestStateBytes()), bytes(plain + middle, size - middle)));
        assert(ContentDigestFinish(bytes(state, ContentDigestStateBytes()), bytes(hash, 32)));
        assert(crypto_hash_sha256(reference_hash, plain, size) == 0);
        assert(memcmp(hash, reference_hash, 32) == 0);
        free(state);
        for (int mutation = 0; mutation < 4; mutation++) {
            memset(opened, 0xff, size);
            if (mutation == 0) sealed[size + 15] ^= 1;
            if (mutation == 1) aad[0] ^= 1;
            if (mutation == 2) key[0] ^= 1;
            if (mutation == 3) nonce[0] ^= 1;
            assert(ContentOpen(bytes(sealed, size + 16), bytes(aad, sizeof aad), bytes(key, 32),
                bytes(nonce, 24), bytes(opened, size)) == -1);
            for (size_t i = 0; i < size; i++) assert(opened[i] == 0);
            if (mutation == 0) sealed[size + 15] ^= 1;
            if (mutation == 1) aad[0] ^= 1;
            if (mutation == 2) key[0] ^= 1;
            if (mutation == 3) nonce[0] ^= 1;
        }
        assert(ContentSeal(bytes(plain, size), bytes(aad, sizeof aad), bytes(key, 31),
            bytes(nonce, 24), bytes(sealed, size + 16)) == -1);
        assert(ContentSeal(bytes(plain, size), bytes(aad, sizeof aad), bytes(key, 32),
            bytes(nonce, 23), bytes(sealed, size + 16)) == -1);
        assert(ContentSeal(bytes(plain, size), bytes(aad, sizeof aad), bytes(key, 32),
            bytes(nonce, 24), bytes(sealed, size + 15)) == -1);
        free(plain); free(sealed); free(reference); free(opened);
    }
    assert(ContentOpen(bytes(key, 15), bytes(NULL, 0), bytes(key, 32), bytes(nonce, 24), bytes(hash, 32)) == -1);
    for (size_t i = 0; i < sizeof hash; i++) assert(hash[i] == 0);
    assert(!ContentDigestStart(bytes(key, 1)));
    assert(!ContentDigest(bytes(key, 32), bytes(hash, 31)));
    assert(ContentRandomBytes(bytes(hash, 32)));
    ContentClear(bytes(hash, 32));
    for (size_t i = 0; i < sizeof hash; i++) assert(hash[i] == 0);
    unsigned char public_key[32], reference_public[32], private_key[64], signature[64], reference_signature[64];
    unsigned long long written = 0;
    assert(crypto_sign_seed_keypair(reference_public, private_key, key) == 0);
    assert(ContentDevicePublic(bytes(key, 32), bytes(public_key, 32)));
    assert(memcmp(public_key, reference_public, 32) == 0);
    assert(crypto_sign_detached(reference_signature, &written, aad, sizeof aad, private_key) == 0);
    assert(ContentSignDevice(bytes(key, 32), bytes(aad, sizeof aad), bytes(signature, 64)));
    assert(written == 64 && memcmp(signature, reference_signature, 64) == 0);
    assert(!ContentSignDevice(bytes(key, 31), bytes(aad, sizeof aad), bytes(signature, 64)));
    assert(crypto_pwhash(reference_hash, 32, (const char *)key, 32, nonce, 1, 8192, 2) == 0);
    assert(ContentDerivePassword(bytes(key, 32), bytes(nonce, 16), bytes(hash, 32), 1, 8192));
    assert(memcmp(hash, reference_hash, 32) == 0);
    assert(!ContentDerivePassword(bytes(key, 32), bytes(nonce, 15), bytes(hash, 32), 1, 8192));
    for (size_t i = 0; i < sizeof hash; i++) assert(hash[i] == 0);
    puts("Daochi native content crypto matches released blobs and rejects changed context/key/nonce/tag");
    return 0;
}
