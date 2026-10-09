#include "transaction.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void hex_text(char *text, char fill, size_t count)
{
    memset(text, fill, count);
    text[count] = 0;
}

int main(void)
{
    char account[65], key[65], tx_id[65], nonce[65], hash[65];
    char account_signature[4841], device_signature[129];
    char output[8192];
    hex_text(account, 'a', 64);
    hex_text(key, 'b', 64);
    hex_text(tx_id, 'd', 64);
    hex_text(nonce, 'e', 64);
    hex_text(hash, 'f', 64);
    hex_text(account_signature, 'c', 4840);
    hex_text(device_signature, 'd', 128);
    Slice buffer = {.data = output, .length = sizeof output};
    DeviceRegistration registration = {
        .account_id = StringView(account, 64),
        .app_id = StringLiteral("inbe"),
        .device_key_id = StringView(key, 64),
        .client_id = StringLiteral("client-1"),
        .public_key_hex = StringView(key, 64),
        .nonce = StringView(nonce, 64),
        .expires_at = 1700000300,
    };
    assert(BuildDeviceRegistrationMessage(registration, buffer));
    assert(strncmp(output, "daochi-device-registration-v1\n", 30) == 0);
    assert(strstr(output, "\ninbe\n") != NULL);
    assert(strstr(output, "\nclient-1\n") != NULL);
    assert(strstr(output, "\n1700000300\n") != NULL);
    assert(BuildDeviceRegistrationBody(registration,
        StringView(account_signature, 4840), buffer));
    assert(strstr(output, "\"device_key_id\":\"bbbb") != NULL);
    assert(strstr(output, "\"expires_at\":1700000300") != NULL);
    assert(strstr(output, "\"signature\":\"cccc") != NULL);

    SyncTransaction transaction = {
        .account_id = StringView(account, 64),
        .app_id = StringLiteral("inbe"),
        .device_key_id = StringView(key, 64),
        .tx_id = StringView(tx_id, 64),
        .nonce = StringView(nonce, 64),
        .body_sha256_hex = StringView(hash, 64),
        .expires_at = 1700000300,
    };
    assert(BuildSyncTransactionMessage(transaction, buffer));
    assert(strncmp(output, "daochi-tx-v1\n6\n", 15) == 0);
    assert(strstr(output, "\nPOST\n/api/v1/sync\n") != NULL);
    assert(strstr(output, "\n1700000300\n") != NULL);
    assert(BuildSyncTransactionHeader(transaction,
        StringView(account_signature, 4840),
        StringView(device_signature, 128), buffer));
    assert(strstr(output, "\"protocol_version\":6") != NULL);
    assert(strstr(output, "\"signature_context\":\"daochi-tx-v1\"") != NULL);
    assert(strstr(output, "\"device_signature\":\"dddd") != NULL);

    char legacy[8192];
    strcpy(legacy, output);
    assert(BuildTransactionHeader(transaction, StringLiteral("POST"), StringLiteral("/api/v1/sync"),
        StringView(account_signature, 4840), StringView(device_signature, 128), buffer));
    assert(strcmp(legacy, output) == 0);
    assert(BuildSyncTransactionMessage(transaction, buffer));
    strcpy(legacy, output);
    assert(BuildTransactionMessage(transaction, StringLiteral("POST"), StringLiteral("/api/v1/sync"), buffer));
    assert(strcmp(legacy, output) == 0);
    const char *methods[] = {"GET", "HEAD", "PUT", "POST"};
    for (size_t i = 0; i < sizeof methods / sizeof *methods; i++) {
        String method = StringView(methods[i], strlen(methods[i]));
        String path = StringLiteral("/api/v1/blobs/photos/abcdef?part=1");
        assert(BuildTransactionMessage(transaction, method, path, buffer));
        char expected[128];
        snprintf(expected, sizeof expected, "\n%s\n/api/v1/blobs/photos/abcdef?part=1\n", methods[i]);
        assert(strstr(output, expected));
        assert(BuildTransactionHeader(transaction, method, path,
            StringView(account_signature, 4840), StringView(device_signature, 128), buffer));
        snprintf(expected, sizeof expected, "\"method\":\"%s\",\"path\":\"/api/v1/blobs/photos/abcdef?part=1\"", methods[i]);
        assert(strstr(output, expected));
    }
    const char *invalid_paths[] = {"", "https://example.com/api/v1/sync", "/api/v1/sync\nGET", "/api/v1/sync\r", "/api/v1/sync bad", "/bad\\path", "/bad\"path"};
    for (size_t i = 0; i < sizeof invalid_paths / sizeof *invalid_paths; i++) {
        String path = StringView(invalid_paths[i], strlen(invalid_paths[i]));
        assert(!BuildTransactionMessage(transaction, StringLiteral("POST"), path, buffer));
        assert(output[0] == 0);
        assert(!BuildTransactionHeader(transaction, StringLiteral("POST"), path,
            StringView(account_signature, 4840), StringView(device_signature, 128), buffer));
        assert(output[0] == 0);
    }
    assert(!BuildTransactionMessage(transaction, StringLiteral("post"), StringLiteral("/api/v1/sync"), buffer));
    assert(output[0] == 0);

    buffer.length = 32;
    assert(!BuildSyncTransactionHeader(transaction,
        StringView(account_signature, 4840),
        StringView(device_signature, 128), buffer));
    assert(output[0] == 0);
    transaction.tx_id = StringLiteral("invalid");
    buffer.length = sizeof output;
    assert(!BuildSyncTransactionMessage(transaction, buffer));
    assert(output[0] == 0);
    puts("Daochi Ziran v6 transaction wire passed");
    return 0;
}
