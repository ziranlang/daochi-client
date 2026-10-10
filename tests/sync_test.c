#include "sync.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct FakeServer {
    int stage;
    int account_signs;
    int device_signs;
    int nonces;
} FakeServer;

static bool digest(String body, Slice output)
{
    assert(body.length > 0 && output.length >= 65);
    memset(output.data, 'f', 64);
    ((char *)output.data)[64] = 0;
    return true;
}

static bool account_sign(void *context, String message, Slice output)
{
    FakeServer *server = context;
    ++server->account_signs;
    if (server->account_signs == 1) {
        assert(message.length > 20);
        assert(memcmp(message.data, "daochi-sync-v1\nPOST\n/api/v1/sync/login\n", 39) == 0);
    } else if (server->account_signs == 2) {
        assert(memcmp(message.data, "daochi-device-registration-v1\n", 30) == 0);
        assert(strstr(message.data, "\ninbe\n") != NULL);
        assert(strstr(message.data, "\n1700000300\n") != NULL);
    } else {
        assert(server->account_signs == 3);
        assert(memcmp(message.data, "daochi-tx-v1\n6\n", 15) == 0);
        assert(strstr(message.data, "\nPOST\n/api/v1/sync\n") != NULL);
        assert(strstr(message.data, "\n1700000300\n") != NULL);
    }
    assert(output.length >= 4841);
    memset(output.data, 'a', 4840);
    ((char *)output.data)[4840] = 0;
    return true;
}

static bool device_sign(void *context, String message, Slice output)
{
    FakeServer *server = context;
    ++server->device_signs;
    assert(server->device_signs == 1);
    assert(memcmp(message.data, "daochi-tx-v1\n6\n", 15) == 0);
    assert(output.length >= 129);
    memset(output.data, 'd', 128);
    ((char *)output.data)[128] = 0;
    return true;
}

static bool nonce(void *context, Slice output)
{
    FakeServer *server = context;
    ++server->nonces;
    assert(server->nonces <= 3 && output.length >= 65);
    memset(output.data, '0' + server->nonces, 64);
    ((char *)output.data)[64] = 0;
    return true;
}

static bool send_request(void *context, HttpRequest request,
                         Slice output, int32_t *status)
{
    FakeServer *server = context;
    ++server->stage;
    assert(request.url.length < 1024);
    assert(request.url.data[request.url.length] == 0);
    switch (server->stage) {
    case 1:
        assert(strstr(request.url.data, "/api/v1/sync/challenge?") != NULL);
        strcpy(output.data, "{\"nonce\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}");
        break;
    case 2:
        assert(strstr(request.url.data, "/api/v1/sync/login") != NULL);
        assert(request.headers.length == 2);
        strcpy(output.data, "{\"auth_token\":\"token\",\"expires_in_seconds\":1800,\"server_time\":1700000000}");
        break;
    case 3:
        assert(strstr(request.url.data, "/api/v1/account/devices") != NULL);
        assert(request.token.length == 5);
        assert(strstr(request.body.data, "\"app_id\":\"inbe\"") != NULL);
        assert(strstr(request.body.data, "\"nonce\":\"111111") != NULL);
        assert(strstr(request.body.data, "\"expires_at\":1700000300") != NULL);
        strcpy(output.data, "{}");
        break;
    case 4: {
        assert(strstr(request.url.data, "/api/v1/sync") != NULL);
        assert(request.headers.length == 3);
        const HttpHeader *headers = request.headers.data;
        assert(headers[2].name.length == 11);
        assert(memcmp(headers[2].name.data, "X-Daochi-Tx", 11) == 0);
        assert(strstr(headers[2].value.data, "\"protocol_version\":6") != NULL);
        assert(strstr(headers[2].value.data, "\"tx_id\":\"222222") != NULL);
        assert(strstr(headers[2].value.data, "\"nonce\":\"333333") != NULL);
        assert(strstr(headers[2].value.data, "\"body_sha256\":\"ffffff") != NULL);
        assert(strstr(headers[2].value.data, "\"device_signature\":\"dddddd") != NULL);
        assert(request.body.length == 22);
        assert(memcmp(request.body.data, "{\"protocol_version\":6}", 22) == 0);
        strcpy(output.data, "{\"server_version\":7}");
        break;
    }
    default:
        assert(!"unexpected request");
    }
    *status = 200;
    return true;
}

typedef struct HeaderPreparation {
    char message[4096];
    int account_signs;
    int device_signs;
    bool fail_device;
} HeaderPreparation;

static String expected_body;

static bool request_digest(String body, Slice output)
{
    assert(body.length == expected_body.length);
    assert(body.length == 0 || memcmp(body.data, expected_body.data, body.length) == 0);
    assert(output.length >= 65);
    memset(output.data, 'f', 64);
    ((char *)output.data)[64] = 0;
    return true;
}

static bool request_account_sign(void *context, String message, Slice output)
{
    HeaderPreparation *prepared = context;
    assert(message.length < sizeof prepared->message);
    memcpy(prepared->message, message.data, message.length);
    prepared->message[message.length] = 0;
    ++prepared->account_signs;
    assert(output.length >= 4841);
    memset(output.data, 'a', 4840);
    ((char *)output.data)[4840] = 0;
    return true;
}

static bool request_device_sign(void *context, String message, Slice output)
{
    HeaderPreparation *prepared = context;
    assert(message.length == strlen(prepared->message));
    assert(memcmp(message.data, prepared->message, message.length) == 0);
    ++prepared->device_signs;
    if (prepared->fail_device) return false;
    assert(output.length >= 129);
    memset(output.data, 'd', 128);
    ((char *)output.data)[128] = 0;
    return true;
}

static bool request_nonce(void *context, Slice output)
{
    (void)context;
    assert(output.length >= 65);
    memset(output.data, 'b', 64);
    ((char *)output.data)[64] = 0;
    return true;
}

static void check_request_preparation(Client client, Device device)
{
    HeaderPreparation prepared = {0};
    client.identity.signing_context = &prepared;
    client.signer = request_account_sign;
    client.digest = request_digest;
    device.signing_context = &prepared;
    device.signer = request_device_sign;
    Session session = {.server_time = 1700000000, .login_local_time = 1000};
    char output[8192], legacy[8192];
    Slice buffer = {.data = output, .length = sizeof output};
    const char binary[] = {'\0', '\xff', 'x', '\0'};
    const char *methods[] = {"GET", "HEAD", "PUT", "POST"};
    for (size_t i = 0; i < sizeof methods / sizeof *methods; ++i) {
        expected_body = i < 2 ? StringLiteral("") : StringView(binary, sizeof binary);
        String method = StringView(methods[i], strlen(methods[i]));
        String path = StringLiteral("/api/v1/blobs/photos/abcdef?part=1");
        assert(sync_PrepareRequestHeader(client, &session, device, 1007, NULL, request_nonce,
            method, path, expected_body, buffer) == AuthResult_AUTH_OK);
        char expected[128];
        snprintf(expected, sizeof expected, "\n%s\n/api/v1/blobs/photos/abcdef?part=1\n", methods[i]);
        assert(strstr(prepared.message, expected));
        assert(strstr(prepared.message, "\n1700000307\n"));
        assert(strstr(output, "\"expires_at\":1700000307"));
    }

    expected_body = StringLiteral("{\"protocol_version\":6}");
    assert(sync_PrepareSyncHeader(client, &session, device, 1007, NULL, request_nonce,
        expected_body, buffer) == AuthResult_AUTH_OK);
    strcpy(legacy, output);
    assert(sync_PrepareRequestHeader(client, &session, device, 1007, NULL, request_nonce,
        StringLiteral("POST"), StringLiteral("/api/v1/sync"), expected_body,
        buffer) == AuthResult_AUTH_OK);
    assert(strcmp(legacy, output) == 0);

    char path[2049];
    memset(path, 'x', sizeof path - 1);
    path[0] = '/';
    path[sizeof path - 1] = 0;
    assert(sync_PrepareRequestHeader(client, &session, device, 1007, NULL, request_nonce,
        StringLiteral("PUT"), StringView(path, sizeof path - 1), expected_body,
        buffer) == AuthResult_AUTH_OK);

    int signs = prepared.account_signs;
    assert(sync_PrepareRequestHeader(client, &session, device, 1007, NULL, request_nonce,
        StringLiteral("PUT"), StringLiteral("/bad\npath"), expected_body,
        buffer) == AuthResult_AUTH_PAYLOAD_FAILED);
    assert(output[0] == 0 && prepared.account_signs == signs);
    assert(sync_PrepareRequestHeader(client, NULL, device, 1007, NULL, request_nonce,
        StringLiteral("PUT"), StringLiteral("/valid"), expected_body,
        buffer) == AuthResult_AUTH_PAYLOAD_FAILED);
    assert(output[0] == 0 && prepared.account_signs == signs);
    assert(sync_PrepareRequestHeader(client, &session, device, 1007, NULL, NULL,
        StringLiteral("PUT"), StringLiteral("/valid"), expected_body,
        buffer) == AuthResult_AUTH_PAYLOAD_FAILED);

    char hex[65];
    memset(hex, 'c', 64);
    hex[64] = 0;
    SyncTransaction transaction = {
        .account_id = client.identity.account_id,
        .app_id = client.app_id,
        .device_key_id = device.key_id,
        .tx_id = StringView(hex, 64),
        .nonce = StringView(hex, 64),
        .body_sha256_hex = StringView(hex, 64),
        .expires_at = 2000000000,
    };
    assert(sync_SignTransactionHeader(client, device, transaction, StringLiteral("HEAD"),
        StringLiteral("/api/v1/blobs/photos/abcdef"), buffer) == AuthResult_AUTH_OK);
    assert(strstr(output, "\"expires_at\":2000000000"));
    signs = prepared.account_signs;
    SyncTransaction wrong = transaction;
    wrong.account_id = StringView(hex, 64);
    assert(sync_SignTransactionHeader(client, device, wrong, StringLiteral("HEAD"),
        StringLiteral("/valid"), buffer) == AuthResult_AUTH_PAYLOAD_FAILED);
    wrong = transaction;
    wrong.app_id = StringLiteral("another-app");
    assert(sync_SignTransactionHeader(client, device, wrong, StringLiteral("HEAD"),
        StringLiteral("/valid"), buffer) == AuthResult_AUTH_PAYLOAD_FAILED);
    wrong = transaction;
    wrong.device_key_id = StringView(hex, 64);
    assert(sync_SignTransactionHeader(client, device, wrong, StringLiteral("HEAD"),
        StringLiteral("/valid"), buffer) == AuthResult_AUTH_PAYLOAD_FAILED);
    assert(output[0] == 0 && prepared.account_signs == signs);
    prepared.fail_device = true;
    assert(sync_SignTransactionHeader(client, device, transaction, StringLiteral("HEAD"),
        StringLiteral("/valid"), buffer) == AuthResult_AUTH_SIGN_FAILED);
    assert(output[0] == 0);
    prepared.fail_device = false;
    Slice tiny = {.data = output, .length = 16};
    assert(sync_SignTransactionHeader(client, device, transaction, StringLiteral("HEAD"),
        StringLiteral("/valid"), tiny) == AuthResult_AUTH_PAYLOAD_FAILED);
    assert(output[0] == 0);
    device.signer = NULL;
    assert(sync_SignTransactionHeader(client, device, transaction, StringLiteral("HEAD"),
        StringLiteral("/valid"), buffer) == AuthResult_AUTH_PAYLOAD_FAILED);
    assert(output[0] == 0);
}

int main(void)
{
    FakeServer server = {0};
    char account[65], device_key[65];
    memset(account, 'a', 64);
    account[64] = 0;
    memset(device_key, 'b', 64);
    device_key[64] = 0;
    Client client = {0};
    client.server_url = StringLiteral("http://127.0.0.1:8080");
    client.app_id = StringLiteral("inbe");
    client.identity.account_id = StringView(account, 64);
    client.identity.public_key = StringLiteral("public-key");
    client.identity.client_id = StringLiteral("client-1");
    client.identity.signing_context = &server;
    client.digest = digest;
    client.signer = account_sign;
    client.send = send_request;
    client.transport_context = &server;
    Device device = {
        .key_id = StringView(device_key, 64),
        .public_key_hex = StringView(device_key, 64),
        .signing_context = &server,
        .signer = device_sign,
    };
    Session session = {0};
    char response[256];
    int32_t status = 0;
    AuthResult result = Sync(client, &session, device, 1000, &server, nonce,
        StringLiteral("{\"protocol_version\":6}"),
        (Slice){.data = response, .length = sizeof response}, &status);
    assert(result == AuthResult_AUTH_OK);
    assert(status == 200 && server.stage == 4);
    assert(server.account_signs == 3 && server.device_signs == 1);
    assert(server.nonces == 3);
    assert(strcmp(response, "{\"server_version\":7}") == 0);
    check_request_preparation(client, device);
    puts("Daochi Ziran signed sync passed");
    return 0;
}
