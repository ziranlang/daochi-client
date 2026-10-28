#include "auth.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool digest(String body, Slice output)
{
    const char *prefix = "{\"user_id_hash\":\"";
    assert(body.length > strlen(prefix));
    assert(memcmp(body.data, prefix, strlen(prefix)) == 0);
    assert(output.length >= 65);
    memset(output.data, 'b', 64);
    ((char *)output.data)[64] = 0;
    return true;
}

static bool sign_message(void *context, String message, Slice output)
{
    assert(context == (void *)0x1);
    const char prefix[] = "daochi-sync-v1\nPOST\n/api/v1/sync/login\n";
    size_t head = sizeof prefix - 1;
    assert(message.length == head + 64 + 1 + 64 + 1);
    assert(memcmp(message.data, prefix, head) == 0);
    for (size_t index = 0; index < 64; ++index) {
        assert(message.data[head + index] == 'b');
        assert(message.data[head + 65 + index] == 'c');
    }
    assert(message.data[head + 64] == '\n');
    assert(message.data[head + 129] == '\n');
    assert(output.length >= 4841);
    memset(output.data, 'd', 4840);
    ((char *)output.data)[4840] = 0;
    return true;
}

int main(void)
{
    char account_id[65];
    char body[4096];
    char signature[4841];
    memset(account_id, 'a', 64);
    account_id[64] = 0;
    Identity identity = {
        .account_id = StringView(account_id, 64),
        .public_key = StringLiteral("public-key"),
        .client_id = StringLiteral("client-1"),
        .signing_context = (void *)0x1,
    };
    Slice body_buffer = {.data = body, .length = sizeof body};
    Slice signature_buffer = {.data = signature, .length = sizeof signature};
    char challenge[80];
    snprintf(challenge, sizeof challenge, "{\"nonce\":\"%064d\"}", 0);
    memset(challenge + 10, 'c', 64);
    AuthResult result = PrepareLogin(identity,
        StringView(challenge, strlen(challenge)), digest, sign_message,
        body_buffer, signature_buffer);
    assert(result == AuthResult_AUTH_OK);
    assert(strstr(body, "\"client_id\":\"client-1\"") != NULL);
    assert(strlen(signature) == 4840);

    result = PrepareLogin(identity, StringLiteral("{\"nonce\":\"short\"}"),
        digest, sign_message, body_buffer, signature_buffer);
    assert(result == AuthResult_AUTH_CHALLENGE_FAILED);
    assert(body[0] == 0 && signature[0] == 0);

    Session session = {0};
    result = AcceptLogin(200, StringLiteral(
        "{\"auth_token\":\"token\",\"expires_in_seconds\":1800,"
        "\"server_time\":1700000000}"), &session);
    assert(result == AuthResult_AUTH_OK);
    assert(strcmp((char *)session.token, "token") == 0);
    assert(session.expires_in_seconds == 1800);
    assert(session.server_time == 1700000000);

    result = AcceptLogin(200, StringLiteral("{\"auth_token\":\"token\",\"account_alias\":\"live_tester\"}"), &session);
    assert(result == AuthResult_AUTH_OK && session.account_alias_known);
    assert(strcmp((const char *)session.account_alias, "live_tester") == 0);
    result = AcceptLogin(200, StringLiteral("{\"auth_token\":\"token\",\"account_alias\":\"\"}"), &session);
    assert(result == AuthResult_AUTH_OK && session.account_alias_known && session.account_alias[0] == 0);
    result = AcceptLogin(200, StringLiteral("{\"auth_token\":\"token\"}"), &session);
    assert(result == AuthResult_AUTH_OK && !session.account_alias_known && session.account_alias[0] == 0);
    result = AcceptLogin(401, StringLiteral("{}"), &session);
    assert(result == AuthResult_AUTH_FAILED);
    assert(session.token[0] == 0);
    result = AcceptLogin(200, StringLiteral("{}"), &session);
    assert(result == AuthResult_AUTH_PAYLOAD_FAILED);
    puts("Daochi Ziran login protocol passed");
    return 0;
}
