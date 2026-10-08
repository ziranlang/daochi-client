#include "authorization.h"
#include "authorization_owner.h"
#include "delegated.h"
#include "async_delegated.h"
#include "envelope.h"
#include "json_scan.h"
#include "crypto.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char fixture[40000], answer[18000], challenge_json[2048];
static char session_signature[129], expected_session_message[1024];
static char proof_message[2048], proof_signature[129];
static GrantStorage original, verified;
static RequestedScope wanted[1];
static DelegateClient client;
static int transfers, polls, stage, cancels, nonce_counter;
static int response_status;
static bool active, failed_transport;
static int64_t clock_now = 1791400000;
static int64_t server_advance, challenge_delivery_delay, session_delivery_delay, sign_advance;
static bool dynamic_timing;
static int64_t current_time(void *context)
{
    (void)context;
    return clock_now;
}

static void replace_number(char *json, const char *name, int64_t value)
{
    char key[64];
    snprintf(key, sizeof key, "\"%s\"", name);
    char *found = strstr(json, key);
    assert(found);
    char *start = strchr(found, ':') + 1;
    while (*start == ' ') {
        start++;
    }
    char *end = start;
    while (*end >= '0' && *end <= '9') {
        end++;
    }
    char number[32];
    snprintf(number, sizeof number, "%lld", (long long)value);
    size_t count = strlen(number);
    memmove(start + count, end, strlen(end) + 1);
    memcpy(start, number, count);
}

static String text(const char *value)
{
    return StringView(value, strlen(value));
}

static Slice bytes(void *value, size_t size)
{
    return (Slice){.data = value, .length = size};
}

static void copy_output(Slice output, const char *value)
{
    assert(strlen(value) < (size_t)output.length);
    memcpy(output.data, value, strlen(value) + 1);
}

static String object(String document, const char *name)
{
    int32_t start = FieldAt(document, 0, text(name));
    int32_t end = ValueEnd(document, start, 0);
    assert(start >= 0 && end > start);
    return StringView(document.data + start, (uint64_t)(end - start));
}

static void field(String document, const char *name, char *output, size_t size)
{
    int32_t start = FieldAt(document, 0, text(name));
    assert(ReadStringText(document, start, bytes(output, size)) >= 0);
}

static bool sign_delegate(void *context, String message, Slice output)
{
    (void)context;
    assert(message.length > 20);
    if (StringEqual(message, text(expected_session_message))) {
        copy_output(output, session_signature);
    } else {
        clock_now += sign_advance;
        memset(output.data, 'a', 128);
        ((char *)output.data)[128] = 0;
    }
    return true;
}

static bool random_id(void *context, Slice output)
{
    (void)context;
    assert(output.length >= 33);
    nonce_counter++;
    memset(output.data, '9', 32);
    ((char *)output.data)[31] = (char)('0' + nonce_counter % 10);
    ((char *)output.data)[32] = 0;
    return true;
}

static bool start(void *context, HttpRequest request, Slice output)
{
    (void)context;
    assert(!active);
    assert(request.token.length == 0);
    assert(StringEqual(request.method, StringLiteral("POST")));
    active = true;
    transfers++;
    polls = 0;
    const char *url = request.url.data;
    if (strstr(url, "/authorization/challenge")) {
        stage = 1;
        assert(request.headers.length == 0);
        clock_now += server_advance;
        char current[2048];
        strcpy(current, challenge_json);
        if (dynamic_timing) {
            replace_number(current, "expires_at", clock_now + 90);
        }
        copy_output(output, current);
    } else if (strstr(url, "/authorization/session")) {
        stage = 2;
        assert(request.headers.length == 0);
        clock_now += server_advance;
        char current[18000];
        strcpy(current, answer);
        if (dynamic_timing) {
            replace_number(current, "expires_at", clock_now + 300);
        }
        copy_output(output, current);
    } else {
        stage = 3;
        assert(strstr(url, "/delegated/sync"));
        assert(request.headers.length == 2);
        HttpHeader *headers = request.headers.data;
        assert(StringEqual(headers[0].name, StringLiteral("Authorization")));
        assert(strncmp(headers[0].value.data, "Delegate ds1.", 13) == 0);
        assert(StringEqual(headers[1].name, StringLiteral("X-Daochi-Delegate")));
        assert(strstr(headers[1].value.data, "\"node_id\":"));
        copy_output(output, "{\"collection\":\"private.inbe.v2.lumi\",\"records\":[],\"next_version\":1,\"truncated\":false,\"applied\":0}");
    }
    return true;
}

static int32_t poll(void *context, int32_t *status)
{
    (void)context;
    assert(active);
    if (++polls == 1) {
        return -1;
    }
    active = false;
    if (stage == 1) {
        clock_now += challenge_delivery_delay;
    }
    if (stage == 2) {
        clock_now += session_delivery_delay;
    }
    *status = stage == 3 ? response_status : 200;
    return failed_transport ? 0 : 1;
}

static void cancel(void *context)
{
    (void)context;
    assert(active);
    active = false;
    cancels++;
}

static bool send(void *context, HttpRequest request, Slice output, int32_t *status)
{
    if (!start(context, request, output)) {
        return false;
    }
    int32_t result;
    do {
        result = poll(context, status);
    } while (result < 0);
    return result != 0;
}

static bool start_async(void *closure, void *context, HttpRequest request, Slice output)
{
    (void)closure;
    return start(context, request, output);
}
static int32_t poll_async(void *closure, void *context, int32_t *status)
{
    (void)closure;
    return poll(context, status);
}
static void cancel_async(void *closure, void *context)
{
    (void)closure;
    cancel(context);
}

static void configure(String document)
{
    String response = object(document, "answer");
    assert(response.length < sizeof answer);
    memcpy(answer, response.data, response.length);
    answer[response.length] = 0;
    assert(authorization_ReadGrantAt(object(response, "grant"), 0, &original));
    String challenge = object(document, "challenge");
    memcpy(challenge_json, challenge.data, challenge.length);
    challenge_json[challenge.length] = 0;
    field(document, "challenge_message", expected_session_message, sizeof expected_session_message);
    field(document, "proof_message", proof_message, sizeof proof_message);
    field(object(document, "proof"), "signature", proof_signature, sizeof proof_signature);
    /* The host signer remains explicit. Wire canonicalization is fixture tested;
       real Ed25519 verification of these signatures is performed by the server. */
    memset(session_signature, 'a', 128);
    session_signature[128] = 0;
    wanted[0] = (RequestedScope){.collection = StringLiteral("private.inbe.v2.lumi"),
        .read = true, .write = true};
    client = (DelegateClient){
        .server_url = text((char *)original.audience),
        .account_id = text((char *)original.account_id),
        .app_id = text((char *)original.app_id),
        .client_id = text((char *)original.client_id),
        .grant_id = text((char *)original.grant_id),
        .node_id = text((char *)original.node_id),
        .audience = text((char *)original.audience),
        .signing_key = text((char *)original.signing_key),
        .encryption_key = text((char *)original.encryption_key),
        .scopes = bytes(wanted, 1), .grant = &verified,
        .signer = sign_delegate, .random = random_id, .send = send, .clock = current_time,
        .bot_id = original.bot_id, .telegram_id = original.telegram_id,
    };
}

static void check_messages(String document)
{
    GrantScope scopes[16];
    Grant grant = {0};
    assert(authorization_ViewGrant(&original, bytes(scopes, 16), &grant));
    char output[12000], expected[12000];
    assert(authorization_BuildGrantMessage(grant, bytes(output, sizeof output)));
    field(document, "grant_message", expected, sizeof expected);
    assert(strcmp(output, expected) == 0);
    String response = object(document, "answer");
    char public_key[2625];
    field(response, "owner_public_key", public_key, sizeof public_key);
    assert(authorization_VerifyGrantSignature(grant, text(public_key), 1791400000));
    grant.app_id = StringLiteral("other");
    assert(!authorization_VerifyGrantSignature(grant, text(public_key), 1791400000));
    grant.app_id = StringLiteral("inbe");
    scopes[0].key_id = StringLiteral("inbe-lumi-2");
    assert(!authorization_VerifyGrantSignature(grant, text(public_key), 1791400000));
    assert(authorization_ViewGrant(&original, bytes(scopes, 16), &grant));
    grant.node_id = grant.client_id;
    assert(!authorization_VerifyGrantSignature(grant, text(public_key), 1791400000));
    assert(authorization_ViewGrant(&original, bytes(scopes, 16), &grant));
    assert(!authorization_VerifyGrantSignature(grant, text(public_key), grant.expires_at));
    SessionChallenge challenge;
    assert(authorization_ReadChallenge(text(challenge_json), &challenge));
    assert(delegated_BuildSessionMessage(&challenge, bytes(output, sizeof output)));
    field(document, "challenge_message", expected, sizeof expected);
    assert(strcmp(output, expected) == 0);
    String proof = object(document, "proof");
    char body_hash[65], nonce[33];
    field(proof, "body_sha256", body_hash, sizeof body_hash);
    field(proof, "nonce", nonce, sizeof nonce);
    RequestProof request = {
        .grant_id = client.grant_id, .session_id = StringLiteral("77777777777777777777777777777777"),
        .account_id = client.account_id, .app_id = client.app_id, .client_id = client.client_id,
        .node_id = client.node_id, .audience = client.audience,
        .challenge = StringLiteral("88888888888888888888888888888888"),
        .method = StringLiteral("POST"), .path = StringLiteral("/api/v1/delegated/sync"),
        .query = StringLiteral(""), .body_sha256 = text(body_hash), .expires_at = 1791400030,
        .nonce = text(nonce),
    };
    assert(delegated_BuildProofMessage(request, bytes(output, sizeof output)));
    assert(strcmp(output, proof_message) == 0);
    request.path = StringLiteral("/api/v1/account/delete");
    assert(!delegated_BuildProofMessage(request, bytes(output, sizeof output)));
    request.path = StringLiteral("/api/v1/sync");
    assert(!delegated_BuildProofMessage(request, bytes(output, sizeof output)));
    assert(!delegated_RequestRoute(StringLiteral("GET"), StringLiteral("/api/v1/delegated/ws"),
        StringLiteral("collection=private.inbe.v2.lumi&token=stolen")));
    assert(!authorization_Collection(StringLiteral("private.inbe.v1.cells")));
    assert(!authorization_Collection(StringLiteral("account.keys")));
    assert(!authorization_Collection(StringLiteral("private.inbe.v1.sessions")));
    PublicRendezvous pending;
    assert(authorization_ReadPublicRendezvous(object(document, "public_pending"), &pending));
    assert(!authorization_ReadPublicRendezvous(object(document, "pending"), &pending));
    assert(authorization_ReadPublicRendezvous(object(document, "public_pending"), &pending));
    assert(authorization_BuildClaimMessage(&pending, client.client_id, client.signing_key,
        client.encryption_key, StringLiteral(""), bytes(output, sizeof output)));
    field(document, "claim_message", expected, sizeof expected);
    assert(strcmp(output, expected) == 0);
    assert(!authorization_BuildClaimMessage(&pending, StringLiteral("malformed"), client.signing_key,
        client.encryption_key, StringLiteral(""), bytes(output, sizeof output)));
}

static void check_acceptance(void)
{
    DelegateSession session;
    assert(delegated_AcceptSessionAnswer(client, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_OK);
    assert(delegated_SessionValid(client, &session, 1791400000));
    DelegateClient wrong = client;
    wrong.account_id = client.client_id;
    assert(delegated_AcceptSessionAnswer(wrong, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    assert(!session.session_id[0]);
    wrong = client;
    wrong.node_id = client.client_id;
    assert(delegated_AcceptSessionAnswer(wrong, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    wrong = client;
    wrong.signing_key = client.client_id;
    assert(delegated_AcceptSessionAnswer(wrong, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    wanted[0].write = false;
    assert(delegated_AcceptSessionAnswer(client, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    wanted[0].write = true;
    clock_now = 1791400300;
    assert(delegated_AcceptSessionAnswer(client, 200, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    clock_now = 1791400000;
    assert(delegated_AcceptSessionAnswer(client, 401, text(answer), 1791400000, &session) == AuthResult_AUTH_FAILED);
    char mutated[18000];
    strcpy(mutated, answer);
    char *signature = strstr(mutated, "\"signature\"");
    assert(signature);
    signature = strchr(strchr(signature, ':') + 1, '"') + 1;
    *signature = *signature == '0' ? '1' : '0';
    assert(delegated_AcceptSessionAnswer(client, 200, text(mutated), 1791400000, &session) == AuthResult_AUTH_FAILED);
    strcpy(mutated, answer);
    char *generation = strstr(mutated, "inbe-lumi-1");
    assert(generation);
    generation[10] = '2';
    assert(delegated_AcceptSessionAnswer(client, 200, text(mutated), 1791400000, &session) == AuthResult_AUTH_FAILED);
    int32_t offsets[2];
    String names[] = {StringLiteral("key"), StringLiteral("other")};
    assert(!authorization_ObjectFields(StringLiteral("{\"key\":1,\"\\u006bey\":2,\"other\":3}"),
        0, bytes(names, 2), bytes(offsets, 2)));
    assert(!authorization_WholeJson(StringLiteral("{} trailing")));
}

static void reject_open(Grant grant, GrantScope scope, EncryptionKeys *keys,
    uint8_t output[32])
{
    memset(output, 0x42, 32);
    assert(!envelope_OpenCollectionKey(grant, scope, keys, bytes(output, 32)));
    for (size_t i = 0; i < 32; i++) {
        assert(output[i] == 0);
    }
}

static void check_envelopes(void)
{
    EncryptionKeys recipient, other;
    assert(envelope_CreateEncryptionKeys(&recipient));
    assert(envelope_CreateEncryptionKeys(&other));
    char public_hex[2369], opaque[4096];
    assert(envelope_EncryptionPublicHex(&recipient, bytes(public_hex, sizeof public_hex)));
    GrantScope scopes[16];
    Grant grant = {0};
    assert(authorization_ViewGrant(&original, bytes(scopes, 16), &grant));
    grant.encryption_key = text(public_hex);
    uint8_t key[32], opened[32];
    memset(key, 0x42, sizeof key);
    assert(envelope_SealCollectionKey(grant, scopes[0], bytes(key, 32), bytes(opaque, sizeof opaque)));
    scopes[0].key_envelope = text(opaque);
    assert(envelope_OpenCollectionKey(grant, scopes[0], &recipient, bytes(opened, 32)));
    assert(memcmp(key, opened, 32) == 0);
    memset(opened, 0x42, sizeof opened);
    reject_open(grant, scopes[0], NULL, opened);
    for (size_t i = 0; i < 32; i++) {
        assert(opened[i] == 0);
    }
    String valid_envelope = scopes[0].key_envelope;
    scopes[0].key_envelope = StringLiteral("malformed");
    memset(opened, 0x42, sizeof opened);
    reject_open(grant, scopes[0], &recipient, opened);
    for (size_t i = 0; i < 32; i++) {
        assert(opened[i] == 0);
    }
    scopes[0].key_envelope = valid_envelope;
    reject_open(grant, scopes[0], &other, opened);
    EncryptionKeys mismatched = other;
    memcpy(mismatched.public_key, recipient.public_key, sizeof mismatched.public_key);
    reject_open(grant, scopes[0], &mismatched, opened);
    envelope_ClearEncryptionKeys(&mismatched);
    for (size_t i = 0; i < 32; i++) {
        assert(opened[i] == 0);
    }
    scopes[0].key_id = StringLiteral("inbe-lumi-2");
    reject_open(grant, scopes[0], &recipient, opened);
    scopes[0].key_id = StringLiteral("inbe-lumi-1");
    scopes[0].collection = StringLiteral("private.inbe.v1.sessions");
    reject_open(grant, scopes[0], &recipient, opened);
    scopes[0].collection = StringLiteral("private.inbe.v2.lumi");
    char *ciphertext = strstr(opaque, "\"ciphertext\"");
    assert(ciphertext);
    ciphertext = strchr(strchr(ciphertext, ':') + 1, '"') + 1;
    *ciphertext = *ciphertext == '0' ? '1' : '0';
    reject_open(grant, scopes[0], &recipient, opened);
    assert(!envelope_SealCollectionKey(grant, scopes[0], bytes(key, 31), bytes(opaque, sizeof opaque)));
    envelope_ClearEncryptionKeys(&recipient);
    envelope_ClearEncryptionKeys(&other);
    for (size_t i = 0; i < 2400; i++) {
        assert(recipient.secret_key[i] == 0);
    }
}

static void check_transports(void)
{
    DelegateSession session = {0};
    char output[18000], body[4096], proof[4096], credential[46];
    int32_t status;
    response_status = 200;
    assert(delegated_RenewDelegateSession(client, &session, 1791400000,
        bytes(output, sizeof output)) == AuthResult_AUTH_OK);
    assert(transfers == 2);
    assert(delegated_BuildDelegatedSyncBody(client, wanted[0].collection, true, 0, 128,
        bytes(NULL, 0), bytes(body, sizeof body)));
    assert(!delegated_BuildDelegatedSyncBody(client, StringLiteral("private.inbe.v1.cells"),
        true, 0, 128, bytes(NULL, 0), bytes(body, sizeof body)));
    assert(!delegated_BuildDelegatedSyncBody(client, StringLiteral("private.inbe.v2.diary"),
        true, 0, 128, bytes(NULL, 0), bytes(body, sizeof body)));
    assert(delegated_DelegatedSyncBodyValid(client, text(body)));
    DelegatedResponseInfo info;
    assert(delegated_ReadDelegatedSyncResponse(client,
        StringLiteral("{\"collection\":\"private.inbe.v2.lumi\",\"records\":[{\"collection\":\"private.inbe.v2.lumi\",\"id\":\"record\",\"key_id\":\"inbe-lumi-1\"}],\"next_version\":1,\"truncated\":false,\"applied\":0}"),
        wanted[0].collection, &info));
    assert(info.record_count == 1);
    assert(!delegated_ReadDelegatedSyncResponse(client,
        StringLiteral("{\"collection\":\"private.inbe.v2.lumi\",\"records\":[{\"collection\":\"private.inbe.v2.lumi\",\"id\":\"record\",\"key_id\":\"inbe-lumi-2\"}],\"next_version\":1,\"truncated\":false,\"applied\":0}"),
        wanted[0].collection, &info));
    assert(!delegated_ReadDelegatedSyncResponse(client,
        StringLiteral("{\"collection\":\"private.inbe.v2.lumi\",\"records\":[{\"collection\":\"private.inbe.v2.diary\",\"id\":\"record\",\"key_id\":\"inbe-lumi-1\"}],\"next_version\":1,\"truncated\":false,\"applied\":0}"),
        wanted[0].collection, &info));
    char escalation[4096];
    strcpy(escalation, body);
    char *scope = strstr(escalation, "private.inbe.v2.lumi");
    assert(scope);
    memcpy(scope, "private.inbe.v1.cell", 19);
    assert(!delegated_DelegatedSyncBodyValid(client, text(escalation)));
        assert(delegated_DelegateRequest(client, &session, 1791400000, text(body),
        bytes(output, sizeof output), &status) == AuthResult_AUTH_OK);
    assert(status == 200);
    assert(delegated_PrepareDelegateHeaders(client, &session, 1791400000,
        StringLiteral("POST"), StringLiteral("/api/v1/delegated/sync"), StringLiteral(""),
        text(body), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) == AuthResult_AUTH_OK);
    char first_nonce[33], second_nonce[33];
    field(text(proof), "nonce", first_nonce, sizeof first_nonce);
    assert(delegated_PrepareDelegateHeaders(client, &session, 1791400000,
        StringLiteral("POST"), StringLiteral("/api/v1/delegated/sync"), StringLiteral(""),
        text(body), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) == AuthResult_AUTH_OK);
    field(text(proof), "nonce", second_nonce, sizeof second_nonce);
    assert(strcmp(first_nonce, second_nonce) != 0);
    AsyncTransport transport = {.start = {.call = start_async},
        .poll = {.call = poll_async}, .cancel = {.call = cancel_async}};
    PendingDelegate pending = {0};
    session = (DelegateSession){0};
    transfers = 0;
    assert(async_delegated_BeginDelegateRequest(&pending, client, &session, 1791400000,
        transport, text(body), bytes(output, sizeof output)));
    assert(!async_delegated_BeginDelegateRequest(&pending, client, &session, 1791400000,
        transport, text(body), bytes(output, sizeof output)));
    int ticks = 0;
    while (!async_delegated_PollDelegate(&pending) && ++ticks < 20) {
    }
    assert(ticks < 20 && !active && transfers == 3 && pending.result == AuthResult_AUTH_OK);
    response_status = 401;
    pending = (PendingDelegate){0};
    assert(async_delegated_BeginDelegateRequest(&pending, client, &session, 1791400000,
        transport, text(body), bytes(output, sizeof output)));
    while (!async_delegated_PollDelegate(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_FAILED && !session.session_id[0]);
    pending = (PendingDelegate){0};
    assert(async_delegated_BeginDelegateSession(&pending, client, &session, 1791400000,
        transport, bytes(output, sizeof output)));
    async_delegated_CancelDelegate(&pending);
    async_delegated_CancelDelegate(&pending);
    assert(cancels == 1 && !active && async_delegated_PollDelegate(&pending));
    assert(pending.result == AuthResult_AUTH_REQUEST_FAILED);
    pending = (PendingDelegate){0};
    failed_transport = true;
    assert(async_delegated_BeginDelegateSession(&pending, client, &session, 1791400000,
        transport, bytes(output, sizeof output)));
    while (!async_delegated_PollDelegate(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_REQUEST_FAILED && !active);
    assert(!authorization_owner_OwnerAuthorizationRoute(StringLiteral("/api/v1/account/delete")));
    assert(authorization_owner_OwnerAuthorizationRoute(StringLiteral("/api/v1/authorization/revoke")));
}

static void reset_timing(void)
{
    active = false;
    failed_transport = false;
    response_status = 200;
    transfers = 0;
    clock_now = 1791400000;
    server_advance = 0;
    challenge_delivery_delay = 0;
    session_delivery_delay = 0;
    sign_advance = 0;
    dynamic_timing = true;
}

static void check_advancing_clock(void)
{
    char output[18000], body[4096], proof[4096], credential[46];
    DelegateSession session = {0};
    reset_timing();
    server_advance = 1;
    assert(delegated_RenewDelegateSession(client, &session, 1,
        bytes(output, sizeof output)) == AuthResult_AUTH_OK);
    assert(clock_now == 1791400002 && session.expires_at == clock_now + 300);
    assert(delegated_BuildDelegatedSyncBody(client, wanted[0].collection, true, 0, 128,
        bytes(NULL, 0), bytes(body, sizeof body)));
    assert(delegated_PrepareDelegateHeaders(client, &session, 1,
        StringLiteral("POST"), StringLiteral("/api/v1/delegated/sync"), StringLiteral(""),
        text(body), bytes(proof, sizeof proof), bytes(credential, sizeof credential)) == AuthResult_AUTH_OK);
    int64_t expiry;
    assert(authorization_ReadInteger(text(proof), FieldAt(text(proof), 0,
        StringLiteral("expires_at")), &expiry));
    assert(expiry == clock_now + 60);
    AsyncTransport transport = {.start = {.call = start_async},
        .poll = {.call = poll_async}, .cancel = {.call = cancel_async}};
    PendingDelegate pending = {0};
    reset_timing();
    server_advance = 1;
    session = (DelegateSession){0};
    assert(async_delegated_BeginDelegateRequest(&pending, client, &session, 1,
        transport, text(body), bytes(output, sizeof output)));
    while (!async_delegated_PollDelegate(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_OK && transfers == 3);
    assert(clock_now == 1791400002);
    reset_timing();
    server_advance = 1;
    session.expires_at = clock_now + 4;
    pending = (PendingDelegate){0};
    assert(async_delegated_BeginDelegateRequest(&pending, client, &session, 1,
        transport, text(body), bytes(output, sizeof output)));
    while (!async_delegated_PollDelegate(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_OK && transfers == 3);
    assert(session.expires_at == clock_now + 300);
    reset_timing();
    challenge_delivery_delay = 91;
    session = (DelegateSession){0};
    assert(delegated_RenewDelegateSession(client, &session, 1,
        bytes(output, sizeof output)) == AuthResult_AUTH_FAILED);
    assert(transfers == 1 && !session.session_id[0]);
    reset_timing();
    session_delivery_delay = 301;
    pending = (PendingDelegate){0};
    assert(async_delegated_BeginDelegateSession(&pending, client, &session, 1,
        transport, bytes(output, sizeof output)));
    while (!async_delegated_PollDelegate(&pending)) {
    }
    assert(pending.result == AuthResult_AUTH_FAILED && transfers == 2 && !session.session_id[0]);
    reset_timing();
    assert(delegated_RenewDelegateSession(client, &session, 1,
        bytes(output, sizeof output)) == AuthResult_AUTH_OK);
    transfers = 0;
    sign_advance = 61;
    int32_t status;
    assert(delegated_DelegateRequest(client, &session, 1, text(body),
        bytes(output, sizeof output), &status) == AuthResult_AUTH_SIGN_FAILED);
    assert(transfers == 0);
    sign_advance = 0;
    clock_now = 0;
    assert(!delegated_SessionValid(client, &session, 1791400000));
    assert(delegated_RenewDelegateSession(client, &session, 1791400000,
        bytes(output, sizeof output)) == AuthResult_AUTH_PAYLOAD_FAILED);
    DelegateClient no_clock = client;
    no_clock.clock = NULL;
    assert(!delegated_DelegateClientValid(no_clock));
    assert(delegated_RenewDelegateSession(no_clock, &session, 1791400000,
        bytes(output, sizeof output)) == AuthResult_AUTH_PAYLOAD_FAILED);
    reset_timing();
    dynamic_timing = false;
}

static void check_telegram_binding(String document)
{
    AccountKeys owner;
    assert(CreateAccountKeys(&owner));
    GrantScope scopes[16];
    Grant grant = {0};
    assert(authorization_ViewGrant(&original, bytes(scopes, 16), &grant));
    grant.account_id = text((char *)owner.public_id);
    grant.bot_id = 123456;
    grant.telegram_id = 1234;
    char message[8192], signature[4841], grant_json[12000], telegram_answer[18000];
    assert(authorization_BuildGrantMessage(grant, bytes(message, sizeof message)));
    assert(SignAccountMessage(&owner, text(message), bytes(signature, sizeof signature)));
    grant.signature = text(signature);
    assert(authorization_BuildGrantBody(grant, bytes(grant_json, sizeof grant_json)));
    String credential = object(object(document, "answer"), "credential");
    int count = snprintf(telegram_answer, sizeof telegram_answer,
        "{\"credential\":%.*s,\"grant\":%s,\"owner_public_key\":\"%s\"}",
        (int)credential.length, credential.data, grant_json, owner.public_key_hex);
    assert(count > 0 && count < (int)sizeof telegram_answer);
    DelegateClient telegram = client;
    telegram.account_id = grant.account_id;
    telegram.bot_id = grant.bot_id;
    telegram.telegram_id = grant.telegram_id;
    DelegateSession session;
    assert(delegated_AcceptSessionAnswer(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_OK);
    telegram.bot_id = 123457;
    assert(delegated_AcceptSessionAnswer(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_FAILED);
    telegram.bot_id = 123456;
    telegram.telegram_id = 1235;
    assert(delegated_AcceptSessionAnswer(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_FAILED);
    telegram.bot_id = 0;
    telegram.telegram_id = 0;
    assert(delegated_AcceptSessionAnswer(telegram, 200, text(telegram_answer), 1,
        &session) == AuthResult_AUTH_FAILED);
    telegram.bot_id = 123456;
    assert(!delegated_DelegateClientValid(telegram));
    SecureWipe(owner.private_key_hex, sizeof owner.private_key_hex);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    size_t count = fread(fixture, 1, sizeof fixture - 1, file);
    assert(!ferror(file) && feof(file));
    fclose(file);
    fixture[count] = 0;
    String document = text(fixture);
    configure(document);
    check_messages(document);
    check_acceptance();
    check_envelopes();
    check_transports();
    check_advancing_clock();
    check_telegram_binding(document);
    puts("Daochi delegated fixtures, ownership, scopes, envelopes and async transports passed");
    return 0;
}
