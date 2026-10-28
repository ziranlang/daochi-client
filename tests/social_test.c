#include "social.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct FakeServer {
    int calls;
    const char *method;
    const char *path;
    const char *body;
} FakeServer;

static bool send_request(void *context, HttpRequest request,
                         Slice output, int32_t *status)
{
    FakeServer *server = context;
    ++server->calls;
    assert(request.method.length == strlen(server->method));
    assert(memcmp(request.method.data, server->method,
        request.method.length) == 0);
    assert(strstr(request.url.data, server->path) != NULL);
    assert(request.body.length == strlen(server->body));
    assert(memcmp(request.body.data, server->body,
        request.body.length) == 0);
    assert(request.token.length == 5);
    assert(memcmp(request.token.data, "token", 5) == 0);
    strcpy(output.data, "{}");
    *status = 200;
    return true;
}

int main(void)
{
    char buffer[512];
    Slice output = {.data = buffer, .length = sizeof buffer};
    assert(NormalizeFriendTarget(StringLiteral("  @Alice_24  "), output));
    assert(strcmp(buffer, "@alice_24") == 0);
    assert(!NormalizeFriendTarget(StringLiteral("alice!"), output));
    assert(NormalizeFriendTarget(StringLiteral(" @A "), output));
    assert(strcmp(buffer, "@a") == 0);
    assert(NormalizeFriendTarget(StringLiteral("AB"), output));
    assert(strcmp(buffer, "@ab") == 0);
    assert(BuildFriendRequestBody(StringLiteral("@Wao"), output));
    assert(strcmp(buffer, "{\"target\":\"@wao\"}") == 0);
    assert(!NormalizeFriendTarget(StringLiteral(" @ "), output));
    assert(!NormalizeFriendTarget(StringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ignored"), output));
    assert(NormalizeFriendTarget(StringLiteral(" AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "), output));
    assert(strcmp(buffer, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    assert(BuildFriendRequestBody(StringLiteral("Alice_24"), output));
    assert(strcmp(buffer, "{\"target\":\"@alice_24\"}") == 0);
    assert(BuildFriendStatsPath(StringLiteral("inbe"),
        StringLiteral("prac tice"), StringLiteral("avg/after"), output));
    assert(strcmp(buffer,
        "/api/v1/friends/stats?app=inbe&practice=prac%20tice&metric=avg%2Fafter") == 0);
    assert(!BuildFriendStatsPath(StringLiteral(""),
        StringLiteral("practice"), StringLiteral("streak"), output));
    assert(BuildFriendActionPath(StringLiteral("req-1"),
        StringLiteral("accept"), output));
    assert(strcmp(buffer, "/api/v1/friends/requests/req-1/accept") == 0);
    assert(!BuildFriendActionPath(StringLiteral("../admin"),
        StringLiteral("accept"), output));
    assert(!BuildFriendActionPath(StringLiteral("req-1"),
        StringLiteral("delete"), output));
    char account[65];
    memset(account, 'a', 64);
    account[64] = 0;
    assert(BuildFriendPath(StringView(account, 64), output));
    assert(BuildAliasBody(StringView(account, 64),
        StringLiteral("A\"B\n"), output));
    assert(strstr(buffer, "\"alias\":\"A\\\"B\\n\"") != NULL);

    FakeServer server = {0};
    Client client = {0};
    client.server_url = StringLiteral("http://127.0.0.1:8080");
    client.app_id = StringLiteral("inbe");
    client.identity.account_id = StringView(account, 64);
    client.identity.client_id = StringLiteral("client-1");
    client.send = send_request;
    client.transport_context = &server;
    Session session = {0};
    strcpy((char *)session.token, "token");
    session.expires_at_local = 2000;
    int32_t status = 0;

    server.method = "POST";
    server.path = "/api/v1/friends/requests";
    server.body = "{\"target\":\"@alice_24\"}";
    assert(SendFriendRequest(client, &session, 1000,
        StringLiteral("Alice_24"), output, &status) == AuthResult_AUTH_OK);
    server.path = "/api/v1/friends/requests/req-1/accept";
    server.body = "{}";
    assert(FriendAction(client, &session, 1000,
        StringLiteral("req-1"), StringLiteral("accept"),
        output, &status) == AuthResult_AUTH_OK);
    server.method = "DELETE";
    server.path = "/api/v1/friends/";
    server.body = "";
    assert(RemoveFriend(client, &session, 1000,
        StringView(account, 64), output, &status) == AuthResult_AUTH_OK);
    server.method = "GET";
    server.path = "/api/v1/friends/requests";
    assert(FriendRequests(client, &session, 1000,
        output, &status) == AuthResult_AUTH_OK);
    server.path = "/api/v1/friends/stats?app=inbe&practice=whm&metric=streak";
    assert(FriendStats(client, &session, 1000,
        StringLiteral("whm"), StringLiteral("streak"),
        output, &status) == AuthResult_AUTH_OK);
    server.method = "POST";
    server.path = "/api/v1/account/alias";
    server.body = "{\"user_id_hash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"alias\":\"Alice\"}";
    assert(RegisterAlias(client, &session, 1000,
        StringLiteral("Alice"), output, &status) == AuthResult_AUTH_OK);
    assert(server.calls == 6 && status == 200);
    puts("Daochi Ziran social requests passed");
    return 0;
}
