#include "rewards.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct FakeNode {
    int calls;
} FakeNode;

static bool send_request(void *context, HttpRequest request,
                         Slice output, int32_t *status)
{
    FakeNode *node = context;
    ++node->calls;
    assert(request.method.length == 4 && memcmp(request.method.data, "POST", 4) == 0);
    assert(strstr(request.url.data, "/api/v1/rewards") != NULL);
    assert(request.body.length == strlen("{\"reward\":\"shovey.secret-chest\"}"));
    assert(memcmp(request.body.data, "{\"reward\":\"shovey.secret-chest\"}", request.body.length) == 0);
    assert(request.token.length == 5 && memcmp(request.token.data, "token", 5) == 0);
    strcpy(output.data, "{\"reward\":\"shovey.secret-chest\",\"units\":200000,\"credited\":true,\"balance\":700000}");
    *status = 200;
    return true;
}

int main(void)
{
    char buffer[256];
    Slice output = {.data = buffer, .length = sizeof buffer};
    // The client names only a reward the node could accept, never an amount.
    assert(BuildRewardBody(StringLiteral("shovey.secret-chest"), output));
    assert(strcmp(buffer, "{\"reward\":\"shovey.secret-chest\"}") == 0);
    assert(!BuildRewardBody(StringLiteral(""), output));
    assert(!BuildRewardBody(StringLiteral("free dew"), output));
    assert(!BuildRewardBody(StringLiteral("shovey.chest\",\"units\":9"), output));
    assert(!RewardNameValid(StringLiteral("12345678901234567890123456789012345678901234567890123456789012345")));
    assert(RewardNameValid(StringLiteral("shovey.campaign-complete")));

    RewardClaim claim;
    memset(&claim, 0, sizeof claim);
    assert(ParseRewardClaim(StringLiteral("{\"reward\":\"a\",\"units\":500000,\"credited\":false,\"balance\":1200000}"), &claim));
    assert(claim.units == 500000 && claim.balance == 1200000 && !claim.credited);
    assert(ParseRewardClaim(StringLiteral("{\"reward\":\"a\",\"units\":200000,\"credited\":true,\"balance\":200000}"), &claim));
    assert(claim.credited);
    assert(!ParseRewardClaim(StringLiteral("{\"error\":\"unknown reward\"}"), &claim));
    assert(!ParseRewardClaim(StringLiteral("{\"units\":0,\"credited\":true,\"balance\":0}"), &claim));
    assert(!ParseRewardClaim(StringLiteral("not json"), &claim));

    // A blocking claim with a valid session sends one bearer request.
    FakeNode node = {0};
    Client client = {0};
    client.server_url = StringLiteral("http://127.0.0.1:8080");
    client.app_id = StringLiteral("shovey");
    client.send = send_request;
    client.transport_context = &node;
    Session session = {0};
    strcpy((char *)session.token, "token");
    session.expires_at_local = 2000;
    int32_t status = 0;
    char answer[256];
    Slice reply = {.data = answer, .length = sizeof answer};
    assert(ClaimReward(client, &session, 1000, StringLiteral("shovey.secret-chest"), reply, &status) == AuthResult_AUTH_OK);
    assert(node.calls == 1 && status == 200);
    assert(ParseRewardClaim(StringView(answer, strlen(answer)), &claim) && claim.credited && claim.balance == 700000);
    puts("Daochi rewards: claim body, answer parsing and a bearer claim passed");
    return 0;
}
