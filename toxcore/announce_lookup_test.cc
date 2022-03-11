#include "announce_lookup.h"

#include <gtest/gtest.h>

#include <memory>

#include "util.h"

namespace
{

struct Lookup_Deleter {
    void operator()(Lookup *arr)
    {
        lookup_kill(arr);
    }
};

Lookup_Route random_dummy_route(uint16_t length)
{
    assert(length <= MAX_FORWARD_CHAIN_LENGTH);
    Lookup_Route route;
    route.chain_length = length;
    random_bytes(route.nodes[length].public_key, CRYPTO_PUBLIC_KEY_SIZE);
    return route;
}

bool dummy_routes_eq(Lookup_Route route1, Lookup_Route route2)
{
    return (route1.chain_length == route2.chain_length
            && id_equal(route_destination(&route1)->public_key,
                        route_destination(&route2)->public_key));
}

using Lookup_Ptr = std::unique_ptr<Lookup, Lookup_Deleter>;

TEST(Lookup, StoredRouteCanBeRetrieved)
{
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(pk, CRYPTO_PUBLIC_KEY_SIZE);
    Lookup_Ptr const lookup(lookup_new(pk, 2, nullptr, nullptr));
    Lookup_Route route = random_dummy_route(2);
    lookup_add_node(lookup.get(), &route);
    Lookup_Node *node = lookup_find_node(lookup.get(), route_destination(&route)->public_key);
    EXPECT_NE(node, nullptr);
    EXPECT_EQ(true, dummy_routes_eq(route, node->route));
}

}  // namespace
