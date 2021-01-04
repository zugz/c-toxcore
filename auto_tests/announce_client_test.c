#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "../toxcore/announce.c"
#include "../toxcore/announce_client.c"
#include "../toxcore/tox.h"
#include "../testing/misc_tools.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
} State;

#include "run_auto_test.h"

static bool should_retrieve_callback(void *object, const uint8_t *hash)
{
    return true;
}

static void on_retrieve_callback(void *object, const uint8_t *data, uint16_t length)
{
    bool *retrieved = (bool *)object;

    if (length == 5 && memcmp(data, "hello", length) == 0) {
        *retrieved = true;
    }
}

static void basic_lookup_test(Tox **toxes, State *state)
{
    Announcements *announcements;
    Announce_Client *announce_client;
    Forwarding *forwarding[2];
    Mono_Time *mono_time[2];

    for (uint32_t i = 0; i < 2; ++i) {
        // TODO(iphydf): Don't rely on toxcore internals.
        Messenger *m = *(Messenger **)toxes[i];
        forwarding[i] = new_forwarding(
                            m->mono_time,
                            m->dht);
        ck_assert(forwarding[i] != nullptr);
        mono_time[i] = m->mono_time;

        if (i == 0) {
            announcements = new_announcements(m->mono_time, forwarding[i]);
            ck_assert(announcements != nullptr);
        } else {
            announce_client = new_announce_client(
                                  m->mono_time, forwarding[i],
                                  m->net_crypto);
            ck_assert(announce_client != nullptr);
        }
    }

    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(pk, sk);

    uint8_t test_data[5];
    memcpy(test_data, "hello", 5);
    add_announce(announce_client, pk, 2, sk, test_data, sizeof(test_data));
    const Lookup *announce_lookup = find_lookup(&announce_client->lookups, pk);
    ck_assert(announce_client != nullptr);

    /* A simple announce and lookup with 2 nodes and perfect network
     * conditions should reliably succeed with no timeouts needing to be
     * triggered, so we do not advance time when iterating. */

    do {
        iterate_all_wait(2, toxes, state, 0);
        do_announce_client(announce_client);
    } while (!is_announced(mono_time[1], announce_lookup));

    bool retrieved = false;
    add_search(announce_client, pk, 2, should_retrieve_callback, on_retrieve_callback, &retrieved);

    do {
        iterate_all_wait(2, toxes, state, 0);
        do_announce_client(announce_client);
    } while (!retrieved);

    kill_announce_client(announce_client);
    kill_announcements(announcements);

    for (uint32_t i = 0; i < 2; ++i) {
        kill_forwarding(forwarding[i]);
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, lookup_test, false);
    return 0;
}
