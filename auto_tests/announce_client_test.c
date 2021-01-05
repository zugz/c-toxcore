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

static void basic_lookup_test(const uint32_t num_toxes, bool advance_time,
                              Tox **toxes, State *state)
{
    Announce_Client *announce_client[num_toxes];
    Announcements *announcements[num_toxes];
    Forwarding *forwarding[num_toxes];
    Mono_Time *mono_time[num_toxes];

    for (uint32_t i = 0; i < num_toxes; ++i) {
        // TODO(iphydf): Don't rely on toxcore internals.
        Messenger *m = *(Messenger **)toxes[i];
        forwarding[i] = new_forwarding(
                            m->mono_time,
                            m->dht);
        ck_assert(forwarding[i] != nullptr);
        mono_time[i] = m->mono_time;

        announce_client[i] = new_announce_client(
                                 m->mono_time, forwarding[i],
                                 m->net_crypto);
        ck_assert(announce_client != nullptr);

        announcements[i] = new_announcements(m->mono_time, forwarding[i]);
        ck_assert(announcements != nullptr);
    }

    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(pk, sk);

    uint8_t test_data[5];
    memcpy(test_data, "hello", 5);
    add_announce(announce_client[0], pk, 2, sk, test_data, sizeof(test_data));
    const Lookup *announce_lookup = find_lookup(&announce_client[0]->lookups, pk);
    ck_assert(announce_client != nullptr);

    do {
        iterate_all_wait(num_toxes, toxes, state, advance_time ? ITERATION_INTERVAL : 0);
        do_announce_client(announce_client[0]);
    } while (!is_announced(mono_time[1], announce_lookup));

    bool retrieved[num_toxes];
    memset(retrieved, 0, sizeof(retrieved));

    for (uint32_t i = 0; i < num_toxes; ++i) {
        add_search(announce_client[i], pk, 2, should_retrieve_callback, on_retrieve_callback, &retrieved[i]);
    }

    bool all_retrieved;

    do {
        iterate_all_wait(num_toxes, toxes, state, advance_time ? ITERATION_INTERVAL : 0);
        all_retrieved = true;

        for (uint32_t i = 0; i < num_toxes; ++i) {
            if (num_toxes == 2 && i == 1) {
                // this tox is the only one storing the announcement,
                // so won't find it
                continue;
            }

            do_announce_client(announce_client[i]);
            all_retrieved &= retrieved[i];
        }
    } while (!all_retrieved);

    for (uint32_t i = 0; i < num_toxes; ++i) {
        kill_announce_client(announce_client[i]);
        kill_announcements(announcements[i]);
        kill_forwarding(forwarding[i]);
    }
}

static void basic_lookup_test_two(Tox **toxes, State *state)
{
    /* A simple announce and lookup with 2 nodes and perfect network
     * conditions should reliably succeed with no timeouts needing to be
     * triggered, so we do not advance time when iterating. */

    basic_lookup_test(2, false, toxes, state);
}

#define NUM_LOOKUP_MANY_TOXES 20

static void basic_lookup_test_many(Tox **toxes, State *state)
{
    basic_lookup_test(NUM_LOOKUP_MANY_TOXES, true, toxes, state);
}


    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, basic_lookup_test_two, true);

    run_auto_test(NUM_LOOKUP_MANY_TOXES, basic_lookup_test_many, true);
    return 0;
}
