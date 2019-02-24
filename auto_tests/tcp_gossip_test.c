/* Auto Tests: Many TCP.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

#define TCP_GOSSIP_BASE_RELAY_PORT 33440

#define NUM_TOXES_TCP_GOSSIP 4

typedef struct State {
    uint32_t index;
    uint64_t clock;

    bool message_received;
} State;

#include "run_auto_test.h"

static void message_callback(Tox *m, uint32_t friendnumber, Tox_Message_Type type,
                             const uint8_t *string, size_t length, void *userdata)
{
    State *state = (State *)userdata;
    state->message_received = true;
}

static void test_tcp_gossip(Tox **toxes, State *state)
{
    printf("checking #3 and #4 can communicate via #2 when #1 stops iterating\n");
    tox_callback_friend_message(toxes[3], &message_callback);
    const uint8_t *msg = (const uint8_t *) "heyho";
    tox_friend_send_message(toxes[2], 2, TOX_MESSAGE_TYPE_NORMAL, msg, 5, nullptr);

    do {
        for (int i = 1; i < NUM_TOXES_TCP_GOSSIP; ++i) {
            tox_iterate(toxes[i], &state[i]);
            state[i].clock += ITERATION_INTERVAL;
        }
    } while (! state[3].message_received);
}

static void add_tcp(Tox **toxes, State *state)
{
    uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(toxes[0], dpk);

    Tox_Err_Bootstrap error = TOX_ERR_BOOTSTRAP_OK;

    for (int i = 0; i < NUM_TOXES_TCP_GOSSIP; ++i) {
        ck_assert_msg(tox_add_tcp_relay(toxes[i], TOX_LOCALHOST, TCP_GOSSIP_BASE_RELAY_PORT, dpk, &error),
                      "add relay error, %u, %d", i,
                      error);
    }

    tox_self_get_dht_id(toxes[1], dpk);
    ck_assert_msg(tox_add_tcp_relay(toxes[1], TOX_LOCALHOST, TCP_GOSSIP_BASE_RELAY_PORT+1, dpk, &error),
                  "add relay error, %u, %d", 1, error);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *opts_list[NUM_TOXES_TCP_GOSSIP];

    for (int i = 0; i < NUM_TOXES_TCP_GOSSIP; ++i) {
        opts_list[i] = tox_options_new(nullptr);

        if (i < 2) {
            tox_options_set_tcp_port(opts_list[i], TCP_GOSSIP_BASE_RELAY_PORT + i);
        } else {
            tox_options_set_udp_enabled(opts_list[i], false);
        }
    }

    run_auto_test(NUM_TOXES_TCP_GOSSIP, test_tcp_gossip, false, opts_list, add_tcp);

    return 0;
}
