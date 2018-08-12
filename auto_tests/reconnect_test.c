/* Auto Tests: Conferences.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

#define NUM_TOXES 2

typedef struct State {
    uint32_t id;
} State;

static void handle_self_connection_status(
    Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected\n", state->id);
    } else {
        printf("tox #%u: is now disconnected\n", state->id);
    }
}

static void handle_friend_connection_status(
    Tox *tox, uint32_t friendnumber, TOX_CONNECTION connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected to friend %u\n", state->id, friendnumber);
    } else {
        printf("tox #%u: is now disconnected from friend %u\n", state->id, friendnumber);
    }
}

static void test_reconnect(void)
{
    const time_t test_start_time = time(nullptr);

    Tox *toxes[NUM_TOXES];
    State state[NUM_TOXES];
    memset(state, 0, NUM_TOXES * sizeof(State));
    time_t cur_time = time(nullptr);
    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_start_port(opts, 33445);
    tox_options_set_end_port(opts, 34445);

    printf("creating %d toxes\n", NUM_TOXES);

    for (uint16_t i = 0; i < NUM_TOXES; ++i) {
        TOX_ERR_NEW err;
        toxes[i] = tox_new_log(opts, &err, &state[i]);
        state[i].id = i + 1;

        ck_assert_msg(toxes[i] != nullptr, "failed to create tox instance %u: error %d", i, err);
        tox_callback_self_connection_status(toxes[i], &handle_self_connection_status);
        tox_callback_friend_connection_status(toxes[i], &handle_friend_connection_status);

        if (i != 0) {
            uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
            tox_self_get_dht_id(toxes[0], dht_key);
            const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);

            tox_bootstrap(toxes[i], "localhost", dht_port, dht_key, nullptr);
        }
    }

    tox_options_free(opts);

    printf("creating a chain of friends\n");

    for (unsigned i = 1; i < NUM_TOXES; ++i) {
        TOX_ERR_FRIEND_ADD err;
        uint8_t key[TOX_PUBLIC_KEY_SIZE];

        tox_self_get_public_key(toxes[i - 1], key);
        tox_friend_add_norequest(toxes[i], key, &err);
        ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "failed to add friend: error %d", err);

        tox_self_get_public_key(toxes[i], key);
        tox_friend_add_norequest(toxes[i - 1], key, &err);
        ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "failed to add friend: error %d", err);
    }

    printf("waiting for everyone to come online\n");
    unsigned online_count = 0;

    while (online_count != NUM_TOXES) {
        online_count = 0;

        for (uint16_t i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(toxes[i], &state[i]);
            online_count += tox_friend_get_connection_status(toxes[i], 0, nullptr) != TOX_CONNECTION_NONE;
        }

        printf("currently %u toxes are online\n", online_count);
        fflush(stdout);

        c_sleep(200);
    }

    printf("friends connected, took %d seconds\n", (int)(time(nullptr) - cur_time));

    printf("letting connection settle\n");
    for (uint16_t j = 0; j < 60 * 20; ++j) {
        for (uint16_t i = 0; i < NUM_TOXES; ++i) {
                tox_iterate(toxes[i], &state[i].id);
        }

        c_sleep(50);
    }

    uint16_t disconnect = random_u16() % NUM_TOXES;
    printf("disconnecting #%u\n", state[disconnect].id);

    for (uint16_t j = 0; j < 70 * 20; ++j) {
        for (uint16_t i = 0; i < NUM_TOXES; ++i) {
            if (i != disconnect) {
                tox_iterate(toxes[i], &state[i].id);
            }
        }

        c_sleep(50);
    }

    printf("reconnecting\n");

    for (uint16_t j = 0; j < 5 * 20; ++j) {
        for (uint16_t i = 0; i < NUM_TOXES; ++i) {
                tox_iterate(toxes[i], &state[i].id);
        }

        c_sleep(50);
    }

    if (disconnect < NUM_TOXES-1) {
        ck_assert_msg(tox_friend_get_connection_status(toxes[disconnect+1], 0, nullptr), "failed to reconnect");
    } else {
        ck_assert_msg(tox_friend_get_connection_status(toxes[disconnect-1], NUM_TOXES > 2, nullptr), "failed to reconnect");
    }


    printf("tearing down toxes\n");

    for (uint16_t i = 0; i < NUM_TOXES; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_reconnect succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_reconnect();
    return 0;
}
