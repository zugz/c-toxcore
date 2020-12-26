#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "../toxcore/announce.c"
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

static void basic_announce_tests()
{
    uint8_t key1[CRYPTO_PUBLIC_KEY_SIZE], key2[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(key1, sizeof(key1));
    memcpy(key2, key1, CRYPTO_PUBLIC_KEY_SIZE);

    ck_assert_msg(get_bucketnum(key1, key2) == 0, "Bad bucketnum");

    key2[4] ^= 0x09;
    key2[5] ^= 0xc5;

    ck_assert_msg(get_bucketnum(key1, key2) == 7, "Bad bucketnum");

    key2[4] ^= 0x09;

    ck_assert_msg(get_bucketnum(key1, key2) == 17, "Bad bucketnum");

    key2[5] ^= 0xc5;
    key2[31] ^= 0x09;

    ck_assert_msg(get_bucketnum(key1, key2) == 4, "Bad bucketnum");

    Logger *log = logger_new();
    logger_callback_log(log, (logger_cb *)print_debug_log, nullptr, nullptr);
    Mono_Time *mono_time = mono_time_new();
    Networking_Core *net = new_networking_no_udp(log);
    DHT *dht = new_dht(log, mono_time, net, true);
    Forwarding *forwarding = new_forwarding(mono_time, dht);
    Announcements *announce = new_announcements(mono_time, forwarding);

    uint8_t data[MAX_ANNOUNCEMENT_SIZE];
    random_bytes(data, sizeof(data));

    Announce_Entry *stored = get_stored(announce, key1);
    ck_assert_msg(stored == nullptr, "Unstored announcement exists");

    ck_assert_msg(store_data(announce, key1, data, sizeof(data),
                             MAX_ANNOUNCEMENT_TIMEOUT), "Failed to store announcement");

    stored = get_stored(announce, key1);
    ck_assert_msg(stored, "Failed to get stored announcement");

    ck_assert_msg(stored->length == sizeof(data), "Bad stored announcement length");
    ck_assert_msg(crypto_memcmp(stored->data, data, sizeof(data)) == 0, "Bad stored announcement data");

    const uint8_t *const base = announce->public_key;
    ck_assert_msg(store_data(announce, base, nullptr, 0, 1), "failed to store base");

    uint8_t test_keys[ANNOUNCE_BUCKET_SIZE + 1][CRYPTO_PUBLIC_KEY_SIZE];

    for (uint8_t i = 0; i < ANNOUNCE_BUCKET_SIZE + 1; ++i) {
        memcpy(test_keys[i], base, CRYPTO_PUBLIC_KEY_SIZE);
        test_keys[i][i] ^= 1;
        ck_assert_msg(store_data(announce, test_keys[i], nullptr, 0, 1), "Failed to store announcement %d", i);
    }

    stored = get_stored(announce, base);
    ck_assert_msg(get_stored(announce, base), "base was evicted");
    ck_assert_msg(get_stored(announce, test_keys[0]) == nullptr, "furthest was not evicted");
    ck_assert_msg(!store_data(announce, test_keys[0], nullptr, 0, 1), "furthest evicted closer");

    kill_announcements(announce);
    kill_forwarding(forwarding);
    kill_dht(dht);
    kill_networking(net);
    mono_time_free(mono_time);
    logger_kill(log);
}

static void announce_test(Tox **toxes, State *state)
{
    // Nothing to do here. When copying this test, add test-specific code here.
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    basic_announce_tests();

    run_auto_test(2, announce_test, false);
    return 0;
}
