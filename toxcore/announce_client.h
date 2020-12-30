/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_CLIENT_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_CLIENT_H

#include "forwarding.h"
#include "net_crypto.h"

typedef struct Announce_Client Announce_Client;

Announce_Client *new_announce_client(Mono_Time *mono_time, Forwarding *forwarding, Net_Crypto *c);

/* Replaces any existing announce/search for this key. */
bool add_announce(Announce_Client *announce_client,
                  const uint8_t *data_public_key, uint16_t width,
                  const uint8_t *data_secret_key, const uint8_t *data, uint16_t length);

typedef bool should_retrieve_cb(void *object, const uint8_t *hash);
typedef void on_retrieve_cb(void *object, const uint8_t *data, uint16_t length);

/* Replaces any existing announce/search for this key. */
bool add_search(Announce_Client *announce_client,
                const uint8_t *data_public_key, uint16_t width,
                should_retrieve_cb should_retrieve_callback,
                on_retrieve_cb on_retrieve_callback,
                void *callbacks_object);

bool delete_search_or_announce(Announce_Client *announce_client, const uint8_t *data_public_key);

void do_announce_client(Announce_Client *announce_client);

void kill_announce_client(Announce_Client *announce_client);

#endif
