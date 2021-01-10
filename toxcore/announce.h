/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_H

#include "forwarding.h"

#define MAX_ANNOUNCEMENT_SIZE 512

typedef void on_retrieve_cb(void *object, const uint8_t *data, uint16_t length);

uint8_t response_of_request_type(uint8_t request_type);

typedef struct Announcements Announcements;

Announcements *new_announcements(Mono_Time *mono_time, Forwarding *forwarding);

/* If data is stored, run `on_retrieve_callback` on it.
 * Return true if data is stored, false otherwise.
 */
bool on_stored(const Announcements *announce, const uint8_t *data_public_key,
               on_retrieve_cb on_retrieve_callback, void *object);

void set_synch_offset(Announcements *announce, int32_t synch_offset);

void kill_announcements(Announcements *announce);

#endif
