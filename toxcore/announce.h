/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_H

#include "forwarding.h"

typedef struct Announcements Announcements;

Announcements *new_announcements(Mono_Time *mono_time, Forwarding *forwarding);

void set_synch_offset(Announcements *announce, int32_t synch_offset);

void kill_announcements(Announcements *announce);

#endif
