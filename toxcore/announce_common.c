/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#include "network.h"

#include <assert.h>
#include <stdint.h>

uint8_t response_of_request_type(uint8_t request_type)
{
    switch (request_type) {
        case NET_PACKET_DATA_SEARCH_REQUEST :
            return NET_PACKET_DATA_SEARCH_RESPONSE;

        case NET_PACKET_DATA_RETRIEVE_REQUEST :
            return NET_PACKET_DATA_RETRIEVE_RESPONSE;

        case NET_PACKET_STORE_ANNOUNCE_REQUEST :
            return NET_PACKET_STORE_ANNOUNCE_RESPONSE;

        default :
            assert(false);
    }
}
