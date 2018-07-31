/*
 * Slightly better groupchats implementation.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2014 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GROUP_H
#define GROUP_H

#include "Messenger.h"

typedef enum Groupchat_Status {
    GROUPCHAT_STATUS_NONE,
    GROUPCHAT_STATUS_VALID,
    GROUPCHAT_STATUS_CONNECTED
} Groupchat_Status;

typedef enum Groupchat_Type {
    GROUPCHAT_TYPE_TEXT,
    GROUPCHAT_TYPE_AV
} Groupchat_Type;

#define MAX_LOSSY_COUNT 256

typedef struct Message_Info {
    uint32_t message_number;
    uint8_t  message_id;
} Message_Info;

#define MAX_LAST_MESSAGE_INFOS 8

typedef struct Group_Peer {
    uint8_t     real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t     temp_pk[CRYPTO_PUBLIC_KEY_SIZE];

    uint64_t    last_recv;

    Message_Info
    last_message_infos[MAX_LAST_MESSAGE_INFOS]; /* received messages, strictly decreasing in message_number */
    uint8_t         num_last_message_infos;

    uint8_t     nick[MAX_NAME_LENGTH];
    uint8_t     nick_len;
    bool        nick_updated;

    uint16_t peer_number;

    uint8_t  recv_lossy[MAX_LOSSY_COUNT];
    uint16_t bottom_lossy_number;
    uint16_t top_lossy_number;

    void *object;
} Group_Peer;

#define DESIRED_CLOSE_CONNECTIONS 4
#define MAX_GROUP_CONNECTIONS 16
#define GROUP_IDENTIFIER_LENGTH (1 + CRYPTO_SYMMETRIC_KEY_SIZE) // type + CRYPTO_SYMMETRIC_KEY_SIZE so we can use new_symmetric_key(...) to fill it

typedef enum Groupchat_Close_Type {
    GROUPCHAT_CLOSE_NONE,
    GROUPCHAT_CLOSE_CONNECTION,
    GROUPCHAT_CLOSE_ONLINE
} Groupchat_Close_Type;

typedef struct Groupchat_Close {
    uint8_t type; /* GROUPCHAT_CLOSE_* */
    bool closest; /* connected to peer because it is one of our closest peers */
    bool introducer; /* connected to peer because it introduced us to the group */
    bool introduced; /* connected to peer because we introduced it to the group */
    uint32_t number;
    uint16_t group_number;
} Groupchat_Close;

typedef struct Groupchat_Close_Connection {
    uint8_t entry;
    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
} Groupchat_Close_Connection;

typedef void peer_on_join_cb(void *object, uint32_t conference_number, uint32_t peer_number);
typedef void peer_on_leave_cb(void *object, uint32_t conference_number, void *peer_object);
typedef void group_on_delete_cb(void *object, uint32_t conference_number);

typedef struct Group_c {
    uint8_t status;

    Group_Peer *group;
    uint32_t numpeers;

    /* TODO(zugz) rename close to something more accurate - "connected"? */
    Groupchat_Close close[MAX_GROUP_CONNECTIONS];

    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    Groupchat_Close_Connection closest_peers[DESIRED_CLOSE_CONNECTIONS];
    uint8_t changed;

    uint8_t identifier[GROUP_IDENTIFIER_LENGTH];

    uint8_t title[MAX_NAME_LENGTH];
    uint8_t title_len;

    uint32_t message_number;
    uint16_t lossy_message_number;
    uint16_t peer_number;

    uint64_t last_sent_ping;

    int number_joined; /* friendcon_id of person that invited us to the chat. (-1 means none) */

    void *object;

    peer_on_join_cb *peer_on_join;
    peer_on_leave_cb *peer_on_leave;
    group_on_delete_cb *group_on_delete;
} Group_c;

typedef void g_conference_invite_cb(Messenger *m, uint32_t friend_number, int type, const uint8_t *cookie,
                                    size_t length, void *user_data);
typedef void g_conference_message_cb(Messenger *m, uint32_t conference_number, uint32_t peer_number, int type,
                                     const uint8_t *message, size_t length, void *user_data);
typedef void peer_name_cb(Messenger *m, uint32_t conference_number, uint32_t peer_number, const uint8_t *name,
                          size_t length, void *user_data);
typedef void peer_list_changed_cb(Messenger *m, uint32_t conference_number, void *user_data);
typedef void title_cb(Messenger *m, uint32_t conference_number, uint32_t peer_number, const uint8_t *title,
                      size_t length, void *user_data);
typedef int lossy_packet_cb(void *object, uint32_t conference_number, uint32_t peer_number, void *peer_object,
                            const uint8_t *packet, uint16_t length);

typedef struct Group_Lossy_Handler {
    lossy_packet_cb *function;
} Group_Lossy_Handler;

typedef struct Group_Chats {
    Messenger *m;
    Friend_Connections *fr_c;

    Group_c *chats;
    uint16_t num_chats;

    g_conference_invite_cb *invite_callback;
    g_conference_message_cb *message_callback;
    peer_name_cb *peer_name_callback;
    peer_list_changed_cb *peer_list_changed_callback;
    title_cb *title_callback;

    Group_Lossy_Handler lossy_packethandlers[256];
} Group_Chats;

/* Set the callback for group invites.
 *
 *  Function(Group_Chats *g_c, uint32_t friendnumber, uint8_t type, uint8_t *data, uint16_t length, void *userdata)
 *
 *  data of length is what needs to be passed to join_groupchat().
 */
void g_callback_group_invite(Group_Chats *g_c, g_conference_invite_cb *function);

/* Set the callback for group messages.
 *
 *  Function(Group_Chats *g_c, uint32_t groupnumber, uint32_t friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void g_callback_group_message(Group_Chats *g_c, g_conference_message_cb *function);


/* Set callback function for title changes.
 *
 * Function(Group_Chats *g_c, uint32_t groupnumber, uint32_t friendgroupnumber, uint8_t * title, uint8_t length, void *userdata)
 * if friendgroupnumber == -1, then author is unknown (e.g. initial joining the group)
 */
void g_callback_group_title(Group_Chats *g_c, title_cb *function);

/* Set callback function for peer nickname changes.
 *
 * It gets called every time a peer changes their nickname.
 *  Function(Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, const uint8_t *nick, size_t nick_len, void *userdata)
 */
void g_callback_peer_name(Group_Chats *g_c, peer_name_cb *function);

/* Set callback function for peer list changes.
 *
 * It gets called every time the name list changes(new peer, deleted peer)
 *  Function(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
 */
void g_callback_peer_list_changed(Group_Chats *g_c, peer_list_changed_cb *function);

/* Creates a new groupchat and puts it in the chats array.
 *
 * type is one of GROUPCHAT_TYPE_*
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Group_Chats *g_c, uint8_t type);

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 */
int del_groupchat(Group_Chats *g_c, uint32_t groupnumber);

/* Copy the public key of peernumber who is in groupnumber to pk.
 * pk must be CRYPTO_PUBLIC_KEY_SIZE long.
 *
 * return 0 on success
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peer_pubkey(const Group_Chats *g_c, uint32_t groupnumber, int peernumber, uint8_t *pk);

/*
 * Return the size of peernumber's name.
 *
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peername_size(const Group_Chats *g_c, uint32_t groupnumber, int32_t peernumber);

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least MAX_NAME_LENGTH long.
 *
 * return length of name if success
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peername(const Group_Chats *g_c, uint32_t groupnumber, int peernumber, uint8_t *name);

/* invite friendnumber to groupnumber
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 * return -2 if invite packet failed to send.
 */
int invite_friend(Group_Chats *g_c, uint32_t friendnumber, uint32_t groupnumber);

/* Join a group (you need to have been invited first.)
 *
 * expected_type is the groupchat type we expect the chat we are joining is.
 *
 * return group number on success.
 * return -1 if data length is invalid.
 * return -2 if group is not the expected type.
 * return -3 if friendnumber is invalid.
 * return -4 if client is already in this group.
 * return -5 if group instance failed to initialize.
 * return -6 if join packet fails to send.
 */
int join_groupchat(Group_Chats *g_c, uint32_t friendnumber, uint8_t expected_type, const uint8_t *data,
                   uint16_t length);

/* send a group message
 * return 0 on success
 * see: send_message_group() for error codes.
 */
int group_message_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *message, uint16_t length);

/* send a group action
 * return 0 on success
 * see: send_message_group() for error codes.
 */
int group_action_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *action, uint16_t length);

/* set the group's title, limited to MAX_NAME_LENGTH
 * return 0 on success
 * return -1 if groupnumber is invalid.
 * return -2 if title is too long or empty.
 * return -3 if packet fails to send.
 */
int group_title_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *title, uint8_t title_len);


/* return the group's title size.
 * return -1 of groupnumber is invalid.
 * return -2 if title is too long or empty.
 */
int group_title_get_size(const Group_Chats *g_c, uint32_t groupnumber);

/* Get group title from groupnumber and put it in title.
 * Title needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 * return length of copied title if success.
 * return -1 if groupnumber is invalid.
 * return -2 if title is too long or empty.
 */
int group_title_get(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *title);

/* Return the number of peers in the group chat on success.
 * return -1 if groupnumber is invalid.
 */
int group_number_peers(const Group_Chats *g_c, uint32_t groupnumber);

/* return 1 if the peernumber corresponds to ours.
 * return 0 if the peernumber is not ours.
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 * return -3 if we are not connected to the group chat.
 */
int group_peernumber_is_ours(const Group_Chats *g_c, uint32_t groupnumber, int peernumber);

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][MAX_NAME_LENGTH] array.
 *
 * Copies the lengths of the names to lengths[length]
 *
 * returns the number of peers on success.
 *
 * return -1 on failure.
 */
int group_names(const Group_Chats *g_c, uint32_t groupnumber, uint8_t names[][MAX_NAME_LENGTH], uint16_t lengths[],
                uint16_t length);

/* Set handlers for custom lossy packets.
 *
 * NOTE: Handler must return 0 if packet is to be relayed, -1 if the packet should not be relayed.
 *
 * Function(void *group object (set with group_set_object), uint32_t groupnumber, uint32_t friendgroupnumber, void *group peer object (set with group_peer_set_object), const uint8_t *packet, uint16_t length)
 */
void group_lossy_packet_registerhandler(Group_Chats *g_c, uint8_t byte, lossy_packet_cb *function);

/* High level function to send custom lossy packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_group_lossy_packet(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length);

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist.
 */
uint32_t count_chatlist(const Group_Chats *g_c);

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_chatlist(const Group_Chats *g_c, uint32_t *out_list, uint32_t list_size);

/* return the type of groupchat (GROUPCHAT_TYPE_) that groupnumber is.
 *
 * return -1 on failure.
 * return type on success.
 */
int group_get_type(const Group_Chats *g_c, uint32_t groupnumber);

/* Copies the unique id of group_chat[groupnumber] into uid.
*
* return false on failure.
* return true on success.
*/
bool conference_get_uid(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *uid);

int32_t conference_by_uid(const Group_Chats *g_c, const uint8_t *uid);

/* Send current name (set in messenger) to all online groups.
 */
void send_name_all_groups(Group_Chats *g_c);

/* Set the object that is tied to the group chat.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_set_object(const Group_Chats *g_c, uint32_t groupnumber, void *object);

/* Set the object that is tied to the group peer.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_peer_set_object(const Group_Chats *g_c, uint32_t groupnumber, int peernumber, void *object);

/* Return the object tide to the group chat previously set by group_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_get_object(const Group_Chats *g_c, uint32_t groupnumber);

/* Return the object tide to the group chat peer previously set by group_peer_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_peer_get_object(const Group_Chats *g_c, uint32_t groupnumber, int peernumber);

/* Set a function to be called when a new peer joins a group chat.
 *
 * Function(void *group object (set with group_set_object), int groupnumber, int friendgroupnumber)
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_new(const Group_Chats *g_c, uint32_t groupnumber, peer_on_join_cb *function);

/* Set a function to be called when a peer leaves a group chat.
 *
 * Function(void *group object (set with group_set_object), uint32_t groupnumber, void *group peer object (set with group_peer_set_object))
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_delete(Group_Chats *g_c, uint32_t groupnumber, peer_on_leave_cb *function);

/* Set a function to be called when the group chat is deleted.
 *
 * Function(void *group object (set with group_set_object), uint32_t groupnumber)
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_delete(Group_Chats *g_c, uint32_t groupnumber, group_on_delete_cb *function);

/* Create new groupchat instance. */
Group_Chats *new_groupchats(Messenger *m);

/* main groupchats loop. */
void do_groupchats(Group_Chats *g_c, void *userdata);

/* Free everything related with group chats. */
void kill_groupchats(Group_Chats *g_c);

#endif
