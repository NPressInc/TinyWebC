#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "message.h"

struct TW_Message {
    char* messageType;
    char* sender;
    char* receiver;
    char* context;
    char* groupId;
    char* conversationId;
    int dateTime;
    int status;
    char* encryptionKeyId;
};

TW_Message* TW_Message_create(const char* messageType, const char* sender, const char* receiver,
                             const char* context, const char* groupId, const char* conversationId, int dateTime) {
    TW_Message* msg = malloc(sizeof(TW_Message));
    if (msg) {
        msg->messageType = strdup(messageType);
        msg->sender = strdup(sender);
        msg->receiver = strdup(receiver);
        msg->context = strdup(context);
        msg->groupId = strdup(groupId);
        msg->conversationId = strdup(conversationId);
        msg->dateTime = dateTime;
        msg->status = 0;
        msg->encryptionKeyId = NULL;
    }
    return msg;
}

void TW_Message_set_status(TW_Message* msg, int status) {
    if (msg) msg->status = status;
}

int TW_Message_get_status(TW_Message* msg) {
    return msg ? msg->status : 0;
}

void TW_Message_set_encryptionKeyId(TW_Message* msg, const char* keyId) {
    if (msg) {
        free(msg->encryptionKeyId);
        msg->encryptionKeyId = keyId ? strdup(keyId) : NULL;
    }
}

const char* TW_Message_get_encryptionKeyId(TW_Message* msg) {
    return msg ? msg->encryptionKeyId : NULL;
}


const char* TW_Message_toJson(TW_Message* msg) {
    // Placeholder - implement with cJSON later
    return strdup("{\"json\": \"stub\"}");
}

void TW_Message_destroy(TW_Message* msg) {
    if (msg) {
        free(msg->messageType);
        free(msg->sender);
        free(msg->receiver);
        free(msg->context);
        free(msg->groupId);
        free(msg->conversationId);
        free(msg->encryptionKeyId);
        free(msg);
    }
}