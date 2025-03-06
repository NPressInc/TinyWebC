#ifndef TW_MESSAGE_H
#define TW_MESSAGE_H

typedef struct TW_Message TW_Message;

TW_Message* TW_Message_create(const char* messageType, const char* sender, const char* receiver,
                             const char* context, const char* groupId, const char* conversationId, int dateTime);
void TW_Message_set_status(TW_Message* msg, int status);
int TW_Message_get_status(TW_Message* msg);
void TW_Message_set_encryptionKeyId(TW_Message* msg, const char* keyId);
const char* TW_Message_get_encryptionKeyId(TW_Message* msg);
const char* TW_Message_toJson(TW_Message* msg); // Placeholder for JSON serialization
void TW_Message_destroy(TW_Message* msg);

#endif