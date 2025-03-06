#ifndef TW_GROUP_H
#define TW_GROUP_H

typedef struct TW_Group TW_Group;

TW_Group* TW_Group_create(const char* messageType, const char* sender, const char* groupType,
                         const char** entities, int entityCount, const char* description, const char* groupId);
void TW_Group_set_creationTime(TW_Group* group, int creationTime);
int TW_Group_get_creationTime(TW_Group* group);
void TW_Group_destroy(TW_Group* group);

#endif