#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "group.h"

struct TW_Group {
    char* messageType;
    char* sender;
    char* groupType;
    char** entities;
    int entityCount;
    char* description;
    char* groupId;
    int creationTime;
};

TW_Group* TW_Group_create(const char* messageType, const char* sender, const char* groupType,
                         const char** entities, int entityCount, const char* description, const char* groupId) {
    TW_Group* group = malloc(sizeof(TW_Group));
    if (group) {
        group->messageType = strdup(messageType);
        group->sender = strdup(sender);
        group->groupType = strdup(groupType);
        group->entities = malloc(entityCount * sizeof(char*));
        for (int i = 0; i < entityCount; i++) group->entities[i] = strdup(entities[i]);
        group->entityCount = entityCount;
        group->description = strdup(description);
        group->groupId = strdup(groupId);
        group->creationTime = 0;
    }
    return group;
}

void TW_Group_set_creationTime(TW_Group* group, int creationTime) {
    if (group) group->creationTime = creationTime;
}

int TW_Group_get_creationTime(TW_Group* group) {
    return group ? group->creationTime : 0;
}

void TW_Group_destroy(TW_Group* group) {
    if (group) {
        free(group->messageType);
        free(group->sender);
        free(group->groupType);
        for (int i = 0; i < group->entityCount; i++) free(group->entities[i]);
        free(group->entities);
        free(group->description);
        free(group->groupId);
        free(group);
    }
}