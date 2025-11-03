#ifndef DATABASE_GOSSIP_H
#define DATABASE_GOSSIP_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

int db_init_gossip(const char* db_path);
int db_is_initialized(void);
sqlite3* db_get_handle(void);
int db_close(void);

#endif // DATABASE_GOSSIP_H
