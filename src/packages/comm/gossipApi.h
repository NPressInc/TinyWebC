#ifndef GOSSIP_API_H
#define GOSSIP_API_H

#include <stdint.h>
#include <stdbool.h>
#include "packages/comm/gossip/gossip.h"
#include "packages/validation/gossip_validation.h"

int gossip_api_start(uint16_t port,
                     GossipService* service,
                     const GossipValidationConfig* config);

void gossip_api_stop(void);

bool gossip_api_is_running(void);

#endif // GOSSIP_API_H

