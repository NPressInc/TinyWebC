#ifndef BLOCKCHAIN_IO_H
#define BLOCKCHAIN_IO_H

#include <stdbool.h>
#include "packages/structures/blockChain/blockchain.h"

// Save blockchain to a file
// Returns true if successful, false otherwise
bool saveBlockChainToFile(TW_BlockChain* blockChain);

// Read blockchain from a file
// Returns pointer to newly allocated BlockChain if successful, NULL otherwise
// Caller is responsible for freeing the returned BlockChain
TW_BlockChain* readBlockChainFromFile(void);

bool writeBlockChainToJson(TW_BlockChain* blockChain);

#endif // BLOCKCHAIN_IO_H
