// src/packages/comm/blockChainQueryApi.h
#ifndef BLOCKCHAINQUERYAPI_H
#define BLOCKCHAINQUERYAPI_H

#include <microhttpd.h>

// Function to start the blockchain query API server
void start_blockChainQueryApi(void);

// Route handlers
enum MHD_Result handle_hello_world(void *cls, struct MHD_Connection *connection,
                                  const char *url, const char *method,
                                  const char *version, const char *upload_data,
                                  size_t *upload_data_size, void **con_cls);

enum MHD_Result handle_CheckBlockChain(void *cls, struct MHD_Connection *connection,
                                      const char *url, const char *method,
                                      const char *version, const char *upload_data,
                                      size_t *upload_data_size, void **con_cls);

enum MHD_Result handle_GetAllGroups(void *cls, struct MHD_Connection *connection,
                                   const char *url, const char *method,
                                   const char *version, const char *upload_data,
                                   size_t *upload_data_size, void **con_cls);

enum MHD_Result handle_GetSentMessages(void *cls, struct MHD_Connection *connection,
                                      const char *url, const char *method,
                                      const char *version, const char *upload_data,
                                      size_t *upload_data_size, void **con_cls);

enum MHD_Result handle_GetReceivedMessages(void *cls, struct MHD_Connection *connection,
                                          const char *url, const char *method,
                                          const char *version, const char *upload_data,
                                          size_t *upload_data_size, void **con_cls);

enum MHD_Result handle_SendMessage(void *cls, struct MHD_Connection *connection,
                                  const char *url, const char *method,
                                  const char *version, const char *upload_data,
                                  size_t *upload_data_size, void **con_cls);

enum MHD_Result handle_CheckDigestParity(void *cls, struct MHD_Connection *connection,
                                        const char *url, const char *method,
                                        const char *version, const char *upload_data,
                                        size_t *upload_data_size, void **con_cls);
                                        

#endif