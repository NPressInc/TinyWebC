#include "codec.h"
#include <stdlib.h>
#include <string.h>

#include "content.pb-c.h"

typedef struct {
    uint32_t content_type;
    uint32_t schema_version;
    tw_encode_fn enc;
    tw_decode_fn dec;
} entry_t;

static entry_t* g_entries = NULL;
static size_t g_count = 0;

int tw_codec_register(uint32_t content_type, uint32_t schema_version,
                      tw_encode_fn enc, tw_decode_fn dec) {
    entry_t* n = realloc(g_entries, sizeof(entry_t) * (g_count + 1));
    if (!n) return -1;
    g_entries = n;
    g_entries[g_count].content_type = content_type;
    g_entries[g_count].schema_version = schema_version;
    g_entries[g_count].enc = enc;
    g_entries[g_count].dec = dec;
    g_count++;
    return 0;
}

static entry_t* find(uint32_t ct, uint32_t sv) {
    for (size_t i = 0; i < g_count; ++i) {
        if (g_entries[i].content_type == ct && g_entries[i].schema_version == sv)
            return &g_entries[i];
    }
    return NULL;
}

int tw_codec_encode(uint32_t ct, uint32_t sv, const void* msg, unsigned char** out, size_t* out_len) {
    entry_t* e = find(ct, sv);
    if (!e || !e->enc) return -1;
    return e->enc(msg, out, out_len);
}

void* tw_codec_decode(uint32_t ct, uint32_t sv, const unsigned char* buf, size_t len) {
    entry_t* e = find(ct, sv);
    if (!e || !e->dec) return NULL;
    return e->dec(buf, len);
}

// Default protobuf-c codec helpers for our basic messages
static int encode_direct(const void* msg, unsigned char** out, size_t* out_len) {
    const Tinyweb__DirectMessage* m = (const Tinyweb__DirectMessage*)msg;
    size_t n = tinyweb__direct_message__get_packed_size((Tinyweb__DirectMessage*)m);
    unsigned char* b = malloc(n); if (!b) return -1;
    tinyweb__direct_message__pack((Tinyweb__DirectMessage*)m, b);
    *out = b; *out_len = n; return 0;
}
static void* decode_direct(const unsigned char* buf, size_t len) {
    return tinyweb__direct_message__unpack(NULL, len, buf);
}

static int encode_group(const void* msg, unsigned char** out, size_t* out_len) {
    const Tinyweb__GroupMessage* m = (const Tinyweb__GroupMessage*)msg;
    size_t n = tinyweb__group_message__get_packed_size((Tinyweb__GroupMessage*)m);
    unsigned char* b = malloc(n); if (!b) return -1;
    tinyweb__group_message__pack((Tinyweb__GroupMessage*)m, b);
    *out = b; *out_len = n; return 0;
}
static void* decode_group(const unsigned char* buf, size_t len) {
    return tinyweb__group_message__unpack(NULL, len, buf);
}

static int encode_loc(const void* msg, unsigned char** out, size_t* out_len) {
    const Tinyweb__LocationUpdate* m = (const Tinyweb__LocationUpdate*)msg;
    size_t n = tinyweb__location_update__get_packed_size((Tinyweb__LocationUpdate*)m);
    unsigned char* b = malloc(n); if (!b) return -1;
    tinyweb__location_update__pack((Tinyweb__LocationUpdate*)m, b);
    *out = b; *out_len = n; return 0;
}
static void* decode_loc(const unsigned char* buf, size_t len) {
    return tinyweb__location_update__unpack(NULL, len, buf);
}

static int encode_alert(const void* msg, unsigned char** out, size_t* out_len) {
    const Tinyweb__EmergencyAlert* m = (const Tinyweb__EmergencyAlert*)msg;
    size_t n = tinyweb__emergency_alert__get_packed_size((Tinyweb__EmergencyAlert*)m);
    unsigned char* b = malloc(n); if (!b) return -1;
    tinyweb__emergency_alert__pack((Tinyweb__EmergencyAlert*)m, b);
    *out = b; *out_len = n; return 0;
}
static void* decode_alert(const unsigned char* buf, size_t len) {
    return tinyweb__emergency_alert__unpack(NULL, len, buf);
}

__attribute__((constructor)) static void tw_codec_bootstrap(void) {
    // Register default codecs with schema_version = 1
    tw_codec_register(1, 1, encode_direct, decode_direct);
    tw_codec_register(2, 1, encode_group, decode_group);
    tw_codec_register(3, 1, encode_loc, decode_loc);
    tw_codec_register(4, 1, encode_alert, decode_alert);
}


