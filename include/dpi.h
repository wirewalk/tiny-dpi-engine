#ifndef DPI_H
#define DPI_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define DPI_MAX_SIG_LEN 256
#define DPI_FLOW_TABLE_SIZE 65537
#define DPI_MAX_FLOWS       1048576

typedef enum {
    DPI_PROTO_UNKNOWN = 0,
    DPI_PROTO_HTTP,
    DPI_PROTO_HTTPS,
    DPI_PROTO_DNS,
    DPI_PROTO_SSH,
    DPI_PROTO_FTP,
    DPI_PROTO_SMTP,
    DPI_PROTO_RTP,
    DPI_PROTO_SIP,
    DPI_PROTO_RTCP,
    DPI_PROTO_QUIC,
    DPI_PROTO_DHCP,
    DPI_PROTO_NTP,
    DPI_PROTO_ICMP,
    DPI_PROTO_TLS,
    DPI_PROTO_MAX
} dpi_protocol_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ip_proto;
} dpi_5tuple_t;

typedef struct {
    dpi_5tuple_t  tuple;
    dpi_protocol_t proto;
    uint64_t       packets;
    uint64_t       bytes;
    time_t         first_seen;
    time_t         last_seen;
    int            matched_sig_id;
} dpi_flow_t;

typedef struct dpi_flow_node {
    dpi_flow_t             flow;
    struct dpi_flow_node  *next;
} dpi_flow_node_t;

typedef struct {
    dpi_flow_node_t *buckets[DPI_FLOW_TABLE_SIZE];
    int              count;
} dpi_flow_table_t;

typedef struct {
    int   id;
    char  pattern[DPI_MAX_SIG_LEN];
    int   pattern_len;
    dpi_protocol_t proto;
} dpi_signature_t;

typedef struct {
    int               count;
    int               capacity;
    dpi_signature_t  *sigs;
} dpi_sig_db_t;

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t classified;
    uint64_t unclassified;
    uint64_t by_proto[DPI_PROTO_MAX];
} dpi_stats_t;

typedef struct {
    char             name[64];
    dpi_protocol_t   proto;
} dpi_proto_name_t;

void         dpi_proto_name(dpi_protocol_t proto, char *buf, size_t len);
const char  *dpi_proto_str(dpi_protocol_t proto);

void    dpi_flow_table_init(dpi_flow_table_t *ft);
void    dpi_flow_table_free(dpi_flow_table_t *ft);
dpi_flow_t *dpi_flow_lookup_or_create(dpi_flow_table_t *ft, const dpi_5tuple_t *tuple);
void    dpi_flow_table_stats(const dpi_flow_table_t *ft, dpi_stats_t *stats);
void    dpi_flow_table_print(const dpi_flow_table_t *ft);

int     dpi_sig_db_load(dpi_sig_db_t *db, const char *path);
void    dpi_sig_db_free(dpi_sig_db_t *db);

typedef struct dpi_ac_node {
    struct dpi_ac_node *children[256];
    struct dpi_ac_node *fail;
    int                 sig_id;
} dpi_ac_node_t;

typedef struct {
    dpi_ac_node_t *root;
    int             node_count;
} dpi_ac_t;

int     dpi_ac_build(dpi_ac_t *ac, const dpi_sig_db_t *db);
void    dpi_ac_free(dpi_ac_t *ac);
int     dpi_ac_search(const dpi_ac_t *ac, const uint8_t *data, size_t len);

typedef struct {
    uint8_t   dst_mac[6];
    uint8_t   src_mac[6];
    uint16_t  ethertype;
} dpi_eth_header_t;

typedef struct {
    uint8_t   version_ihl;
    uint8_t   tos;
    uint16_t  total_length;
    uint16_t  id;
    uint16_t  flags_offset;
    uint8_t   ttl;
    uint8_t   protocol;
    uint16_t  checksum;
    uint32_t  src_ip;
    uint32_t  dst_ip;
} dpi_ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t data_offset_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} dpi_tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} dpi_udp_header_t;

typedef struct {
    const dpi_eth_header_t *eth;
    const dpi_ip_header_t  *ip;
    const dpi_tcp_header_t *tcp;
    const dpi_udp_header_t *udp;
    const uint8_t          *payload;
    size_t                  payload_len;
    dpi_5tuple_t            tuple;
    int                     parsed_ok;
} dpi_parsed_packet_t;

int     dpi_parse_packet(const uint8_t *raw, size_t raw_len, dpi_parsed_packet_t *out);

void    dpi_stats_init(dpi_stats_t *stats);
void    dpi_stats_print(const dpi_stats_t *stats, const dpi_flow_table_t *ft);

int     dpi_classify(const dpi_ac_t *ac, const dpi_parsed_packet_t *pkt,
                     dpi_flow_table_t *ft, dpi_stats_t *stats);

int     dpi_capture_run(const char *iface, const char *bpf_filter,
                        dpi_ac_t *ac, dpi_flow_table_t *ft, dpi_stats_t *stats,
                        int max_packets, int timeout_sec);
int     dpi_capture_file(const char *path, dpi_ac_t *ac, dpi_flow_table_t *ft,
                         dpi_stats_t *stats, int max_packets);

#endif
