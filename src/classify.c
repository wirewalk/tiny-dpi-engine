#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static dpi_protocol_t classify_by_ports(const dpi_5tuple_t *tuple) {
    uint16_t src = ntohs(tuple->src_port);
    uint16_t dst = ntohs(tuple->dst_port);

    if (dst == 80 || src == 80)       return DPI_PROTO_HTTP;
    if (dst == 443 || src == 443)     return DPI_PROTO_HTTPS;
    if (dst == 53 || src == 53)       return DPI_PROTO_DNS;
    if (dst == 22 || src == 22)       return DPI_PROTO_SSH;
    if (dst == 21 || src == 21)       return DPI_PROTO_FTP;
    if (dst == 25 || src == 25)       return DPI_PROTO_SMTP;
    if (dst == 5060 || src == 5060)   return DPI_PROTO_SIP;
    if (dst == 67 || dst == 68 ||
        src == 67 || src == 68)       return DPI_PROTO_DHCP;
    if (dst == 123 || src == 123)     return DPI_PROTO_NTP;

    return DPI_PROTO_UNKNOWN;
}

static dpi_protocol_t classify_by_payload(const dpi_ac_t *ac,
                                           const uint8_t *payload,
                                           size_t payload_len,
                                           int *matched_sig_id,
                                           const dpi_sig_db_t *db) {
    if (!payload || payload_len == 0) return DPI_PROTO_UNKNOWN;

    if (payload_len >= 5 && memcmp(payload, "HTTP/", 5) == 0)
        return DPI_PROTO_HTTP;
    if (payload_len >= 4 && (memcmp(payload, "GET ", 4) == 0 ||
                             memcmp(payload, "POST", 4) == 0 ||
                             memcmp(payload, "PUT ", 4) == 0 ||
                             memcmp(payload, "HEAD", 4) == 0 ||
                             memcmp(payload, "DELE", 4) == 0))
        return DPI_PROTO_HTTP;

    if (payload_len >= 3 && memcmp(payload, "SSH", 3) == 0)
        return DPI_PROTO_SSH;

    if (payload_len >= 4 && memcmp(payload, "SIP/", 4) == 0)
        return DPI_PROTO_SIP;
    if (payload_len >= 4 && memcmp(payload, "BYE ", 4) == 0)
        return DPI_PROTO_SIP;
    if (payload_len >= 8 && memcmp(payload, "INVITE ", 7) == 0)
        return DPI_PROTO_SIP;
    if (payload_len >= 8 && memcmp(payload, "REGISTER", 8) == 0)
        return DPI_PROTO_SIP;

    if (payload_len >= 2 && (payload[0] == 0x16) && payload[1] == 0x03)
        return DPI_PROTO_TLS;

    if (payload_len >= 9 && memcmp(payload, "QUIC", 4) == 0)
        return DPI_PROTO_QUIC;

    if (payload_len >= 12) {
        int is_rtp = (payload[0] & 0xC0) == 0x80;
        int pt = payload[1] & 0x7F;
        if (is_rtp && pt >= 0 && pt <= 34) {
            if (ac) {
                int sig = dpi_ac_search(ac, payload, payload_len);
                if (sig >= 0 && db) {
                    *matched_sig_id = sig;
                    return db->sigs[sig].proto;
                }
            }
            return DPI_PROTO_RTP;
        }
        if (is_rtp && pt >= 200 && pt <= 207)
            return DPI_PROTO_RTCP;
    }

    if (ac && payload_len > 0) {
        int sig = dpi_ac_search(ac, payload, payload_len);
        if (sig >= 0 && db) {
            *matched_sig_id = sig;
            return db->sigs[sig].proto;
        }
    }

    return DPI_PROTO_UNKNOWN;
}

dpi_sig_db_t *g_sig_db = NULL;

int dpi_classify(const dpi_ac_t *ac, const dpi_parsed_packet_t *pkt,
                 dpi_flow_table_t *ft, dpi_stats_t *stats) {
    if (!pkt->parsed_ok) return -1;

    dpi_flow_t *flow = dpi_flow_lookup_or_create(ft, &pkt->tuple);
    if (!flow) return -1;

    flow->packets++;
    flow->bytes += pkt->payload_len + (pkt->tcp ? 20 : 8) +
                   (pkt->ip ? ((pkt->ip->version_ihl & 0x0F) * 4) : 0);
    flow->last_seen = time(NULL);

    if (flow->proto != DPI_PROTO_UNKNOWN) {
        stats->total_packets++;
        stats->total_bytes += pkt->payload_len;
        stats->classified++;
        stats->by_proto[flow->proto < DPI_PROTO_MAX ? flow->proto : 0]++;
        return 0;
    }

    int matched_sig_id = -1;
    dpi_protocol_t proto = DPI_PROTO_UNKNOWN;

    if (pkt->payload && pkt->payload_len > 0) {
        proto = classify_by_payload(ac, pkt->payload, pkt->payload_len,
                                    &matched_sig_id, g_sig_db);
    }

    if (proto == DPI_PROTO_UNKNOWN) {
        proto = classify_by_ports(&pkt->tuple);
    }

    if (proto != DPI_PROTO_UNKNOWN) {
        flow->proto = proto;
        flow->matched_sig_id = matched_sig_id;
        stats->classified++;
        stats->by_proto[proto < DPI_PROTO_MAX ? proto : 0]++;
    } else {
        stats->unclassified++;
    }

    stats->total_packets++;
    stats->total_bytes += pkt->payload_len;

    return 0;
}
