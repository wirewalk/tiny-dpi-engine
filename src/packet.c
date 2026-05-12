#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stddef.h>

#define ETH_HDR_LEN     14
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

static uint16_t read_u16_be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

int dpi_parse_packet(const uint8_t *raw, size_t raw_len, dpi_parsed_packet_t *out) {
    memset(out, 0, sizeof(*out));
    out->parsed_ok = 0;

    if (raw_len < ETH_HDR_LEN) return -1;

    const uint8_t *ptr = raw;
    const uint8_t *end = raw + raw_len;

    out->eth = (const dpi_eth_header_t *)ptr;
    uint16_t ethertype = ntohs(out->eth->ethertype);
    ptr += ETH_HDR_LEN;

    if (ethertype == 0x8100) {
        if (ptr + 4 > end) return -1;
        ethertype = read_u16_be(ptr + 2);
        ptr += 4;
    }

    if (ethertype != 0x0800) return -1;

    if (ptr + 20 > end) return -1;
    out->ip = (const dpi_ip_header_t *)ptr;

    uint8_t ihl = (out->ip->version_ihl & 0x0F) * 4;
    if (ihl < 20 || ptr + ihl > end) return -1;

    uint16_t ip_total = ntohs(out->ip->total_length);
    const uint8_t *ip_end = ptr + ip_total;
    if (ip_end > end) ip_end = end;

    ptr += ihl;

    out->tuple.src_ip = out->ip->src_ip;
    out->tuple.dst_ip = out->ip->dst_ip;
    out->tuple.ip_proto = out->ip->protocol;

    uint8_t proto = out->ip->protocol;

    if (proto == IP_PROTO_TCP) {
        if (ptr + 20 > ip_end) return -1;
        out->tcp = (const dpi_tcp_header_t *)ptr;
        uint16_t tcp_hdr_len = ((ntohs(out->tcp->data_offset_flags) >> 12) & 0xF) * 4;
        if (tcp_hdr_len < 20) return -1;
        ptr += tcp_hdr_len;
        if (ptr > ip_end) return -1;

        out->tuple.src_port = out->tcp->src_port;
        out->tuple.dst_port = out->tcp->dst_port;
        out->payload = ptr;
        out->payload_len = (size_t)(ip_end - ptr);
    } else if (proto == IP_PROTO_UDP) {
        if (ptr + 8 > ip_end) return -1;
        out->udp = (const dpi_udp_header_t *)ptr;
        ptr += 8;

        out->tuple.src_port = out->udp->src_port;
        out->tuple.dst_port = out->udp->dst_port;
        out->payload = ptr;
        out->payload_len = (size_t)(ip_end - ptr);
    } else if (proto == IP_PROTO_ICMP) {
        out->tuple.src_port = 0;
        out->tuple.dst_port = 0;
        out->payload = ptr;
        out->payload_len = (size_t)(ip_end - ptr);
    } else {
        return -1;
    }

    out->parsed_ok = 1;
    return 0;
}
