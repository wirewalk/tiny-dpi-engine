/*
 * Маппинг enum протоколов в строковые имена.
 */

#include "dpi.h"
#include <stdio.h>
#include <string.h>

static const struct {
    dpi_protocol_t proto;
    const char    *name;
} proto_names[] = {
    {DPI_PROTO_UNKNOWN, "unknown"},
    {DPI_PROTO_HTTP,    "HTTP"},
    {DPI_PROTO_HTTPS,   "HTTPS"},
    {DPI_PROTO_DNS,     "DNS"},
    {DPI_PROTO_SSH,     "SSH"},
    {DPI_PROTO_FTP,     "FTP"},
    {DPI_PROTO_SMTP,    "SMTP"},
    {DPI_PROTO_RTP,     "RTP"},
    {DPI_PROTO_SIP,     "SIP"},
    {DPI_PROTO_RTCP,    "RTCP"},
    {DPI_PROTO_QUIC,    "QUIC"},
    {DPI_PROTO_DHCP,    "DHCP"},
    {DPI_PROTO_NTP,     "NTP"},
    {DPI_PROTO_ICMP,    "ICMP"},
    {DPI_PROTO_TLS,     "TLS"},
};

void dpi_proto_name(dpi_protocol_t proto, char *buf, size_t len) {
    size_t n = sizeof(proto_names) / sizeof(proto_names[0]);
    for (size_t i = 0; i < n; i++) {
        if (proto_names[i].proto == proto) {
            snprintf(buf, len, "%s", proto_names[i].name);
            return;
        }
    }
    snprintf(buf, len, "proto_%d", (int)proto);
}

const char *dpi_proto_str(dpi_protocol_t proto) {
    size_t n = sizeof(proto_names) / sizeof(proto_names[0]);
    for (size_t i = 0; i < n; i++) {
        if (proto_names[i].proto == proto) {
            return proto_names[i].name;
        }
    }
    return "unknown";
}
