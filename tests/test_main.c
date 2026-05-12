#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { tests_passed++; } \
    else { fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); } \
} while(0)

static void test_ethernet_ip_udp(void) {
    uint8_t raw[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x08,0x00,
        0x45,0x00,0x00,0x2e,
        0x00,0x01,0x00,0x00,
        0x40,0x11,0x00,0x00,
        0xc0,0xa8,0x01,0x01,
        0xc0,0xa8,0x01,0x02,
        0x00,0x35,0x00,0x35,
        0x00,0x1a,0x00,0x00,
        0xde,0xad,0xbe,0xef,
        0xca,0xfe,0xba,0xbe,
    };

    dpi_parsed_packet_t pkt;
    int ret = dpi_parse_packet(raw, sizeof(raw), &pkt);
    ASSERT(ret == 0, "parse Ethernet/IP/UDP should succeed");
    ASSERT(pkt.parsed_ok == 1, "parsed_ok should be 1");
    ASSERT(pkt.ip != NULL, "IP header should be present");
    ASSERT(pkt.udp != NULL, "UDP header should be present");
    ASSERT(pkt.tcp == NULL, "TCP header should be NULL");

    struct in_addr sa = {pkt.tuple.src_ip};
    struct in_addr da = {pkt.tuple.dst_ip};
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &da, dst_str, sizeof(dst_str));

    ASSERT(strcmp(src_str, "192.168.1.1") == 0, "src IP should be 192.168.1.1");
    ASSERT(strcmp(dst_str, "192.168.1.2") == 0, "dst IP should be 192.168.1.2");
    ASSERT(ntohs(pkt.tuple.src_port) == 53, "src port should be 53");
    ASSERT(ntohs(pkt.tuple.dst_port) == 53, "dst port should be 53");
    ASSERT(pkt.tuple.ip_proto == 17, "IP protocol should be 17 (UDP)");
}

static void test_ethernet_ip_tcp_http(void) {
    uint8_t raw[256] = {
        0xff,0xff,0xff,0xff,0xff,0xff,
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x08,0x00,
        0x45,0x00,0x00,0x50,
        0x00,0x01,0x00,0x00,
        0x40,0x06,0x00,0x00,
        0xc0,0xa8,0x01,0x01,
        0xc0,0xa8,0x01,0x02,
        0x04,0x01, 0x00,0x50,
        0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,
        0x50,0x02, 0x00,0x00,
        0x00,0x00, 0x00,0x00,
    };

    const char *http_req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t http_len = strlen(http_req);
    size_t total = 54 + http_len;
    memcpy(raw + 54, http_req, http_len);

    raw[16] = (uint8_t)((total - 14) >> 8);
    raw[17] = (uint8_t)((total - 14) & 0xFF);

    dpi_parsed_packet_t pkt;
    int ret = dpi_parse_packet(raw, total, &pkt);
    ASSERT(ret == 0, "parse TCP packet should succeed");
    ASSERT(pkt.parsed_ok == 1, "parsed_ok should be 1");
    ASSERT(pkt.tcp != NULL, "TCP header should be present");
    ASSERT(pkt.udp == NULL, "UDP header should be NULL");
    ASSERT(ntohs(pkt.tuple.dst_port) == 80, "dst port should be 80");
    ASSERT(pkt.payload != NULL, "payload should be present");
    ASSERT(pkt.payload_len >= http_len, "payload length should cover HTTP data");
}

static void test_truncated_packet(void) {
    uint8_t raw[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x08,0x00,
    };

    dpi_parsed_packet_t pkt;
    int ret = dpi_parse_packet(raw, sizeof(raw), &pkt);
    ASSERT(ret != 0, "truncated packet should fail");
    ASSERT(pkt.parsed_ok == 0, "parsed_ok should be 0 for truncated");
}

static void test_non_ip(void) {
    uint8_t raw[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x86,0xDD,
        0x60,0x00,0x00,0x00,
    };

    dpi_parsed_packet_t pkt;
    int ret = dpi_parse_packet(raw, sizeof(raw), &pkt);
    ASSERT(ret != 0, "IPv6 packet should be rejected (unsupported)");
}

static void test_flow_table_basic(void) {
    dpi_flow_table_t ft;
    dpi_flow_table_init(&ft);

    dpi_5tuple_t t1 = {
        .src_ip = inet_addr("10.0.0.1"),
        .dst_ip = inet_addr("10.0.0.2"),
        .src_port = htons(12345),
        .dst_port = htons(80),
        .ip_proto = 6,
    };

    dpi_flow_t *f1 = dpi_flow_lookup_or_create(&ft, &t1);
    ASSERT(f1 != NULL, "flow lookup should return non-NULL");
    f1->packets++;
    f1->bytes += 100;

    dpi_5tuple_t t2 = {
        .src_ip = inet_addr("10.0.0.2"),
        .dst_ip = inet_addr("10.0.0.1"),
        .src_port = htons(80),
        .dst_port = htons(12345),
        .ip_proto = 6,
    };

    dpi_flow_t *f2 = dpi_flow_lookup_or_create(&ft, &t2);
    ASSERT(f2 != NULL, "reverse flow should find same entry");
    ASSERT(f2->packets == 1, "reverse flow should have 1 packet from forward");
    ASSERT(ft.count == 1, "flow table should have exactly 1 entry");

    dpi_flow_table_free(&ft);
}

static void test_aho_corasick(void) {
    dpi_sig_db_t db = {0};
    db.capacity = 4;
    db.sigs = calloc(4, sizeof(dpi_signature_t));

    db.sigs[0] = (dpi_signature_t){0, "GET ", 4, DPI_PROTO_HTTP};
    db.sigs[1] = (dpi_signature_t){1, "SSH-", 4, DPI_PROTO_SSH};
    db.sigs[2] = (dpi_signature_t){2, "POST", 4, DPI_PROTO_HTTP};
    db.sigs[3] = (dpi_signature_t){3, "SIP/", 4, DPI_PROTO_SIP};
    db.count = 4;

    dpi_ac_t ac = {0};
    int ret = dpi_ac_build(&ac, &db);
    ASSERT(ret == 0, "AC build should succeed");

    const uint8_t *http_data = (const uint8_t *)"GET /index.html HTTP/1.1";
    int sig = dpi_ac_search(&ac, http_data, strlen((const char *)http_data));
    ASSERT(sig == 0, "should match GET signature (id=0)");

    const uint8_t *ssh_data = (const uint8_t *)"SSH-2.0-OpenSSH_9.0";
    sig = dpi_ac_search(&ac, ssh_data, strlen((const char *)ssh_data));
    ASSERT(sig == 1, "should match SSH signature (id=1)");

    const uint8_t *random_data = (const uint8_t *)"Hello World!";
    sig = dpi_ac_search(&ac, random_data, strlen((const char *)random_data));
    ASSERT(sig == -1, "should not match any signature");

    dpi_ac_free(&ac);
    free(db.sigs);
}

static void test_sig_db_load(void) {
    const char *tmp_path = "/tmp/test_sigs.sig";
    FILE *f = fopen(tmp_path, "w");
    ASSERT(f != NULL, "should create temp sig file");
    if (f) {
        fprintf(f, "# test signatures\n");
        fprintf(f, "HTTP: GET \n");
        fprintf(f, "SSH: SSH-2.0\n");
        fprintf(f, "\n");
        fprintf(f, "# comment\n");
        fprintf(f, "DNS: \\x00\\x01\\x00\\x00\n");
        fclose(f);

        dpi_sig_db_t db = {0};
        int ret = dpi_sig_db_load(&db, tmp_path);
        ASSERT(ret == 0, "sig db load should succeed");
        ASSERT(db.count == 3, "should load 3 signatures");
        ASSERT(db.sigs[0].proto == DPI_PROTO_HTTP, "first sig should be HTTP");
        ASSERT(db.sigs[1].proto == DPI_PROTO_SSH, "second sig should be SSH");

        dpi_sig_db_free(&db);
        remove(tmp_path);
    }
}

static void test_vlan_tag(void) {
    uint8_t raw[] = {
        0xff,0xff,0xff,0xff,0xff,0xff,
        0x00,0x11,0x22,0x33,0x44,0x55,
        0x81,0x00,
        0x00,0x64,
        0x08,0x00,
        0x45,0x00,0x00,0x2e,
        0x00,0x01,0x00,0x00,
        0x40,0x11,0x00,0x00,
        0xc0,0xa8,0x01,0x01,
        0xc0,0xa8,0x01,0x02,
        0x00,0x35,0x00,0x35,
        0x00,0x1a,0x00,0x00,
        0xde,0xad,0xbe,0xef,
    };

    dpi_parsed_packet_t pkt;
    int ret = dpi_parse_packet(raw, sizeof(raw), &pkt);
    ASSERT(ret == 0, "VLAN-tagged packet should parse OK");
    ASSERT(pkt.parsed_ok == 1, "VLAN packet parsed_ok should be 1");
    ASSERT(pkt.udp != NULL, "VLAN packet should have UDP header");
}

int main(void) {
    printf("Running tiny-dpi-engine tests...\n\n");

    test_ethernet_ip_udp();
    test_ethernet_ip_tcp_http();
    test_truncated_packet();
    test_non_ip();
    test_flow_table_basic();
    test_aho_corasick();
    test_sig_db_load();
    test_vlan_tag();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
