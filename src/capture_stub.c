/*
 * Заглушка для capture-модуля при сборке без libpcap.
 *
 * Позволяет собирать проект на системах без установленного libpcap.
 * Парсинг, классификация и таблица потоков работают —
 * отключён только захват трафика.
 */

#include "dpi.h"
#include <stdio.h>

int dpi_capture_run(const char *iface, const char *bpf_filter,
                    dpi_ac_t *ac, dpi_flow_table_t *ft, dpi_stats_t *stats,
                    int max_packets, int timeout_sec) {
    (void)iface; (void)bpf_filter; (void)ac; (void)ft;
    (void)stats; (void)max_packets; (void)timeout_sec;
    fprintf(stderr, "Error: live capture not available (compiled without libpcap)\n");
    return -1;
}

int dpi_capture_file(const char *path, dpi_ac_t *ac, dpi_flow_table_t *ft,
                     dpi_stats_t *stats, int max_packets) {
    (void)path; (void)ac; (void)ft; (void)stats; (void)max_packets;
    fprintf(stderr, "Error: pcap file reading not available (compiled without libpcap)\n");
    return -1;
}
