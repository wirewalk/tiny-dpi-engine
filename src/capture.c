/*
 * Захват сетевого трафика через libpcap.
 *
 * Поддерживает два режима:
 *   - Живой захват с сетевого интерфейса (dpi_capture_run)
 *   - Чтение из pcap-файла (dpi_capture_file)
 *
 * Каждый захваченный пакет передаётся в пайплайн:
 *   parse → classify → update flow table + stats
 *
 * Корректная остановка: по сигналу SIGINT/SIGTERM
 * или по достижении лимита пакетов.
 */

#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

#include <pcap.h>

static volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* Callback для каждого захваченного пакета.
 * user — массив из 3 указателей: {ac, flow_table, stats}. */
static void dpi_pcap_callback(unsigned char *user, const struct pcap_pkthdr *h,
                              const unsigned char *bytes) {
    if (!g_running) return;

    void **ctx = (void **)user;
    dpi_ac_t          *ac    = (dpi_ac_t *)ctx[0];
    dpi_flow_table_t  *ft    = (dpi_flow_table_t *)ctx[1];
    dpi_stats_t       *stats = (dpi_stats_t *)ctx[2];

    dpi_parsed_packet_t pkt;
    if (dpi_parse_packet(bytes, h->caplen, &pkt) != 0) return;
    if (!pkt.parsed_ok) return;

    dpi_classify(ac, &pkt, ft, stats);
}

int dpi_capture_run(const char *iface, const char *bpf_filter,
                    dpi_ac_t *ac, dpi_flow_table_t *ft, dpi_stats_t *stats,
                    int max_packets, int timeout_sec) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    /* Если интерфейс не указан — выбираем первый доступный */
    if (iface) {
        handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    } else {
        pcap_if_t *alldevs = NULL;
        if (pcap_findalldevs(&alldevs, errbuf) != 0 || !alldevs) {
            fprintf(stderr, "No capture devices found: %s\n", errbuf);
            return -1;
        }
        iface = alldevs->name;
        fprintf(stderr, "Auto-selecting device: %s\n", iface);
        handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
        pcap_freealldevs(alldevs);
    }

    if (!handle) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface ? iface : "any", errbuf);
        return -1;
    }

    /* BPF-фильтр: если задан — компилируем и устанавливаем */
    if (bpf_filter) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, bpf_filter, 0, PCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        if (pcap_setfilter(handle, &fp) != 0) {
            fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return -1;
        }
        pcap_freecode(&fp);
    }

    if (timeout_sec > 0) {
        pcap_set_timeout(handle, timeout_sec * 1000);
    }

    /* Обработка сигналов для graceful shutdown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    void *ctx[3] = {ac, ft, stats};

    fprintf(stderr, "Capturing on %s (max %d packets, Ctrl+C to stop)...\n",
            iface ? iface : "any", max_packets);

    if (max_packets > 0) {
        /* Ограниченное число пакетов — pcap_loop вернёт сам */
        pcap_loop(handle, max_packets, dpi_pcap_callback, (unsigned char *)ctx);
    } else {
        /* Бесконечный захват — останавливается по Ctrl+C или timeout */
        while (g_running) {
            int ret = pcap_dispatch(handle, 64, dpi_pcap_callback, (unsigned char *)ctx);
            if (ret == -1) {
                fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(handle));
                break;
            }
            if (ret == -2) break;
        }
    }

    pcap_close(handle);
    return 0;
}

/* Чтение пакетов из pcap-файла.
 * Аналогично живому захвату, но из сохранённого дампа. */
int dpi_capture_file(const char *path, dpi_ac_t *ac, dpi_flow_table_t *ft,
                     dpi_stats_t *stats, int max_packets) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(path, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_offline(%s): %s\n", path, errbuf);
        return -1;
    }

    void *ctx[3] = {ac, ft, stats};
    fprintf(stderr, "Reading from pcap file: %s\n", path);

    int cnt = max_packets > 0 ? max_packets : 0;
    pcap_loop(handle, cnt, dpi_pcap_callback, (unsigned char *)ctx);

    pcap_close(handle);
    return 0;
}
