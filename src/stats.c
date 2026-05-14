/*
 * Сбор и вывод статистики.
 *
 * Агрегирует: общее число пакетов/байт, классифицированные/неклассифицированные,
 * распределение по протоколам. Выводит в человекочитаемом формате.
 */

#include "dpi.h"
#include <stdio.h>
#include <string.h>

void dpi_stats_init(dpi_stats_t *stats) {
    memset(stats, 0, sizeof(*stats));
}

void dpi_stats_print(const dpi_stats_t *stats, const dpi_flow_table_t *ft) {
    printf("\n=== DPI Statistics ===\n");
    printf("Total packets:   %lu\n", (unsigned long)stats->total_packets);
    printf("Total bytes:     %lu\n", (unsigned long)stats->total_bytes);
    printf("Classified:      %lu\n", (unsigned long)stats->classified);
    printf("Unclassified:    %lu\n", (unsigned long)stats->unclassified);
    printf("Active flows:    %d\n",  ft->count);

    if (stats->total_packets > 0) {
        double pct = 100.0 * (double)stats->classified / (double)stats->total_packets;
        printf("Classification:  %.1f%%\n", pct);
    }

    printf("\nPer-protocol breakdown:\n");
    for (int i = 1; i < DPI_PROTO_MAX; i++) {
        if (stats->by_proto[i] > 0) {
            printf("  %-10s %lu\n", dpi_proto_str((dpi_protocol_t)i),
                   (unsigned long)stats->by_proto[i]);
        }
    }
}
