/*
 * Таблица сетевых потоков.
 *
 * Хэш-таблица с цепочечной (chaining) схемой разрешения коллизий.
 * Ключ — канонический 5-кортеж (src_ip, dst_ip, src_port, dst_port, ip_proto).
 *
 * Канонизация: IP-адреса сортируются по числовому значению,
 * чтобы пакеты A→B и B→A попадали в один поток.
 * Это необходимо для корректной классификации двунаправленных сессий.
 */

#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* Хэш-функция для 5-кортежа.
 * Использует XOR + мультипликативное перемешивание (Murmur-like finalizer).
 * Размер таблицы — простое число, что улучшает распределение. */
static uint32_t flow_hash(const dpi_5tuple_t *t) {
    uint32_t h = t->src_ip;
    h ^= t->dst_ip;
    h ^= (t->src_port << 16) | t->dst_port;
    h ^= t->ip_proto;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = (h >> 16) ^ h;
    return h % DPI_FLOW_TABLE_SIZE;
}

static int tuple_equal(const dpi_5tuple_t *a, const dpi_5tuple_t *b) {
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->ip_proto == b->ip_proto;
}

/* Канонизация 5-кортежа.
 * Упорядочивает IP-адреса (меньший → src), чтобы пакеты обоих
 * направлений одной сессии имели одинаковый ключ.
 * При равенстве IP — упорядочивает по портам. */
static dpi_5tuple_t tuple_canonical(const dpi_5tuple_t *t) {
    dpi_5tuple_t c = *t;
    if (ntohl(t->src_ip) > ntohl(t->dst_ip) ||
        (t->src_ip == t->dst_ip && t->src_port > t->dst_port)) {
        uint32_t tmp_ip = c.src_ip;
        c.src_ip = c.dst_ip;
        c.dst_ip = tmp_ip;
        uint16_t tmp_port = c.src_port;
        c.src_port = c.dst_port;
        c.dst_port = tmp_port;
    }
    return c;
}

void dpi_flow_table_init(dpi_flow_table_t *ft) {
    memset(ft, 0, sizeof(*ft));
}

void dpi_flow_table_free(dpi_flow_table_t *ft) {
    for (int i = 0; i < DPI_FLOW_TABLE_SIZE; i++) {
        dpi_flow_node_t *node = ft->buckets[i];
        while (node) {
            dpi_flow_node_t *next = node->next;
            free(node);
            node = next;
        }
        ft->buckets[i] = NULL;
    }
    ft->count = 0;
}

/* Поиск потока по 5-кортежу. Если не найден — создаёт новый.
 *
 * Алгоритм:
 *   1. Канонизация кортежа
 *   2. Вычисление хэша
 *   3. Линейный поиск по цепочке в бакете
 *   4. Если не найден — выделение нового узла и вставка в голову цепочки
 *
 * Возвращает NULL при превышении лимита (DPI_MAX_FLOWS). */
dpi_flow_t *dpi_flow_lookup_or_create(dpi_flow_table_t *ft, const dpi_5tuple_t *tuple) {
    dpi_5tuple_t canon = tuple_canonical(tuple);
    uint32_t h = flow_hash(&canon);

    dpi_flow_node_t *node = ft->buckets[h];
    while (node) {
        if (tuple_equal(&node->flow.tuple, &canon)) {
            return &node->flow;
        }
        node = node->next;
    }

    if (ft->count >= DPI_MAX_FLOWS) {
        return NULL;
    }

    dpi_flow_node_t *new_node = calloc(1, sizeof(dpi_flow_node_t));
    if (!new_node) return NULL;

    new_node->flow.tuple = canon;
    new_node->flow.proto = DPI_PROTO_UNKNOWN;
    new_node->flow.first_seen = time(NULL);
    new_node->flow.last_seen = new_node->flow.first_seen;
    new_node->next = ft->buckets[h];
    ft->buckets[h] = new_node;
    ft->count++;

    return &new_node->flow;
}

/* Вывод таблицы потоков в формате:
 * SRC_IP PORT -> DST_IP PORT  PROTO  PACKETS  BYTES  SIG */
void dpi_flow_table_print(const dpi_flow_table_t *ft) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char proto_name[64];

    printf("\n%-18s %-6s -> %-18s %-6s  %-8s %10s %10s  %s\n",
           "SRC IP", "PORT", "DST IP", "PORT", "PROTO", "PACKETS", "BYTES", "SIG");
    printf("%s\n", "------------------------------------------------------------------------------------------");

    for (int i = 0; i < DPI_FLOW_TABLE_SIZE; i++) {
        dpi_flow_node_t *node = ft->buckets[i];
        while (node) {
            dpi_flow_t *f = &node->flow;
            struct in_addr sa = {f->tuple.src_ip};
            struct in_addr da = {f->tuple.dst_ip};
            inet_ntop(AF_INET, &sa, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &da, dst_ip, sizeof(dst_ip));
            dpi_proto_name(f->proto, proto_name, sizeof(proto_name));

            printf("%-18s %-6d -> %-18s %-6d  %-8s %10lu %10lu",
                   src_ip, ntohs(f->tuple.src_port),
                   dst_ip, ntohs(f->tuple.dst_port),
                   proto_name,
                   (unsigned long)f->packets,
                   (unsigned long)f->bytes);
            if (f->matched_sig_id >= 0) {
                printf("  sig=%d", f->matched_sig_id);
            }
            printf("\n");
            node = node->next;
        }
    }
}
