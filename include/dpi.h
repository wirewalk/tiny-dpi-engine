/*
 * tiny-dpi-engine — лёгкий движок глубокого инспектирования пакетов (DPI)
 *
 * Заголовочный файл содержит все публичные типы данных и API компонент:
 *   - разбор пакетов (Ethernet/IP/TCP/UDP)
 *   - поиск сигнатур (алгоритм Ахо-Корасик)
 *   - классификация протоколов
 *   - таблица сетевых потоков
 *   - захват трафика (libpcap)
 *   - статистика
 */
#ifndef DPI_H
#define DPI_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Максимальная длина текстовой сигнатуры (байт) */
#define DPI_MAX_SIG_LEN 256

/* Размер хэш-таблицы потоков — простое число для равномерного распределения */
#define DPI_FLOW_TABLE_SIZE 65537

/* Максимальное число одновременных потоков (лимит по памяти) */
#define DPI_MAX_FLOWS       1048576

/*
 * Поддерживаемые протоколы.
 * Порядок важен — используется как индекс в массиве статистики by_proto[].
 */
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

/* 5-кортеж для идентификации сетевого потока.
 * IP-адреса — в сетевом порядке байтов (network byte order). */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ip_proto;
} dpi_5tuple_t;

/* Информация об одном сетевом потоке.
 * Привязывается к каноническому 5-кортежу (см. tuple_canonical в flow.c). */
typedef struct {
    dpi_5tuple_t  tuple;
    dpi_protocol_t proto;
    uint64_t       packets;
    uint64_t       bytes;
    time_t         first_seen;
    time_t         last_seen;
    int            matched_sig_id;   /* id сигнатуры или -1 */
} dpi_flow_t;

/* Узел цепочки в хэш-таблице (chaining для разрешения коллизий) */
typedef struct dpi_flow_node {
    dpi_flow_t             flow;
    struct dpi_flow_node  *next;
} dpi_flow_node_t;

/* Хэш-таблица потоков */
typedef struct {
    dpi_flow_node_t *buckets[DPI_FLOW_TABLE_SIZE];
    int              count;
} dpi_flow_table_t;

/* Одна сигнатура протокола */
typedef struct {
    int   id;
    char  pattern[DPI_MAX_SIG_LEN];
    int   pattern_len;
    dpi_protocol_t proto;
} dpi_signature_t;

/* База сигнатур — загружается из текстового файла */
typedef struct {
    int               count;
    int               capacity;
    dpi_signature_t  *sigs;
} dpi_sig_db_t;

/* Агрегированная статистика по захвату */
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

/* Выводит название протокола в текстовый буфер */
void         dpi_proto_name(dpi_protocol_t proto, char *buf, size_t len);
const char  *dpi_proto_str(dpi_protocol_t proto);

/* --- Таблица потоков --- */

void         dpi_flow_table_init(dpi_flow_table_t *ft);
void         dpi_flow_table_free(dpi_flow_table_t *ft);

/* Поиск потока по 5-кортежу. Если не найден — создаёт новый.
 * Возвращает указатель на поток или NULL при превышении лимита. */
dpi_flow_t  *dpi_flow_lookup_or_create(dpi_flow_table_t *ft, const dpi_5tuple_t *tuple);
void         dpi_flow_table_stats(const dpi_flow_table_t *ft, dpi_stats_t *stats);
void         dpi_flow_table_print(const dpi_flow_table_t *ft);

/* --- База сигнатур --- */

/* Загружает сигнатуры из файла формата "ПРОТОКОЛ: шаблон".
 * Возвращает 0 при успехе, -1 при ошибке. */
int          dpi_sig_db_load(dpi_sig_db_t *db, const char *path);
void         dpi_sig_db_free(dpi_sig_db_t *db);

/* --- Ахо-Корасик --- */

/* Узел trie-дерева для алгоритма Ахо-Корасик.
 * children[256] — переходы по байтам (полный алфавит).
 * fail — ссылка на суффиксный переход (failure link).
 * sig_id — id совпадающей сигнатуры или -1. */
typedef struct dpi_ac_node {
    struct dpi_ac_node *children[256];
    struct dpi_ac_node *fail;
    int                 sig_id;
} dpi_ac_node_t;

typedef struct {
    dpi_ac_node_t *root;
    int             node_count;
} dpi_ac_t;

/* Строит автомат Ахо-Корасик по базе сигнатур.
 * Двухфазный алгоритм:
 *   1. Построение trie-дерева по всем сигнатурам
 *   2. BFS для вычисления failure-ссылок */
int          dpi_ac_build(dpi_ac_t *ac, const dpi_sig_db_t *db);
void         dpi_ac_free(dpi_ac_t *ac);

/* Ищет совпадение любой сигнатуры в данных.
 * Возвращает id сигнатуры или -1 если не найдено.
 * Сложность: O(n), где n — длина данных. */
int          dpi_ac_search(const dpi_ac_t *ac, const uint8_t *data, size_t len);

/* --- Структуры заголовков пакетов --- */

typedef struct {
    uint8_t   dst_mac[6];
    uint8_t   src_mac[6];
    uint16_t  ethertype;
} dpi_eth_header_t;

typedef struct {
    uint8_t   version_ihl;   /* версия (4 бита) + длина заголовка (4 бита) */
    uint8_t   tos;
    uint16_t  total_length;
    uint16_t  id;
    uint16_t  flags_offset;  /* флаги (3 бита) + смещение фрагмента (13 бит) */
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
    uint16_t data_offset_flags;  /* data offset (4 бита) + reserved + flags */
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

/* Результат разбора сырого пакета.
 * Все указатели ссылаются на оригинальный буфер (zero-copy). */
typedef struct {
    const dpi_eth_header_t *eth;
    const dpi_ip_header_t  *ip;
    const dpi_tcp_header_t *tcp;
    const dpi_udp_header_t *udp;
    const uint8_t          *payload;     /* данные после заголовков L4 */
    size_t                  payload_len;
    dpi_5tuple_t            tuple;       /* извлечённый 5-кортеж */
    int                     parsed_ok;   /* 1 если пакет разобран полностью */
} dpi_parsed_packet_t;

/* Разбирает сырой Ethernet-кадр.
 * Поддерживает: Ethernet II, 802.1Q VLAN, IPv4, TCP, UDP, ICMP.
 * Не поддерживает: IPv6, фрагментацию, TCP reassembly.
 * Возвращает 0 при успехе, -1 при ошибке/неподдерживаемом формате. */
int     dpi_parse_packet(const uint8_t *raw, size_t raw_len, dpi_parsed_packet_t *out);

/* --- Статистика --- */

void    dpi_stats_init(dpi_stats_t *stats);
void    dpi_stats_print(const dpi_stats_t *stats, const dpi_flow_table_t *ft);

/* --- Классификация --- */

/* Классифицирует пакет и обновляет таблицу потоков и статистику.
 * Трёхстадийная стратегия:
 *   1. Если поток уже классифицирован — пропускаем
 *   2. Инспекция payload: сигнатуры → встроенные эвристики → Ахо-Корасик
 *   3. Фолбэк на номера портов */
int     dpi_classify(const dpi_ac_t *ac, const dpi_parsed_packet_t *pkt,
                     dpi_flow_table_t *ft, dpi_stats_t *stats);

/* --- Захват трафика --- */

/* Живой захват с сетевого интерфейса через libpcap.
 * max_packets > 0: захватить N пакетов и остановиться.
 * max_packets == 0: захват до Ctrl+C или timeout. */
int     dpi_capture_run(const char *iface, const char *bpf_filter,
                        dpi_ac_t *ac, dpi_flow_table_t *ft, dpi_stats_t *stats,
                        int max_packets, int timeout_sec);

/* Чтение пакетов из pcap-файла (офлайн-анализ) */
int     dpi_capture_file(const char *path, dpi_ac_t *ac, dpi_flow_table_t *ft,
                         dpi_stats_t *stats, int max_packets);

#endif
