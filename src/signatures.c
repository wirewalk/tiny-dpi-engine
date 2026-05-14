/*
 * Загрузка базы сигнатур из текстового файла.
 *
 * Формат файла:
 *   # строка комментария
 *   ПРОТОКОЛ: шаблон_поиска
 *
 * Пример:
 *   HTTP: GET
 *   SSH: SSH-2.0
 *   TLS: \x16\x03\x01
 *
 * Шаблон — последовательность байтов (текст или \xHH эскейпы).
 * Одна сигнатура на строку. Протокол должен быть из списка в dpi_protocol_t.
 */

#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Увеличивает массив сигнатур в 2 раза при заполнении */
static int sig_db_grow(dpi_sig_db_t *db) {
    int new_cap = db->capacity == 0 ? 32 : db->capacity * 2;
    dpi_signature_t *new_sigs = realloc(db->sigs, (size_t)new_cap * sizeof(dpi_signature_t));
    if (!new_sigs) return -1;
    db->sigs = new_sigs;
    db->capacity = new_cap;
    return 0;
}

int dpi_sig_db_load(dpi_sig_db_t *db, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("sig_db_load: fopen");
        return -1;
    }

    char line[1024];
    int line_no = 0;
    db->count = 0;
    db->capacity = 0;
    db->sigs = NULL;

    while (fgets(line, sizeof(line), f)) {
        line_no++;

        /* Пропускаем пустые строки и комментарии */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        /* Убираем завершающий \n / \r */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        nl = strchr(line, '\r');
        if (nl) *nl = '\0';

        /* Разделяем строку по первому двоеточию: "ПРОТОКОЛ: шаблон" */
        char *colon = strchr(line, ':');
        if (!colon) continue;

        *colon = '\0';
        char *proto_str = line;
        char *pattern = colon + 1;

        while (*pattern == ' ') pattern++;

        if (*pattern == '\0') continue;

        /* Маппинг имени протокола на enum */
        dpi_protocol_t proto = DPI_PROTO_UNKNOWN;
        if (strcmp(proto_str, "HTTP") == 0)     proto = DPI_PROTO_HTTP;
        else if (strcmp(proto_str, "HTTPS") == 0) proto = DPI_PROTO_HTTPS;
        else if (strcmp(proto_str, "DNS") == 0)   proto = DPI_PROTO_DNS;
        else if (strcmp(proto_str, "SSH") == 0)   proto = DPI_PROTO_SSH;
        else if (strcmp(proto_str, "FTP") == 0)   proto = DPI_PROTO_FTP;
        else if (strcmp(proto_str, "SMTP") == 0)  proto = DPI_PROTO_SMTP;
        else if (strcmp(proto_str, "RTP") == 0)   proto = DPI_PROTO_RTP;
        else if (strcmp(proto_str, "SIP") == 0)   proto = DPI_PROTO_SIP;
        else if (strcmp(proto_str, "RTCP") == 0)  proto = DPI_PROTO_RTCP;
        else if (strcmp(proto_str, "QUIC") == 0)  proto = DPI_PROTO_QUIC;
        else if (strcmp(proto_str, "DHCP") == 0)  proto = DPI_PROTO_DHCP;
        else if (strcmp(proto_str, "TLS") == 0)   proto = DPI_PROTO_TLS;

        if (proto == DPI_PROTO_UNKNOWN) continue;

        if (db->count >= db->capacity) {
            if (sig_db_grow(db) != 0) {
                fclose(f);
                return -1;
            }
        }

        dpi_signature_t *sig = &db->sigs[db->count];
        sig->id = db->count;
        sig->proto = proto;

        size_t plen = strlen(pattern);
        if (plen >= DPI_MAX_SIG_LEN) plen = DPI_MAX_SIG_LEN - 1;
        memcpy(sig->pattern, pattern, plen);
        sig->pattern[plen] = '\0';
        sig->pattern_len = (int)plen;

        db->count++;
    }

    fclose(f);
    return db->count > 0 ? 0 : -1;
}

void dpi_sig_db_free(dpi_sig_db_t *db) {
    free(db->sigs);
    db->sigs = NULL;
    db->count = 0;
    db->capacity = 0;
}
