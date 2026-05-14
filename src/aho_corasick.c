/*
 * Ахо-Корасик — алгоритм множественного поиска подстрок.
 *
 * Построение автомата:
 *   1. Все сигнатуры вставляются в trie-дерево
 *   2. BFS от корня вычисляет failure-ссылки (суффиксные переходы)
 *
 * Поиск: один проход по входным данным, O(n) по длине входа,
 * независимо от количества сигнатур.
 *
 * Реализация использует пул аллокаций — все узлы в одном массиве.
 * Это улучшает локальность кэша и упрощает освобождение памяти.
 */

#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AC_POOL_SIZE 65536

/* Пул узлов trie-дерева. Узлы выделяются последовательно из одного массива,
 * что обеспечивает хорошее использование кэша при обходе дерева. */
typedef struct {
    dpi_ac_node_t *nodes;
    int            used;
    int            capacity;
} ac_pool_t;

/* Выделяет один узел из пула. При исчерпании — удваивает размер.
 * sig_id инициализируется в -1 (нет совпадения). */
static dpi_ac_node_t *pool_alloc(ac_pool_t *pool) {
    if (pool->used >= pool->capacity) {
        int new_cap = pool->capacity * 2;
        dpi_ac_node_t *new_nodes = realloc(pool->nodes, (size_t)new_cap * sizeof(dpi_ac_node_t));
        if (!new_nodes) return NULL;
        pool->nodes = new_nodes;
        pool->capacity = new_cap;
    }
    dpi_ac_node_t *node = &pool->nodes[pool->used++];
    memset(node, 0, sizeof(*node));
    node->sig_id = -1;
    return node;
}

static ac_pool_t g_pool;

int dpi_ac_build(dpi_ac_t *ac, const dpi_sig_db_t *db) {
    g_pool.nodes = malloc(AC_POOL_SIZE * sizeof(dpi_ac_node_t));
    if (!g_pool.nodes) return -1;
    g_pool.used = 0;
    g_pool.capacity = AC_POOL_SIZE;

    ac->root = pool_alloc(&g_pool);
    if (!ac->root) return -1;
    ac->root->fail = ac->root;
    ac->root->sig_id = -1;

    /* Фаза 1: построение trie-дерева по всем сигнатурам.
     * Каждый байт сигнатуры — переход по соответствующему потомку.
     * Если потомка нет — создаётся новый узел.
     * В листе записывается sig_id. */
    for (int i = 0; i < db->count; i++) {
        dpi_ac_node_t *cur = ac->root;
        const uint8_t *pat = (const uint8_t *)db->sigs[i].pattern;
        int plen = db->sigs[i].pattern_len;

        for (int j = 0; j < plen; j++) {
            uint8_t ch = pat[j];
            if (!cur->children[ch]) {
                cur->children[ch] = pool_alloc(&g_pool);
                if (!cur->children[ch]) return -1;
            }
            cur = cur->children[ch];
        }
        cur->sig_id = db->sigs[i].id;
    }

    /* Фаза 2: вычисление failure-ссылок (BFS).
     *
     * Failure-ссылка узла — это самый длинный суффикс пути от корня
     * до этого узла, который является также путём в trie.
     *
     * Алгоритм:
     *   1. Дети корня: fail = root
     *   2. Для прочих узлов: идём по fail-ссылкам родителей,
     *      пока не найдём узел с подходящим переходом.
     *
     * Дополнительно: отсутствующие переходы корня замыкаются на сам root.
     * Это устраняет особый случай в функции поиска — cur всегда можно
     * продвигать через children[] без проверки на NULL. */
    dpi_ac_node_t **queue = malloc((size_t)g_pool.used * sizeof(dpi_ac_node_t *));
    if (!queue) return -1;
    int head = 0, tail = 0;

    /* Дети корня: fail → root, отсутствующие → root */
    for (int c = 0; c < 256; c++) {
        if (ac->root->children[c]) {
            ac->root->children[c]->fail = ac->root;
            queue[tail++] = ac->root->children[c];
        } else {
            ac->root->children[c] = ac->root;
        }
    }

    /* BFS по уровням trie */
    while (head < tail) {
        dpi_ac_node_t *node = queue[head++];
        for (int c = 0; c < 256; c++) {
            if (node->children[c] && node->children[c] != ac->root) {
                /* Ищём failure-ссылку: поднимаемся по fail родителя,
                 * пока не найдём узел с переходом по символу c */
                dpi_ac_node_t *f = node->fail;
                while (f != ac->root && !f->children[c]) {
                    f = f->fail;
                }
                if (f->children[c] && f->children[c] != node->children[c]) {
                    node->children[c]->fail = f->children[c];
                } else {
                    node->children[c]->fail = ac->root;
                }
                queue[tail++] = node->children[c];
            }
        }
    }

    free(queue);
    ac->node_count = g_pool.used;
    return 0;
}

void dpi_ac_free(dpi_ac_t *ac) {
    if (g_pool.nodes) {
        free(g_pool.nodes);
        g_pool.nodes = NULL;
    }
    ac->root = NULL;
    ac->node_count = 0;
}

/* Поиск совпадений в данных.
 *
 * Двигаемся по автомату: для каждого байта данных —
 *   1. Если текущий узел не имеет перехода по этому байту —
 *      идём по failure-ссылкам, пока не найдём.
 *   2. Продвигаемся в найденный узел.
 *   3. Если узел содержит sig_id >= 0 — сигнатура найдена.
 *
 * Возвращает id первой совпавшей сигнатуры или -1. */
int dpi_ac_search(const dpi_ac_t *ac, const uint8_t *data, size_t len) {
    if (!ac->root || !data || len == 0) return -1;

    dpi_ac_node_t *cur = ac->root;
    for (size_t i = 0; i < len; i++) {
        while (cur != ac->root && !cur->children[data[i]]) {
            cur = cur->fail;
        }
        if (cur->children[data[i]]) {
            cur = cur->children[data[i]];
        }
        if (cur->sig_id >= 0) {
            return cur->sig_id;
        }
    }
    return -1;
}
