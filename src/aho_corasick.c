#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AC_POOL_SIZE 65536

typedef struct {
    dpi_ac_node_t *nodes;
    int            used;
    int            capacity;
} ac_pool_t;

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

    dpi_ac_node_t **queue = malloc((size_t)g_pool.used * sizeof(dpi_ac_node_t *));
    if (!queue) return -1;
    int head = 0, tail = 0;

    for (int c = 0; c < 256; c++) {
        if (ac->root->children[c]) {
            ac->root->children[c]->fail = ac->root;
            queue[tail++] = ac->root->children[c];
        } else {
            ac->root->children[c] = ac->root;
        }
    }

    while (head < tail) {
        dpi_ac_node_t *node = queue[head++];
        for (int c = 0; c < 256; c++) {
            if (node->children[c] && node->children[c] != ac->root) {
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
