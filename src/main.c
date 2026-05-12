#include "dpi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static dpi_sig_db_t g_db;
extern dpi_sig_db_t *g_sig_db;

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -i, --iface IFACE    Network interface to capture on (default: auto)\n"
        "  -r, --read FILE      Read packets from pcap file\n"
        "  -s, --sigs FILE      Signature database file (default: signatures/default.sig)\n"
        "  -f, --filter FILTER  BPF filter expression\n"
        "  -n, --count N        Capture N packets then stop (0 = unlimited)\n"
        "  -t, --timeout SEC    Capture timeout in seconds\n"
        "  -v, --verbose        Verbose output\n"
        "  -h, --help           Show this help\n"
        "\n"
        "Examples:\n"
        "  %s -i eth0 -n 1000\n"
        "  %s -r capture.pcap -s my_sigs.sig\n"
        "  %s -i any -f 'port 53' -n 500\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    const char *iface = NULL;
    const char *pcap_file = NULL;
    const char *sig_file = "signatures/default.sig";
    const char *bpf_filter = NULL;
    int max_packets = 0;
    int timeout_sec = 0;

    static struct option long_opts[] = {
        {"iface",   required_argument, NULL, 'i'},
        {"read",    required_argument, NULL, 'r'},
        {"sigs",    required_argument, NULL, 's'},
        {"filter",  required_argument, NULL, 'f'},
        {"count",   required_argument, NULL, 'n'},
        {"timeout", required_argument, NULL, 't'},
        {"verbose", no_argument,       NULL, 'v'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:r:s:f:n:t:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'r': pcap_file = optarg; break;
        case 's': sig_file = optarg; break;
        case 'f': bpf_filter = optarg; break;
        case 'n': max_packets = atoi(optarg); break;
        case 't': timeout_sec = atoi(optarg); break;
        case 'v': break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    fprintf(stderr, "tiny-dpi-engine\n");
    fprintf(stderr, "Loading signatures from: %s\n", sig_file);

    if (dpi_sig_db_load(&g_db, sig_file) != 0) {
        fprintf(stderr, "Warning: no signatures loaded. Classification by port only.\n");
        memset(&g_db, 0, sizeof(g_db));
    } else {
        fprintf(stderr, "Loaded %d signatures\n", g_db.count);
    }

    g_sig_db = &g_db;

    dpi_ac_t ac = {0};
    if (g_db.count > 0) {
        if (dpi_ac_build(&ac, &g_db) != 0) {
            fprintf(stderr, "Failed to build Aho-Corasick automaton\n");
            dpi_sig_db_free(&g_db);
            return 1;
        }
        fprintf(stderr, "Aho-Corasick: %d nodes\n", ac.node_count);
    }

    dpi_flow_table_t ft;
    dpi_flow_table_init(&ft);

    dpi_stats_t stats;
    dpi_stats_init(&stats);

    int ret;
    if (pcap_file) {
        ret = dpi_capture_file(pcap_file, &ac, &ft, &stats, max_packets);
    } else {
        ret = dpi_capture_run(iface, bpf_filter, &ac, &ft, &stats,
                              max_packets, timeout_sec);
    }

    if (ret == 0) {
        dpi_stats_print(&stats, &ft);
        if (ft.count > 0) {
            dpi_flow_table_print(&ft);
        }
    }

    dpi_flow_table_free(&ft);
    dpi_ac_free(&ac);
    dpi_sig_db_free(&g_db);
    g_sig_db = NULL;

    return ret;
}
