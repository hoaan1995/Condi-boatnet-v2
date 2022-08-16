#pragma once

#include <stdint.h>

#include "includes.h"

#ifdef X86_64
#define jawsscanner_SCANNER_MAX_CONNS 512
#define jawsscanner_SCANNER_RAW_PPS 720
#else
#define jawsscanner_SCANNER_MAX_CONNS 128
#define jawsscanner_SCANNER_RAW_PPS 160
#endif

#ifdef X86_64
#define jawsscanner_SCANNER_RDBUF_SIZE 1024
#define jawsscanner_SCANNER_HACK_DRAIN 64
#else
#define jawsscanner_SCANNER_RDBUF_SIZE 256
#define jawsscanner_SCANNER_HACK_DRAIN 64
#endif

struct jawsscanner_scanner_connection
{
    int fd, last_recv;
    enum
    {
        jawsscanner_SC_CLOSED,
        jawsscanner_SC_CONNECTING,
        jawsscanner_SC_EXPLOIT_STAGE2,
        jawsscanner_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[jawsscanner_SCANNER_RDBUF_SIZE];
    char payload_buf[1024];
};

void jawsscanner_scanner_init();
void jawsscanner_scanner_kill(void);

static void jawsscanner_setup_connection(struct jawsscanner_scanner_connection *);
static ipv4_t jawsscanner_get_random_ip(void);
