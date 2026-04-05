/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_json.h>
#include <petlib/pet_list.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"
#include "timer.h"

extern int petnet_errno;

/*
 * Listen table: match packets using bind_addr/bind_port passed into tcp_listen()
 * (struct socket is opaque here — we must not read sock->local_port, etc.).
 */
struct tcp_listener {
    struct socket     *sock;
    struct ipv4_addr  *bind_addr;
    uint16_t           bind_port;
    struct list_head   node;
};

struct tcp_state {
    struct tcp_con_map *con_map;
    struct list_head    listen_list;
    pthread_mutex_t     listen_lock;
};

static void __tcp_con_reset_tx(struct tcp_connection *con);
static void __tcp_wake_sock_send(struct socket *sock);
static void tcp_rtx_handler(struct pet_timeout *to, void *arg);

static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet *pkt)
{
    struct tcp_raw_hdr *tcp_hdr =
        pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}

static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet *pkt, uint32_t option_len)
{
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet *pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr *ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) -
                           (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    }

    log_error("Unhandled layer 3 packet format\n");
    return NULL;
}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr *hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16(hdr_json, "src port", ntohs(hdr->src_port));
    pet_json_add_u16(hdr_json, "dst port", ntohs(hdr->dst_port));
    pet_json_add_u32(hdr_json, "seq num", ntohl(hdr->seq_num));
    pet_json_add_u32(hdr_json, "ack num", ntohl(hdr->ack_num));
    pet_json_add_u8(hdr_json, "header len", hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag", hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag", hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "PSH flag", hdr->flags.PSH);
    pet_json_add_bool(hdr_json, "RST flag", hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag", hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag", hdr->flags.FIN);
    pet_json_add_u16(hdr_json, "recv win", ntohs(hdr->recv_win));
    pet_json_add_u16(hdr_json, "checksum", ntohs(hdr->checksum));
    pet_json_add_u16(hdr_json, "urgent ptr", ntohs(hdr->urgent_ptr));

    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ)
        pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}

void
print_tcp_header(struct tcp_raw_hdr *tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;
    char          *json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);
}

static uint32_t
__tcp_new_isn(void)
{
    return (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)pthread_self();
}

static uint32_t
__tcp_mss(void)
{
    return petnet_state->device_mtu - sizeof(struct eth_raw_hdr) -
           (uint32_t)ipv4_expected_hdr_len() - sizeof(struct tcp_raw_hdr);
}

static uint16_t
__tcp_checksum(struct ipv4_addr *src_ip,
               struct ipv4_addr *dst_ip,
               struct packet    *pkt)
{
    struct ipv4_pseudo_hdr ph;
    uint16_t               sum = 0;

    memset(&ph, 0, sizeof(ph));
    ipv4_addr_to_octets(src_ip, ph.src_ip);
    ipv4_addr_to_octets(dst_ip, ph.dst_ip);
    ph.proto  = IPV4_PROTO_TCP;
    ph.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

    sum = calculate_checksum_begin(&ph, sizeof(ph) / 2);
    sum = calculate_checksum_continue(sum, pkt->layer_4_hdr,
                                      pkt->layer_4_hdr_len / 2);
    sum = calculate_checksum_continue(sum, pkt->payload, pkt->payload_len / 2);

    if ((pkt->payload_len % 2) != 0) {
        uint16_t tmp =
            *(uint8_t *)(pkt->payload + pkt->payload_len - 1);
        sum = calculate_checksum_finalize(sum, &tmp, 1);
    } else {
        sum = calculate_checksum_finalize(sum, NULL, 0);
    }

    return sum;
}

static int
__tcp_verify_checksum(struct ipv4_raw_hdr *ipv4,
                      struct tcp_raw_hdr  *tcp,
                      void                *payload,
                      size_t               payload_len)
{
    struct packet       fake;
    uint16_t            got  = ntohs(tcp->checksum);
    uint16_t            calc = 0;
    struct ipv4_addr *src  = ipv4_addr_from_octets(ipv4->src_ip);
    struct ipv4_addr *dst  = ipv4_addr_from_octets(ipv4->dst_ip);

    memset(&fake, 0, sizeof(fake));
    fake.layer_4_hdr     = tcp;
    fake.layer_4_hdr_len = tcp->header_len * 4;
    fake.payload         = payload;
    fake.payload_len     = payload_len;

    tcp->checksum = 0;
    calc          = __tcp_checksum(src, dst, &fake);
    tcp->checksum = htons(got);

    free_ipv4_addr(src);
    free_ipv4_addr(dst);

    return (calc == got) ? 0 : -1;
}

static int
__listener_add(struct tcp_state      *ts,
                 struct socket         *sock,
                 struct ipv4_addr      *local_addr,
                 uint16_t               local_port)
{
    struct tcp_listener *L   = NULL;
    struct list_head    *pos = NULL;

    pthread_mutex_lock(&ts->listen_lock);
    for (pos = ts->listen_list.next; pos != &ts->listen_list; pos = pos->next) {
        L = list_entry(pos, struct tcp_listener, node);
        if (L->bind_port == local_port &&
            ipv4_addr_compare(L->bind_addr, local_addr) == 0) {
            pthread_mutex_unlock(&ts->listen_lock);
            return -1;
        }
    }

    L            = pet_malloc(sizeof(*L));
    L->sock      = pet_get_socket(sock);
    L->bind_addr = ipv4_addr_clone(local_addr);
    if (L->bind_addr == NULL) {
        pet_put_socket(L->sock);
        pet_free(L);
        pthread_mutex_unlock(&ts->listen_lock);
        return -1;
    }
    L->bind_port = local_port;
    list_add_tail(&L->node, &ts->listen_list);
    pthread_mutex_unlock(&ts->listen_lock);
    return 0;
}

/* Returns 1 if /sock/ was a listening socket and was removed. */
static int
__listener_unbind(struct tcp_state *ts, struct socket *sock)
{
    struct list_head *pos = NULL;
    struct list_head *n   = NULL;
    int               got = 0;

    pthread_mutex_lock(&ts->listen_lock);
    for (pos = ts->listen_list.next, n = pos->next; pos != &ts->listen_list;
         pos = n, n = pos->next) {
        struct tcp_listener *L = list_entry(pos, struct tcp_listener, node);

        if (L->sock == sock) {
            list_del(&L->node);
            pet_put_socket(L->sock);
            free_ipv4_addr(L->bind_addr);
            pet_free(L);
            got = 1;
            break;
        }
    }
    pthread_mutex_unlock(&ts->listen_lock);
    return got;
}

static struct socket *
__listener_lookup(struct tcp_state *ts,
                  struct ipv4_addr *dst_ip,
                  uint16_t          dst_port)
{
    struct tcp_listener *L     = NULL;
    struct socket       *s     = NULL;
    struct list_head    *pos   = NULL;

    pthread_mutex_lock(&ts->listen_lock);
    for (pos = ts->listen_list.next; pos != &ts->listen_list; pos = pos->next) {
        L = list_entry(pos, struct tcp_listener, node);
        if (L->bind_port == dst_port &&
            ipv4_addr_compare(L->bind_addr, dst_ip) == 0) {
            s = pet_get_socket(L->sock);
            break;
        }
    }
    pthread_mutex_unlock(&ts->listen_lock);
    return s;
}

static void
__tcp_con_reset_tx(struct tcp_connection *con)
{
    if (con->rtx_timer) {
        pet_cancel_timeout(con->rtx_timer);
        con->rtx_timer = NULL;
    }
    con->waiting_ack = 0;
    if (con->rtx_buf) {
        pet_free(con->rtx_buf);
        con->rtx_buf     = NULL;
        con->rtx_buf_len = 0;
    }
    con->rtx_is_syn    = 0;
    con->rtx_is_synack = 0;
    con->rtx_is_fin    = 0;
}

static void
__tcp_wake_sock_send(struct socket *sock)
{
    char z;

    (void)pet_socket_sending_data(sock, &z, 0);
}

static void
__tcp_arm_rtx(struct tcp_connection *con)
{
    if (con->rtx_timer)
        pet_cancel_timeout(con->rtx_timer);
    con->rtx_timer = pet_add_timeout(1, tcp_rtx_handler, con);
}

static void
tcp_rtx_handler(struct pet_timeout *to, void *arg)
{
    struct tcp_connection *con = arg;

    (void)to;

    lock_tcp_con(con);
    con->rtx_timer = NULL;

    if (!con->waiting_ack) {
        unlock_tcp_con(con);
        return;
    }

    if (con->rtx_is_syn || con->rtx_is_synack || con->rtx_is_fin ||
        con->rtx_buf_len > 0) {
        struct packet    *pkt   = create_empty_packet();
        struct tcp_raw_hdr *th  = NULL;
        struct ipv4_addr *rmt   = con->ipv4_tuple.remote_ip;
        int               ret   = 0;
        uint32_t          seq   = htonl(con->unack_seq);
        uint32_t          ack   = htonl(con->rcv_nxt);
        int               ackok = 1;

        if (pkt != NULL) {
            th             = __make_tcp_hdr(pkt, 0);
            th->src_port   = htons(con->ipv4_tuple.local_port);
            th->dst_port   = htons(con->ipv4_tuple.remote_port);
            th->seq_num    = seq;
            th->ack_num    = ack;
            th->header_len = sizeof(struct tcp_raw_hdr) / 4;
            th->rsvd       = 0;
            memset(&th->flags, 0, sizeof(th->flags));
            th->recv_win   = htons(4096);
            th->checksum   = 0;
            th->urgent_ptr  = 0;

            if (con->rtx_is_syn) {
                th->flags.SYN = 1;
                ackok         = 0;
            } else if (con->rtx_is_synack) {
                th->flags.SYN = 1;
                th->flags.ACK = 1;
            } else {
                th->flags.ACK = 1;
                if (con->rtx_is_fin)
                    th->flags.FIN = 1;
            }

            if (!ackok)
                th->ack_num = 0;

            if (con->rtx_buf_len > 0) {
                pkt->payload_len = con->rtx_buf_len;
                pkt->payload     = pet_malloc(con->rtx_buf_len);
                memcpy(pkt->payload, con->rtx_buf, con->rtx_buf_len);
            }

            th->checksum = __tcp_checksum(con->ipv4_tuple.local_ip,
                                          con->ipv4_tuple.remote_ip, pkt);

            ret = ipv4_pkt_tx(pkt, rmt);
            if (ret == -1)
                free_packet(pkt);
        }
    }

    if (con->waiting_ack)
        __tcp_arm_rtx(con);

    unlock_tcp_con(con);
}

static int
__tcp_send_segment(struct tcp_connection *con,
                   int syn, int ack, int fin, int rst,
                   const void *payload, size_t payload_len,
                   uint32_t seq_val, int arm_timer)
{
    struct packet    *pkt   = create_empty_packet();
    struct tcp_raw_hdr *th  = NULL;
    struct ipv4_addr *rmt   = con->ipv4_tuple.remote_ip;
    int               ret   = 0;
    uint32_t          seq   = htonl(seq_val);
    uint32_t          ackv  = htonl(con->rcv_nxt);

    if (pkt == NULL)
        return -1;

    th             = __make_tcp_hdr(pkt, 0);
    th->src_port   = htons(con->ipv4_tuple.local_port);
    th->dst_port   = htons(con->ipv4_tuple.remote_port);
    th->seq_num    = seq;
    th->ack_num    = ack ? ackv : 0;
    th->header_len = sizeof(struct tcp_raw_hdr) / 4;
    th->rsvd       = 0;
    memset(&th->flags, 0, sizeof(th->flags));
    th->flags.SYN  = syn ? 1 : 0;
    th->flags.ACK  = ack ? 1 : 0;
    th->flags.FIN  = fin ? 1 : 0;
    th->flags.RST  = rst ? 1 : 0;
    th->recv_win   = htons(4096);
    th->checksum   = 0;
    th->urgent_ptr  = 0;

    if (payload_len > 0) {
        pkt->payload_len = payload_len;
        pkt->payload     = pet_malloc(payload_len);
        memcpy(pkt->payload, payload, payload_len);
    }

    th->checksum = __tcp_checksum(con->ipv4_tuple.local_ip,
                                  con->ipv4_tuple.remote_ip, pkt);

    ret = ipv4_pkt_tx(pkt, rmt);
    if (ret == -1) {
        free_packet(pkt);
        return -1;
    }

    if (!arm_timer)
        return 0;

    __tcp_con_reset_tx(con);

    con->waiting_ack = 1;
    con->unack_seq   = seq_val;
    con->unack_len   = payload_len + (syn ? 1 : 0) + (fin ? 1 : 0);
    con->rtx_is_syn    = syn && !ack;
    con->rtx_is_synack = syn && ack;
    con->rtx_is_fin    = fin;

    if (payload_len > 0) {
        con->rtx_buf     = pet_malloc(payload_len);
        con->rtx_buf_len = payload_len;
        memcpy(con->rtx_buf, payload, payload_len);
    }

    __tcp_arm_rtx(con);
    return 0;
}

static int
__tcp_ack_accepted(struct tcp_connection *con, uint32_t ack_peer)
{
    if (!con->waiting_ack)
        return 0;
    if (ack_peer < con->unack_seq + con->unack_len)
        return 0;
    __tcp_con_reset_tx(con);
    if (con->sock)
        __tcp_wake_sock_send(con->sock);
    return 1;
}

static void
__tcp_init_con(struct tcp_connection *con)
{
    con->iss = con->peer_iss = 0;
    con->snd_nxt = con->rcv_nxt = 0;
    __tcp_con_reset_tx(con);
    con->listen_parent = NULL;
}

int
tcp_listen(struct socket *sock, struct ipv4_addr *local_addr, uint16_t local_port)
{
    struct tcp_state *ts = petnet_state->tcp_state;

    return __listener_add(ts, sock, local_addr, local_port);
}

int
tcp_connect_ipv4(struct socket    *sock,
                 struct ipv4_addr *local_addr,
                 uint16_t          local_port,
                 struct ipv4_addr *remote_addr,
                 uint16_t          remote_port)
{
    struct tcp_state      *ts       = petnet_state->tcp_state;
    struct tcp_connection *con      = NULL;

    (void)local_addr;

    con = create_ipv4_tcp_con(ts->con_map, petnet_state->addr_v4, remote_addr,
                              local_port, remote_port);
    if (con == NULL)
        return -1;

    __tcp_init_con(con);
    con->iss     = __tcp_new_isn();
    con->snd_nxt = con->iss + 1;
    con->rcv_nxt = 0;
    con->con_state = SYN_SENT;

    if (add_sock_to_tcp_con(ts->con_map, con, sock) == -1) {
        remove_tcp_con(ts->con_map, con);
        put_and_unlock_tcp_con(con);
        return -1;
    }

    if (__tcp_send_segment(con, 1, 0, 0, 0, NULL, 0, con->iss, 1) == -1) {
        remove_tcp_con(ts->con_map, con);
        put_and_unlock_tcp_con(con);
        pet_socket_error(sock, ECONNREFUSED);
        return -1;
    }

    put_and_unlock_tcp_con(con);
    return 0;
}

int
tcp_send(struct socket *sock)
{
    struct tcp_state      *ts  = petnet_state->tcp_state;
    struct tcp_connection *con = NULL;
    uint32_t               cap = 0;
    uint32_t               mss = __tcp_mss();
    size_t                 chunk;
    char                  *tmp = NULL;
    int                    ret = 0;

    con = get_and_lock_tcp_con_from_sock(ts->con_map, sock);
    if (con == NULL) {
        log_error("TCP connection is not established\n");
        return -1;
    }

    if (con->con_state != ESTABLISHED) {
        log_error("TCP connection is not established\n");
        ret = -1;
        goto out;
    }

    if (con->waiting_ack)
        goto out;

    cap = pet_socket_send_capacity(sock);
    if (cap == 0)
        goto out;

    chunk = cap < mss ? cap : mss;
    tmp   = pet_malloc(chunk);
    if (tmp == NULL) {
        ret = -1;
        goto out;
    }

    if (pet_socket_sending_data(sock, tmp, chunk) == -1) {
        pet_free(tmp);
        ret = -1;
        goto out;
    }

    if (__tcp_send_segment(con, 0, 1, 0, 0, tmp, chunk, con->snd_nxt, 1) ==
        -1) {
        pet_free(tmp);
        ret = -1;
        goto out;
    }

    con->snd_nxt += (uint32_t)chunk;
    pet_free(tmp);

out:
    put_and_unlock_tcp_con(con);
    return ret;
}

int
tcp_close(struct socket *sock)
{
    struct tcp_state      *ts  = petnet_state->tcp_state;
    struct tcp_connection *con = NULL;

    if (__listener_unbind(ts, sock))
        return 0;

    con = get_and_lock_tcp_con_from_sock(ts->con_map, sock);
    if (con == NULL)
        return 0;

    switch (con->con_state) {
    case SYN_SENT:
    case SYN_RCVD:
        __tcp_con_reset_tx(con);
        remove_tcp_con(ts->con_map, con);
        put_and_unlock_tcp_con(con);
        return 0;
    case ESTABLISHED:
    case CLOSE_WAIT:
        if (__tcp_send_segment(con, 0, 1, 1, 0, NULL, 0, con->snd_nxt, 1) ==
            0)
            con->snd_nxt += 1;
        __tcp_con_reset_tx(con);
        remove_tcp_con(ts->con_map, con);
        put_and_unlock_tcp_con(con);
        return 0;
    default:
        __tcp_con_reset_tx(con);
        remove_tcp_con(ts->con_map, con);
        put_and_unlock_tcp_con(con);
        return 0;
    }
}

static int
__tcp_rx_on_con(struct tcp_connection *con,
                struct ipv4_raw_hdr   *ipv4,
                struct tcp_raw_hdr    *th,
                void                  *payload,
                size_t                 payload_len)
{
    struct tcp_state *ts       = petnet_state->tcp_state;
    uint32_t          seq      = ntohl(th->seq_num);
    uint32_t          ack      = ntohl(th->ack_num);
    int               has_fin  = th->flags.FIN;
    int               has_rst  = th->flags.RST;
    int               has_syn  = th->flags.SYN;
    int               has_ack  = th->flags.ACK;
    struct socket    *sk       = NULL;

    if (has_rst) {
        sk = con->sock ? pet_get_socket(con->sock) : NULL;
        __tcp_con_reset_tx(con);
        remove_tcp_con(ts->con_map, con);
        put_and_unlock_tcp_con(con);
        if (sk) {
            pet_socket_error(sk, ECONNRESET);
            pet_put_socket(sk);
        }
        return 0;
    }

    if (con->con_state == SYN_SENT && has_syn && has_ack) {
        if (ack != con->iss + 1) {
            unlock_tcp_con(con);
            put_tcp_con(con);
            return 0;
        }
        con->peer_iss = seq;
        con->rcv_nxt  = seq + 1;
        __tcp_ack_accepted(con, ack);
        if (__tcp_send_segment(con, 0, 1, 0, 0, NULL, 0, con->snd_nxt, 0) ==
            -1) {
            sk = pet_get_socket(con->sock);
            unlock_tcp_con(con);
            if (sk) {
                pet_socket_error(sk, ECONNREFUSED);
                pet_put_socket(sk);
            }
            put_tcp_con(con);
            return 0;
        }
        con->con_state = ESTABLISHED;
        sk             = pet_get_socket(con->sock);
        unlock_tcp_con(con);
        pet_socket_connected(sk);
        pet_put_socket(sk);
        put_tcp_con(con);
        return 0;
    }

    if (con->con_state == SYN_RCVD && has_ack && !has_syn) {
        struct ipv4_addr *rip;
        uint16_t          rport;
        struct socket    *ns;

        if (ack != con->iss + 1) {
            unlock_tcp_con(con);
            put_tcp_con(con);
            return 0;
        }
        __tcp_ack_accepted(con, ack);
        con->con_state = ESTABLISHED;

        sk   = con->listen_parent;
        con->listen_parent = NULL;
        rip  = ipv4_addr_clone(con->ipv4_tuple.remote_ip);
        rport = con->ipv4_tuple.remote_port;

        unlock_tcp_con(con);

        ns = pet_socket_accepted(sk, rip, rport);
        free_ipv4_addr(rip);
        pet_put_socket(sk);

        lock_tcp_con(con);
        if (ns == NULL) {
            remove_tcp_con(ts->con_map, con);
            put_and_unlock_tcp_con(con);
            return 0;
        }
        if (add_sock_to_tcp_con(ts->con_map, con, ns) == 0)
            pet_put_socket(ns);
        else
            pet_put_socket(ns);
        unlock_tcp_con(con);

        put_tcp_con(con);
        return 0;
    }

    if (has_ack)
        __tcp_ack_accepted(con, ack);

    if (payload_len > 0 && con->con_state == ESTABLISHED) {
        if (seq != con->rcv_nxt) {
            unlock_tcp_con(con);
            put_tcp_con(con);
            return 0;
        }
        sk = pet_get_socket(con->sock);
        unlock_tcp_con(con);
        pet_socket_received_data(sk, payload, payload_len);
        pet_put_socket(sk);
        lock_tcp_con(con);
        con->rcv_nxt += (uint32_t)payload_len;
        __tcp_send_segment(con, 0, 1, 0, 0, NULL, 0, con->snd_nxt, 0);
    }

    if (has_fin && con->con_state == ESTABLISHED) {
        if (seq + payload_len != con->rcv_nxt) {
            unlock_tcp_con(con);
            put_tcp_con(con);
            return 0;
        }
        con->rcv_nxt += 1;
        sk = pet_get_socket(con->sock);
        unlock_tcp_con(con);
        pet_socket_closed(sk);
        pet_put_socket(sk);
        lock_tcp_con(con);
        con->con_state = CLOSE_WAIT;
        __tcp_send_segment(con, 0, 1, 0, 0, NULL, 0, con->snd_nxt, 0);
    }

    unlock_tcp_con(con);
    put_tcp_con(con);
    return 0;
}

static int
__tcp_rx_listen_syn(struct tcp_state      *ts,
                    struct ipv4_addr      *src_ip,
                    struct ipv4_addr      *dst_ip,
                    uint16_t               src_port,
                    uint16_t               dst_port,
                    struct tcp_raw_hdr    *th,
                    struct ipv4_raw_hdr   *ipv4)
{
    (void)ipv4;
    struct socket         *ls   = NULL;
    struct tcp_connection *con  = NULL;
    uint32_t               cisn = ntohl(th->seq_num);

    ls = __listener_lookup(ts, dst_ip, dst_port);
    if (ls == NULL)
        return 0;

    con = create_ipv4_tcp_con(ts->con_map, dst_ip, src_ip, dst_port, src_port);
    if (con == NULL) {
        pet_put_socket(ls);
        return -1;
    }

    __tcp_init_con(con);
    con->peer_iss  = cisn;
    con->rcv_nxt   = cisn + 1;
    con->iss       = __tcp_new_isn();
    con->snd_nxt   = con->iss + 1;
    con->con_state = SYN_RCVD;
    con->listen_parent = ls;

    if (__tcp_send_segment(con, 1, 1, 0, 0, NULL, 0, con->iss, 1) == -1) {
        remove_tcp_con(ts->con_map, con);
        put_and_unlock_tcp_con(con);
        return -1;
    }

    put_and_unlock_tcp_con(con);
    return 0;
}

int
tcp_pkt_rx(struct packet *pkt)
{
    struct tcp_state    *ts      = petnet_state->tcp_state;
    struct ipv4_raw_hdr *ipv4    = NULL;
    struct tcp_raw_hdr  *th      = NULL;
    void                *payload = NULL;
    size_t               paylen  = 0;
    struct ipv4_addr    *src_ip  = NULL;
    struct ipv4_addr    *dst_ip  = NULL;
    struct tcp_connection *con   = NULL;

    if (pkt->layer_3_type != IPV4_PKT)
        return -1;

    ipv4 = pkt->layer_3_hdr;
    th   = __get_tcp_hdr(pkt);
    if (th->header_len < 5)
        return 0;

    payload = __get_payload(pkt);
    paylen  = pkt->payload_len;

    if (__tcp_verify_checksum(ipv4, th, payload, paylen) != 0)
        return 0;

    src_ip = ipv4_addr_from_octets(ipv4->src_ip);
    dst_ip = ipv4_addr_from_octets(ipv4->dst_ip);

    if (petnet_state->debug_enable) {
        pet_printf("Received TCP segment\n");
        print_tcp_header(th);
    }

    con = get_and_lock_tcp_con_from_ipv4(ts->con_map, dst_ip, src_ip,
                                         ntohs(th->dst_port),
                                         ntohs(th->src_port));

    if (con) {
        __tcp_rx_on_con(con, ipv4, th, payload, paylen);
        free_ipv4_addr(src_ip);
        free_ipv4_addr(dst_ip);
        return 0;
    }

    if (th->flags.SYN && !th->flags.ACK) {
        __tcp_rx_listen_syn(ts, src_ip, dst_ip, ntohs(th->src_port),
                            ntohs(th->dst_port), th, ipv4);
        free_ipv4_addr(src_ip);
        free_ipv4_addr(dst_ip);
        return 0;
    }

    free_ipv4_addr(src_ip);
    free_ipv4_addr(dst_ip);
    return 0;
}

int
tcp_init(struct petnet *pstate)
{
    struct tcp_state *state = pet_malloc(sizeof(*state));

    state->con_map = create_tcp_con_map();
    INIT_LIST_HEAD(&state->listen_list);
    pthread_mutex_init(&state->listen_lock, NULL);

    pstate->tcp_state = state;

    return 0;
}
