/*
 * @f ccn-lite-riot.c
 * @b RIOT adaption layer
 *
 * Copyright (C) 2011-14, Christian Tschudin, University of Basel
 * Copyright (C) 2015, 2016, Oliver Hahm, INRIA
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File history:
 * 2015-10-26 created (based on ccn-lite-minimalrelay.c)
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* RIOT specific includes */
#include "kernel_types.h"
#include "random.h"
#include "timex.h"
#include "xtimer.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/netapi.h"
#include "net/packet.h"
#include "ccn-lite-riot.h"

#include "ccnl-os-time.c"

/**
 * @brief Some macro definitions
 * @{
 */

#define free_2ptr_list(a,b)     ccnl_free(a), ccnl_free(b)
#define free_3ptr_list(a,b,c)   ccnl_free(a), ccnl_free(b), ccnl_free(c)
#define free_4ptr_list(a,b,c,d) ccnl_free(a), ccnl_free(b), ccnl_free(c), ccnl_free(d);
#define free_5ptr_list(a,b,c,d,e) ccnl_free(a), ccnl_free(b), ccnl_free(c), ccnl_free(d), ccnl_free(e);

/**
 * Frees all memory directly and indirectly allocated for prefix information
 */
#define free_prefix(p)  do{ if(p) \
                free_5ptr_list(p->bytes,p->comp,p->complen,p->chunknum,p); } while(0)

/**
 * Frees memory for a given content and the associated packet data
 */
#define free_content(c) do{ /* free_prefix(c->name); */ free_packet(c->pkt); \
                        ccnl_free(c); } while(0)

/**
 * @}
 */

/**
 * @brief May be defined for ad-hoc content creation
 */
int local_producer(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                   struct ccnl_pkt_s *pkt);

/**
 * @brief May be defined for a particular caching strategy
 */
int cache_strategy_remove(struct ccnl_relay_s *relay, struct ccnl_content_s *c);

/**
 * @brief RIOT specific local variables
 * @{
 */

/**
 * @brief message queue for eventloop
 */
static msg_t _msg_queue[CCNL_QUEUE_SIZE];

/**
 * @brief stack for the CCN-Lite eventloop
 */
static char _ccnl_stack[CCNL_STACK_SIZE];

/**
 * PID of the eventloop thread
 */
static kernel_pid_t _ccnl_event_loop_pid = KERNEL_PID_UNDEF;

/**
 * Timer to process ageing
 */
static xtimer_t _ageing_timer = { .target = 0, .long_target = 0 };

/**
 * local producer function defined by the application
 */
static ccnl_producer_func _prod_func = NULL;

/**
 * caching strategy removal function
 */
static ccnl_cache_strategy_func _cs_remove_func = NULL;

/**
 * currently configured suite
 */
static int _ccnl_suite = CCNL_SUITE_NDNTLV;

/**
 * @}
 */

#include "ccnl-defs.h"
#include "ccnl-core.h"

/**
 * @brief function prototypes required by ccnl-core.c
 * @{
 */
void free_packet(struct ccnl_pkt_s *pkt);

struct ccnl_interest_s* ccnl_interest_remove(struct ccnl_relay_s *ccnl,
                     struct ccnl_interest_s *i);
int ccnl_pkt2suite(unsigned char *data, int len, int *skip);

char* ccnl_prefix_to_path_detailed(struct ccnl_prefix_s *pr,
                    int ccntlv_skip, int escape_components, int call_slash);
#define ccnl_prefix_to_path(P) ccnl_prefix_to_path_detailed(P, 1, 0, 0)

char* ccnl_addr2ascii(sockunion *su);
void ccnl_core_addToCleanup(struct ccnl_buf_s *buf);
const char* ccnl_suite2str(int suite);
bool ccnl_isSuite(int suite);

/**
 * @}
 */

/**
 * @brief Central relay information
 */
struct ccnl_relay_s ccnl_relay;

/**
 * @brief Local loopback face
 */
static struct ccnl_face_s *loopback_face;

/**
 * @brief Debugging level
 */
extern int debug_level;

/**
 * @brief (Link layer) Send function
 *
 * @par[in] ccnl    Relay to use
 * @par[in] ifc     Interface to send over
 * @par[in] dest    Destination's address information
 * @par[in] buf     Data to send
 */
void
ccnl_ll_TX(struct ccnl_relay_s *ccnl, struct ccnl_if_s *ifc,
           sockunion *dest, struct ccnl_buf_s *buf);

/**
 * @brief Callback for packet reception which should be passed to the application
 *
 * @par[in] ccnl    The relay the packet was received on
 * @par[in] c       Content of the received packet
 *
 * @returns 0 on success
 * @return -1 on error
 */
int ccnl_app_RX(struct ccnl_relay_s *ccnl, struct ccnl_content_s *c);

#include "ccnl-core.c"

/**
 * @brief netreg entry for CCN-Lite packets
 */
static gnrc_netreg_entry_t _ccnl_ne;

/**
 * @brief Some function pointers
 * @{
 */
typedef int (*ccnl_mkInterestFunc)(struct ccnl_prefix_s*, int*, unsigned char*, int);
typedef int (*ccnl_isContentFunc)(unsigned char*, int);

extern ccnl_mkInterestFunc ccnl_suite2mkInterestFunc(int suite);
extern ccnl_isContentFunc ccnl_suite2isContentFunc(int suite);

/**
 * @}
 */

#ifdef USE_SUITE_COMPAS
#include "compas/routing/nam.h"
#include "compas/routing/pam.h"
#endif

// ----------------------------------------------------------------------
struct ccnl_buf_s*
ccnl_buf_new(void *data, int len)
{
    struct ccnl_buf_s *b = ccnl_malloc(sizeof(*b) + len);

    if (!b)
        return NULL;
    b->next = NULL;
    b->datalen = len;
    if (data)
        memcpy(b->data, data, len);
    return b;
}

/* add a netif to CCN-lite's interfaces, set the nettype, and register a receiver */
int
ccnl_open_netif(kernel_pid_t if_pid, gnrc_nettype_t netreg_type)
{
    assert(pid_is_valid(if_pid));
    if (!gnrc_netif_exist(if_pid)) {
        return -1;
    }
    if (ccnl_relay.ifcount >= CCNL_MAX_INTERFACES) {
        DEBUGMSG(WARNING, "cannot open more than %u interfaces for CCN-Lite\n",
                 (unsigned) CCNL_MAX_INTERFACES);
        return -1;
    }

    /* get current interface from CCN-Lite's relay */
    struct ccnl_if_s *i;
    i = &ccnl_relay.ifs[ccnl_relay.ifcount];
    i->mtu = NDN_DEFAULT_MTU;
    i->fwdalli = 1;
    i->if_pid = if_pid;
    i->addr.sa.sa_family = AF_PACKET;

    int res;
    res = gnrc_netapi_get(if_pid, NETOPT_MAX_PACKET_SIZE, 0, &(i->mtu), sizeof(i->mtu));
    if (res < 0) {
        DEBUGMSG(ERROR, "error: unable to determine MTU for if=<%u>\n", (unsigned) i->if_pid);
        return -ECANCELED;
    }
    DEBUGMSG(DEBUG, "interface's MTU is set to %i\n", i->mtu);

    res = gnrc_netapi_get(if_pid, NETOPT_ADDR_LEN, 0, &(i->addr_len), sizeof(i->addr_len));
    if (res < 0) {
        DEBUGMSG(ERROR, "error: unable to determine address length for if=<%u>\n", (unsigned) if_pid);
        return -ECANCELED;
    }
    DEBUGMSG(DEBUG, "interface's address length is %u\n", (unsigned) i->addr_len);

    res = gnrc_netapi_get(if_pid, NETOPT_ADDRESS, 0, i->hwaddr, i->addr_len);
    if (res < 0) {
        DEBUGMSG(ERROR, "error: unable to get address for if=<%u>\n", (unsigned) if_pid);
        return -ECANCELED;
    }
    DEBUGMSG(DEBUG, "interface's address is %s\n", ll2ascii(i->hwaddr, i->addr_len));

    /* advance interface counter in relay */
    ccnl_relay.ifcount++;

    /* configure the interface to use the specified nettype protocol */
    gnrc_netapi_set(if_pid, NETOPT_PROTO, 0, &netreg_type, sizeof(gnrc_nettype_t));
    /* register for this nettype */
    gnrc_netreg_entry_init_pid(&_ccnl_ne, GNRC_NETREG_DEMUX_CTX_ALL,
                               _ccnl_event_loop_pid);
    return gnrc_netreg_register(netreg_type, &_ccnl_ne);
}

static msg_t _ageing_reset = { .type = CCNL_MSG_AGEING };

void compas_send_pam(struct ccnl_relay_s *ccnl)
{
    compas_dodag_t *dodag = &ccnl->dodag;
    gnrc_pktsnip_t *hdr = NULL;
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_pam_len(dodag) + 2, GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("error: packet buffer full");
        return;
    }

    memset(pkt->data, 0x80, 1);
    memset(((uint8_t *) pkt->data) + 1, CCNL_ENC_COMPAS, 1);
    compas_pam_create(dodag, (compas_pam_t *) (((uint8_t *) pkt->data) + 2));

    hdr = gnrc_netif_hdr_build(NULL, 0, NULL, 0);

    if (hdr == NULL) {
        puts("error: packet buffer full");
        gnrc_pktbuf_release(pkt);
        return;
    }

    LL_PREPEND(pkt, hdr);
    gnrc_netif_hdr_t *nethdr = (gnrc_netif_hdr_t *)hdr->data;
    nethdr->flags = GNRC_NETIF_HDR_FLAGS_BROADCAST;

    struct ccnl_if_s *ifc = NULL;
    for (int i = 0; i < ccnl->ifcount; i++) {
        if (ccnl->ifs[i].if_pid != 0) {
            ifc = &ccnl->ifs[i];
            break;
        }
    }

    if (gnrc_netapi_send(ifc->if_pid, pkt) < 1) {
        puts("error: unable to send\n");
        gnrc_pktbuf_release(pkt);
        return;
    }
}

static void _compas_dodag_parent_timeout(struct ccnl_relay_s *ccnl)
{
    ccnl->compas_dodag_parent_timeout = 1;
    ccnl->dodag.flags |= COMPAS_DODAG_FLAGS_FLOATING;
    printf("timeout;%u;%u;%d;", (unsigned) ccnl->dodag.rank, ccnl->compas_dodag_parent_timeout, ccnl->dodag.flags);
    for (int i = 0; i < ccnl->dodag.parent.face_addr_len - 1; i++) {
        printf("%02x:", ccnl->dodag.parent.face_addr[i]);
    }
    printf("%02x", ccnl->dodag.parent.face_addr[ccnl->dodag.parent.face_addr_len - 1]);
    for (struct ccnl_content_s *c = ccnl->contents; c; c = c->next) {
        if (!(c->flags & CCNL_COMPAS_CONTENT_REQUESTED)) {
            char *s = ccnl_prefix_to_path(c->pkt->pfx);
            printf(";%s", s);
            ccnl_free(s);
        }
    }
    printf("\n");
}

bool compas_send_nam(struct ccnl_relay_s *ccnl, const char *name, uint16_t name_len)
{
    compas_dodag_t *dodag = &ccnl->dodag;

    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        puts("Error: not part of a DODAG");
        return false;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL,
                                          2 + sizeof(compas_nam_t) +
                                          2 * (COMPAS_NAME_LEN + sizeof(compas_tlv_t)) +
                                          2 * (sizeof(uint16_t) + sizeof(compas_tlv_t)),
                                          GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("error: packet buffer full");
        return false;
    }

    memset(pkt->data, 0x80, 1);
    memset(((uint8_t *) pkt->data) + 1, CCNL_ENC_COMPAS, 1);
    compas_nam_t *nam = (compas_nam_t *)(((uint8_t *) pkt->data) + 2);
    compas_nam_create(nam);
    if (name) {
        printf("sendnam;%u;%u;%u;%lu;%lu;%.*s\n", COMPAS_NAM_PERIOD_BASE, ccnl->dodag.rank, ccnl->compas_dodag_parent_timeout,
                                                  (unsigned long) (xtimer_now_usec64() - ccnl->compas_started),
                                                  (unsigned long) (xtimer_now_usec64()),
                                                  name_len, name);
        compas_nam_tlv_add_name(nam, name, name_len);
    }
    else {
        char dodag_prefix[COMPAS_NAME_LEN + 1];
        memcpy(dodag_prefix, ccnl->dodag.prefix, ccnl->dodag.prefix_len);
        dodag_prefix[ccnl->dodag.prefix_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(dodag_prefix, CCNL_SUITE_NDNTLV, NULL, NULL);

        int rc = 0;
        char *s = NULL;

        for (struct ccnl_content_s *c = ccnl->contents; c; c = c->next) {
            if (c->pkt->pfx->compcnt <= prefix->compcnt) {
                continue;
            }
            rc = ccnl_prefix_cmp(c->pkt->pfx, NULL, prefix, CMP_LONGEST);
            if (rc >= prefix->compcnt) {
                if (!(c->flags & CCNL_COMPAS_CONTENT_REQUESTED)) {
                    if (c->retries) {
                        c->retries--;
                        s = ccnl_prefix_to_path(c->pkt->pfx);
                        printf("sendnam;%u;%u;%u;%u;%lu;%lu;%s\n", COMPAS_NAM_PERIOD_BASE, ccnl->dodag.rank, ccnl->compas_dodag_parent_timeout, c->retries,
                                                                   (unsigned long) (xtimer_now_usec64() - ccnl->compas_started),
                                                                   (unsigned long) (xtimer_now_usec64()),
                                                                   s);
                        compas_nam_tlv_add_name(nam, s, strlen(s));
                        ccnl_free(s);
                        break;
                    }
                    else {
                        nam->len = 0;
                        _compas_dodag_parent_timeout(ccnl);
                        break;
                    }
                }
            }
        }
        free_prefix(prefix);
    }

    if (nam->len == 0) {
        gnrc_pktbuf_release(pkt);
        return false;
    }

    gnrc_pktbuf_realloc_data(pkt, 2 + nam->len + sizeof(*nam));

    gnrc_pktsnip_t *hdr = gnrc_netif_hdr_build(NULL, 0, dodag->parent.face_addr, dodag->parent.face_addr_len);

    if (hdr == NULL) {
        puts("error: packet buffer full");
        gnrc_pktbuf_release(pkt);
        return false;
    }

    LL_PREPEND(pkt, hdr);

    struct ccnl_if_s *ifc = NULL;
    for (int i = 0; i < ccnl->ifcount; i++) {
        if (ccnl->ifs[i].if_pid != 0) {
            ifc = &ccnl->ifs[i];
            break;
        }
    }

    if (gnrc_netapi_send(ifc->if_pid, pkt) < 1) {
        puts("error: unable to send\n");
        gnrc_pktbuf_release(pkt);
        return false;
    }

    return true;
}

/* (link layer) sending function */
void
ccnl_ll_TX(struct ccnl_relay_s *ccnl, struct ccnl_if_s *ifc,
           sockunion *dest, struct ccnl_buf_s *buf)
{
    (void) ccnl;
    int rc;
    DEBUGMSG(TRACE, "ccnl_ll_TX %d bytes to %s\n", (int)(buf ? buf->datalen : -1), ccnl_addr2ascii(dest));
    /* reset ageing timer */
    xtimer_remove(&_ageing_timer);
    xtimer_set_msg(&_ageing_timer, US_PER_SEC, &_ageing_reset, _ccnl_event_loop_pid);
    DEBUGMSG(TRACE, "ccnl_ll_TX: reset timer\n");

    switch(dest->sa.sa_family) {
        /* link layer sending */
        case AF_PACKET: {
                            /* allocate memory */
                            gnrc_pktsnip_t *hdr = NULL;
                            gnrc_pktsnip_t *pkt= gnrc_pktbuf_add(NULL, buf->data,
                                                                 buf->datalen,
                                                                 GNRC_NETTYPE_CCN);

                            if (pkt == NULL) {
                                puts("error: packet buffer full");
                                return;
                            }

                            /* check for loopback */
                            bool is_loopback = false;
                            if (ifc->addr_len == dest->linklayer.sll_halen) {
                                if (memcmp(ifc->hwaddr, dest->linklayer.sll_addr, dest->linklayer.sll_halen) == 0) {
                                    /* build link layer header */
                                    hdr = gnrc_netif_hdr_build(NULL, dest->linklayer.sll_halen,
                                                               dest->linklayer.sll_addr,
                                                               dest->linklayer.sll_halen);

                                    gnrc_netif_hdr_set_src_addr((gnrc_netif_hdr_t *)hdr->data, ifc->hwaddr, ifc->addr_len);
                                    is_loopback = true;
                                }
                            }

                            /* for the non-loopback case */
                            if (hdr == NULL) {
                                hdr = gnrc_netif_hdr_build(NULL, 0,
                                                           dest->linklayer.sll_addr,
                                                           dest->linklayer.sll_halen);
                            }

                            /* check if header building succeeded */
                            if (hdr == NULL) {
                                puts("error: packet buffer full");
                                gnrc_pktbuf_release(pkt);
                                return;
                            }
                            LL_PREPEND(pkt, hdr);

                            if (is_loopback) {
                                    DEBUGMSG(DEBUG, "loopback packet\n");
                                    if (gnrc_netapi_receive(_ccnl_event_loop_pid, pkt) < 1) {
                                        DEBUGMSG(ERROR, "error: unable to loopback packet, discard it\n");
                                        gnrc_pktbuf_release(pkt);
                                    }
                                    return;
                            }

                            /* distinguish between broadcast and unicast */
                            bool is_bcast = true;
                            /* TODO: handle broadcast addresses which are not all 0xFF */
                            for (unsigned i = 0; i < dest->linklayer.sll_halen; i++) {
                                if (dest->linklayer.sll_addr[i] != UINT8_MAX) {
                                    is_bcast = false;
                                    break;
                                }
                            }

                            if (is_bcast) {
                                DEBUGMSG(DEBUG, " is broadcast\n");
                                gnrc_netif_hdr_t *nethdr = (gnrc_netif_hdr_t *)hdr->data;
                                nethdr->flags = GNRC_NETIF_HDR_FLAGS_BROADCAST;
                            }

                            /* actual sending */
                            DEBUGMSG(DEBUG, " try to pass to GNRC (%i): %p\n", (int) ifc->if_pid, (void*) pkt);
                            if (gnrc_netapi_send(ifc->if_pid, pkt) < 1) {
                                puts("error: unable to send\n");
                                gnrc_pktbuf_release(pkt);
                                return;
                            }
                            break;
                        }
        default:
                        DEBUGMSG(WARNING, "unknown transport\n");
                        break;
    }
    (void) rc; /* just to silence a compiler warning (if USE_DEBUG is not set) */
}

/* packets delivered to the application */
int
ccnl_app_RX(struct ccnl_relay_s *ccnl, struct ccnl_content_s *c)
{
    (void) ccnl;
    DEBUGMSG(DEBUG, "Received something of size %u for the application\n", c->pkt->contlen);

    gnrc_pktsnip_t *pkt= gnrc_pktbuf_add(NULL, c->pkt->content,
                                         c->pkt->contlen,
                                         GNRC_NETTYPE_CCN_CHUNK);
    if (pkt == NULL) {
        DEBUGMSG(WARNING, "Something went wrong allocating buffer for the chunk!\n");
        return -1;
    }

    if (!gnrc_netapi_dispatch_receive(GNRC_NETTYPE_CCN_CHUNK,
                                      GNRC_NETREG_DEMUX_CTX_ALL, pkt)) {
        DEBUGMSG(DEBUG, "ccn-lite: unable to forward packet as no one is \
                 interested in it\n");
        gnrc_pktbuf_release(pkt);
    }

    return 0;
}

/* periodic callback */
void
ccnl_ageing(void *relay, void *aux)
{
    ccnl_do_ageing(relay, aux);
    ccnl_set_timer(US_PER_SEC, ccnl_ageing, relay, 0);
}

/* receiving callback for CCN packets */
void
_receive(struct ccnl_relay_s *ccnl, msg_t *m)
{
    int i;
    /* iterate over interfaces */
    for (i = 0; i < ccnl->ifcount; i++) {
        if (ccnl->ifs[i].if_pid == m->sender_pid) {
            break;
        }
    }

    if (i == ccnl->ifcount) {
        DEBUGMSG(WARNING, "No matching CCN interface found, assume it's from the default interface\n");
        i = 0;
    }

    /* packet parsing */
    gnrc_pktsnip_t *pkt = (gnrc_pktsnip_t *)m->content.ptr;
    gnrc_pktsnip_t *ccn_pkt, *netif_pkt;
    LL_SEARCH_SCALAR(pkt, ccn_pkt, type, GNRC_NETTYPE_CCN);
    LL_SEARCH_SCALAR(pkt, netif_pkt, type, GNRC_NETTYPE_NETIF);
    gnrc_netif_hdr_t *nethdr = (gnrc_netif_hdr_t *)netif_pkt->data;
    /*
    if (nethdr->lqi < 215) {
        //printf("dropped;%u\n", nethdr->lqi);
        gnrc_pktbuf_release(pkt);
        return;
    }
    */
    sockunion su;
    memset(&su, 0, sizeof(su));
    su.sa.sa_family = AF_PACKET;
    su.linklayer.sll_halen = nethdr->src_l2addr_len;
    memcpy(su.linklayer.sll_addr, gnrc_netif_hdr_get_src_addr(nethdr), nethdr->src_l2addr_len);

    /* call CCN-lite callback and free memory in packet buffer */
    ccnl_core_RX(ccnl, i, ccn_pkt->data, ccn_pkt->size, &su.sa, sizeof(su.sa));
    gnrc_pktbuf_release(pkt);
}

/* the main event-loop */
void
*_ccnl_event_loop(void *arg)
{
    msg_init_queue(_msg_queue, CCNL_QUEUE_SIZE);
    struct ccnl_relay_s *ccnl = (struct ccnl_relay_s*) arg;

    ccnl->compas_pam_msg.type = COMPAS_PAM_MSG;
    ccnl->compas_nam_msg.type = COMPAS_NAM_MSG;
    ccnl->compas_dodag_parent_msg.type = COMPAS_DODAG_PARENT_TIMEOUT_MSG;
    ccnl->compas_started = 0;

    /* XXX: https://xkcd.com/221/ */
    random_init(0x4);

    while(!ccnl->halt_flag) {
        msg_t m, reply;
        /* start periodic timer */
        reply.type = CCNL_MSG_AGEING;
        DEBUGMSG(VERBOSE, "ccn-lite: waiting for incoming message.\n");
        msg_receive(&m);

        switch (m.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUGMSG(DEBUG, "ccn-lite: GNRC_NETAPI_MSG_TYPE_RCV received\n");
                _receive(ccnl, &m);
                break;

            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUGMSG(DEBUG, "ccn-lite: GNRC_NETAPI_MSG_TYPE_SND received\n");
                gnrc_pktsnip_t *pkt = (gnrc_pktsnip_t*) m.content.ptr;
                if (pkt->type != GNRC_NETTYPE_CCN) {
                    DEBUGMSG(WARNING, "ccn-lite: wrong nettype\n");
                }
                else {
                    ccnl_interest_t *i = (ccnl_interest_t*) pkt->data;
                    ccnl_send_interest(i->prefix, i->buf, i->buflen);
                }
                gnrc_pktbuf_release(pkt);
                break;

            case GNRC_NETAPI_MSG_TYPE_GET:
            case GNRC_NETAPI_MSG_TYPE_SET:
                DEBUGMSG(DEBUG, "ccn-lite: reply to unsupported get/set\n");
                reply.content.value = -ENOTSUP;
                msg_reply(&m, &reply);
                break;
            case CCNL_MSG_AGEING:
                DEBUGMSG(VERBOSE, "ccn-lite: ageing timer\n");
                ccnl_do_ageing(arg, NULL);
                xtimer_remove(&_ageing_timer);
                xtimer_set_msg(&_ageing_timer, US_PER_SEC, &reply, sched_active_pid);
                break;
            case COMPAS_PAM_MSG:
                compas_send_pam(ccnl);
                //printf("pamtx;%d\n", ccnl->dodag.rank);
                xtimer_set_msg(&ccnl->compas_pam_timer,
                               COMPAS_PAM_PERIOD + random_uint32_range(0,200) * US_PER_MS,
                               &ccnl->compas_pam_msg, sched_active_pid);
                break;
            case COMPAS_NAM_MSG:
                ccnl->compas_nam_timer_running = 0;

                char dodag_prefix[COMPAS_NAME_LEN];
                memcpy(dodag_prefix, ccnl->dodag.prefix, ccnl->dodag.prefix_len);
                dodag_prefix[ccnl->dodag.prefix_len] = '\0';

                bool work_to_do = false;

                if (ccnl->dodag.rank > COMPAS_DODAG_ROOT_RANK && !ccnl->compas_dodag_parent_timeout) {
                    work_to_do |= compas_send_nam(ccnl, NULL, 0);
                }

                if (work_to_do) {
                    xtimer_set_msg(&ccnl->compas_nam_timer, COMPAS_NAM_PERIOD, &ccnl->compas_nam_msg, sched_active_pid);
                    ccnl->compas_nam_timer_running = 1;
                }

                break;
            case COMPAS_DODAG_PARENT_TIMEOUT_MSG:
                _compas_dodag_parent_timeout(ccnl);
                break;
            default:
                DEBUGMSG(WARNING, "ccn-lite: unknown message type\n");
                break;
        }

    }
    return NULL;
}

/* trampoline function creating the loopback face */
kernel_pid_t
ccnl_start(void)
{
    loopback_face = ccnl_get_face_or_create(&ccnl_relay, -1, NULL, 0);
    loopback_face->flags |= CCNL_FACE_FLAGS_STATIC;

    ccnl_relay.max_cache_entries = CCNL_CACHE_SIZE;
    ccnl_relay.max_pit_entries = CCNL_DEFAULT_MAX_PIT_ENTRIES;
    /* start the CCN-Lite event-loop */
    ccnl_relay.pid = _ccnl_event_loop_pid =  thread_create(_ccnl_stack, sizeof(_ccnl_stack),
                                          THREAD_PRIORITY_MAIN - 1,
                                          THREAD_CREATE_STACKTEST, _ccnl_event_loop,
                                          &ccnl_relay, "ccnl");
    return _ccnl_event_loop_pid;
}

static xtimer_t _wait_timer = { .target = 0, .long_target = 0 };
static msg_t _timeout_msg;
int
ccnl_wait_for_chunk(void *buf, size_t buf_len, uint64_t timeout)
{
    int res = (-1);

    if (timeout == 0) {
        timeout = CCNL_MAX_INTEREST_RETRANSMIT * US_PER_SEC;
    }

    while (1) { /* wait for a content pkt (ignore interests) */
        DEBUGMSG(DEBUG, "  waiting for packet\n");

        /* TODO: receive from socket or interface */
        _timeout_msg.type = CCNL_MSG_TIMEOUT;
        xtimer_set_msg64(&_wait_timer, timeout, &_timeout_msg, sched_active_pid);
        msg_t m;
        msg_receive(&m);
        if (m.type == GNRC_NETAPI_MSG_TYPE_RCV) {
            DEBUGMSG(TRACE, "It's from the stack!\n");
            gnrc_pktsnip_t *pkt = (gnrc_pktsnip_t *)m.content.ptr;
            DEBUGMSG(DEBUG, "Type is: %i\n", pkt->type);
            if (pkt->type == GNRC_NETTYPE_CCN_CHUNK) {
                char *c = (char*) pkt->data;
                DEBUGMSG(INFO, "Content is: %s\n", c);
                size_t len = (pkt->size > buf_len) ? buf_len : pkt->size;
                memcpy(buf, pkt->data, len);
                res = (int) len;
                gnrc_pktbuf_release(pkt);
            }
            else {
                DEBUGMSG(WARNING, "Unkown content\n");
                gnrc_pktbuf_release(pkt);
                continue;
            }
            xtimer_remove(&_wait_timer);
            break;
        }
        else if (m.type == CCNL_MSG_TIMEOUT) {
            res = -ETIMEDOUT;
            break;
        }
        else {
            /* TODO: reduce timeout value */
            DEBUGMSG(DEBUG, "Unknow message received, ignore it\n");
        }
    }

    return res;
}

/* TODO: move everything below here to ccn-lite-core-utils */

/* generates and send out an interest */
int
ccnl_send_interest(struct ccnl_prefix_s *prefix, unsigned char *buf, size_t buf_len)
{
    int ret = -1;

    if (_ccnl_suite != CCNL_SUITE_NDNTLV) {
        DEBUGMSG(WARNING, "Suite not supported by RIOT!");
        return ret;
    }

    ccnl_mkInterestFunc mkInterest;
    ccnl_isContentFunc isContent;

    mkInterest = ccnl_suite2mkInterestFunc(_ccnl_suite);
    isContent = ccnl_suite2isContentFunc(_ccnl_suite);

    if (!mkInterest || !isContent) {
        DEBUGMSG(WARNING, "No functions for this suite were found!");
        return ret;
    }

    DEBUGMSG(INFO, "interest for chunk number: %u\n", (prefix->chunknum == NULL) ? 0 : *prefix->chunknum);

    if (!prefix) {
        DEBUGMSG(ERROR, "prefix could not be created!\n");
        return ret;
    }

    int nonce = random_uint32();
    DEBUGMSG(DEBUG, "nonce: %i\n", nonce);

    int len = mkInterest(prefix, &nonce, buf, buf_len);

    unsigned char *start = buf;
    unsigned char *data = buf;
    struct ccnl_pkt_s *pkt;

    int typ;
    int int_len;

    /* TODO: support other suites */
    if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) || (int) int_len > len) {
        DEBUGMSG(WARNING, "  invalid packet format\n");
        return ret;
    }
    pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);

    ret = ccnl_fwd_handleInterest(&ccnl_relay, loopback_face, &pkt, ccnl_ndntlv_cMatch);

    free_packet(pkt);

    return ret;
}

void
ccnl_set_local_producer(ccnl_producer_func func)
{
    _prod_func = func;
}

void
ccnl_set_cache_strategy_remove(ccnl_cache_strategy_func func)
{
    _cs_remove_func = func;
}

int
local_producer(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                   struct ccnl_pkt_s *pkt)
{
    if (_prod_func) {
        return _prod_func(relay, from, pkt);
    }
    return 0;
}

int
cache_strategy_remove(struct ccnl_relay_s *relay, struct ccnl_content_s *c)
{
    if (_cs_remove_func) {
        return _cs_remove_func(relay, c);
    }
    return 0;
}
