/*
 * Copyright (C) 2015, 2016 INRIA
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef CCN_LITE_RIOT_H
#define CCN_LITE_RIOT_H

/**
 * @defgroup    pkg_ccnlite CCN-Lite stack
 * @ingroup     pkg
 * @ingroup     net
 * @brief       Provides a NDN implementation
 *
 * This package provides the CCN-Lite stack as a port of NDN for RIOT.
 *
 * @{
 */

#include <unistd.h>
#include "kernel_types.h"
#include "arpa/inet.h"
#include "net/packet.h"
#include "net/ethernet/hdr.h"
#include "sys/socket.h"
#include "ccnl-core.h"
#include "ccnl-pkt-ndntlv.h"
#include "net/gnrc/netreg.h"
#include "ccnl-dispatch.h"
//#include "ccnl-pkt-builder.h"

#include "irq.h"
#include "evtimer.h"
#include "evtimer_msg.h"

#include "net/netstats.h"
#include "ps.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Dynamic memory allocation used in CCN-Lite
 *
 * @{
 */
#define ccnl_malloc(s)                  malloc(s)
#define ccnl_calloc(n,s)                calloc(n,s)
#define ccnl_realloc(p,s)               realloc(p,s)
#define ccnl_free(p)                    free(p)
/**
 * @}
 */

/**
 * Constant string
 */
#define CONSTSTR(s)                     s

/**
 * Stack size for CCN-Lite event loop
 */
#ifndef CCNL_STACK_SIZE
#define CCNL_STACK_SIZE (THREAD_STACKSIZE_MAIN)
#endif

/**
 * Size of the message queue of CCN-Lite's event loop
 */
#ifndef CCNL_QUEUE_SIZE
#define CCNL_QUEUE_SIZE     (8)
#endif

/**
 * Interest retransmission interval in milliseconds
 */
#ifndef CCNL_INTEREST_RETRANS_TIMEOUT
#define CCNL_INTEREST_RETRANS_TIMEOUT   (1000)
#endif

/**
 * @brief Data structure for interest packet
 */
typedef struct {
    struct ccnl_prefix_s *prefix;   /**< requested prefix */
    unsigned char *buf;             /**< buffer to store the interest packet */
    size_t buflen;                  /**< size of the buffer */
} ccnl_interest_t;

/**
 * PID of the eventloop thread
 */
extern kernel_pid_t ccnl_event_loop_pid;

/**
 * Maximum string length for prefix representation
 */
#define CCNL_PREFIX_BUFSIZE     (50)

/**
 * Message type for signalling a timeout while waiting for a content chunk
 */
#define CCNL_MSG_TIMEOUT        (0x1701)

/**
 * Message type for advancing the ageing timer
 */
#define CCNL_MSG_AGEING         (0x1702)

/**
 * Message type for Interest retransmissions
 */
#define CCNL_MSG_INT_RETRANS    (0x1703)

/**
 * Message type for adding content store entries
 */
#define CCNL_MSG_CS_ADD         (0x1704)

/**
 * Message type for deleting content store entries
 */
#define CCNL_MSG_CS_DEL         (0x1705)

/**
 * Message type for performing a content store lookup
 */
#define CCNL_MSG_CS_LOOKUP      (0x1706)

/**
 * Message type for Interest timeouts
 */
#define CCNL_MSG_INT_TIMEOUT    (0x1707)

/**
 * Message type for Face timeouts
 */
#define CCNL_MSG_FACE_TIMEOUT   (0x1708)

/**
 * Maximum number of elements that can be cached
 */
#ifndef CCNL_CACHE_SIZE
#define CCNL_CACHE_SIZE     (5)
#endif
#ifdef DOXYGEN
#define CCNL_CACHE_SIZE
#endif

#ifndef CCNL_THREAD_PRIORITY
#define CCNL_THREAD_PRIORITY (THREAD_PRIORITY_MAIN - 1)
#endif

/**
 * @brief Local loopback face
 */
extern struct ccnl_face_s *loopback_face;


/**
 * Struct holding CCN-Lite's central relay information
 */
extern struct ccnl_relay_s ccnl_relay;

/**
 * Struct Evtimer for various ccnl events
 */
extern evtimer_msg_t ccnl_evtimer;

/**
 * @brief Function pointer type for caching strategy function
 */
typedef int (*ccnl_cache_strategy_func)(struct ccnl_relay_s *relay,
                                        struct ccnl_content_s *c);

/**
 * @brief   Start the main CCN-Lite event-loop
 *
 * @return  The PID of the event-loop's thread
 */
kernel_pid_t ccnl_start(void);

/**
 * @brief Opens a @ref net_gnrc_netif device for use with CCN-Lite
 *
 * @param[in] if_pid        The pid of the @ref net_gnrc_netif device driver
 * @param[in] netreg_type   The @ref net_gnrc_nettype @p if_pid should be
 *                          configured to use
 *
 * @return 0 on success,
 * @return -EINVAL if eventloop could not be registered for @p netreg_type
 */
int ccnl_open_netif(kernel_pid_t if_pid, gnrc_nettype_t netreg_type);

/**
 * @brief Sends out an Interest
 *
 * @param[in] prefix    The name that is requested
 * @param[out] buf      Buffer to write the content chunk to
 * @param[in] buf_len   Size of @p buf
 * @param[in] int_opts  Interest options (@ref ccnl_interest_opts_u)
 *
 * @return 0 on success
 * @return -1, packet format not supported
 * @return -2, prefix is NULL
 * @return -3, packet deheading failed
 * @return -4, parsing failed
 */
int ccnl_send_interest(struct ccnl_prefix_s *prefix,
                       unsigned char *buf, int buf_len,
                       ccnl_interest_opts_u *int_opts,
                       struct ccnl_face_s *to);

/**
 * @brief Wait for incoming content chunk
 *
 * @pre The thread has to register for CCNL_CONT_CHUNK in @ref net_gnrc_netreg
 *      first
 *
 * @post The thread should unregister from @ref net_gnrc_netreg after this
 *       function returns
 *
 * @param[out] buf      Buffer to stores the received content
 * @param[in]  buf_len  Size of @p buf
 * @param[in]  timeout  Maximum to wait for the chunk, set to a default value if 0
 *
 * @return 0 if a content was received
 * @return -ETIMEDOUT if no chunk was received until timeout
 */
int ccnl_wait_for_chunk(void *buf, size_t buf_len, uint64_t timeout);

/**
 * @brief Set a function to control the caching strategy
 *
 * The given function will be called if the cache is full and a new content
 * chunk arrives. It shall remove (at least) one entry from the cache.
 *
 * If the return value of @p func is 0, the default caching strategy will be
 * applied by the CCN-lite stack. If the return value is 1, it is assumed that
 * (at least) one entry has been removed from the cache.
 *
 * @param[in] func  The function to be called for an incoming content chunk if
 *                  the cache is full.
 */
void ccnl_set_cache_strategy_remove(ccnl_cache_strategy_func func);

/**
 * @brief Send a message to the CCN-lite thread to add @p to the content store
 *
 * @param[in] content   The content to add to the content store
 */
static inline void ccnl_msg_cs_add(struct ccnl_content_s *content)
{
    msg_t ms = { .type = CCNL_MSG_CS_ADD, .content.ptr = content };
    msg_send(&ms, ccnl_event_loop_pid);
}

/**
 * @brief Send a message to the CCN-lite thread to remove a content with
 * the @p prefix from the content store
 *
 * @param[in] content   The prefix of the content to remove from the content store
 */
static inline void ccnl_msg_cs_remove(struct ccnl_prefix_s *prefix)
{
    msg_t ms = { .type = CCNL_MSG_CS_DEL, .content.ptr = prefix };
    msg_send(&ms, ccnl_event_loop_pid);
}

/**
 * @brief Send a message to the CCN-lite thread to perform a content store
 * lookup for the @p prefix
 *
 * @param[in] content   The prefix of the content to perform a lookup for
 *
 * @return              pointer to the content, if found
 * @reutn               NULL, if not found
 */
static inline struct ccnl_content_s *ccnl_msg_cs_lookup(struct ccnl_prefix_s *prefix)
{
    msg_t mr, ms = { .type = CCNL_MSG_CS_LOOKUP, .content.ptr = prefix };
    msg_send_receive(&ms, &mr, ccnl_event_loop_pid);
    return (struct ccnl_content_s *) mr.content.ptr;
}

/**
 * @brief Reset Interest retransmissions
 *
 * @param[in] i         The interest to update
 */
static inline void ccnl_evtimer_reset_interest_retrans(struct ccnl_interest_s *i)
{
    evtimer_del((evtimer_t *)(&ccnl_evtimer), (evtimer_event_t *)&i->evtmsg_retrans);
    i->evtmsg_retrans.msg.type = CCNL_MSG_INT_RETRANS;
    i->evtmsg_retrans.msg.content.ptr = i;
    ((evtimer_event_t *)&i->evtmsg_retrans)->offset = CCNL_INTEREST_RETRANS_TIMEOUT;
    evtimer_add_msg(&ccnl_evtimer, &i->evtmsg_retrans, ccnl_event_loop_pid);
}

/**
 * @brief Reset Interest timeout
 *
 * @param[in] i         The interest to update
 */
static inline void ccnl_evtimer_reset_interest_timeout(struct ccnl_interest_s *i)
{
    evtimer_del((evtimer_t *)(&ccnl_evtimer), (evtimer_event_t *)&i->evtmsg_timeout);
    i->evtmsg_timeout.msg.type = CCNL_MSG_INT_TIMEOUT;
    i->evtmsg_timeout.msg.content.ptr = i;
    ((evtimer_event_t *)&i->evtmsg_timeout)->offset = i->lifetime * 1000; // ms
    evtimer_add_msg(&ccnl_evtimer, &i->evtmsg_timeout, ccnl_event_loop_pid);
}

/**
 * @brief Reset Face timeout
 *
 * @param[in] f         The face to update
 */
static inline void ccnl_evtimer_reset_face_timeout(struct ccnl_face_s *f)
{
    evtimer_del((evtimer_t *)(&ccnl_evtimer), (evtimer_event_t *)&f->evtmsg_timeout);
    f->evtmsg_timeout.msg.type = CCNL_MSG_FACE_TIMEOUT;
    f->evtmsg_timeout.msg.content.ptr = f;
    ((evtimer_event_t *)&f->evtmsg_timeout)->offset = CCNL_FACE_TIMEOUT * 1000; // ms
    evtimer_add_msg(&ccnl_evtimer, &f->evtmsg_timeout, ccnl_event_loop_pid);
}

/**
 * @brief Set content timeout
 *
 * @param[in] c         The content to timeout
 */
static inline void ccnl_evtimer_set_cs_timeout(struct ccnl_content_s *c)
{
    evtimer_del((evtimer_t *)(&ccnl_evtimer), (evtimer_event_t *)&c->evtmsg_cstimeout);
    c->evtmsg_cstimeout.msg.type = CCNL_MSG_CS_DEL;
    c->evtmsg_cstimeout.msg.content.ptr = c->pkt->pfx;
    ((evtimer_event_t *)&c->evtmsg_cstimeout)->offset = CCNL_CONTENT_TIMEOUT * 1000; // ms
    evtimer_add_msg(&ccnl_evtimer, &c->evtmsg_cstimeout, ccnl_event_loop_pid);
}

/**
 * @brief Remove RIOT related structures for Interests
 *
 * @param[in] et        RIOT related event queue that holds timer events
 * @param[in] i         The Interest structure
 */
static inline void ccnl_riot_interest_remove(evtimer_t *et, struct ccnl_interest_s *i)
{
    evtimer_del(et, (evtimer_event_t *)&i->evtmsg_retrans);
    evtimer_del(et, (evtimer_event_t *)&i->evtmsg_timeout);

    unsigned state = irq_disable();
    /* remove messages that relate to this interest from the message queue */
    thread_t *me = (thread_t*) sched_threads[sched_active_pid];
    for (unsigned j = 0; j <= me->msg_queue.mask; j++) {
        if (me->msg_array[j].content.ptr == i) {
            /* removing is done by setting to zero */
            memset(&(me->msg_array[j]), 0, sizeof(me->msg_array[j]));
        }
    }
    irq_restore(state);
}

extern uint32_t fwd_interest;
extern uint32_t retrans_send_interest;
extern uint32_t send_drop_interest;
extern uint32_t recv_interest;
extern uint32_t cs_send_data;
extern uint32_t fwd_data;
extern uint32_t recv_data;
extern uint32_t recv_drop_data;
extern uint32_t ccnl_dup_drop;
extern uint32_t netdev_evt_tx_noack;
extern uint32_t discard_802154_cnt;
extern uint32_t recv_nam;
extern uint32_t send_nam;
extern uint32_t recv_pam;
extern uint32_t send_pam;
extern uint32_t recv_sol;
extern uint32_t send_sol;

static inline void print_fwd_interest(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("itf;%lu;%s;%u;%u\n", (unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    fwd_interest++;
}

static inline void print_retrans_send_interest(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("irf;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    retrans_send_interest++;
}

static inline void print_send_drop_interest(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("itd;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    send_drop_interest++;
}

static inline void print_recv_interest(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("ivf;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    recv_interest++;
}

static inline void print_dropdup_interest(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("idd;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    ccnl_dup_drop++;
}

static inline void print_cs_send_data(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("dtc;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    cs_send_data++;
}

static inline void print_fwd_data(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("dtf;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    fwd_data++;
}

static inline void print_recv_drop_data(struct ccnl_pkt_s *pkt) { // not yet tested
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("dvd;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    recv_drop_data++;
}

static inline void print_recv_data(struct ccnl_pkt_s *pkt) {
#ifdef PRINT_ALL_EVENTS
    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    printf("dvf;%lu;%s;%u;%u\n",(unsigned long)xtimer_now_usec64(), &s[0],ccnl_relay.pitcnt, ccnl_relay.contentcnt);
#endif
    (void)pkt;
    recv_data++;
}

static inline void print_send_pam(void) {
#ifdef PRINT_ALL_EVENTS
    printf("hpt;%lu;%*.s\n", (unsigned long)xtimer_now_usec64());
#endif
    send_pam++;
}
static inline void print_recv_pam(void) {
#ifdef PRINT_ALL_EVENTS
    printf("hpr;%lu;%*.s\n", (unsigned long)xtimer_now_usec64());
#endif
    recv_pam++;
}
static inline void print_send_sol(void) {
#ifdef PRINT_ALL_EVENTS
    printf("hst;%lu;%*.s\n", (unsigned long)xtimer_now_usec64());
#endif
    send_sol++;
}
static inline void print_recv_sol(void) {
#ifdef PRINT_ALL_EVENTS
    printf("hsr;%lu;%*.s\n", (unsigned long)xtimer_now_usec64());
#endif
    recv_sol++;
}
static inline void print_send_nam(char *name, size_t name_len) {
#ifdef PRINT_ALL_EVENTS
    printf("hnt;%lu;%*.s\n", (unsigned long)xtimer_now_usec64(), name_len, name);
#endif
    send_nam++;
}
static inline void print_recv_nam(char *name, size_t name_len) {
#ifdef PRINT_ALL_EVENTS
    printf("hnr;%lu;%*.s\n", (unsigned long)xtimer_now_usec64(), name_len, name);
#endif
    recv_nam++;
}

static inline void print_accumulated_stats(void) {
    netstats_t *stats;
    gnrc_netif_t *netif;

    netif = gnrc_netif_iter(NULL);
    gnrc_netapi_get(netif->pid, NETOPT_STATS, NETSTATS_LAYER2, &stats,
                    sizeof(&stats));

    printf("STATS;%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";"
           "%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";"
           "%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";",
           "%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32 ";",
           fwd_interest,
           retrans_send_interest,
           recv_interest,
           send_drop_interest,
           cs_send_data,
           fwd_data,
           recv_drop_data,
           recv_data,
           ccnl_dup_drop,
           stats->tx_unicast_count,
           stats->tx_mcast_count,
           stats->tx_bytes,
           stats->tx_success,
           stats->tx_failed,
           netdev_evt_tx_noack,
           discard_802154_cnt,
           send_pam,
           recv_pam,
           send_nam,
           recv_nam,
           send_sol,
           recv_sol
        );

    ps();
}




#ifdef __cplusplus
}
#endif
#endif /* CCN_LITE_RIOT_H */
/** @} */
