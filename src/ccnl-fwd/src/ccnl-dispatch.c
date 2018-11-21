/*
 * @f ccnl-dispatch.c
 *
 * Copyright (C) 2011-18, University of Basel
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
 * 2017-06-20 created
 */

#include "ccnl-dispatch.h"

#include "ccnl-os-time.h"

#include "ccnl-localrpc.h"

#include "ccnl-relay.h"
#include "ccnl-pkt-util.h"

#include "ccnl-fwd.h"

#include "ccnl-pkt-ccnb.h"
#include "ccnl-pkt-ccntlv.h"
#include "ccnl-pkt-ndntlv.h"
#include "ccnl-pkt-switch.h"
#include "ccnl-pkt-localrpc.h"

#include "ccnl-logging.h"

#ifdef MODULE_GNRC_ICNLOWPAN_HC
#ifndef ICNL_SCRATCH_SIZE
#define ICNL_SCRATCH_SIZE (256)
#endif
uint8_t icnl_scratch[ICNL_SCRATCH_SIZE];
#endif

extern uint32_t networking_recv_net;
extern uint32_t networking_recv_lowpan;

struct ccnl_suite_s ccnl_core_suites[CCNL_SUITE_LAST];

#ifdef MODULE_GNRC_ICNLOWPAN_HC
static uint8_t hopid;

void get_hopid(uint8_t local_hopid)
{
    hopid = local_hopid;
}

typedef struct {
    struct ccnl_relay_s *relay;
} icnl_context_t;

unsigned icnl_name_decompress(uint8_t *out, uint8_t hop_id, void *context)
{
    struct ccnl_relay_s *relay = ((icnl_context_t *) context)->relay;
    struct ccnl_interest_s *i;
    struct ccnl_pendint_s *pend;

    bool dobreak = false;

    for (i = relay->pit; i; i = i->next) {
        pend = i->pending;
        while (pend) {
            if (pend->hop_id_out == hop_id) {
                dobreak = true;
                break;
            }
            pend = pend->next;
        }
        if (dobreak) {
            break;
        }
    }

    if (i) {
        unsigned name_len = i->pkt->pfx->nameptr[1];
        memcpy(out, i->pkt->pfx->nameptr + 2, name_len);
        return name_len;
    }

    return 0;
}

unsigned icnl_context_name_decompress(uint8_t *out, uint8_t prefix_cid, void *context)
{
    (void) context;
    (void) prefix_cid;
    //const char name[] = { 0x08, 0x03, 'H', 'A', 'W', 0x08, 0x03, 'B', 'T', '7', 0x08, 0x04, 'R', 'o', 'o', 'm', 0x00 };
    const char name[] = { ICNL_PREFIX_CUT };
    unsigned name_len = strlen(name);

    memcpy(out, name, name_len);

    return name_len;
}

#endif

void
ccnl_core_RX(struct ccnl_relay_s *relay, int ifndx, unsigned char *data,
             int datalen, struct sockaddr *sa, int addrlen)
{

#ifdef MODULE_GNRC_ICNLOWPAN_HC
    networking_recv_lowpan = xtimer_now_usec();
    icnl_context_t ctx = { .relay = relay };
    icnl_cb_hopid = get_hopid;
    icnl_cb_hopid_decompress_name = icnl_name_decompress;
    icnl_cb_context_decompress_name = icnl_context_name_decompress;
    datalen = icnl_decode(icnl_scratch, data, datalen, &ctx);
    data = icnl_scratch;
    networking_recv_lowpan = xtimer_now_usec() - networking_recv_lowpan;
    networking_recv_net += networking_recv_lowpan;
#endif
    unsigned char *base = data;
    struct ccnl_face_s *from;
    int enc, suite = -1, skip;
    dispatchFct dispatch;
    (void) enc;

    (void) base; // silence compiler warning (if USE_DEBUG is not set)

    DEBUGMSG_CORE(DEBUG, "ccnl_core_RX ifndx=%d, %d bytes\n", ifndx, datalen);
    //    DEBUGMSG_ON(DEBUG, "ccnl_core_RX ifndx=%d, %d bytes\n", ifndx, datalen);

#ifdef USE_STATS
    if (ifndx >= 0)
        relay->ifs[ifndx].rx_cnt++;
#endif

    from = ccnl_get_face_or_create(relay, ifndx, sa, addrlen);
    if (!from) {
        DEBUGMSG_CORE(DEBUG, "  no face\n");
        return;
    } else {
        DEBUGMSG_CORE(DEBUG, "  face %d, peer=%s\n", from->faceid,
                    ccnl_addr2ascii(&from->peer));
    }

    // loop through all packets in the received frame (UDP, Ethernet etc)
    while (datalen > 0) {
        // work through explicit code switching
        while (!ccnl_switch_dehead(&data, &datalen, &enc))
            suite = ccnl_enc2suite(enc);
        if (suite == -1)
            suite = ccnl_pkt2suite(data, datalen, &skip);

        if (!ccnl_isSuite(suite)) {
            DEBUGMSG_CORE(WARNING, "?unknown packet format? ccnl_core_RX ifndx=%d, %d bytes starting with 0x%02x at offset %d\n",
                     ifndx, datalen, *data, (int)(data - base));
            return;
        }

        dispatch = ccnl_core_suites[suite].RX;
        if (!dispatch) {
            DEBUGMSG_CORE(ERROR, "Forwarder not initialized or dispatcher "
                     "for suite %s does not exist.\n", ccnl_suite2str(suite));
            return;
        }
#ifdef MODULE_GNRC_ICNLOWPAN_HC
        if (dispatch(relay, from, &data, &datalen, hopid) < 0)
#else
        if (dispatch(relay, from, &data, &datalen) < 0)
#endif
            break;
        if (datalen > 0) {
            DEBUGMSG_CORE(WARNING, "ccnl_core_RX: %d bytes left\n", datalen);
        }
    }
}

// ----------------------------------------------------------------------

void
ccnl_core_init(void)
{
#ifdef USE_SUITE_CCNB
    ccnl_core_suites[CCNL_SUITE_CCNB].RX         = ccnl_ccnb_forwarder;
    ccnl_core_suites[CCNL_SUITE_CCNB].cMatch     = ccnl_ccnb_cMatch;
#endif
#ifdef USE_SUITE_CCNTLV
    ccnl_core_suites[CCNL_SUITE_CCNTLV].RX       = ccnl_ccntlv_forwarder;
    ccnl_core_suites[CCNL_SUITE_CCNTLV].cMatch   = ccnl_ccntlv_cMatch;
#endif
#ifdef USE_SUITE_LOCALRPC
    ccnl_core_suites[CCNL_SUITE_LOCALRPC].RX     = ccnl_localrpc_exec;
    //    ccnl_core_suites[CCNL_SUITE_LOCALRPC].cMatch = ccnl_localrpc_cMatch;
#endif
#ifdef USE_SUITE_NDNTLV
    ccnl_core_suites[CCNL_SUITE_NDNTLV].RX       = ccnl_ndntlv_forwarder;
    ccnl_core_suites[CCNL_SUITE_NDNTLV].cMatch   = ccnl_ndntlv_cMatch;
#endif
}
