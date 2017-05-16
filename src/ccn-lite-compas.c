/*
 * @f ccn-lite-compas.c
 * @b COMPAS adaption layer
 *
 * Copyright (C) 2017, Cenk Gündoğan, HAW Hamburg
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
 * 2017-05-12 created
 */

#include "arpa/inet.h"
#include "net/packet.h"
#include "net/ethernet/hdr.h"
#include "sys/socket.h"
#include "ccnl-defs.h"
#include "ccnl-core.h"
#include "ccnl-headers.h"
#include "ccn-lite-compas.h"

#include "compas/routing/nam.h"
#include "compas/routing/pam.h"

void compas_dodag_parent_timeout(struct ccnl_relay_s *ccnl)
{
    ccnl->compas_dodag_parent_timeout = 1;
    ccnl->dodag.flags |= COMPAS_DODAG_FLAGS_FLOATING;
    printf("timeout;%u;%u;%d;", (unsigned) ccnl->dodag.rank, ccnl->compas_dodag_parent_timeout, ccnl->dodag.flags);
    for (int i = 0; i < ccnl->dodag.parent.face.face_addr_len - 1; i++) {
        printf("%02x:", ccnl->dodag.parent.face.face_addr[i]);
    }
    printf("%02x", ccnl->dodag.parent.face.face_addr[ccnl->dodag.parent.face.face_addr_len - 1]);
    for (struct ccnl_content_s *c = ccnl->contents; c; c = c->next) {
        if (!(c->flags & CCNL_COMPAS_CONTENT_REQUESTED)) {
            char *s = ccnl_prefix_to_path(c->pkt->pfx);
            printf(";%s", s);
            ccnl_free(s);
        }
    }
    printf("\n");
}

void ccnl_compas_send_pam(struct ccnl_relay_s *relay)
{
    compas_dodag_t *dodag = &relay->dodag;
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
    for (int i = 0; i < relay->ifcount; i++) {
        if (relay->ifs[i].if_pid != 0) {
            ifc = &relay->ifs[i];
            break;
        }
    }

    if (gnrc_netapi_send(ifc->if_pid, pkt) < 1) {
        puts("error: unable to send\n");
        gnrc_pktbuf_release(pkt);
        return;
    }
}

bool compas_send_nam(struct ccnl_relay_s *ccnl, const compas_name_t *name)
{
    compas_dodag_t *dodag = &ccnl->dodag;

    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        puts("Error: not part of a DODAG");
        return false;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL,
                                          2 + sizeof(compas_nam_t) +
                                          name->name_len + sizeof(compas_tlv_t)
                                          GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("error: packet buffer full");
        return false;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_COMPAS;
    compas_nam_t *nam = (compas_nam_t *)(((uint8_t *) pkt->data) + 2);
    compas_nam_create(nam);
    printf("sendnam;%u;%u;%u;%lu;%lu;%.*s\n", COMPAS_NAM_PERIOD_BASE, ccnl->dodag.rank, ccnl->compas_dodag_parent_timeout,
                                              (unsigned long) (xtimer_now_usec64() - ccnl->compas_started),
                                              (unsigned long) (xtimer_now_usec64()),
                                              name->name_len, name->name);
    compas_nam_tlv_add_name(nam, name);

    if (nam->len == 0) {
        gnrc_pktbuf_release(pkt);
        return false;
    }

    gnrc_pktbuf_realloc_data(pkt, 2 + nam->len + sizeof(*nam));

    gnrc_pktsnip_t *hdr = gnrc_netif_hdr_build(NULL, 0, dodag->parent.face.face_addr, dodag->parent.face.face_addr_len);

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
