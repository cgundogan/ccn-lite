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
#include "sys/socket.h"
#include "ccnl-defs.h"
#include "ccnl-core.h"
#include "ccnl-headers.h"

#include "compas/routing/nam.h"
#include "compas/routing/pam.h"

void compas_dodag_parent_timeout(struct ccnl_relay_s *ccnl)
{
    ccnl->compas_dodag_parent_timeout = 1;
    ccnl->dodag.flags |= COMPAS_DODAG_FLAGS_FLOATING;
}

#if defined(CCNL_RIOT)
bool compas_send(struct ccnl_relay_s *ccnl, void *param, uint8_t *addr, uint8_t addr_len)
{
    gnrc_pktsnip_t *pkt = (gnrc_pktsnip_t *) param;
    gnrc_pktsnip_t *hdr = gnrc_netif_hdr_build(NULL, 0, addr, addr_len);

    if (hdr == NULL) {
        puts("error: packet buffer full");
        gnrc_pktbuf_release(pkt);
        return false;
    }

    LL_PREPEND(pkt, hdr);

    if (!addr) {
        gnrc_netif_hdr_t *nethdr = (gnrc_netif_hdr_t *)hdr->data;
        nethdr->flags = GNRC_NETIF_HDR_FLAGS_BROADCAST;
    }

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
#endif

void compas_send_pam(struct ccnl_relay_s *ccnl)
{
    compas_dodag_t *dodag = &ccnl->dodag;
    (void) dodag;

#if defined(CCNL_RIOT)
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_pam_len(dodag) + 2, GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("error: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_COMPAS;
    compas_pam_create(dodag, (compas_pam_t *) (((uint8_t *) pkt->data) + 2));

    compas_send(ccnl, pkt, NULL, 0);
#else
#ifdef USE_WPAN
    struct ccnl_buf_s *buf;
    int datalen = sizeof(*buf) + compas_pam_len(dodag) + 2;
    buf = ccnl_malloc(datalen);
    buf->data[0] = 0x80;
    buf->data[1] = CCNL_ENC_COMPAS;
    compas_pam_create(dodag, (compas_pam_t *) (buf->data + 2));
    buf->next = NULL;
    buf->datalen = datalen;

    struct ccnl_face_s *face = NULL;
    sockunion sun;
    /* initialize address with 0xFF for broadcast */
    sun.sa.sa_family = AF_IEEE802154;
    sun.wpan.addr.addr_type = IEEE802154_ADDR_SHORT;
    sun.wpan.addr.pan_id = 0xffff;
    sun.wpan.addr.addr.short_addr = 0xffff;

    face = ccnl_get_face_or_create(ccnl, 0, &sun.sa, sizeof(sun.wpan));
    if (face) {
        ccnl_face_enqueue(ccnl, face, buf);
    }
#endif
#endif
}

bool compas_send_nam(struct ccnl_relay_s *ccnl, const compas_name_t *name)
{
    compas_dodag_t *dodag = &ccnl->dodag;

    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        puts("Error: not part of a DODAG");
        return false;
    }

#if defined(CCNL_RIOT)
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL,
                                          2 + sizeof(compas_nam_t) +
                                          name->name_len + sizeof(compas_tlv_t),
                                          GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("error: packet buffer full");
        return false;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_COMPAS;
    compas_nam_t *nam = (compas_nam_t *)(((uint8_t *) pkt->data) + 2);
    compas_nam_create(nam);
    compas_nam_tlv_add_name(nam, name);

    if (nam->len == 0) {
        gnrc_pktbuf_release(pkt);
        return false;
    }

    gnrc_pktbuf_realloc_data(pkt, 2 + nam->len + sizeof(*nam));
    return compas_send(ccnl, pkt, dodag->parent.face.face_addr, dodag->parent.face.face_addr_len);

#else
#ifdef USE_WPAN
    struct ccnl_buf_s *buf;
    int datalen = sizeof(*buf) + 2 + sizeof(compas_nam_t) + name->name_len +
                  sizeof(compas_tlv_t);
    buf = ccnl_malloc(datalen);
    buf->data[0] = 0x80;
    buf->data[1] = CCNL_ENC_COMPAS;
    compas_nam_t *nam = (compas_nam_t *)(buf->data + 2);
    compas_nam_create(nam);
    compas_nam_tlv_add_name(nam, name);
    buf->next = NULL;
    buf->datalen = datalen;

    if (ccnl->dodag_face) {
        ccnl_face_enqueue(ccnl, ccnl->dodag_face, buf);
        return true;
    }

#endif
    return false;
#endif
}

bool compas_handle_nam(struct ccnl_relay_s *ccnl)
{
    bool work_to_do = false;
    ccnl->compas_nam_timer_running = 0;
    if ((ccnl->dodag.rank != COMPAS_DODAG_ROOT_RANK) && !ccnl->compas_dodag_parent_timeout) {
        for (compas_nam_cache_entry_t *n = ccnl->dodag.nam_cache;
             n < ccnl->dodag.nam_cache + COMPAS_NAM_CACHE_LEN;
             ++n) {
            if (n->in_use) {
                char tmp[COMPAS_NAME_LEN + 1];
                memcpy(tmp, n->name.name, n->name.name_len);
                tmp[n->name.name_len] = '\0';
                struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(tmp, CCNL_SUITE_NDNTLV, NULL, NULL);

                bool found = false;
                for (struct ccnl_content_s *c = ccnl->contents; c; c = c->next) {
                    if (!ccnl_prefix_cmp(c->pkt->pfx, NULL, prefix, CMP_EXACT)) {
                        found = true;
                        break;
                    }
                }
                free_prefix(prefix);
                if (!found) {
                    memset(n, 0, sizeof(*n));
                    continue;
                }

                if (!compas_nam_cache_requested(n->flags)) {
                    if (n->retries--) {
                        compas_send_nam(ccnl, &n->name);
                        work_to_do = true;
                        ccnl->compas_nam_timer_running = 1;
                    }
                    else {
                        n->retries = COMPAS_NAM_CACHE_RETRIES;
                        compas_dodag_parent_timeout(ccnl);
                        work_to_do = false;
                        break;
                    }
                }
            }
        }
    }
    return work_to_do;
}

#ifndef CCNL_RIOT
void ccnl_compas_send_pam(void *arg1, void *arg2)
{
    (void) arg2;
    struct ccnl_relay_s *ccnl = (struct ccnl_relay_s *) arg1;

    if (ccnl->dodag.rank != COMPAS_DODAG_UNDEF) {
        compas_send_pam(ccnl);
        ccnl_set_timer(COMPAS_PAM_PERIOD, ccnl_compas_send_pam, ccnl, NULL);
    }
}

void ccnl_compas_send_nam(void *arg1, void *arg2)
{
    (void) arg2;
    struct ccnl_relay_s *ccnl = (struct ccnl_relay_s *) arg1;

    if (compas_handle_nam(ccnl)) {
        ccnl_set_timer(COMPAS_NAM_PERIOD, ccnl_compas_send_nam, ccnl, NULL);
    }
}

void ccnl_compas_timeout(void *arg1, void *arg2)
{
    (void) arg2;
    struct ccnl_relay_s *ccnl = (struct ccnl_relay_s *) arg1;

    compas_dodag_parent_timeout(ccnl);
}
#endif
