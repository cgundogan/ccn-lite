/*
 * @f pkt-ndntlv.h
 * @b CCN lite - header file for NDN (TLV pkt format March 2014)
 *
 * Copyright (C) 2014-15, Christian Tschudin, University of Basel
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
 * 2014-03-05 created
 */

#ifndef CCNL_PKT_NDNTLV_H
#define CCNL_PKT_NDNTLV_H

#include <stdint.h>
#include <stddef.h>

#include "ccnl-content.h"
#include "ndnv03/data.h"

/**
 * Default interest lifetime in milliseconds. If the element is omitted by a user, a default
 * value of 4 seconds is used.
 */
#ifndef NDN_DEFAULT_INTEREST_LIFETIME
#define NDN_DEFAULT_INTEREST_LIFETIME (4000u)
#endif

#define NDN_UDP_PORT                    6363
#define NDN_DEFAULT_MTU                 4096

struct ccnl_ndntlv03_interest_s {
    uint32_t nonce;                   /**< nonce of the interest */
    uint32_t lifetime;                /**< lifetime of the interest */

    uint8_t can_be_prefix;            /**< if present, the name element in the interest is a prefix, exact, or full name of the requested data packet */

    uint8_t must_be_fresh;            /**< indicates whether a content store may satisfy the interest with stale data */

    /* TODO add parameters TLV */

    uint8_t hop_limit;                /**< hop limit */

    uint8_t lifetime_enabled :1;      /**< indicates if the lifetime field is set*/
    uint8_t can_be_prefix_enabled :1; /**< indicates if @ref can_be_prefix field is set */
    uint8_t must_be_fresh_enabled :1; /**< indicates if @ref must_be_fresh field is set */
    uint8_t parameters_enabled :1;    /**< indicates if parameters field is set */
    uint8_t hop_limit_enabled :1;     /**< indicates if field @ref hop_limit is set */
};

struct ccnl_ndntlv03_data_s {
    ndn_data_metainfo_t metainfo;          /**< MetaInfo TLV */
    ndn_data_content_t content;            /**< Content TLV */
    uint8_t metainfo_enabled :1;           /**< indicates if @ref metainfo is included */
    uint8_t contenttype_enabled :1;        /**< indicates if @ref metainfo::contenttype is set */
    uint8_t freshnessperiod_enabled :1;    /**< indicates if @ref metainfo::freshnessperiod is set */
    uint8_t finalblockid_enabled :1;       /**< indicates if @ref metainfo::finalblockid is set */
    uint8_t content_enabled :1;            /**< indicates if @ref content is set */
};

/**
 * @brief NDN Interest options
 */
struct ccnl_ndntlv_interest_opts_s {
    int32_t nonce;              /**< Nonce value */
    /* Selectors */
    uint8_t mustbefresh;           /**< MustBeFresh Selector */
    /* Guiders */
    uint32_t interestlifetime;  /**< Interest Lifetime Guider */
};

/**
 * @brief NDN Data options
 */
struct ccnl_ndntlv_data_opts_s {
    /* MetaInfo */
    uint32_t freshnessperiod;       /**< freshness period */
    /* FinalBlockID is actually from type NameComponent.
     * Use integer for simplicity for now */
    uint32_t finalblockid;          /**< final block ID */
};

/**
 * Opens a TLV and reads the Type and the Length Value
 * @param buf allocated buffer in which the tlv should be opened
 * @param len length of the buffer
 * @param typ return value via pointer: type value of the tlv
 * @param vallen return value via pointer: length value of the tlv
 * @return 0 on success, -1 on failure.
 */
int8_t
ccnl_ndntlv_dehead(uint8_t **buf, size_t *len,
                   uint64_t *typ, size_t *vallen);

struct ccnl_pkt_s*
ccnl_ndntlv_bytes2pkt(uint64_t pkttype, uint8_t *start,
                      uint8_t **data, size_t *datalen);

int8_t
ccnl_ndntlv_cMatch(struct ccnl_pkt_s *p, struct ccnl_content_s *c);

int8_t
ccnl_ndntlv_prependInterest(struct ccnl_prefix_s *name, int scope, struct ccnl_ndntlv_interest_opts_s *opts,
                            size_t *offset, uint8_t *buf, size_t *reslen);

int8_t
ccnl_ndntlv_prependContent(struct ccnl_prefix_s *name,
                           uint8_t *payload, size_t paylen,
                           size_t *contentpos, struct ccnl_ndntlv_data_opts_s *opts,
                           size_t *offset, uint8_t *buf, size_t *reslen);

static inline bool
ccnl_ndntlv_is_data(unsigned type) {
    return (type == tlv_data);
}

#endif /* CCNL_PKT_NDNTLV_H */
