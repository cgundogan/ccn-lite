#include <stdint.h>
#include "ndnv03/ccnl-pkt-ndntlv.h"
#include <ccnl-core.h>
#include "ndnv03/buffer.h"
#include "ndnv03/tlv.h"
#include "ndnv03/interest.h"
#include "ndnv03/data.h"

int8_t
ccnl_ndntlv_dehead(uint8_t **buf, size_t *len,
                   uint64_t *typ, size_t *vallen)
{
    buffer_read_t buffer = { .buffer = *buf, .offset = 0, .length = *len };

    tlfield_decode(&buffer, (tlfield_t *) typ);
    tlfield_decode(&buffer, (tlfield_t *) vallen);

    *len -= buffer.offset;
    *buf += buffer.offset;

    return 0;
}

struct ccnl_pkt_s*
ccnl_ndntlv_bytes2pkt(uint64_t pkttype, uint8_t *start,
                      uint8_t **data, size_t *datalen)
{
    struct ccnl_pkt_s *pkt = NULL;

    if ((pkt = (struct ccnl_pkt_s *) ccnl_calloc(1, sizeof(struct ccnl_pkt_s))) == NULL) {
        return NULL;
    }

    pkt->type = pkttype;
    pkt->suite = CCNL_SUITE_NDNTLV;

    switch (pkt->type) {
    case tlv_interest:
        pkt->flags |= CCNL_PKT_REQUEST;
        break;
    case tlv_data:
        pkt->flags |= CCNL_PKT_REPLY;
        break;
    default:
        ccnl_pkt_free(pkt);
        return NULL;
    }
    
    return NULL;
}

int8_t
ccnl_ndntlv_cMatch(struct ccnl_pkt_s *p, struct ccnl_content_s *c)
{
    return 0;
}

int8_t
ccnl_ndntlv_prependInterest(struct ccnl_prefix_s *name, int scope, struct ccnl_ndntlv_interest_opts_s *opts,
                            size_t *offset, uint8_t *buf, size_t *reslen)
{
    return 0;
}

int8_t
ccnl_ndntlv_prependContent(struct ccnl_prefix_s *name,
                           uint8_t *payload, size_t paylen,
                           size_t *contentpos, struct ccnl_ndntlv_data_opts_s *opts,
                           size_t *offset, uint8_t *buf, size_t *reslen)
{
    return 0;
}
