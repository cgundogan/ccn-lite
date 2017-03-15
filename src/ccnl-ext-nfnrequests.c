/*
 * @f ccnl-ext-nfncommon.c
 * @b CCN-lite, execution/state management of running computations
 *
 * Copyright (C) 2016, Balazs Faludi, University of Basel
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
 * 2016-02-10 created
 */


#ifdef USE_NFN_REQUESTS

enum nfn_request_type {
    NFN_REQUEST_TYPE_UNKNOWN = 0,
    NFN_REQUEST_TYPE_START,
    NFN_REQUEST_TYPE_PAUSE,
    NFN_REQUEST_TYPE_RESUME,
    NFN_REQUEST_TYPE_CANCEL,
    NFN_REQUEST_TYPE_STATUS,
    NFN_REQUEST_TYPE_KEEPALIVE,
    NFN_REQUEST_TYPE_COUNT_INTERMEDIATES,
    NFN_REQUEST_TYPE_GET_INTERMEDIATE,
    NFN_REQUEST_TYPE_MAX = NFN_REQUEST_TYPE_GET_INTERMEDIATE,
};

char *nfn_request_names[NFN_REQUEST_TYPE_MAX] = {
    "START",
    "PAUSE",
    "RESUME",
    "CANCEL",
    "STATUS",
    "KEEPALIVE",
    "CIM",
    "GIM"};

struct nfn_request_s {
    unsigned char *comp;
    int complen;
    enum nfn_request_type type;
    char *arg;
};

struct ccnl_prefix_s* ccnl_prefix_dup(struct ccnl_prefix_s *prefix);
void ccnl_nfnprefix_clear(struct ccnl_prefix_s *p, unsigned int flags);

struct nfn_request_s*
nfn_request_new(unsigned char *comp, int complen)
{
    struct nfn_request_s *request = 
        (struct nfn_request_s *) ccnl_calloc(1, sizeof(struct nfn_request_s));

    DEBUGMSG_CORE(TRACE, "nfn_request_new(%.*s)\n", complen, comp);

    if (!request)
        return NULL;

    request->complen = complen;
    request->comp = ccnl_malloc(complen);
    memcpy(request->comp, comp, complen);

    request->type = NFN_REQUEST_TYPE_UNKNOWN;
    char *request_name = NULL;
    int request_len = 0;

    int i;
    for (i = 0; i < NFN_REQUEST_TYPE_MAX; i++) {
        request_name = nfn_request_names[i];
        request_len = strlen(request_name);
        if (request_len <= complen && strncmp(request_name, (char *)comp, request_len) == 0) {
            request->type = (enum nfn_request_type)i+1; // 0 is "unknown"
            break;
        }
    }

    if (request->type == NFN_REQUEST_TYPE_UNKNOWN) {
        DEBUGMSG_CORE(DEBUG, "Unknown request: %.*s\n", complen, comp);
        return request;
    }

    request->arg = NULL;
    if (complen >= request_len + 2 && comp[request_len] == ' ') {
        int arglen = complen - request_len - 1;
        // request->arg = request->comp + request_len + 1;
        request->arg = ccnl_malloc(arglen + 1);
        strncpy(request->arg, (char *)comp + request_len + 1, arglen);
        request->arg[arglen] = '\0';
    }

    return request;
}

struct nfn_request_s*
nfn_request_copy(struct nfn_request_s *request)
{
    if (request == NULL) {
        return NULL;
    } 
    return nfn_request_new(request->comp, request->complen);
}

void 
nfn_request_free(struct nfn_request_s *request)
{
    if (request) {
        if (request->comp) {
            ccnl_free(request->comp);
        }
        if (request->arg) {
            ccnl_free(request->arg);
        }
        ccnl_free(request);
    }
}

int 
nfn_request_get_arg_int(struct nfn_request_s* request)
{
    // TODO: verify arg, error handling
    // TODO: add arg index as parameter
    return strtol(request->arg, NULL, 0);
}

void // TODO: is this still needed?
nfn_request_set_arg_int(struct nfn_request_s* request, int arg)
{
    if (request->arg) {
        ccnl_free(request->arg);
    }
    int arglen = snprintf(NULL, 0, "%d", arg);
    request->arg = ccnl_malloc(arglen+1);
    sprintf(request->arg, "%d", arg);
}

void // TODO: is this still needed?
nfn_request_update_component(struct nfn_request_s *request)
{
    if (request->comp) {
        ccnl_free(request->comp);
    }
    char *command = nfn_request_names[request->type];
    int commandlen = strlen(command);
    int arglen = strlen(request->arg);
    request->complen = commandlen + 1 + arglen;
    request->comp = ccnl_malloc(request->complen);
    memcpy(request->comp, command, commandlen);
    request->comp[commandlen] = (unsigned char)" ";
    memcpy(request->comp + commandlen + 1, request->arg, arglen);
}

char *
nfn_request_description_new(struct nfn_request_s* request)
{
    int len = 0;
    char *buf = (char*) ccnl_malloc(256);
    
    if (request == NULL) {
        len += sprintf(buf + len, "request(NULL)");
    } else {
        len += sprintf(buf + len, "request(");
        if (request->complen > 0) {
            len += sprintf(buf + len, "comp: %.*s, ", request->complen, request->comp);
        }
        if (request->type == NFN_REQUEST_TYPE_UNKNOWN) {
            len += sprintf(buf + len, "type: %s, ", "UNKNOWN");
        } else {
            len += sprintf(buf + len, "type: %s, ", nfn_request_names[request->type-1]);
        }
        len += sprintf(buf + len, "arg: %s", request->arg);
        len += sprintf(buf + len, ")");
    }

    buf[len] = '\0';
    return buf;
}

// Return the highest consecutive intermediate number for the prefix, starts with 0.
// -1 if no intermediate result is found.
int nfn_request_intermediate_num(struct ccnl_relay_s *relay, struct ccnl_prefix_s *prefix) {
    struct ccnl_content_s *c;
    int highest = -1;
    for (c = relay->contents; c; c = c->next) {
        if (ccnl_nfnprefix_isIntermediate(c->pkt->pfx)) {
            if (prefix->compcnt == ccnl_prefix_cmp(prefix, NULL, c->pkt->pfx, CMP_LONGEST)) {
                int internum = nfn_request_get_arg_int(c->pkt->pfx->request);
                if (highest < internum) {
                    highest = internum;
                }
            }
        }
    }
    return highest;
}

int
nfn_request_handleInterest(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                           struct ccnl_pkt_s **pkt, cMatchFct cMatch)
{
    switch ((*pkt)->pfx->request->type) {
        case NFN_REQUEST_TYPE_KEEPALIVE: {
            DEBUGMSG_CFWD(DEBUG, "  is a keepalive interest\n");
            if (ccnl_nfn_already_computing(relay, (*pkt)->pfx)) {
                DEBUGMSG_CFWD(DEBUG, "  running computation found");
                struct ccnl_buf_s *buf = ccnl_mkSimpleContent((*pkt)->pfx, NULL, 0, NULL);
                ccnl_face_enqueue(relay, from, buf);
                return 0;
            } else {
                DEBUGMSG_CFWD(DEBUG, "  no running computation found.\n");
            }
            break;
        }
        case NFN_REQUEST_TYPE_COUNT_INTERMEDIATES: {
            DEBUGMSG_CFWD(DEBUG, "  is a count intermediates interest\n");
            if (ccnl_nfn_already_computing(relay, (*pkt)->pfx)) {
                int internum = nfn_request_intermediate_num(relay, (*pkt)->pfx);
                DEBUGMSG_CFWD(DEBUG, "  highest intermediate result: %i\n", internum);
                int offset;
                char reply[16];
                snprintf(reply, 16, "%d", internum);
                int size = internum >= 0 ? strlen(reply) : 0;
                struct ccnl_buf_s *buf  = ccnl_mkSimpleContent((*pkt)->pfx, (unsigned char *)reply, size, &offset);
                ccnl_face_enqueue(relay, from, buf);
                return 0;
            } else {
                DEBUGMSG_CFWD(DEBUG, "  no running computation found.\n");
            }
            break;
        }
        case NFN_REQUEST_TYPE_GET_INTERMEDIATE: {
            DEBUGMSG_CFWD(DEBUG, "  is a get intermediates interest\n");
            break;
        }
        default: {
            DEBUGMSG_CFWD(DEBUG, "  Unknown request type.\n");
            break;
        }
    }
    return 0;
}



#endif

// eof
