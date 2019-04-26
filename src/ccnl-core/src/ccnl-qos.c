/*
 * @f ccnl-qos.c
 * @b QoS
 *
 * Copyright (C) 2019 HAW Hamburg
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
 */

#include <string.h>
#include "ccnl-qos.h"

static qos_traffic_class_t *tcs = NULL;
static size_t tcs_len = 0;

void ccnl_qos_set_tcs(qos_traffic_class_t *arg, size_t len)
{
    tcs = arg;
    tcs_len = len;
}

qos_traffic_class_t *qos_traffic_class(char *name)
{
    const size_t name_len = strlen(name);

    size_t len;

    qos_traffic_class_t *class = NULL;

    for (qos_traffic_class_t *tc = tcs; tc < (tcs + tcs_len); tc++) {
        len = strlen(tc->traffic_class);
        if (name_len < len) {
            continue;
        }

        if (memcmp(tc->traffic_class, name, len) == 0) {
            if ((name_len == len) || ((name_len > len) && (name[len] == '/'))) {
                if (!class || (len > strlen(class->traffic_class))) {
                    class = tc;
                }
            }
        }
    }

    return class;
}
