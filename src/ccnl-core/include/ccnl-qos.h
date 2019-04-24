/*
 * @f ccnl-qos.h
 * @b CCN lite - header file for QoS
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

#ifndef CCN_LITE_QOS_H
#define CCN_LITE_QOS_H

#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QOS_MAX_TC_LENGTH (32)

typedef struct {
    char traffic_class[QOS_MAX_TC_LENGTH];
    bool expedited;
    bool reliable;
} qos_traffic_class_t;

qos_traffic_class_t *qos_traffic_class(char *name);

#ifdef __cplusplus
}
#endif
#endif /* CCN_LITE_QOS_H */
