/*
 * @f pkt-qos.c
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
#include "pkt-qos.h"

#define QOS_MAX_TC_ENTRIES (4)
#define QOS_MAX_TC_LENGTH (16)

char tcs[QOS_MAX_TC_ENTRIES][QOS_MAX_TC_LENGTH] =
{
    "/HAW",
    "/SafetyIO/Site/A",
};

char *qos_traffic_class(char *name)
{
    const size_t tcs_len = sizeof(tcs) / sizeof(tcs[0]);
    const size_t name_len = strlen(name);

    size_t len;

    char *class = NULL;

    for (size_t i = 0; i < tcs_len; i++) {
        len = strlen(tcs[i]);
        if (name_len < len) {
            continue;
        }

        if (memcmp(tcs[i], name, len) == 0) {
            if ((name_len > len) && (name[len] == '/')) {
                if (len > strlen(class)) {
                    class = tcs[i];
                }
            }
        }
    }

    return class;
}
