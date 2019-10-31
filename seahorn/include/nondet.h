#include <stdint.h>

#pragma once
extern "C" {
    long nd(void);
    long nd_read(void);
    long nd_get(void);
    long nd_put(void);
    long nd_send(void);
    long nd_get_len(void);
    long nd_get_id(void);
    uint8_t nd_message_read(void);
}
