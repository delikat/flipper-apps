#pragma once

#include <stddef.h>
#include <stdint.h>

static inline void tesla_secure_zero(void* data, size_t size) {
    volatile uint8_t* bytes = data;
    while(size-- != 0U)
        *bytes++ = 0;
}
