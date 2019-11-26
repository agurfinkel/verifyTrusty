#include <stdint.h>

#pragma once
#ifdef __cplusplus
extern "C" {
#endif
long nd_long(void);
uint16_t nd_short(void);
int32_t nd_int(void);
uint8_t nd_char(void);
uint32_t nd_unsigned(void);
void* nd_ptr(void);
#ifdef __cplusplus
}
#endif
