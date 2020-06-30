/** Verify Trusty */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/**
   Implementation of libc realloc()
 */
void *realloc(void *ptr, size_t new_size) {
  if (ptr) {free(ptr);}
  ptr = malloc(new_size);
  return ptr;
}
