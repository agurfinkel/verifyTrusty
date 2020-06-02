/** Verify Trusty

    Implementation of realloc()

 */

#include "sea_mem_helper.h"
#include "nondet.h"

#include <stdint.h>
#include <stddef.h>

int8_t *g_ptr0 = NULL;
size_t g_ptr0_size;

void *realloc(void *ptr, size_t new_size) {
  if (ptr) {free(ptr);}

  ptr = malloc(new_size);

  /** instrumentation for memory checking properties */
  /** TODO: factor out from generic realloc() implementation */
  if (nd_store_mem_size() && g_ptr0 == NULL) {
    g_ptr0 = (int8_t *)ptr;
    g_ptr0_size = new_size;
  }
  return ptr;
}

/** Helper functions to get access to meta-data about allocated memory */
bool sea_ptr_size_stored(void *ptr) {
  return ptr != NULL && (int8_t *)ptr == g_ptr0 && g_ptr0_size > 0;
}

size_t sea_get_alloc_size(void *ptr) {
  if ((int8_t *)ptr == g_ptr0)
    return g_ptr0_size;
  return nd_get_alloc_size();
}
