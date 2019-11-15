#include <stdlib.h>

void *realloc( void *ptr, size_t new_size ) {
    if (ptr) {
        free(ptr);
    }
    ptr = malloc(new_size);
    return ptr;
}
