#pragma once
#include <stdlib.h>
#include <stdbool.h>

// #define sea_countof(arr) maybe_store_arr_len(arr, countof(arr))

/*  Return size of object pointed by \p ptr  */
size_t sea_get_alloc_size(void *ptr);

/*  Return true if the size of objected pointed to by \p ptr is known  */
bool sea_ptr_size_stored(void *ptr);

/* Return true if the length of the array pointed by \p arr is known */
bool sea_arr_len_stored(void *arr);

/* Return the length of the array pointed to by \p arr */
size_t sea_get_arr_len(void *arr);

/* TODO: figure out what this function is doing */
size_t sea_maybe_store_arr_len(void *arr, size_t len);
