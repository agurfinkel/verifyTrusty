#pragma once
#include <trusty_ipc.h> // for INVALID_IPC_HANDLE and handle_t
#include "seahorn/seahorn.h"
#ifndef __cplusplus
#include <stdbool.h>
#endif
/*
Single class for holding a map of handles
*/
#ifdef __cplusplus
extern "C" {
#endif
struct handle_table {
    // In keymaster_ipc, assuming handles are treated one by one,
    // each either "handled" or removed by close(),
    // so one handle_t each for port and channel is sufficient
    handle_t secure_port_handle;
    bool secure_port_handle_active;
    void* secure_port_cookie;

    handle_t non_secure_port_handle;
    bool non_secure_port_handle_active;
    void* non_secure_port_cookie;

    handle_t chan_handle;
    bool chan_handle_active;
    void* chan_cookie;
};

void add_handle(handle_t handle);
void remove_handle(handle_t handle);
bool contains_handle(handle_t handle);
void* get_handle_cookie(handle_t handle);
void set_handle_cookie(handle_t handle, void* cookie);
#ifdef __cplusplus
}
#endif
