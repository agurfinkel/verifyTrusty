#include "handle_table.h"

// only allow access from functions within this file
static struct handle_table ht = {
    .secure_port_handle = INVALID_IPC_HANDLE,
    .secure_port_handle_active = false,
    .secure_port_cookie = NULL,

    .non_secure_port_handle = INVALID_IPC_HANDLE,
    .non_secure_port_handle_active = false,
    .non_secure_port_cookie = NULL,

    .chan_handle = INVALID_IPC_HANDLE,
    .chan_handle_active = false,
    .chan_cookie = NULL,
};

void add_handle(handle_t handle) {
    if (handle & 0x2) { // port
        // assume(!ht.port_handle_active);
        if (handle & 0x1) { // secure port
            ht.secure_port_handle = handle;
            ht.secure_port_handle_active = true;
        } else {
            ht.non_secure_port_handle = handle;
            ht.non_secure_port_handle_active = true;
        }
   } else {
        // assume(!ht.chan_handle_active);
        ht.chan_handle = handle;
        ht.chan_handle_active = true;
   }
}

void remove_handle(handle_t handle) {
    if (handle == ht.secure_port_handle)
    {
        ht.secure_port_handle_active = false;
    }
    else if (handle == ht.non_secure_port_handle)
    {
        ht.non_secure_port_handle_active = false;
    }
    else if (handle == ht.chan_handle)
    {
        ht.chan_handle_active = false;
    }
}

bool contains_handle(handle_t handle) {
    if (handle == ht.secure_port_handle)
    {
        return ht.secure_port_handle_active;
    }
    else if (handle == ht.non_secure_port_handle)
    {
        return ht.non_secure_port_handle_active;
    }
    else if (handle == ht.chan_handle)
    {
        return ht.chan_handle_active;
    }
    else return false;
}

void* get_handle_cookie(handle_t handle) {
    if (handle == ht.secure_port_handle)
    {
        return ht.secure_port_cookie;
    }
    else if (handle == ht.non_secure_port_handle)
    {
        return ht.non_secure_port_cookie;
    }
    else if (handle == ht.chan_handle)
    {
        return ht.chan_cookie;
    }
    else return nullptr;
}

void set_handle_cookie(handle_t handle, void* cookie) {
    if (handle == ht.secure_port_handle)
    {
        ht.secure_port_cookie = cookie;
    }
    else if (handle == ht.non_secure_port_handle)
    {
        ht.non_secure_port_cookie = cookie;
    }
    else if (handle == ht.chan_handle)
    {
        ht.chan_cookie = cookie;
    }
}
