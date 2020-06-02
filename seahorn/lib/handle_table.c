/**
   Channel and Port Handles.

   Current implementation supports one channel, one secure port,  and one non-secure port.

   A channel/port is active if a handle is registered for it.

   All handles are distinct. Ties are broken by priority on ports and channels (see code for details).
 */
#include "handle_table.h"

// only allow access from functions within this file
static handle_table_t ht;

void handle_table_init(handle_t secure_port, handle_t non_secure_port, handle_t channel) {
    ht.secure_port_handle = secure_port;
    ht.secure_port_handle_active = secure_port != INVALID_IPC_HANDLE;

    ht.non_secure_port_handle = non_secure_port;
    ht.non_secure_port_handle_active = non_secure_port != INVALID_IPC_HANDLE;

    ht.chan_handle = channel;
    ht.chan_handle_active = channel != INVALID_IPC_HANDLE;
    return;
}

#define IS_PORT_HANDLE(h) ((h) & 0x2)
#define IS_SECURE_HANDLE(h) ((h) & 0x1)
void add_handle(handle_t handle) {
  if (IS_PORT_HANDLE(handle)) {
    if (IS_SECURE_HANDLE(handle)) {
      ht.secure_port_handle = handle;
      ht.secure_port_handle_active = true;
    } else {
      ht.non_secure_port_handle = handle;
      ht.non_secure_port_handle_active = true;
    }
  } else {
    ht.chan_handle = handle;
    ht.chan_handle_active = true;
  }
}

void remove_handle(handle_t handle) {
  if (handle == ht.secure_port_handle) {
    ht.secure_port_handle_active = false;
  } else if (handle == ht.non_secure_port_handle) {
    ht.non_secure_port_handle_active = false;
  } else if (handle == ht.chan_handle) {
    ht.chan_handle_active = false;
  }
}

bool contains_handle(handle_t handle) {
  if (handle == ht.secure_port_handle) {
    return ht.secure_port_handle_active;
  } else if (handle == ht.non_secure_port_handle) {
    return ht.non_secure_port_handle_active;
  } else if (handle == ht.chan_handle) {
    return ht.chan_handle_active;
  }
  return false;
}

void *get_handle_cookie(handle_t handle) {
  if (handle == ht.secure_port_handle) {
    return ht.secure_port_cookie;
  } else if (handle == ht.non_secure_port_handle) {
    return ht.non_secure_port_cookie;
  } else if (handle == ht.chan_handle) {
    return ht.chan_cookie;
  }
  return NULL;
}

void set_handle_cookie(handle_t handle, void *cookie) {
  if (handle == ht.secure_port_handle) {
    ht.secure_port_cookie = cookie;
  } else if (handle == ht.non_secure_port_handle) {
    ht.non_secure_port_cookie = cookie;
  } else if (handle == ht.chan_handle) {
    ht.chan_cookie = cookie;
  }
}

handle_t get_secure_port_handle(void) {return ht.secure_port_handle;}
handle_t get_non_secure_port_handle(void) {return ht.non_secure_port_handle;}
handle_t get_current_chan_handle(void) {return ht.chan_handle;}

bool is_secure_port_active(void) {return ht.secure_port_handle_active;}
bool is_non_secure_port_active(void) {return ht.non_secure_port_handle_active;}
bool is_current_chan_active(void) {return ht.chan_handle_active;}

