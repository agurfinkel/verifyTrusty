/** Verify Trusty

    Implementation of TrustyOS Messaging API
    https://source.android.com/security/trusty/trusty-ref

 */

#include "seahorn/seahorn.h"
#include "nondet.h"
#include "handle_table.h"
#include "sea_mem_helper.h"

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>

// trusty reference for definitions only
#include <trusty_ipc.h> // -> ipc structs
#include <uapi/err.h> // NO_ERROR definition


static uint32_t cur_msg_id;
static bool cur_msg_retired = true;

static bool msg_retired(uint32_t msg_id) {
    return msg_id == cur_msg_id && cur_msg_retired;
}

/** Gets meta-information about the next message in an incoming message queue */
int get_msg(handle_t handle, ipc_msg_info_t *msg_info) {
  (void)handle;
  int retval = nd_get_msg_ret();
  size_t msg_len = nd_msg_len();
  uint32_t msg_id = nd_msg_id();
  if (retval == NO_ERROR) {
    assume(msg_len > 0);
    assume(msg_id > 0);
    cur_msg_id = msg_id;
    cur_msg_retired = false;
  } else {
    msg_len = 0;
    msg_id = 0;
  }
  msg_info->len = msg_len;
  msg_info->id = msg_id;
  return retval;
}

/*  Reads the content of the message with the specified ID starting from the
 * specified offset. */
ssize_t read_msg(handle_t handle, uint32_t msg_id, uint32_t offset,
                 ipc_msg_t *msg) {
  // return Total number of bytes stored in the dst buffers on success;
  // a negative error otherwise
  (void)handle;
  (void)offset;
  sassert(!msg_retired(msg_id));
  ssize_t res = nd_read_msg_ret();
  struct iovec *iovecs = msg->iov;
  size_t iovec_cnt = msg->num_iov;
  if (res >= 0) {
    for (size_t i = 0; i < iovec_cnt; i++) {
      /* check whether buffer allocated is enough for incoming msg */
      struct iovec iv = iovecs[i];
      if (sea_ptr_size_stored(iv.iov_base)) {
        sassert(sea_get_alloc_size(iv.iov_base) >= iv.iov_len);
      }
    }
  }
  return res;
}

/* Sends a message over a specified channel.*/
ssize_t send_msg(handle_t handle, ipc_msg_t *msg) {
  // Total number of bytes sent on success; a negative error otherwise
  (void)handle;
  ssize_t ret = nd_send_msg_ret();
  struct iovec *iovecs = msg->iov;
  size_t iovec_cnt = msg->num_iov;
  if (ret >= 0) {
    for (size_t i = 0; i < iovec_cnt; i++) {
      /* check whether buffer allocated is enough for incoming msg */
      struct iovec iv = iovecs[i];
      if (sea_ptr_size_stored(iv.iov_base)) {
        sassert(sea_get_alloc_size(iv.iov_base) >= iv.iov_len);
      }
    }
  }
  return ret;
}

/* Retires a message with a specified ID */
int put_msg(handle_t handle, uint32_t msg_id) {
  // return NO_ERROR on success; a negative error otherwise
  // assume(retval == NO_ERROR || retval < 0);
  (void)handle;
  if (cur_msg_id == msg_id) {
    cur_msg_retired = true;
  }
  return nd_int();
}

/* Waits for an event to occur on a given handle for specified period of time. */
int wait(handle_t handle, uevent_t *event, uint32_t timeout_msecs) {
  (void)timeout_msecs;
  int ret = nd_wait_ret();
  if (ret == NO_ERROR) {
    event->handle = handle;
    event->cookie = get_handle_cookie(event->handle);
    event->event = nd_event_flag();
    assume(event->event < (uint32_t)0x16); // max is (1111)2
  }
  return ret;
}

/* Wait for any kind of event, could be port or channel

   This implementation only handles the channel event of the latest port event
   if they happen to match.

   Update: assume if success, only returns handles currently on the table
*/
int wait_any(uevent_t *ev, uint32_t timeout_msecs) {
  (void)timeout_msecs;
  handle_t active_handle;
  uint32_t event_flag;
  // -- chose a handle of a currently active channel or port. break ties.
  if (is_current_chan_active()) {
    active_handle = get_current_chan_handle();
  } else if (is_secure_port_active()) {
    active_handle = get_secure_port_handle();
  } else if (is_non_secure_port_active()) {
    active_handle = get_non_secure_port_handle();
  } else {
    active_handle = nd_wait_handle();
  }
  ev->handle = active_handle;
  ev->cookie = get_handle_cookie(ev->handle);

  event_flag = nd_event_flag();
  assume(event_flag < (uint32_t)0x16); // max is (1111)2
  ev->event = event_flag;

  int ret = nd_wait_any_ret();
  assume(ret <= NO_ERROR);
  return ret;
}

/* Creates a named service port. */
handle_t port_create(const char *path, uint32_t num_recv_bufs,
                     uint32_t recv_buf_size, uint32_t flags) {
  (void)path;
  (void)num_recv_bufs;
  (void)recv_buf_size;
  handle_t retval = nd_port_handle();
  if (retval < 0)
    return retval; // return error message as is

  retval |= 0x2;   // is port, set 2nd bit to 1

  if ((flags & IPC_PORT_ALLOW_TA_CONNECT) &&
      !(flags & IPC_PORT_ALLOW_NS_CONNECT)) {
    // open secure port only, set 1st bit to 1
    retval |= 0x1;
  } else if (!(flags & IPC_PORT_ALLOW_TA_CONNECT) &&
             (flags & IPC_PORT_ALLOW_NS_CONNECT)) {
    // open non secure port only, set 1st bit to 0
    retval &= ~(0x1);
  }
  add_handle(retval);
  return retval;
}

/** Associates the caller-provided private data with a specified handle. */
int set_cookie(handle_t handle, void *cookie) {
  // the handle should at least be stored in the handle table?
  // similar check can be seen in trusty/kernel/lib/trusty/uctx.c
  // sassert(contains_handle(handle));
  if (!contains_handle(handle)) {return -1;}

  int ret = nd_set_cookie_ret(); // model other results (including failure)
  assume(ret <= 0); // NO_ERROR on success, < 0 error code otherwise
  if (ret == 0) {set_handle_cookie(handle, cookie);}
  return ret;
}

/** Accepts an incoming connection and gets a handle to a channel. */
handle_t accept(handle_t port_handle, uuid_t *peer_uuid) {
  (void)port_handle;
  handle_t chan = nd_chan_handle();
  if (chan >= 0) {
    assume(!(chan & 0x2)); // is channel
    // define peer_uuid to a dummy value
    peer_uuid->time_low = nd_time_low();
    peer_uuid->time_mid = nd_time_mid();
    peer_uuid->time_hi_and_version = nd_time_hi_n_ver();
    add_handle(chan);
  }
  return chan;
}

/** Destroys the resource associated with the specified handle and removes it
   from the handle table. */
int close(handle_t handle) {
    int ret = nd_close_ret();
    assume(ret <= 0); // "0 if success; a negative error otherwise"
    remove_handle(handle);
    return ret;
}
