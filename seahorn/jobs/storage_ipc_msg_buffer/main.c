#include <assert.h>
#include <lk/list.h>
#include <stdlib.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include "ipc.h"

#include "tipc_limits.h"
#include <interface/storage/storage.h>

#include "handle_table.h"
#include "seahorn/seahorn.h"

/** entry point in ipc.c for even handling */
extern void dispatch_event(const uevent_t *ev);

static void sea_ipc_disconnect_handler(struct ipc_channel_context *context) {
  if (context)
    free(context);
}

static int sea_ipc_msg_handler(struct ipc_channel_context *context, void *msg,
                               size_t msg_size) {
  // sassert(msg_size <= MSG_BUF_MAX_SIZE);
  struct iovec iov = {
      .iov_base = msg,
      .iov_len = msg_size,
  };
  ipc_msg_t i_msg = {
      .iov = &iov,
      .num_iov = 1,
  };
  int rc = send_msg(context->common.handle, &i_msg);
  if (rc < 0) {
    return rc;
  }
  return NO_ERROR;
}

/*
 * directly return a channel context given uuid and chan handle
 */
static struct ipc_channel_context *
sea_channel_connect(struct ipc_port_context *parent_ctx,
                    const uuid_t *peer_uuid, handle_t chan_handle) {
  struct ipc_channel_context *pctx = malloc(sizeof(struct ipc_channel_context));
  pctx->ops.on_disconnect = sea_ipc_disconnect_handler;
  pctx->ops.on_handle_msg = sea_ipc_msg_handler;
  return pctx;
}

/**
   verification entry point
 */
int main(void) {
  handle_table_init(INVALID_IPC_HANDLE, INVALID_IPC_HANDLE, INVALID_IPC_HANDLE);
  struct ipc_port_context ctx = {
      .ops = {.on_connect = sea_channel_connect},
  };
  int rc =
      ipc_port_create(&ctx, STORAGE_DISK_PROXY_PORT, 1, STORAGE_MAX_BUFFER_SIZE,
                      IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT);

  if (rc < 0) {
    return rc;
  }

  // ipc_loop();
  // first event should be port event
  uevent_t event1;
  event1.handle = INVALID_IPC_HANDLE;
  event1.event = 0;
  event1.cookie = NULL;
  rc = wait_any(&event1, INFINITE_TIME);
  if (rc < 0) {
    return rc;
  }
  if (rc == NO_ERROR) { /* got an event */
    dispatch_event(&event1);
  }
  // get second event, could be either port or channel
  uevent_t event2;
  event2.handle = INVALID_IPC_HANDLE;
  event2.event = 0;
  event2.cookie = NULL;
  rc = wait_any(&event2, INFINITE_TIME);
  if (rc < 0) {
    return rc;
  }
  if (rc == NO_ERROR) { /* got an event */
    dispatch_event(&event2);
  }

  ipc_port_destroy(&ctx);

  return 0;
}
