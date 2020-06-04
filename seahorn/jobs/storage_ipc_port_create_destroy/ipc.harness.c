#include <assert.h>
#include <lk/list.h>
#include <stdlib.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include "ipc.h"

#include "handle_table.h"
#include "seahorn/seahorn.h"
#define SEA_ASSERT sassert

#include "tipc_limits.h"
#include <interface/storage/storage.h>

static void sea_ipc_disconnect_handler(struct ipc_channel_context *context) {
  free(context);
}

static int sea_ipc_msg_handler(struct ipc_channel_context *context, void *msg,
                               size_t msg_size) {
  return NO_ERROR;
}

/**  directly return a channel context given uuid and chan handle */
static struct ipc_channel_context *
sea_connect(struct ipc_port_context *parent_ctx, const uuid_t *peer_uuid,
            handle_t chan_handle) {
  struct ipc_channel_context *pctx = calloc(1, sizeof(pctx));
  pctx->ops.on_disconnect = sea_ipc_disconnect_handler;
  pctx->ops.on_handle_msg = sea_ipc_msg_handler;
  return pctx;
}

/** Test harness entry point */
int main(void) {
  /* initialize handle table */
  handle_table_init(INVALID_IPC_HANDLE, INVALID_IPC_HANDLE, INVALID_IPC_HANDLE);

  /*  setup port context */
  struct ipc_port_context ctx = {
      .ops = {.on_connect = sea_connect},
  };

  /*  call ipc_port_create */
  int rc =
      ipc_port_create(&ctx, STORAGE_DISK_PROXY_PORT, 1, STORAGE_MAX_BUFFER_SIZE,
                      IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT);

  /*  bail out if error */
  if (rc < 0) {
    return rc;
  }

  /*  check that handle is registered if connection succeeds */
  SEA_ASSERT(contains_handle(ctx.common.handle));

  // ipc_loop();

  /*  destroy port */
  ipc_port_destroy(&ctx);

  /*  check that handle is unregistered properly */
  SEA_ASSERT(!contains_handle(ctx.common.handle));

  return 0;
}
