/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <assert.h>
#include <lk/list.h>
#include <stdlib.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include "ipc.h"

#include "seahorn/seahorn.h"
#include "handle_table.h"

#include <interface/storage/storage.h>
#include "tipc_limits.h"

#define MSG_BUF_MAX_SIZE 4096

#define TLOG_TAG "ss-ipc"

static void* msg_buf;
static size_t msg_buf_size;

static void handle_channel(struct ipc_context* ctx, const struct uevent* ev);
static void handle_port(struct ipc_context* ctx, const struct uevent* ev);

int mock_ipc_msg_handler(struct ipc_channel_context* context, void* msg, size_t msg_size);

static int maybe_grow_msg_buf(size_t new_max_size) {
    if (new_max_size > msg_buf_size) {
        uint8_t* tmp = realloc(msg_buf, new_max_size);
        if (tmp == NULL) {
            return ERR_NO_MEMORY;
        }
        msg_buf = tmp;
        msg_buf_size = new_max_size;
    }
    return NO_ERROR;
}

static inline void handle_port_errors(const uevent_t* ev) {
    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_HUP) ||
        (ev->event & IPC_HANDLE_POLL_MSG) ||
        (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        /* should never happen with port handles */
        TLOGE("error event (0x%x) for port (%d)\n", ev->event, ev->handle);
        abort();
    }
}

static inline void handle_chan_errors(const uevent_t* ev) {
    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_READY)) {
        TLOGE("error event (0x%x) for chan (%d)\n", ev->event, ev->handle);
        abort();
    }
}

static int is_valid_port_ops(struct ipc_port_ops* ops) {
    return (ops->on_connect != NULL);
}

static bool is_valid_chan_ops(struct ipc_channel_ops* ops) {
    return (ops->on_disconnect != NULL);
}

static struct ipc_port_context* to_port_context(struct ipc_context* context) {
    assert(context);
    return containerof(context, struct ipc_port_context, common);
}

static struct ipc_channel_context* to_channel_context(
        struct ipc_context* context) {
    assert(context);
    return containerof(context, struct ipc_channel_context, common);
}

static int do_connect(struct ipc_port_context* ctx, const uevent_t* ev) {
    int rc;
    handle_t chan_handle;
    struct ipc_channel_context* chan_ctx;

    if (ev->event & IPC_HANDLE_POLL_READY) {
        /* incoming connection: accept it */
        uuid_t peer_uuid;
        rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            TLOGE("failed (%d) to accept on port %d\n", rc, ev->handle);
            return rc;
        }

        chan_handle = (handle_t)rc;

        chan_ctx = ctx->ops.on_connect(ctx, &peer_uuid, chan_handle);
        if (chan_ctx == NULL) {
            TLOGE("%s: failure initializing channel state (%d)\n", __func__,
                  rc);
            rc = ERR_GENERIC;
            goto err_on_connect;
        }

        assert(is_valid_chan_ops(&chan_ctx->ops));

        chan_ctx->common.evt_handler = handle_channel;
        chan_ctx->common.handle = chan_handle;

        rc = set_cookie(chan_handle, chan_ctx);
        if (rc < 0) {
            TLOGE("failed (%d) to set_cookie on chan %d\n", rc, chan_handle);
            goto err_set_cookie;
        }
        list_add_tail(&ctx->channels, &chan_ctx->node);
    }

    return NO_ERROR;

err_set_cookie:
    chan_ctx->ops.on_disconnect(chan_ctx);
err_on_connect:
    close(chan_handle);
    return rc;
}

static int do_handle_msg(struct ipc_channel_context* ctx, const uevent_t* ev) {
    handle_t chan = ev->handle;

    /* get message info */
    ipc_msg_info_t msg_inf;
    int rc = get_msg(chan, &msg_inf);
    if (rc == ERR_NO_MSG)
        return NO_ERROR; /* no new messages */

    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to get_msg for chan (%d), closing connection\n", rc,
              chan);
        return rc;
    }

    // sassert( (rc == NO_ERROR) == (msg_inf.len > 0));

    if (msg_inf.len > MSG_BUF_MAX_SIZE) {
        TLOGE("%s: message too large %zu\n", __func__, msg_inf.len);
        put_msg(chan, msg_inf.id);
        return ERR_NOT_ENOUGH_BUFFER;
    }

    /* read msg content */
    struct iovec iov = {
            .iov_base = msg_buf,
            .iov_len = msg_inf.len,
    };
    ipc_msg_t msg = {
            .iov = &iov,
            .num_iov = 1,
    };

    rc = read_msg(chan, msg_inf.id, 0, &msg);
    put_msg(chan, msg_inf.id);
    if (rc < 0) {
        TLOGE("failed to read msg (%d, %d)\n", rc, chan);
        return rc;
    }

    if (((size_t)rc) < msg_inf.len) {
        TLOGE("invalid message of size (%d, %d)\n", rc, chan);
        return ERR_NOT_VALID;
    }

    rc = ctx->ops.on_handle_msg(ctx, msg_buf, msg_inf.len);

err_handle_msg:
err_read_msg:
    return rc;
}

static void do_disconnect(struct ipc_channel_context* context,
                          const uevent_t* ev) {
    list_delete(&context->node);
    context->ops.on_disconnect(context);
    close(ev->handle);
}

static void handle_port(struct ipc_context* ctx, const struct uevent* ev) {
    struct ipc_port_context* port_ctx = to_port_context(ctx);
    assert(is_valid_port_ops(&port_ctx->ops));

    handle_port_errors(ev);

    do_connect(port_ctx, ev);
}

static void handle_channel(struct ipc_context* ctx, const struct uevent* ev) {
    struct ipc_channel_context* channel_ctx = to_channel_context(ctx);
    assert(is_valid_chan_ops(&channel_ctx->ops));

    handle_chan_errors(ev);

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        if (channel_ctx->ops.on_handle_msg != NULL) {
            int rc = do_handle_msg(channel_ctx, ev);
            if (rc < 0) {
                TLOGE("error (%d) in channel, disconnecting "
                      "peer\n",
                      rc);
                do_disconnect(channel_ctx, ev);
                return;
            }
        } else {
            TLOGE("error: unexpected message in channel (%d). closing...\n",
                  ev->handle);
            do_disconnect(channel_ctx, ev);
            return;
        }
    }

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        do_disconnect(channel_ctx, ev);
    }
}

static int read_response(handle_t session,
                         uint32_t msg_id,
                         struct iovec* iovecs,
                         size_t iovec_count) {
    struct ipc_msg rx_msg = {
            .iov = iovecs,
            .num_iov = iovec_count,
    };

    long rc = read_msg(session, msg_id, 0, &rx_msg);
    put_msg(session, msg_id);
    if (rc < 0) {
        TLOGE("%s: failed to read msg (%ld)\n", __func__, rc);
        return rc;
    }

    size_t read_size = (size_t)rc;
    return read_size;
}

static int await_response(handle_t session, struct ipc_msg_info* inf) {
    uevent_t uevt;
    long rc = wait(session, &uevt, INFINITE_TIME);
    if (rc != NO_ERROR) {
        TLOGE("%s: interrupted waiting for response (%ld)", __func__, rc);
        return rc;
    }

    rc = get_msg(session, inf);
    if (rc != NO_ERROR) {
        TLOGE("%s: failed to get_msg (%ld)\n", __func__, rc);
    }

    return rc;
}

static int wait_to_send(handle_t session, struct ipc_msg* msg) {
    int rc;
    struct uevent ev = UEVENT_INITIAL_VALUE(ev);

    rc = wait(session, &ev, INFINITE_TIME);
    if (rc < 0) {
        TLOGE("failed to wait for outgoing queue to free up\n");
        return rc;
    }

    if (ev.event & IPC_HANDLE_POLL_SEND_UNBLOCKED) {
        return send_msg(session, msg);
    }

    if (ev.event & IPC_HANDLE_POLL_MSG) {
        return ERR_BUSY;
    }

    if (ev.event & IPC_HANDLE_POLL_HUP) {
        return ERR_CHANNEL_CLOSED;
    }

    return rc;
}

int sync_ipc_send_msg(handle_t session,
                      struct iovec* tx_iovecs,
                      unsigned int tx_iovec_count,
                      struct iovec* rx_iovecs,
                      unsigned int rx_iovec_count) {
    struct ipc_msg tx_msg = {
            .iov = tx_iovecs,
            .num_iov = tx_iovec_count,
    };

    long rc = send_msg(session, &tx_msg);
    if (rc == ERR_NOT_ENOUGH_BUFFER) {
        rc = wait_to_send(session, &tx_msg);
    }

    if (rc < 0) {
        TLOGE("%s: failed (%ld) to send_msg\n", __func__, rc);
        return rc;
    }

    if (rx_iovecs == NULL || rx_iovec_count == 0) {
        assert(rx_iovec_count == 0);
        assert(rx_iovecs == NULL);
        return NO_ERROR;
    }

    struct ipc_msg_info inf;
    rc = await_response(session, &inf);
    if (rc < 0) {
        TLOGE("%s: failed (%ld) to await response\n", __func__, rc);
        return rc;
    }

    size_t min_len = rx_iovecs[0].iov_len;
    if (inf.len < min_len) {
        TLOGE("%s: invalid response length (%zu)\n", __func__, inf.len);
        put_msg(session, inf.id);
        return ERR_NOT_VALID;
    }

    /* calculate total message size */
    size_t resp_size = 0;
    for (size_t i = 0; i < rx_iovec_count; ++i) {
        resp_size += rx_iovecs[i].iov_len;
    }

    if (resp_size < inf.len) {
        TLOGE("%s: response buffer too short (%zu < %zu) \n", __func__,
              resp_size, inf.len);
        put_msg(session, inf.id);
        return ERR_BAD_LEN;
    }

    rc = read_response(session, inf.id, rx_iovecs, rx_iovec_count);
    put_msg(session, inf.id);
    if (rc < 0) {
        TLOGE("%s: response has error (%ld)\n", __func__, rc);
        return rc;
    }

    size_t read_len = (size_t)rc;
    if (read_len != inf.len) {
        // data read in does not match message length
        TLOGE("%s: invalid response length (%zu)\n", __func__, read_len);
        return ERR_IO;
    }

    return read_len;
}

static void dispatch_event(const uevent_t* ev) {
    assert(ev);

    if (ev->event == IPC_HANDLE_POLL_NONE) {
        return;
    }

    struct ipc_context* context = ev->cookie;
    assert(context);
    assert(context->evt_handler);
    assert(context->handle == ev->handle);

    context->evt_handler(context, ev);
}

int ipc_port_create(struct ipc_port_context* ctxp,
                    const char* port_name,
                    size_t queue_size,
                    size_t max_buffer_size,
                    uint32_t flags) {
    int rc;
    assert(ctxp);
    assert(is_valid_port_ops(&ctxp->ops));

    rc = port_create(port_name, queue_size, max_buffer_size, flags);

    if (rc < 0) {
        TLOGE("Failed to create port %s %d\n", port_name, rc);
        return rc;
    }

    handle_t port_handle = (handle_t)rc;
    rc = set_cookie(port_handle, ctxp);
    if (rc < 0) {
        TLOGE("Failed to set cookie on port %s (%d)\n", port_name, rc);
        goto err_set_cookie;
    }

    rc = maybe_grow_msg_buf(max_buffer_size);
    if (rc < 0) {
        TLOGE("Failed to create msg buffer of size %zu (%d)\n", max_buffer_size,
              rc);
        goto err_grow_msg;
    }

    ctxp->common.handle = port_handle;
    ctxp->common.evt_handler = handle_port;
    list_initialize(&ctxp->channels);
    return NO_ERROR;

err_set_cookie:
err_grow_msg:
    close(port_handle);
    return rc;
}

int ipc_port_destroy(struct ipc_port_context* ctx) {
    close(ctx->common.handle);
    while (!list_is_empty(&ctx->channels)) {
        struct ipc_channel_context* chan_ctx = list_remove_head_type(
                &ctx->channels, struct ipc_channel_context, node);
        assert(chan_ctx);
        handle_t chan_handle = chan_ctx->common.handle;
        TLOGE("client still connected, handle %d\n", chan_handle);
        chan_ctx->ops.on_disconnect(chan_ctx);
        close(chan_handle);
    }
    return NO_ERROR;
}

void ipc_loop(void) {
    int rc;
    uevent_t event;

    while (true) {
        event.handle = INVALID_IPC_HANDLE;
        event.event = 0;
        event.cookie = NULL;
        rc = wait_any(&event, INFINITE_TIME);
        if (rc < 0) {
            TLOGE("wait_any failed (%d)\n", rc);
            break;
        }

        if (rc == NO_ERROR) { /* got an event */
            dispatch_event(&event);
        }
    }
}

void mock_ipc_disconnect_handler(struct ipc_channel_context* context) {
    if (context)
        free(context);
}

int mock_ipc_msg_handler(struct ipc_channel_context* context, void* msg, size_t msg_size)
{
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
    if (rc < 0 ) {
        return rc;
    }
    return NO_ERROR;
}

/*
 * directly return a channel context given uuid and chan handle
 */
struct ipc_channel_context* mock_channel_connect(struct ipc_port_context* parent_ctx,
        const uuid_t* peer_uuid, handle_t chan_handle) {
    struct ipc_channel_context* pctx = malloc(sizeof(pctx));
    pctx->ops.on_disconnect = mock_ipc_disconnect_handler;
    pctx->ops.on_handle_msg = mock_ipc_msg_handler;
    return pctx;
}

/*
    mocks main
 */
int main(void) {
    handle_table_init(INVALID_IPC_HANDLE, INVALID_IPC_HANDLE, INVALID_IPC_HANDLE);
    struct ipc_port_context ctx = {
            .ops = {.on_connect = mock_channel_connect},
    };
    int rc = ipc_port_create(
            &ctx, STORAGE_DISK_PROXY_PORT, 1, STORAGE_MAX_BUFFER_SIZE,
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
        TLOGE("wait_any failed (%d)\n", rc);
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
        TLOGE("wait_any failed (%d)\n", rc);
        return rc;
    }
    if (rc == NO_ERROR) { /* got an event */
        dispatch_event(&event2);
    }

    ipc_port_destroy(&ctx);

    return 0;
}
