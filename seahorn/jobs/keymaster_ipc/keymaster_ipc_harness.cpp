// RUN: %sea bpf -m64 -O3 --entry=handle_msg --bmc=mono --horn-bv2=true --inline  --horn-bv2-ptr-size=8 --horn-bv2-word-size=8 --log=opsem "%s" 2>&1 | OutputCheck %s
// CHECK-L: unsat
/*
 * Based on ipc msg handler code from /trusty/app/keymaster/ipc/keymaster_ipc.cpp 
 */


#include "seahorn/seahorn.h"
#include "keymaster_ipc.h"

#include <lk/macros.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_ipc.h>
#include <uapi/err.h>

#include <interface/keymaster/keymaster.h>

#include <keymaster/UniquePtr.h>

#include "trusty_keymaster.h"
#include "trusty_logger.h"
#include "nondet.h"

using namespace keymaster;

typedef void (*event_handler_proc_t)(const uevent_t* ev, void* ctx);

struct tipc_event_handler {
    event_handler_proc_t proc;
    void* priv;
};

struct keymaster_chan_ctx {
    struct tipc_event_handler handler;
    uid_t uuid;
    handle_t chan;
    long (*dispatch)(keymaster_chan_ctx*,
                     keymaster_message*,
                     uint32_t,
                     keymaster::UniquePtr<uint8_t[]>*,
		     uint32_t*);
};

class MessageDeleter {
public:
    explicit MessageDeleter(handle_t chan, int id) {
        chan_ = chan;
        id_ = id;
    }

    ~MessageDeleter() { put_msg(chan_, id_); }

private:
    handle_t chan_;
    int id_;
};

static long handle_msg(keymaster_chan_ctx* ctx) {
    assume(ctx->chan > 0);
    handle_t chan = ctx->chan;

    /* get message info */
    ipc_msg_info_t msg_inf;
    int rc = get_msg(chan, &msg_inf);
    if (rc == ERR_NO_MSG)
        return NO_ERROR; /* no new messages */

    // fatal error
    if (rc != NO_ERROR) {
        LOG_E("failed (%d) to get_msg for chan (%d), closing connection", rc,chan);
        return rc;
    }
    sassert( (rc == NO_ERROR) == (msg_inf.len > 0) );
    MessageDeleter md(chan, msg_inf.id);

    // allocate msg_buf, with one extra byte for null-terminator
    keymaster::UniquePtr<uint8_t[]> msg_buf(new uint8_t[msg_inf.len + 1]);
    msg_buf[msg_inf.len] = 0;
     // for assertion in read_msg()
    assume(msg_buf[0] == 0);

    /* read msg content */
    struct iovec iov = {msg_buf.get(), msg_inf.len};
    ipc_msg_t msg = {1, &iov, 0, NULL};

    rc = read_msg(chan, msg_inf.id, 0, &msg);

    assume(rc <= (int)msg_inf.len);
    // this is probably checked in read_msg, but limiting here to simplify things

    // fatal error
    if (rc < 0) {
        LOG_E("%dfailed to read msg (%d)", rc, chan);
        return rc;
    }
    // LOG_D("Read %d-byte message", rc);

    // need at least 4 bytes as header
    if (((unsigned long)rc) < sizeof(keymaster_message)) {
        LOG_E("%dinvalid message of size (%d)", rc, chan);
        return ERR_NOT_VALID;
    }

    // check message buffer has been written to
    sassert(msg_buf[0] > 0);
    // keymaster::UniquePtr<uint8_t[]> out_buf;
    // uint32_t out_buf_size = 0;
    keymaster_message* in_msg =
            reinterpret_cast<keymaster_message*>(msg_buf.get());

    // rc = ctx->dispatch(ctx, in_msg, msg_inf.len - sizeof(*in_msg), &out_buf,
    //                    &out_buf_size);
    // if (rc == ERR_NOT_CONFIGURED) {
    //     LOG_E("configure error (%d)", rc);
    //     return send_error_response(chan, in_msg->cmd,
    //                                device->get_configure_error());
    // } else if (rc < 0) {
    //     LOG_E("error handling message (%d)", rc);
    //     return send_error_response(chan, in_msg->cmd, KM_ERROR_UNKNOWN_ERROR);
    // }

    // LOG_D("Sending %d-byte response", out_buf_size);
    // return send_response(chan, in_msg->cmd, out_buf.get(), out_buf_size);
    return (int)in_msg->cmd;
}

int main(void) {
    void* priv = nd_ptr();
    keymaster_chan_ctx* ctx = reinterpret_cast<keymaster_chan_ctx*>(priv);
    // the only thing we test within handle_msg right now is ->chan
    ctx->chan = (handle_t)nd_int();
    int res = -1;
    if (ctx->chan > 0) {
        res = handle_msg(ctx);
    }
    return res;
}

