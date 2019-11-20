#include "seahorn/seahorn.h"
#include "nondet.h"
#include "handle_table.h"
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>

// trusty reference for definitions only
#include <trusty_ipc.h> // -> ipc structs
#include <uapi/err.h> // NO_ERROR definition


/* Redefine trusty messaging APIs */
int get_msg(handle_t handle, ipc_msg_info_t *msg_info) {
    int retval = nd_int();
    size_t msg_len = (size_t) nd_unsigned();
    uint32_t msg_id = (uint32_t) nd_unsigned();
    if (retval == NO_ERROR) {
	 assume(msg_len > 0);
	 assume(msg_id > 0);
    } else {
	 assume(msg_len == 0);
	 assume(msg_id == 0);
    }
    msg_info->len = msg_len;
    msg_info->id = msg_id;
    return retval;
}

ssize_t read_msg(handle_t handle, uint32_t msg_id, uint32_t offset, ipc_msg_t *msg) {
    // return Total number of bytes stored in the dst buffers on success;
    // a negative error otherwise
    ssize_t res = (ssize_t)nd_int();
    struct iovec* iv = msg->iov;
    if (res >= 0) {
        /*
        according to documentation, res < 0 means error
        simulate the behaviour of writing meaningful message to buffer
        by setting the first element of buffer to something;
        this should be safe because extra byte added in line 217
         */
        uint8_t element = nd_char();
        assume(element > 0);
        ((uint8_t*)(iv->iov_base))[0] = element;
    }
    return res;
}

ssize_t send_msg(handle_t handle, ipc_msg_t* msg) {
    // Total number of bytes sent on success; a negative error otherwise
    return (ssize_t)nd_int();
}

int put_msg(handle_t handle, uint32_t msg_id) {
    // return NO_ERROR on success; a negative error otherwise
    //assume(retval == NO_ERROR || retval < 0);
    return nd_int();
}

// wait for any kind of event, could be port or channel
// current model only handles the channel event of the latest port event
// if they happen to match
int wait_any(uevent_t* ev, uint32_t timeout_msecs) {
    int ret = nd_int();
    assume(ret <= NO_ERROR && ret >= ERR_USER_BASE);
    if (ret == NO_ERROR) {
        // simulate populating the event with no handler
        // ev->cookie = nd_ptr();
        ev->handle = nd_int();
        ev->cookie = get_handle_cookie(ev->handle);
        assume(ev->handle > INVALID_IPC_HANDLE);
        ev->event = nd_unsigned();
        assume(ev->event < (uint32_t)0x16); // max is (1111)2
    }
    return ret;
}

// returns handle for PORT and adds it to handle table
handle_t port_create(const char* path,
                     uint32_t num_recv_bufs,
                     uint32_t recv_buf_size,
                     uint32_t flags)
                     {
    handle_t retval = (handle_t)nd_int();
    if (retval < 0)
        return retval; // return error message as is
    assume(retval & 0x2); // is port
    if (flags & IPC_PORT_ALLOW_TA_CONNECT)
    { // open secure port
        assume(retval & 0x1);
    } else
    { // open non secure port
        assume(!(retval & 0x1));
    }
    add_handle(retval);
    return retval;
}

int set_cookie(handle_t handle, void* cookie) {
    // the handle should at least be stored in the handle table?
    // similar check can be seen in trusty/kernel/lib/trusty/uctx.c
    sassert(contains_handle(handle));
    // if (!contains_handle(handle)) {
    //     return -1;
    // }
    int ret = nd_int(); // model other results (including failure)
    assume(ret <= 0); // NO_ERROR on success, < 0 error code otherwise
    if (ret == 0) {
        set_handle_cookie(handle, cookie);
    }
    return ret;
}


// given port_handle that references a port, open a channel and
// store channel handle to handle table
handle_t accept(handle_t port_handle, uuid_t* peer_uuid) {
    handle_t chan = (handle_t)nd_int();
    if (chan >= 0) {
        assume(!(chan & 0x2)); // is channel
        // define peer_uuid to a dummy value
        peer_uuid = calloc(1, sizeof(uuid_t));
        add_handle(chan);
    }
    return chan;
}

int close(handle_t handle) {
    int ret = nd_int();
    assume(ret <= 0); // "0 if success; a negative error otherwise"
    if (ret == 0) {
        remove_handle(handle);
    }
    return ret;
}
