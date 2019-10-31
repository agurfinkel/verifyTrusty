// RUN: %sea bpf -m64 -O3 --entry=handle_msg --bmc=mono --horn-bv2=true --inline  --horn-bv2-ptr-size=8 --horn-bv2-word-size=8 --log=opsem "%s" 2>&1 | OutputCheck %s
// CHECK-L: unsat
/*
 * Based on ipc msg handler code from /trusty/app/keymaster/ipc/keymaster_ipc.cpp 
 */


#include "seahorn/seahorn.h"
#include "nondet.h"
// #include <uapi/err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
// #include <trusty_ipc.h>
#define LOG_TAG_E "echo_srv"
#define LOG_TAG_D "debug"
#define LOG_E(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG_E, __LINE__, ##__VA_ARGS__)
#define LOG_D(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG_D, __LINE__, ##__VA_ARGS__)

# define MAX_ECHO_MSG_SIZE 64
# define NO_ERROR 0
# define ERR_NO_MSG -42
# define ERR_NOT_VALID -24
# define ERR_TIMED_OUT -233
// # define YES_ERROR -1
// extern "C" long nd(void);
// extern "C" long nd_read(void);
// extern "C" long nd_get(void);
// extern "C" long nd_put(void);
// extern "C" long nd_send(void);
// extern "C" long nd_get_len(void);
// extern "C" long nd_get_id(void);
// extern "C" uint8_t nd_message_read(void);


// simple stub of keymaster implementation of UniquePtr
namespace keymaster
{
    template <typename T> class UniquePtr;
    template <typename T>
    class UniquePtr<T[]>
    {
    private:
        T* ptr;
    public:
        explicit UniquePtr(T* arr_ptr = NULL) : ptr(arr_ptr) {}
        ~UniquePtr() {
            // maybe do some assertion here to check channel / port state?
            if (ptr) delete[] ptr;
        }
        // Accessors.
        T* get() const { return ptr; }

        T& operator[] (size_t i){ return ptr[i]; };
    };
}; // namespace keymaster

// struct def from documentation
typedef struct iovec {
        void   *base;
        size_t  len;
} iovec_t;

typedef int32_t handle_t;

struct keymaster_message {
	uint32_t cmd;
	uint8_t payload[0];
};

typedef struct ipc_msg {
        uint     num_iov; /* number of iovs in this message */
        iovec_t  *iov;    /* pointer to iov array */

        uint     num_handles; /* reserved, currently not supported */
        handle_t *handles;    /* reserved, currently not supported */
} ipc_msg_t;

typedef struct ipc_msg_info {
        size_t    len;  /* total message length */
        uint32_t  id;   /* message id */
} ipc_msg_info_t;

typedef struct uevent {
        uint32_t handle; /* handle this event is related to */
        uint32_t event;  /* combination of IPC_HANDLE_POLL_XXX flags */
        void *cookie; /* cookie associated with this handle */
} uevent_t;

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

struct keymaster_srv_ctx {
    handle_t port_secure;
    handle_t port_non_secure;
};


/* Define stub APIs */
long get_msg(uint32_t handle, ipc_msg_info_t *msg_info) {
 //   sassert(handle > 0);
    long retval = nd_get();
    size_t msg_len = (size_t) nd_get_len();
    uint32_t msg_id = (uint32_t) nd_get_id();
    if (retval == NO_ERROR) {
	 assume(msg_len > 0);
	 assume(msg_id > 0);
    } else {
	 assume(msg_len == 0);
	 assume(msg_id == 0);
    }
    msg_info->len = msg_len;
    msg_info->id = msg_id;
    sassert( (retval == NO_ERROR) == (msg_info->len > 0) );
    return retval;
}

long read_msg(uint32_t handle, uint32_t msg_id, uint32_t offset, ipc_msg_t *msg) {
    // return Total number of bytes stored in the dst buffers on success;
    // a negative error otherwise
    long res = nd_read();
    assume(res >= ERR_TIMED_OUT);
    iovec_t* iv = msg->iov;
    if (res >= 0) {
        /*
        according to documentation, res < 0 means error
        simulate the behaviour of writing meaningful message to buffer
        by setting the first element of buffer to something;
        this should be safe because extra byte added in line 217
         */
        uint8_t element = nd_message_read();
        assume(element > 0);
        ((uint8_t*)(iv->base))[0] = element;
    }
    return res;
}

long send_msg(uint32_t handle, ipc_msg_t *msg) {
    //sassert(handle > 0);
    // Total number of bytes sent on success; a negative error otherwise
    return nd_send();
}

long put_msg(uint32_t handle, uint32_t msg_id) {
    //sassert(handle > 0 && msg_id > 0);
    // return NO_ERROR on success; a negative error otherwise
    //assume(retval == NO_ERROR || retval < 0);
    return nd_put();
}

long port_create(const char *path,
                 uint num_recv_bufs,
                 size_t recv_buf_size,
                 uint32_t flags) {
    return nd();
}

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
        LOG_E("failed (%d) to get_msg for chan (%d), closing connection", rc,
              chan);
        return rc;
    }
    // sassert( (rc == NO_ERROR) == (msg_inf.len > 0) );
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

    assume(rc <= msg_inf.len);
    // this is probably checked in read_msg, but limiting here to simplify things

    // fatal error
    if (rc < 0) {
        LOG_E("%dfailed to read msg (%d)", rc, chan);
        return rc;
    }
    LOG_D("Read %d-byte message", rc);

    // need at least 4 bytes as header
    if (((unsigned long)rc) < sizeof(keymaster_message)) {
        LOG_E("%dinvalid message of size (%d)", rc, chan);
        return ERR_NOT_VALID;
    }

    // check message buffer has been written to
    sassert(msg_buf[0] > 0);
    // keymaster::UniquePtr<uint8_t[]> out_buf;
    uint32_t out_buf_size = 0;
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


//int main(void) {
  	// long rc = nd();
	// assume(rc >= 0);
	// handle_t chan = (handle_t) rc;
	// int res = handle_msg(chan);
	// return res;
//	return 0;
//}

