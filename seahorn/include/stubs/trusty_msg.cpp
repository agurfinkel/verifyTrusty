#include "seahorn/seahorn.h"
#include "nondet.h"
#include <stdint.h>
#include <sys/types.h>

// trusty reference for definitions only
#include <trusty_ipc.h> // -> ipc structs
#include <uapi/err.h> // NO_ERROR definition

#ifdef get_msg
#undef get_msg
#endif
#ifdef read_msg
#undef read_msg
#endif
#ifdef send_msg
#undef send_msg
#endif
#ifdef put_msg
#undef put_msg
#endif

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
    sassert( (retval == NO_ERROR) == (msg_info->len > 0) );
    return retval;
}

ssize_t read_msg(handle_t handle, uint32_t msg_id, uint32_t offset, ipc_msg_t *msg) {
    // return Total number of bytes stored in the dst buffers on success;
    // a negative error otherwise
    ssize_t res = (ssize_t)nd_int();
    iovec* iv = msg->iov;
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
