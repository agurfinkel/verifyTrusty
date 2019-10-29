// RUN: %sea bpf -m64 -O3 --bmc=mono --horn-bv2=true --inline  --horn-bv2-ptr-size=8 --horn-bv2-word-size=8 --log=opsem "%s" 2>&1 | OutputCheck %s 
// CHECK-L: unsat
/*
 * Based on code example on https://source.android.com/security/trusty/trusty-ref#example_of_a_trusted_application_server
 * exploring accessing structure member by pointer
 * interesting overflow situation in stubbed APIs which returns long
 * e.g. assertion in line 148
 */


#include "seahorn/seahorn.h"
// #include <uapi/err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
// #include <trusty_ipc.h>
#define LOG_TAG "echo_srv"
#define TLOGE(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__, ##__VA_ARGS__)

# define MAX_ECHO_MSG_SIZE 64
# define NO_ERROR 0
# define ERR_NO_MSG -42
# define ERR_TIMED_OUT -233
// # define YES_ERROR -1
extern "C" long nd(void);
extern "C" long nd_read(void);
extern "C" long nd_get(void);
extern "C" long nd_put(void);
extern "C" long nd_send(void);
extern "C" long nd_get_len(void);
extern "C" long nd_get_id(void);

// struct def from documentation
typedef struct iovec {
        void   *base;
        size_t  len;
} iovec_t;

typedef int32_t handle_t;
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

/* Define stub APIs */
long get_msg(uint32_t handle, ipc_msg_info_t *msg_info) {
 //   sassert(handle > 0);
    long retval = nd_get();
    size_t msg_len = (size_t) nd_get_len();
    uint32_t msg_id = (uint32_t) nd_get_id();
    assume(retval < INT_MAX && retval > INT_MIN); // removing this will cause assertion on line 148 to fail
    if (retval == NO_ERROR) {
	 assume(msg_len > 0);
	 assume(msg_id > 0);
    } else {
	 assume(msg_len == 0);
	 assume(msg_id == 0);
    }
    msg_info->len = msg_len;
    msg_info->id = msg_id;
    sassert( (retval == NO_ERROR) == (msg_info->len > 0)  );
    return retval;
}

long read_msg(uint32_t handle, uint32_t msg_id, uint32_t offset, ipc_msg_t *msg) {
    // return Total number of bytes stored in the dst buffers on success;
    // a negative error otherwise
    //sassert(handle > 0 && msg_id > 0);
    return nd_read();
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

long wait(uint32_t handle_id, uevent_t *event, unsigned long timeout_msecs) {
    long retval = nd();
    assume(retval == NO_ERROR || retval == ERR_TIMED_OUT || retval < 0);
    // if (retval == NO_ERROR) {
    //     // TODO: update *event
    // }
    return retval;
}

static const char * srv_name = "com.android.echo.srv.echo";

static uint8_t msg_buf[MAX_ECHO_MSG_SIZE];

int handle_msg(handle_t chan) {
  int rc;
  iovec_t iov;
  ipc_msg_t msg;
  ipc_msg_info_t msg_inf;

  iov.base = msg_buf;
  iov.len = sizeof(msg_buf);

  msg.num_iov = 1;
  msg.iov = &iov;
  msg.num_handles = 0;
  msg.handles = NULL;
  //assume(chan > 0);
  /* get message info */
  rc = get_msg(chan, &msg_inf);
  if (rc == ERR_NO_MSG)
    return NO_ERROR; /* no new messages */

  if (rc != NO_ERROR) {
    TLOGE("failed (%d) to get_msg for chan (%d)\n",
      rc, chan);
    return rc;
  }
  // at this point rc must be NO_ERROR
  sassert( (rc == NO_ERROR) == (msg_inf.len > 0)  );
  //sassert(msg_inf.id > 0 && msg_inf.len > 0);
  /* read msg content */
  rc = read_msg(chan, msg_inf.id, 0, &msg);
  if (rc < 0) {
    TLOGE("failed (%d) to read_msg for chan (%d)\n",
      rc, chan);
    return rc;
  }

  /* update number of bytes received */
  iov.len = (size_t) rc;

  /* send message back to the caller */
  rc = send_msg(chan, &msg);
  if (rc < 0) {
    TLOGE("failed (%d) to send_msg for chan (%d)\n",
      rc, chan);
    return rc;
  }

  /* retire message */
  rc = put_msg(chan, msg_inf.id);
  if (rc != NO_ERROR) {
    TLOGE("failed (%d) to put_msg for chan (%d)\n",
      rc, chan);
    return rc;
  }
  return NO_ERROR;
}

int main(void) {
  	long rc = nd();
	assume(rc >= 0);
	handle_t chan = (handle_t) rc;
	int res = handle_msg(chan);
	return res;
}

