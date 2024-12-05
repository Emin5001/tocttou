#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <string.h>
#include <assert.h>
#include "../../include/read_write.h"

sigjmp_buf jmpbuf;

#define unsafe_get_user(x, p)do {                       \
    if (sigsetjmp(jmpbuf, 1) == 0) {                    \
        x = *p;                                         \
    }                                                   \
} while (0)

#define NUM_IOVS 1000

struct iovec *vecs;
struct user_msghdr msg;
int finish = 0;
int flipping_ready = 0;
int trigger_ready = 0;
unsigned int interval = 0;


static int user_access_begin(void const *ptr, uint64_t len) {
    uintptr_t start = (uintptr_t) ptr;
    uintptr_t end = start + len;

    if (end > (uintptr_t) KERNEL_LAND || start > end) {
        return -1;
    }

    return 0;
}

static int copy_iovec_from_user(struct iovec *iov, const struct iovec *uiov, unsigned long nr_segs)
{
	int ret = -1;

	if (user_access_begin(uiov, nr_segs * sizeof(*uiov)))
		return -1;

	do 
  {
		void *buf;
		ssize_t len = -1;

		unsafe_get_user(len, &uiov->iov_len);
		unsafe_get_user(buf, &uiov->iov_base);

		if (len < 0) {
			ret = -1;
			goto uaccess_end;
		}
		iov->iov_base = buf;
		iov->iov_len = len;

		uiov++; iov++;
	} while (--nr_segs);

	ret = 0;
uaccess_end:
	return ret;
}

struct iovec *iovec_from_user(const struct iovec *uvec, unsigned long nr_segs, unsigned long fast_segs, struct iovec *fast_iov) 
{
	struct iovec *iov = fast_iov;
	int ret;

	/*
	 * SuS says "The readv() function *may* fail if the iovcnt argument was
	 * less than or equal to 0, or greater than {IOV_MAX}.  Linux has
	 * traditionally returned zero for zero segments, so...
	 */
	if (nr_segs == 0)
		return iov;
	if (nr_segs > UIO_MAXIOV)
		return NULL;
	if (nr_segs > fast_segs) 
  {
		iov = malloc(nr_segs * sizeof(struct iovec));
		if (!iov)
			return NULL;
	}

	ret = copy_iovec_from_user(iov, uvec, nr_segs);
	if (ret) 
  {
		if (iov != fast_iov)
			free(iov);
		return NULL;
	}

	return iov;
}

static __attribute__ ((noinline)) ssize_t import_iovec(int type, const struct iovec *uvec, unsigned nr_segs, unsigned fast_segs, struct iovec **iovp, struct iov_iter *i) 
{        
  ssize_t total_len = 0;
	unsigned long seg;
	struct iovec *iov;

  iov = iovec_from_user(uvec, nr_segs, fast_segs, *iovp);

  for (seg = 0; seg < nr_segs; seg++) 
  {
	  ssize_t len = (ssize_t)iov[seg].iov_len;

		if (user_access_begin(iov[seg].iov_base, len)) 
    {
			if (iov != *iovp)
				free(iov);
			*iovp = NULL;
			return -1;
		}

		if (len > MAX_RW_COUNT - total_len) 
    {
			len = MAX_RW_COUNT - total_len;
			iov[seg].iov_len = len;
		}
		total_len += len;
	}

	// iov_iter_init(i, type, iov, nr_segs, total_len);
	if (iov == *iovp)
		*iovp = NULL;
	else
		*iovp = iov;

	return total_len;
}

static inline int audit_sockaddr(int len, void *addr)
{
	return 0;
}

int move_addr_to_kernel(void *uaddr, int ulen, struct sockaddr_storage *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (ulen == 0)
		return 0;

	return audit_sockaddr(ulen, kaddr);
}

int __copy_msghdr(struct msghdr *kmsg, struct user_msghdr *msg, struct sockaddr **save_addr)
{
	ssize_t err;

	kmsg->msg_control_is_user = true;
	kmsg->msg_get_inq = 0;
	kmsg->msg_control_user = msg->msg_control;
	kmsg->msg_controllen = msg->msg_controllen;
	kmsg->msg_flags = msg->msg_flags;

	kmsg->msg_namelen = msg->msg_namelen;
	if (!msg->msg_name)
		kmsg->msg_namelen = 0;

	if (kmsg->msg_namelen < 0)
		return -EINVAL;

	if (kmsg->msg_namelen > sizeof(struct sockaddr_storage))
		kmsg->msg_namelen = sizeof(struct sockaddr_storage);

	if (save_addr)
		*save_addr = msg->msg_name;

	if (msg->msg_name && kmsg->msg_namelen) {
		if (!save_addr) {
			err = move_addr_to_kernel(msg->msg_name,
						  kmsg->msg_namelen,
						  kmsg->msg_name);
			if (err < 0)
				return err;
		}
	} else {
		kmsg->msg_name = NULL;
		kmsg->msg_namelen = 0;
	}

	if (msg->msg_iovlen > UIO_MAXIOV)
		return -EMSGSIZE;

	kmsg->msg_iocb = NULL;
	kmsg->msg_ubuf = NULL;
	return 0;
}

static int copy_msghdr_from_user(struct msghdr *kmsg, struct user_msghdr *umsg, struct sockaddr **save_addr, struct iovec **iov) 
{
  struct user_msghdr msg;
  ssize_t err;

  err = __copy_msghdr(kmsg, &msg, save_addr);

  err = import_iovec(save_addr ? ITER_DEST : ITER_SOURCE, msg.msg_iov, msg.msg_iovlen, UIO_FASTIOV, &iov, &kmsg->msg_iter);

  return err;
}

int sendmsg_copy_msghdr(struct msghdr *msg, struct user_msghdr *umsg, unsigned flags, struct iovec **iov)
{
  int err;

  err = copy_msghdr_from_user(msg, umsg, NULL, iov);

  return err;
}

static int __sys_sendmsg(struct msghdr *msg_sys, unsigned int flags, struct used_address *used_address, unsigned int allowed_msghdr_flags)
{
	unsigned char ctl[sizeof(struct cmsghdr) + 20]
				__aligned(sizeof(__kernel_size_t));
	/* 20 is size of ipv6_pktinfo */
	unsigned char *ctl_buf = ctl;
	int ctl_len;
	ssize_t err;

	err = -ENOBUFS;

	if (msg_sys->msg_controllen > INT_MAX)
		goto out;
	flags |= (msg_sys->msg_flags & allowed_msghdr_flags);
	ctl_len = msg_sys->msg_controllen;
	if ((MSG_CMSG_COMPAT & flags) && ctl_len) {
		ctl_buf = msg_sys->msg_control;
		ctl_len = msg_sys->msg_controllen;
	} else if (ctl_len) {
		msg_sys->msg_control = ctl_buf;
		msg_sys->msg_control_is_user = false;
	}
	flags &= ~MSG_INTERNAL_SENDMSG_FLAGS;
	msg_sys->msg_flags = flags;

	/*
	 * If this is sendmmsg() and current destination address is same as
	 * previously succeeded address, omit asking LSM's decision.
	 * used_address->name_len is initialized to UINT_MAX so that the first
	 * destination address never matches.
	 */
	if (used_address && msg_sys->msg_name &&
	    used_address->name_len == msg_sys->msg_namelen &&
	    !memcmp(&used_address->name, msg_sys->msg_name,
		    used_address->name_len)) {
	}
	/*
	 * If this is sendmmsg() and sending to current destination address was
	 * successful, remember it.
	 */
	if (used_address && err >= 0) {
		used_address->name_len = msg_sys->msg_namelen;
		if (msg_sys->msg_name)
			memcpy(&used_address->name, msg_sys->msg_name,
			       used_address->name_len);
	}
out:
	return err;
}

static int _sys_sendmsg(struct user_msghdr *msg, struct msghdr *msg_sys, unsigned int flags, struct used_address *used_address, unsigned int allowed_msghdr_flags)
{
  struct sockaddr_storage address;
  struct iovec iovstack[UIO_FASTIOV], *iov = iovstack;  
  ssize_t err;

  msg_sys->msg_name = &address;

  err = sendmsg_copy_msghdr(msg_sys, msg, flags, &iov);

  err = __sys_sendmsg(msg_sys, flags, used_address, allowed_msghdr_flags);

  return err;
}

static long __attribute__ ((noinline)) sys_sendmsg(struct user_msghdr *msg, unsigned int flags, bool forbid_cmsg_compat)
{
  struct msghdr msg_sys;
  
  return _sys_sendmsg(msg, &msg_sys, flags, NULL, 0);
}

int main(int argc, char *argv[]) {

	assert(argc == 2 && "Must include a size for the iovec buffer.");
	int size = atoi(argv[1]);
  vecs = calloc (size * sizeof(struct iovec), sizeof(struct iovec));

  for (int i = 0; i < size; i++)
  {
    vecs[i].iov_base = 0xdeadbeef;
    vecs[i].iov_len = 4096;
  };

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = vecs;
  msg.msg_iovlen = size;

  for (int i = 0; i < 100000; i++)
  {
    sys_sendmsg((struct user_msghdr *)&msg, 0, false);
  }

  return 0;
}