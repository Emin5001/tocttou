#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <string.h>
#include "../include/read_write.h"
#include "../../PTEditor/pteditor_header.h"

sigjmp_buf jmpbuf;

#define unsafe_get_user(x, p)do {                       \
    if (sigsetjmp(jmpbuf, 1) == 0) {                    \
        x = *p;                                         \
    }                                                   \
} while (0)

struct iovec *get_iovec_addr(struct iovec *iov_addr, void **writeable_addresses, uintptr_t first_page) {
	uintptr_t base = PAGE_ALIGN(iov_addr, 4096);
	int index = (base - first_page) / 4096;
	struct iovec *translated_iov_addr = (uintptr_t)writeable_addresses[index] + (uintptr_t)PAGE_OFFSET(iov_addr, 4096);
	return translated_iov_addr;
}

void segfault_handler(int signal) 
{
    if (signal == SIGSEGV) 
    {
        fprintf(stderr, "Segmentation fault (signal %d) occurred!\n", signal);
        fail ++;
    }
}

#define NUM_IOVS 10

struct iovec *vecs;
struct user_msghdr msg;
int finish = 0;
int flipping_ready = 0;
int trigger_ready = 0;
unsigned int interval = 0;

int success = 0;
int fail = 0;
int attack = 0;

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

ssize_t __attribute__ ((noinline)) import_iovec(int type, const struct iovec *uvec,
	unsigned nr_segs, unsigned fast_segs,
	struct iovec **iovp, struct iov_iter *i, void **writeable_addresses) {
  ssize_t total_len = 0;
	unsigned long seg;
	struct iovec *iov;

  uintptr_t first_page = (uintptr_t) PAGE_ALIGN(uvec, 4096);
  uintptr_t last_page = (uintptr_t) PAGE_ALIGN((char *)uvec + (nr_segs * sizeof(struct iovec)), 4096);
  int index = 0;
  for (uintptr_t address = first_page; address <= last_page; address += 4096) {
  	ptedit_entry_t vm = ptedit_resolve((void *) address, 0);
    size_t address_pfn = ptedit_get_pfn(vm.pte);

    char* new_addr = ptedit_pmap(address_pfn * ptedit_get_pagesize(), ptedit_get_pagesize());
    writeable_addresses[index] = new_addr;
		index ++;
		ptedit_pte_clear_bit(address, 0, PTEDIT_PAGE_BIT_RW);
    ptedit_invalidate_tlb(address);
  }

  for (seg = 0; seg < nr_segs; seg++) {
		struct iovec *translated_iov_addr = get_iovec_addr(&uvec[seg], writeable_addresses, first_page);
		ssize_t len = translated_iov_addr->iov_len;

		if (user_access_begin(translated_iov_addr->iov_base, len)) {
			if (iov != *iovp)
				// free(iov);
			*iovp = NULL;
			return -1;
		}

		if (len > MAX_RW_COUNT - total_len) {
			len = MAX_RW_COUNT - total_len;
			translated_iov_addr->iov_len = len;
		}
		total_len += len;
	}

	// iov_iter_init(i, type, iov, nr_segs, total_len);
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
	void *writeable_addresses[5];
  err = import_iovec(save_addr ? ITER_DEST : ITER_SOURCE, msg.msg_iov, msg.msg_iovlen, UIO_FASTIOV, &iov, &kmsg->msg_iter, &writeable_addresses);

  //checking if attack is successful
  struct iovec *iovec_ptr = iov;
  if (iovec_ptr[5].iov_base == KERNEL_LAND)
  {
    return -2;
  };

	uintptr_t first_page = (uintptr_t) PAGE_ALIGN(vec, 4096);
	uintptr_t last_page = (uintptr_t) PAGE_ALIGN((char*) msg.msg.iov + (vlen * sizeof(struct iovec)), 4096);

	for (uintptr_t addr = first_page; addr <= last_page; addr += 4096)
	{
		ptedit_pte_set_bit(addr, 0, PTEDIT_PAGE_BIT_RW);
		ptedit_invalidate_tlb(addr);
	}

  return err;
}

int sendmsg_copy_msghdr(struct msghdr *msg, struct user_msghdr *umsg, unsigned flags, struct iovec **iov)
{
  int err;

  err = copy_msghdr_from_user(msg, umsg, NULL, iov);

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

void *attack_array(void *arg) 
{
  printf("attacking\n");
  while (!finish)
  {
    flipping_ready = 1;
    while (trigger_ready) {};

    //usleep(interval);

    vecs[5].iov_base = (void*) KERNEL_LAND;
    interval++;

    if (interval > 10000) 
    {
      interval = 1;
    }

    flipping_ready = 0;
  }

  pthread_exit(NULL);
}

int main()
{
  if (ptedit_init())
  {
    printf("could not initialize ptedit (did you load the kernel module?)\n");
    return 1;
  }

  for (int i = 0; i < NUM_IOVS; i++) 
  {
    vecs[i].iov_base = (void*)(0x10000 * (i + 1));
    vecs[i].iov_len = 4096;
  }
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = vecs;
  msg.msg_iovlen = NUM_IOVS;

  pthread_t attack_thread;
  pthread_create(&attack_thread, NULL, attack_array, NULL);

  for (int i = 0; i < 100000; i++)
  {
    while (!flipping_ready) {};
    trigger_ready = 1;
    finish = 0;
    long ret = sys_sendmsg((struct user_msghdr *)&msg, 0, false);
    if (ret == -1) 
    {
      fail++;
    } 
    else if (ret == -2)
    {
      attack++;
    }
    else 
    {
      success++;
    }

    trigger_ready = 0;
    vecs[5].iov_base = (void*)0x60000;
  }

  finish = 1;
  pthread_join(attack_thread, NULL);

  printf("success:%d, fail:%d, attack:%d\n", success, fail, attack);

  return 0;
}