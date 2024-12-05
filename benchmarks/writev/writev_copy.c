#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "../../include/read_write.h"

struct iovec vecs[10];
int finish = 0;
int flipping_ready = 0;
int trigger_ready = 0;
unsigned int interval = 0;

sigjmp_buf jmpbuf;

#define unsafe_get_user(x, p)do {                       \
    if (sigsetjmp(jmpbuf, 1) == 0) {                    \
        x = *p;                                         \
    }                                                   \
} while (0)

static int user_access_begin(void const *ptr, uint64_t len) {
    uintptr_t start = (uintptr_t) ptr;
    uintptr_t end = start + len;

    if (end > (uintptr_t) KERNEL_LAND || start > end) {
        return -1;
    }

    return 0;
}
static int copy_iovec_from_user(struct iovec *iov,
		const struct iovec *uiov, unsigned long nr_segs)
{
	int ret = -1;

	if (user_access_begin(uiov, nr_segs * sizeof(*uiov)))
		return -1;

	do {
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

struct iovec *iovec_from_user(const struct iovec *uvec,
		unsigned long nr_segs, unsigned long fast_segs,
		struct iovec *fast_iov) {
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
	if (nr_segs > fast_segs) {
		iov = malloc(nr_segs * sizeof(struct iovec));
		if (!iov)
			return NULL;
	}

	ret = copy_iovec_from_user(iov, uvec, nr_segs);
	if (ret) {
		if (iov != fast_iov)
			free(iov);
		return NULL;
	}

	return iov;
}

ssize_t import_iovec(int type, const struct iovec *uvec,
		 unsigned nr_segs, unsigned fast_segs,
		 struct iovec **iovp, struct iov_iter *i) {
        
    ssize_t total_len = 0;
	unsigned long seg;
	struct iovec *iov;

    iov = iovec_from_user(uvec, nr_segs, fast_segs, *iovp);

    for (seg = 0; seg < nr_segs; seg++) {
		ssize_t len = (ssize_t)iov[seg].iov_len;

		if (user_access_begin(iov[seg].iov_base, len)) {
			if (iov != *iovp)
				free(iov);
			*iovp = NULL;
			return -1;
		}

		if (len > MAX_RW_COUNT - total_len) {
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

static ssize_t vfs_writev(const struct iovec *vec, unsigned long vlen) {  
  struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	size_t tot_len;
	ssize_t ret = 0;

    ret = import_iovec(ITER_SOURCE, vec, vlen, ARRAY_SIZE(iovstack), &iov, &iter);

	struct iovec *iovec_ptr = (iov == NULL) ? iovstack : iov;
	if (iovec_ptr[5].iov_base == KERNEL_LAND) {
		return -2;
	}

    // does file stuff with iov
    return ret;
}

void *attack_array(void *arg) {
	while (!finish) {
		flipping_ready = 1;
		while (trigger_ready) {}
		usleep(interval);
		vecs[5].iov_base = (void *) KERNEL_LAND;
		interval ++;
		if (interval > 10000) {
			interval = 1;
		}
		flipping_ready = 0;
	}
	pthread_exit(NULL);
}

int main() {
	vecs[0].iov_base = (void *) 0x10000;
	vecs[0].iov_len = 4096;

	vecs[1].iov_base = (void *) 0x20000;
	vecs[1].iov_len = 4096;

	vecs[2].iov_base = (void *) 0x30000;
	vecs[2].iov_len = 4096;

	vecs[3].iov_base = (void *) 0x40000;
	vecs[3].iov_len = 4096;

	vecs[4].iov_base = (void *) 0x50000;
	vecs[4].iov_len = 4096;

	vecs[5].iov_base = (void *) 0x60000;
	vecs[5].iov_len = 4096;

	vecs[6].iov_base = (void *) 0x70000;
	vecs[6].iov_len = 4096;

	vecs[7].iov_base = (void *) 0x80000;
	vecs[7].iov_len = 4096;

	vecs[8].iov_base = (void *) 0x90000;
	vecs[8].iov_len = 4096;
	
	vecs[9].iov_base = (void *) 0xA0000;
	vecs[9].iov_len = 4096;

	int success = 0;
	int fail = 0;
	int attack = 0;

	pthread_t thread1;
	pthread_create(&thread1, NULL, attack_array, NULL);

	for (int i = 0; i < 100000; i ++) {
		// printf("i = %d:", i);
		while (!flipping_ready) {}
		trigger_ready = 1;
		finish = 0;
		ssize_t ret = vfs_writev(vecs, 10);
		if (ret == -1) {
			// printf("failed to execute writev.\n");
            fail ++;
		}
		else if (ret == -2) {
			// printf("attack worked - vecs[5] address is 0x%lx and length is %lu\n", vecs[5].iov_base, vecs[5].iov_len);
            attack ++;
		}
		else {
			// printf("writev worked correctly.\n");
            success ++;
		}

		trigger_ready = 0;
		vecs[5].iov_base = (void *) 0x60000;
	}

	finish = 1;
	pthread_join(thread1, NULL);

    printf("success: %d, fail: %d, attack: %d\n", success, fail, attack);

}