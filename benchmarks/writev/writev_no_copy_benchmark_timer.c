/*
this file implements the writev syscall but without
the writing; just the checks. 

we attack this syscall with the tocttou double-fetch exploit
and show that we are able to change the `iov` buffer.
*/

#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <assert.h>
#include <time.h>


#include "../../include/read_write.h"

struct iovec *vecs;
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

struct iovec *iovec_from_user(const struct iovec *uvec,
		unsigned long nr_segs) {
	struct iovec *iov = uvec;
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

	if (user_access_begin(uvec, nr_segs * sizeof(*uvec))) {
        return NULL;
    }

	return iov;
}

ssize_t __attribute__ ((noinline)) import_iovec(int type, const struct iovec *uvec,
		 unsigned nr_segs, struct iovec **iovp, struct iov_iter *i) {
        
    ssize_t total_len = 0;
	unsigned long seg;
	struct iovec *iov;

    iov = iovec_from_user(uvec, nr_segs);
    if (iov == NULL) {
        return -1;
    }

    for (seg = 0; seg < nr_segs; seg++) {
		ssize_t len = (ssize_t)iov[seg].iov_len;

		if (user_access_begin(iov[seg].iov_base, len)) {
			return -1;
		}

		if (len > MAX_RW_COUNT - total_len) {
			len = MAX_RW_COUNT - total_len;
			iov[seg].iov_len = len;
		}
		total_len += len;
	}
	
	*iovp = iov;
	return total_len;

}

static ssize_t __attribute__ ((noinline)) vfs_writev(const struct iovec *vec, unsigned long vlen) {
    
	struct iovec *iov = NULL;
	struct iov_iter iter;
	size_t tot_len;
	ssize_t ret = 0;

    ret = import_iovec(ITER_SOURCE, vec, vlen, &iov, &iter);
	if (ret == -1) {
		printf("writev failed bounds check.\n");
		return -1;
	}

	if (iov[5].iov_base == KERNEL_LAND) {
		return -2;
	}

	ssize_t bytes_written = 0;
	for (int i = 0; i < vlen; i ++) {
		bytes_written += iov[i].iov_len;
	}

    // does file stuff with vec
    return bytes_written;
}

int main(int argc, char *argv[]) {

	assert(argc == 2 && "Must include a size for the iovec buffer.");
	int size = atoi(argv[1]);
    vecs = calloc(size * sizeof(struct iovec), sizeof(struct iovec));
	for (int i = 0; i <  size; i ++) {
		vecs[i].iov_base = 0xdeadbeef;
		vecs[i].iov_len = 1;
	}

	 struct timespec start, end;
    
	// warmup
    clock_gettime(CLOCK_MONOTONIC, &start);
	for (int i = 0; i < 10000; i ++) {
		ssize_t warmup = vfs_writev(vecs, size);
	}
    clock_gettime(CLOCK_MONOTONIC, &end);


    clock_gettime(CLOCK_MONOTONIC, &start);
	for (int i = 0; i < 100000; i ++) {
		ssize_t bytes_written = vfs_writev(vecs, size);
	}
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Elapsed time: %f seconds\n", elapsed_time);

}