#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>


#include "../../include/read_write.h"
#include "../../../PTEditor/ptedit_header.h"

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

void segfault_handler(int signal) {
    if (signal == SIGSEGV) {
        fprintf(stderr, "Segmentation fault (signal %d) occurred!\n", signal);
        // fail ++;
        // exit(EXIT_FAILURE); // Exit the program gracefully
    }
}

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

struct iovec *get_iovec_addr(struct iovec *iov_addr, void **writeable_addresses, uintptr_t first_page) {
	uintptr_t base = PAGE_ALIGN(iov_addr, 4096);
	int index = (base - first_page) / 4096;
	struct iovec *translated_iov_addr = (uintptr_t)writeable_addresses[index] + (uintptr_t)PAGE_OFFSET(iov_addr, 4096);
	return translated_iov_addr;
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

static ssize_t __attribute__ ((noinline)) vfs_writev(const struct iovec *vec, unsigned long vlen) {
    
    struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	size_t tot_len;
	ssize_t ret = 0;

	// translating address of iov aray to VAs that have wrte permissions.
	// max size of uvec is 1024 entries, sizeof(iovec) is 16, can max out at 4 pages do 5 for rounding
    void *writeable_addresses[5];
    ret = import_iovec(ITER_SOURCE, vec, vlen, ARRAY_SIZE(iovstack), &iov, &iter, &writeable_addresses);
	struct iovec *iovec_ptr = (iov == NULL) ? iovstack : iov;
	if (iovec_ptr[5].iov_base == KERNEL_LAND) {
		return -2;
	}

	uintptr_t first_page = (uintptr_t) PAGE_ALIGN(vec, 4096);
    uintptr_t last_page = (uintptr_t) PAGE_ALIGN((char *)vec + (vlen * sizeof(struct iovec)), 4096);

	ssize_t bytes_written = 0;
	for (int i = 0; i < vlen; i ++) {
		// bytes_written += get_iovec_addr(&vec[i], &writeable_addresses, first_page)->iov_len;
	}

   
    for (uintptr_t address = first_page; address <= last_page; address += 4096) {
		ptedit_pte_set_bit(address, 0, PTEDIT_PAGE_BIT_RW);
        ptedit_invalidate_tlb(address);
    }

    // does file stuff with iov
    return bytes_written;
}

int main(int argc, char *argv[]) {

	if (ptedit_init()) {
        printf("Could not initialize ptedit (did you load the kernel module?)\n");
        return 1;
    }

	assert(argc == 2 && "Must include a size for the iovec buffer.");
	int size = atoi(argv[1]);
	vecs = calloc(size * sizeof(struct iovec), sizeof(struct iovec));
	for (int i = 0; i <  size; i ++) {
		vecs[i].iov_base = 0xdeadbeef;
		vecs[i].iov_len = 1;
	}


	// warmup
	for (int i = 0; i < 10000; i ++) {
		ssize_t warmup = vfs_writev(vecs, size);
	}

	for (int i = 0; i < 100000; i ++) {
		ssize_t bytes_written = vfs_writev(vecs, size);
	}

}