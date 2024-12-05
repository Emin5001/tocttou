#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>
#include <pthread.h>

#include "../../include/read_write.h";

sigjmp_buf jmpbuf;

#define unsafe_get_user(x, p)do {                       \
    if (sigsetjmp(jmpbuf, 1) == 0) {                    \
        x = *p;                                         \
    }                                                   \
} while (0)

#define NUM_IOVS 10

struct iovec vecs[10];
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

struct iovec *iovec_from_user(const struct iovec *uvec, unsigned long nr_segs, unsigned long fast_segs, struct iovec *fast_iov) 
{
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

	if (user_access_begin(uvec, nr_segs * sizeof(*uvec))) 
  {
		return NULL;
	}

	return iov;
}

ssize_t import_iovec(int type, const struct iovec *uvec, unsigned nr_segs, unsigned fast_segs, struct iovec **iovp, struct iov_iter *i) 
{        
  ssize_t total_len = 0;
	unsigned long seg;
	struct iovec *iov;

  iov = iovec_from_user(uvec, nr_segs, fast_segs, *iovp);

  if (iov == NULL) 
  {
    return -1;
  };

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

	*iovp = iov;

	return total_len;
}

static ssize_t __attribute__((noinline)) vmsplice(const struct iovec *iov, size_t nr_segs, unsigned int flags) 
{
  struct iovec iovstack[UIO_FASTIOV], *iov = iovstack;
  struct iov_iter iter;
  ssize_t error;
  int type;

  error = import_iovec(type, iov, nr_segs, ARRAY_SIZE(iovstack), &iov, &iter);
}

int main()
{
  return 0; 
}