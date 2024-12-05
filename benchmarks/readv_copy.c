#include <stdlib.h>

#include "../include/read_write.h"

struct iovec vecs[10];

static ssize_t vfs_readv(const struct iovec* vec, unsigned long vlen) 
{
  
}

int main() 
{
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


}