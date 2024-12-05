#include <sys/types.h>
#include <limits.h>
#include <stdbool.h>
#include <unistd.h>

#define UIO_FASTIOV 8
#define ITER_SOURCE 1
#define PAGE_MASK 0xFFFFF000
#define MSG_CMSG_COMPAT	0x80000000
#define MAX_RW_COUNT INT_MAX & PAGE_MASK
#define UIO_MAXIOV 1024
#define KERNEL_LAND (void *)0xffffffff80000000
#define ARRAY_SIZE(array) sizeof(array) / sizeof((array)[0])
#define PAGE_ALIGN(ptr, page_size) (void *)(((uintptr_t)ptr) & ~(page_size - 1))
#define PAGE_OFFSET(ptr, page_size) (void *)(((uintptr_t)ptr) & (page_size - 1))
#define EINVAL 22
#define EMSGSIZE 90
#define ENOBUFS 105
#define MSG_SPLICE_PAGES 0x8000000
#define MSG_SENDPAGE_NOPOLICY 0x10000
#define MSG_SENDPAGE_DECRYPTED	0x100000
#define MSG_INTERNAL_SENDMSG_FLAGS \
	(MSG_SPLICE_PAGES | MSG_SENDPAGE_NOPOLICY | MSG_SENDPAGE_DECRYPTED)

#define __aligned(x) __attribute__((aligned(x)))


typedef unsigned long    __kernel_size_t;
typedef unsigned int __kernel_socklen_t;
typedef unsigned short int sa_family_t;

struct iovec
{
	void *iov_base;
	unsigned long iov_len;
};

struct iov_iter {
	unsigned char iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	/*
	 * Hack alert: overlay ubuf_iovec with iovec + count, so
	 * that the members resolve correctly regardless of the type
	 * of iterator used. This means that you can use:
	 *
	 * &iter->__ubuf_iovec or iter->__iov
	 *
	 * interchangably for the user_backed cases, hence simplifying
	 * some of the cases that need to deal with both.
	 */
	union {
		/*
		 * This really should be a const, but we cannot do that without
		 * also modifying any of the zero-filling iter init functions.
		 * Leave it non-const for now, but it should be treated as such.
		 */
		struct iovec __ubuf_iovec;
		struct {
			union {
				/* use iter_iov() to get the current vec */
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				const struct folio_queue *folioq;
				struct xarray *xarray;
				void *ubuf;
			};
			size_t count;
		};
	};
	union {
		unsigned long nr_segs;
		unsigned char folioq_slot;
		off_t xarray_start;
	};
};

struct user_msghdr {
	void *msg_name;	/* ptr to socket address structure */
	int		msg_namelen;		/* size of socket address structure */
	struct iovec *msg_iov;	/* scatter/gather array */
	__kernel_size_t	msg_iovlen;		/* # elements in msg_iov */
	void *msg_control;	/* ancillary data */
	__kernel_size_t	msg_controllen;		/* ancillary data buffer length */
	unsigned int	msg_flags;		/* flags on received message */
};

struct msghdr {
	void		*msg_name;	/* ptr to socket address structure */
	int		msg_namelen;	/* size of socket address structure */

	int		msg_inq;	/* output, data left in socket */

	struct iov_iter	msg_iter;	/* data */

	/*
	 * Ancillary data. msg_control_user is the user buffer used for the
	 * recv* side when msg_control_is_user is set, msg_control is the kernel
	 * buffer used for all other cases.
	 */
	union {
		void	*msg_control;
		void	*msg_control_user;
	};
	bool		msg_control_is_user : 1;
	bool		msg_get_inq : 1;/* return INQ after receive */
	unsigned int	msg_flags;	/* flags on received message */
	__kernel_size_t	msg_controllen;	/* ancillary data buffer length */
	struct kiocb	*msg_iocb;	/* ptr to iocb for async requests */
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sk_buff *skb,
			    struct iov_iter *from, size_t length);
};

struct sockaddr_storage {
    sa_family_t ss_family;
    char __data[128 - sizeof(sa_family_t)];
};

enum iter_type {
    ITER_IOVEC,       
    ITER_KVEC,        
    ITER_BVEC,        
    ITER_XARRAY,      
    ITER_PIPE,        
    ITER_DISCARD,     
    ITER_DEST        
};

struct cmsghdr {
	__kernel_size_t	cmsg_len;	/* data byte count, including hdr */
        int		cmsg_level;	/* originating protocol */
        int		cmsg_type;	/* protocol-specific type */
};

struct used_address {
	struct sockaddr_storage name;
	unsigned int name_len;
};