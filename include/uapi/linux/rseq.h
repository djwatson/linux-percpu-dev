#ifndef _UAPI_LINUX_RSEQ_H
#define _UAPI_LINUX_RSEQ_H

/*
 * linux/rseq.h
 *
 * Restartable sequences system call API
 *
 * Copyright (c) 2015-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef __KERNEL__
# include <linux/types.h>
#else	/* #ifdef __KERNEL__ */
# include <stdint.h>
#endif	/* #else #ifdef __KERNEL__ */

#include <asm/byteorder.h>

#ifdef __LP64__
# define RSEQ_FIELD_u32_u64(field)	uint64_t field
#elif defined(__BYTE_ORDER) ? \
	__BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
# define RSEQ_FIELD_u32_u64(field)	uint32_t _padding ## field, field
#else
# define RSEQ_FIELD_u32_u64(field)	uint32_t field, _padding ## field
#endif

struct rseq {
	/*
	 * Restartable sequences cpu_id field.
	 * Updated by the kernel, and read by user-space with
	 * single-copy atomicity semantics. Aligned on 32-bit.
	 * Negative values are reserved for user-space.
	 */
	int32_t cpu_id;
	/*
	 * Restartable sequences event_counter field.
	 * Updated by the kernel, and read by user-space with
	 * single-copy atomicity semantics. Aligned on 32-bit.
	 */
	uint32_t event_counter;
	/*
	 * Restartable sequences post_commit_ip field.
	 * Updated by user-space, read by the kernel with
	 * single-copy atomicity semantics. Aligned on 64-bit.
	 */
	RSEQ_FIELD_u32_u64(post_commit_ip);
} __attribute__((aligned(sizeof(uint64_t))));

#endif /* _UAPI_LINUX_RSEQ_H */
