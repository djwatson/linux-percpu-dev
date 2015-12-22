#ifndef _UAPI_LINUX_RSEQ_H
#define _UAPI_LINUX_RSEQ_H

/*
 * linux/rseq.h
 *
 * Restartable sequence API
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

#ifdef __LP64__
# define RSEQ_FIELD_u32_u64(field)	uint64_t field
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define RSEQ_FIELD_u32_u64(field)	uint32_t field, _padding ## field
#else
# define RSEQ_FIELD_u32_u64(field)	uint32_t _padding ## field, field
#endif

/* Should be volatile. */
struct cpudata_rseq {
	RSEQ_FIELD_u32_u64(seqnum);
	uint32_t cpu_id;
} __attribute__((aligned(sizeof(uint64_t))));

struct stack_rseq {
	RSEQ_FIELD_u32_u64(old_thread_seqnum);	/* Snapshot at rseq_start(). */
	uint32_t cpu_id;			/* Snapshot at rseq_start(). */
} __attribute__((aligned(sizeof(uint64_t))));

/* Should be volatile. */
struct thread_rseq {
	RSEQ_FIELD_u32_u64(seqnum);
	RSEQ_FIELD_u32_u64(cpudata_rseq_ptr);
	RSEQ_FIELD_u32_u64(rseq_post_commit_ip);
	uint32_t cpu_id;
} __attribute__((aligned(sizeof(uint64_t))));

#endif /* _UAPI_LINUX_RSEQ_H */
