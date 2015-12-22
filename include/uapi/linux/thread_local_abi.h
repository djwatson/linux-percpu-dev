#ifndef _UAPI_LINUX_THREAD_LOCAL_ABI_H
#define _UAPI_LINUX_THREAD_LOCAL_ABI_H

/*
 * linux/thread_local_abi.h
 *
 * Thread-local ABI system call API
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

/*
 * The thread-local ABI structure should ideally be aligned at least on
 * 32 bytes multiples, but strictly requires to be aligned at least on
 * 64-bit. This accomodate linkers which can have a hard time
 * guaranteeing alignment of variables. Each thread-local ABI has a
 * fixed length of 64 bytes. If more fields are needed than the
 * available 64 bytes, a new thread-local ABI table should be defined.
 */
#define TLABI_MIN_ALIGNMENT	8
#define TLABI_ALIGNMENT		32
#define TLABI_LEN		64

enum thread_local_abi_feature {
	TLABI_FEATURE_NONE = 0,
	TLABI_FEATURE_CPU_ID = (1 << 0),
};

struct thread_local_abi {
	/*
	 * Thread-local ABI features field.
	 * Updated by the kernel, and read by user-space with
	 * single-copy atomicity semantics. Aligned on 32-bit.
	 * This field contains a mask of enabled features.
	 */
	uint32_t features;

	/*
	 * Thread-local ABI cpu_id field.
	 * Updated by the kernel, and read by user-space with
	 * single-copy atomicity semantics. Aligned on 32-bit.
	 */
	uint32_t cpu_id;

	/*
	 * Add new fields here, before padding. Increment TLABI_BYTES_USED
	 * accordingly.
	 */
#define TLABI_BYTES_USED	8
	char padding[TLABI_LEN - TLABI_BYTES_USED];
} __attribute__ ((aligned(TLABI_ALIGNMENT)));

#endif /* _UAPI_LINUX_THREAD_LOCAL_ABI_H */
