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
 * The initial thread-local ABI shared structure is associated with
 * the tlabi_nr parameter value 0 passed to the thread_local_abi system
 * call. It will be henceforth referred to as "tlabi 0".
 *
 * This tlabi 0 structure is strictly required to be aligned on 64
 * bytes. The tlabi 0 structure has a fixed length of 64 bytes. Each of
 * its fields should be naturally aligned so no padding is necessary.
 * The size of tlabi 0 structure is fixed to 64 bytes to ensure that
 * neither the kernel nor user-space have to perform size checks. The
 * choice of 64 bytes matches the L1 cache size on common architectures.
 *
 * If more fields are needed than the available 64 bytes, a new tlabi
 * number should be reserved, associated to its own shared structure
 * layout.
 */
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
} __attribute__ ((aligned(TLABI_LEN)));

#endif /* _UAPI_LINUX_THREAD_LOCAL_ABI_H */
