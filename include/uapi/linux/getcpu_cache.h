#ifndef _UAPI_LINUX_GETCPU_CACHE_H
#define _UAPI_LINUX_GETCPU_CACHE_H

/*
 * linux/getcpu_cache.h
 *
 * getcpu_cache system call API
 *
 * Copyright (c) 2015, 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

/**
 * enum getcpu_cache_cmd - getcpu_cache system call command
 * @GETCPU_CACHE_GET: Get the address of the current thread CPU number
 *                    cache.
 * @GETCPU_CACHE_SET: Set the address of the current thread CPU number
 *                    cache.
 */
enum getcpu_cache_cmd {
	GETCPU_CACHE_GET = 0,
	GETCPU_CACHE_SET = 1,
};

#endif /* _UAPI_LINUX_GETCPU_CACHE_H */
