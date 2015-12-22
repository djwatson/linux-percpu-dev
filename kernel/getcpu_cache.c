/*
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * getcpu cache system call
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/getcpu_cache.h>

static int getcpu_cache_update(int32_t __user *cpu_cache)
{
	if (put_user(raw_smp_processor_id(), cpu_cache))
		return -1;
	return 0;
}

/*
 * This resume handler should always be executed between a migration
 * triggered by preemption and return to user-space.
 */
void __getcpu_cache_handle_notify_resume(struct task_struct *t)
{
	if (unlikely(t->flags & PF_EXITING))
		return;
	if (getcpu_cache_update(t->cpu_cache))
		force_sig(SIGSEGV, t);
}

static int __get_cpu_cache_ptr(int32_t __user **cpu_cache,
		int32_t __user * __user *cpu_cachep)
{
#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		compat_uptr_t __user *compat_cachep =
			(compat_uptr_t __user *) cpu_cachep;
		compat_uptr_t compat_cache;

		if (get_user(compat_cache, compat_cachep))
			return -EFAULT;
		*cpu_cache = compat_ptr(compat_cache);
		return 0;
	}
#endif
	return get_user(*cpu_cache, cpu_cachep);
}

#define get_cpu_cache_ptr(cpu_cache, cpu_cachep)	\
	__get_cpu_cache_ptr(&(cpu_cache), cpu_cachep)

static int put_cpu_cache_ptr(int32_t __user *cpu_cache,
		int32_t __user * __user *cpu_cachep)
{
#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		compat_uptr_t compat_cache = ptr_to_compat(cpu_cache);
		compat_uptr_t __user *compat_cachep =
			(compat_uptr_t __user *) cpu_cachep;

		return put_user(compat_cache, compat_cachep);
	}
#endif
	return put_user(cpu_cache, cpu_cachep);
}

/*
 * sys_getcpu_cache - setup getcpu cache for caller thread
 */
SYSCALL_DEFINE3(getcpu_cache, int, cmd, int32_t __user * __user *, cpu_cachep,
		int, flags)
{
	if (unlikely(flags))
		return -EINVAL;

	switch (cmd) {
	case GETCPU_CACHE_GET:
		if (!current->cpu_cache)
			return -ENOENT;
		if (put_cpu_cache_ptr(current->cpu_cache, cpu_cachep))
			return -EFAULT;
		return 0;
	case GETCPU_CACHE_SET:
	{
		int32_t __user *cpu_cache;

		if (get_cpu_cache_ptr(cpu_cache, cpu_cachep))
			return -EFAULT;
		if (unlikely(!IS_ALIGNED((unsigned long)cpu_cache,
				sizeof(int32_t)) || !cpu_cache))
			return -EINVAL;
		/*
		 * Check if cpu_cache is already registered, and whether
		 * the address differs from *cpu_cachep.
		 */
		if (current->cpu_cache) {
			if (current->cpu_cache != cpu_cache)
				return -EBUSY;
			return 0;
		}
		current->cpu_cache = cpu_cache;
		/*
		 * Migration reads the current->cpu_cache pointer to
		 * decide whether the notify_resume flag should be set.
		 * Therefore, we need to ensure that the scheduler sees
		 * the getcpu cache pointer update before we update the
		 * getcpu cache content with the current CPU number.
		 * This ensures we don't return from the getcpu_cache
		 * system call to userspace with a wrong CPU number in
		 * the cache if preempted and migrated after the initial
		 * successful cpu cache update (below).
		 *
		 * This compiler barrier enforces ordering of the
		 * current->cpu_cache address store before update of the
		 * *cpu_cache.
		 */
		barrier();
		/*
		 * Do an initial cpu cache update to populate the
		 * current CPU value, and to check whether the address
		 * is valid, thus ensuring we return -EFAULT in case or
		 * invalid address rather than triggering a SIGSEGV if
		 * put_user() fails in the resume notifier.
		 */
		if (getcpu_cache_update(cpu_cache)) {
			current->cpu_cache = NULL;
			return -EFAULT;
		}
		return 0;
	}
	default:
		return -EINVAL;
	}
}
