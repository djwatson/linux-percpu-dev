/*
 * Copyright (C) 2015-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Thread-local ABI system call
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
#include <linux/thread_local_abi.h>

#define TLABI_FEATURES_UNKNOWN		(~TLABI_FEATURE_CPU_ID)

/*
 * This resume handler should always be executed between a migration
 * triggered by preemption and return to user-space.
 */
void __tlabi_cpu_id_handle_notify_resume(struct task_struct *t)
{
	if (unlikely(t->flags & PF_EXITING))
		return;
	if (put_user(raw_smp_processor_id(), &t->tlabi->cpu_id))
		force_sig(SIGSEGV, t);
}

/*
 * sys_thread_local_abi - setup thread-local ABI for caller thread
 */
SYSCALL_DEFINE4(thread_local_abi, uint32_t, tlabi_nr, void *, _tlabi,
		uint32_t, feature_mask, int, flags)
{
	struct thread_local_abi __user *tlabi =
			(struct thread_local_abi __user *)_tlabi;
	uint32_t orig_feature_mask;

	/* Sanity check on size of ABI structure. */
	BUILD_BUG_ON(sizeof(struct thread_local_abi) != TLABI_LEN);

	if (unlikely(flags || tlabi_nr))
		return -EINVAL;
	/* Ensure requested features are available. */
	if (feature_mask & TLABI_FEATURES_UNKNOWN)
		return -EINVAL;
	if ((feature_mask & TLABI_FEATURE_CPU_ID)
			&& !tlabi_cpu_id_feature_available())
		return -EINVAL;

	if (tlabi) {
		if (current->tlabi) {
			/*
			 * If tlabi is already registered, check
			 * whether the provided address differs from the
			 * prior one.
			 */
			if (current->tlabi != tlabi)
				return -EBUSY;
		} else {
			/*
			 * If there was no tlabi previously registered,
			 * we need to ensure the provided tlabi is
			 * properly aligned and valid.
			 */
			if (!IS_ALIGNED((unsigned long)tlabi, TLABI_LEN))
				return -EINVAL;
			if (!access_ok(VERIFY_WRITE, tlabi,
					sizeof(struct thread_local_abi)))
				return -EFAULT;
			current->tlabi = tlabi;
		}
	} else {
		if (!current->tlabi)
			return -ENOENT;
	}

	/* Update feature mask for current thread. */
	orig_feature_mask = current->tlabi_features;
	current->tlabi_features |= feature_mask;
	if (put_user(current->tlabi_features, &current->tlabi->features)) {
		current->tlabi = NULL;
		current->tlabi_features = 0;
		return -EFAULT;
	}

	/*
	 * If the CPU_ID feature was previously inactive, and has just
	 * been requested, ensure the cpu_id field is updated before
	 * returning to user-space.
	 */
	if (!(orig_feature_mask & TLABI_FEATURE_CPU_ID))
		tlabi_cpu_id_set_notify_resume(current);
	return 0;
}
