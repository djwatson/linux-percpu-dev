/*
 * Copyright (C) 2015-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Restartable sequence system call
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
#include <linux/rseq.h>

/*
 * This resume handler should always be executed between a migration
 * triggered by preemption and return to user-space.
 */
void __rseq_handle_notify_resume(struct task_struct *t)
{
	if (unlikely(t->flags & PF_EXITING))
		return;
	if (put_user(raw_smp_processor_id(), &t->rseq->cpu_id))
		force_sig(SIGSEGV, t);
}

/*
 * sys_rseq - setup restartable section interface for caller thread
 */
SYSCALL_DEFINE2(rseq, struct thread_rseq __user *, thread_rseq,
		int, flags)
{
	struct thread_rseq __user *old_thread_rseq;

	if (unlikely(flags || !rseq_feature_available()))
		return -EINVAL;

	old_thread_rseq = current->rseq;
	if (thread_rseq) {
		if (old_thread_rseq) {
			/*
			 * If rseq is already registered, check whether
			 * the provided address differs from the prior
			 * one.
			 */
			if (old_thread_rseq != thread_rseq)
				return -EBUSY;
		} else {
			if (!IS_ALIGNED((unsigned long)thread_rseq,
					sizeof(uint64_t)))
				return -EINVAL;
			if (!access_ok(VERIFY_WRITE, thread_rseq,
					sizeof(struct thread_rseq)))
				return -EFAULT;
			current->rseq = thread_rseq;
		}
	} else {
		if (!old_thread_rseq)
			return -ENOENT;
	}

	/*
	 * If the rseq was previously unset, and has just been
	 * requested, ensure the cpu_id field is updated before
	 * returning to user-space.
	 */
	if (!old_thread_rseq)
		rseq_set_notify_resume(current);
	return 0;
}
