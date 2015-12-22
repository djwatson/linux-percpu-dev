/*
 * Restartable sequences system call
 *
 * Restartable sequences are a lightweight interface that allows
 * user-level code to be executed atomically relative to scheduler
 * preemption and signal delivery. Typically used for implementing
 * per-cpu operations.
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
 *
 * Copyright (C) 2015, Google, Inc.,
 * Paul Turner <pjt@google.com> and Andrew Hunter <ahh@google.com>
 * Copyright (C) 2015-2016, EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/rseq.h>
#include <asm/ptrace.h>

/*
 * The algorithm for a restartable sequence is as follows:
 *
 * rseq_start()
 *
 *   0. Userspace loads the current event counter value
 *      from the event_counter field of the registered
 *      struct rseq TLS area,
 *
 * rseq_finish()
 *
 *   (Steps 1-5 (inclusive) need to be a contiguous sequence of
 *   instructions in userspace)
 *
 *   1. Userspace copies the event counter value read at
 *      [0] into the register identified by the
 *      arch-specific rseq_regs_event_counter() accessor,
 *   2. Userspace loads the rip to move to at failure into
 *      the register identified by the arch-specific
 *      rseq_regs_abort_ip() accessor,
 *   3. Userspace loads the rip of the instruction following
 *      the critical section into the post_commit_ip field
 *      of the registered struct rseq TLS area,
 *   4. Userspace tests to see whether the current event
 *      counter values match those loaded at 0.  Manually
 *      jumping to the address from [2] in the case of a
 *      mismatch.
 *
 *      Note that if we are preempted or interrupted by a signal
 *      after [3] and before post_commit_ip, then the kernel also
 *      performs the comparison performed in [4] and conditionally
 *      jump us to [2].
 *   5. Userspace critical section final instruction before
 *      post_commit_ip is the commit. The critical section is
 *      self-terminating.
 *   6. Userspace clears the post_commit_ip field of the struct rseq
 *      TLS area.
 *   7. Return true.
 *
 *   On failure:
 *   F1. Userspace clears the post_commit_ip field of the struct rseq
 *       TLS area.
 *   F2. Return false.
 */

static int rseq_increment_event_counter(struct task_struct *t)
{
	if (__put_user(++t->rseq_event_counter,
			&t->rseq->u.e.event_counter))
		return -1;
	return 0;
}

static int rseq_get_rseq_cs(struct task_struct *t,
		void __user **post_commit_ip,
		void __user **abort_ip)
{
	unsigned long ptr;
	struct rseq_cs __user *rseq_cs;

	if (__get_user(ptr, &t->rseq->rseq_cs))
		return -1;
	if (!ptr)
		return 0;
#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		rseq_cs = compat_ptr((compat_uptr_t)ptr);
		if (get_user(ptr, &rseq_cs->post_commit_ip))
			return -1;
		*post_commit_ip = compat_ptr((compat_uptr_t)ptr);
		if (get_user(ptr, &rseq_cs->abort_ip))
			return -1;
		*abort_ip = compat_ptr((compat_uptr_t)ptr);
		return 0;
	}
#endif
	rseq_cs = (struct rseq_cs __user *)ptr;
	if (get_user(ptr, &rseq_cs->post_commit_ip))
		return -1;
	*post_commit_ip = (void __user *)ptr;
	if (get_user(ptr, &rseq_cs->abort_ip))
		return -1;
	*abort_ip = (void __user *)ptr;
	return 0;
}

static int rseq_ip_fixup(struct pt_regs *regs)
{
	struct task_struct *t = current;
	void __user *post_commit_ip = NULL;
	void __user *abort_ip = NULL;

	if (rseq_get_rseq_cs(t, &post_commit_ip, &abort_ip))
		return -1;

	/* Handle potentially being within a critical section. */
	if ((void __user *)instruction_pointer(regs) < post_commit_ip) {
		if (clear_user(&t->rseq->rseq_cs,
				sizeof(t->rseq->rseq_cs)))
			return -1;

		/*
		 * We set this after potentially failing in
		 * clear_user so that the signal arrives at the
		 * faulting rip.
		 */
		instruction_pointer_set(regs, (unsigned long)abort_ip);
	}
	return 0;
}

/*
 * This resume handler should always be executed between any of:
 * - preemption,
 * - signal delivery,
 * and return to user-space.
 */
void __rseq_handle_notify_resume(struct pt_regs *regs)
{
	struct task_struct *t = current;

	if (unlikely(t->flags & PF_EXITING))
		return;
	if (!access_ok(VERIFY_WRITE, t->rseq, sizeof(*t->rseq)))
		goto error;
	if (__put_user(raw_smp_processor_id(), &t->rseq->u.e.cpu_id))
		goto error;
	if (rseq_increment_event_counter(t))
		goto error;
	if (rseq_ip_fixup(regs))
		goto error;
	return;

error:
	force_sig(SIGSEGV, t);
}

/*
 * sys_rseq - setup restartable sequences for caller thread.
 */
SYSCALL_DEFINE2(rseq, struct rseq __user *, rseq, int, flags)
{
	if (unlikely(flags))
		return -EINVAL;
	if (!rseq_feature_available())
		return -EINVAL;
	if (!rseq) {
		if (!current->rseq)
			return -ENOENT;
		return 0;
	}

	if (current->rseq) {
		/*
		 * If rseq is already registered, check whether
		 * the provided address differs from the prior
		 * one.
		 */
		if (current->rseq != rseq)
			return -EBUSY;
	} else {
		/*
		 * If there was no rseq previously registered,
		 * we need to ensure the provided rseq is
		 * properly aligned and valid.
		 */
		if (!IS_ALIGNED((unsigned long)rseq, sizeof(uint64_t)))
			return -EINVAL;
		if (!access_ok(VERIFY_WRITE, rseq, sizeof(*rseq)))
			return -EFAULT;
		current->rseq = rseq;
		/*
		 * If rseq was previously inactive, and has just
		 * been registered, ensure the cpu_id and
		 * event_counter fields are updated before
		 * returning to user-space.
		 */
		rseq_set_notify_resume(current);
	}

	return 0;
}
