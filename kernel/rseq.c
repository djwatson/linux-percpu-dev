/*
 * Restartable sequences system call
 *
 * Restartable sequences are a lightweight interface that allows
 * user-level code to be executed atomically relative to scheduler
 * preemption and signal delivery. Typically used for implementing
 * per-cpu operations.
 *
 * It allows user-space to perform update operations on per-cpu data
 * without requiring heavy-weight atomic operations.
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
#include <linux/rseq.h>
#include <linux/types.h>
#include <asm/ptrace.h>

#define CREATE_TRACE_POINTS
#include <trace/events/rseq.h>

/*
 * Each restartable sequence assembly block defines a "struct rseq_cs"
 * structure which describes the start_ip and post_commit_ip addresses,
 * as well as the abort_ip address where the kernel should move the
 * thread instruction pointer if a rseq critical section assembly block
 * is preempted or if a signal is delivered on top of a rseq critical
 * section assembly block.
 *
 * The algorithm for a restartable sequence assembly block is as
 * follows:
 *
 * rseq_start()
 *
 *   0. Userspace loads the current event counter value from the
 *      event_counter field of the registered struct rseq TLS area,
 *
 * rseq_finish()
 *
 *   Steps [1]-[3] (inclusive) need to be a sequence of instructions in
 *   userspace that can handle being moved to the abort_ip between any
 *   of those instructions.
 *
 *   The abort_ip address needs to be less than start_ip, or
 *   greater-or-equal the post_commit_ip. Step [4] and the failure
 *   code step [F1] need to be at addresses lesser than start_ip, or
 *   greater-or-equal the post_commit_ip.
 *
 *       [start_ip]
 *   1.  Userspace stores the address of the struct rseq_cs assembly
 *       block descriptor into the rseq_cs field of the registered
 *       struct rseq TLS area. This update is performed through a single
 *       store, followed by a compiler barrier which prevents the
 *       compiler from moving following loads or stores before this
 *       store.
 *
 *   2.  Userspace tests to see whether the current event counter value
 *       match the value loaded at [0]. Manually jumping to [F1] in case
 *       of a mismatch.
 *
 *       Note that if we are preempted or interrupted by a signal
 *       after [1] and before post_commit_ip, then the kernel also
 *       performs the comparison performed in [2], and conditionally
 *       clears the rseq_cs field of struct rseq, then jumps us to
 *       abort_ip.
 *
 *   3.  Userspace critical section final instruction before
 *       post_commit_ip is the commit. The critical section is
 *       self-terminating.
 *       [post_commit_ip]
 *
 *   4.  Userspace clears the rseq_cs field of the struct rseq
 *       TLS area.
 *
 *   5.  Return true.
 *
 *   On failure at [2]:
 *
 *   F1. Userspace clears the rseq_cs field of the struct rseq
 *       TLS area. Followed by step [F2].
 *
 *       [abort_ip]
 *   F2. Return false.
 */

/*
 * The rseq_event_counter allow user-space to detect preemption and
 * signal delivery. It increments at least once before returning to
 * user-space if a thread is preempted or has a signal delivered. It is
 * not meant to be an exact counter of such events.
 *
 * Overflow of the event counter is not a problem in practice. It
 * increments at most once between each user-space thread instruction
 * executed, so we would need a thread to execute 2^32 instructions or
 * more between rseq_start() and rseq_finish(), while single-stepping,
 * for this to be an issue.
 *
 * On 64-bit architectures, both cpu_id and event_counter can be updated
 * with a single 64-bit store. On 32-bit architectures, __put_user() is
 * expected to perform two 32-bit single-copy stores to guarantee
 * single-copy atomicity semantics for other threads.
 */
static bool rseq_update_cpu_id_event_counter(struct task_struct *t)
{
	union rseq_cpu_event u;

	u.e.cpu_id = raw_smp_processor_id();
	u.e.event_counter = ++t->rseq_event_counter;
	if (__put_user(u.v, &t->rseq->u.v))
		return false;
	trace_rseq_update(t);
	return true;
}

static bool rseq_get_rseq_cs(struct task_struct *t,
		void __user **start_ip,
		void __user **post_commit_ip,
		void __user **abort_ip)
{
	unsigned long ptr;
	struct rseq_cs __user *urseq_cs;
	struct rseq_cs rseq_cs;

	if (__get_user(ptr, &t->rseq->rseq_cs))
		return false;
	if (!ptr)
		return true;
	urseq_cs = (struct rseq_cs __user *)ptr;
	if (copy_from_user(&rseq_cs, urseq_cs, sizeof(rseq_cs)))
		return false;
	*start_ip = (void __user *)rseq_cs.start_ip;
	*post_commit_ip = (void __user *)rseq_cs.post_commit_ip;
	*abort_ip = (void __user *)rseq_cs.abort_ip;
	return true;
}

static bool rseq_ip_fixup(struct pt_regs *regs)
{
	struct task_struct *t = current;
	void __user *start_ip = NULL;
	void __user *post_commit_ip = NULL;
	void __user *abort_ip = NULL;
	bool ret;

	ret = rseq_get_rseq_cs(t, &start_ip, &post_commit_ip, &abort_ip);
	trace_rseq_ip_fixup((void __user *)instruction_pointer(regs),
		start_ip, post_commit_ip, abort_ip, t->rseq_event_counter,
		ret);
	if (!ret)
		return false;

	/* Handle potentially not being within a critical section. */
	if ((void __user *)instruction_pointer(regs) >= post_commit_ip ||
			(void __user *)instruction_pointer(regs) < start_ip)
		return true;

	/*
	 * We need to clear rseq_cs upon entry into a signal
	 * handler nested on top of a rseq assembly block, so
	 * the signal handler will not be fixed up if itself
	 * interrupted by a nested signal handler or preempted.
	 */
	if (clear_user(&t->rseq->rseq_cs, sizeof(t->rseq->rseq_cs)))
		return false;

	/*
	 * We set this after potentially failing in
	 * clear_user so that the signal arrives at the
	 * faulting rip.
	 */
	instruction_pointer_set(regs, (unsigned long)abort_ip);
	return true;
}

/*
 * This resume handler should always be executed between any of:
 * - preemption,
 * - signal delivery,
 * and return to user-space.
 *
 * This is how we can ensure that the entire rseq critical section,
 * consisting of both the C part and the assembly instruction sequence,
 * will issue the commit instruction only if executed atomically with
 * respect to other threads scheduled on the same CPU, and with respect
 * to signal handlers.
 */
void __rseq_handle_notify_resume(struct pt_regs *regs)
{
	struct task_struct *t = current;

	if (unlikely(t->flags & PF_EXITING))
		return;
	if (!access_ok(VERIFY_WRITE, t->rseq, sizeof(*t->rseq)))
		goto error;
	if (!rseq_update_cpu_id_event_counter(t))
		goto error;
	if (!rseq_ip_fixup(regs))
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
	if (!rseq) {
		/* Unregister rseq for current thread. */
		if (unlikely(flags & ~RSEQ_FORCE_UNREGISTER))
			return -EINVAL;
		if (flags & RSEQ_FORCE_UNREGISTER) {
			current->rseq = NULL;
			current->rseq_refcount = 0;
			return 0;
		}
		if (!current->rseq_refcount)
			return -ENOENT;
		if (!--current->rseq_refcount)
			current->rseq = NULL;
		return 0;
	}

	if (unlikely(flags))
		return -EINVAL;

	if (current->rseq) {
		/*
		 * If rseq is already registered, check whether
		 * the provided address differs from the prior
		 * one.
		 */
		BUG_ON(!current->rseq_refcount);
		if (current->rseq != rseq)
			return -EBUSY;
		if (current->rseq_refcount == UINT_MAX)
			return -EOVERFLOW;
		current->rseq_refcount++;
	} else {
		/*
		 * If there was no rseq previously registered,
		 * we need to ensure the provided rseq is
		 * properly aligned and valid.
		 */
		BUG_ON(current->rseq_refcount);
		if (!IS_ALIGNED((unsigned long)rseq, __alignof__(*rseq)))
			return -EINVAL;
		if (!access_ok(VERIFY_WRITE, rseq, sizeof(*rseq)))
			return -EFAULT;
		current->rseq = rseq;
		current->rseq_refcount = 1;
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
