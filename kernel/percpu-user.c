/*
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * percpu system call
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

#include <linux/preempt.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>

/*
 * This structure needs to be naturally aligned, so that it does not
 * cross cacheline boundaries.
 */
struct thread_percpu_user {
	int32_t nesting;
	int32_t signal_sent;
	int32_t signo;
	int32_t current_cpu;
};

static void percpu_user_sched_in(struct preempt_notifier *notifier, int cpu)
{
	struct thread_percpu_user __user *tpu_user;
	struct thread_percpu_user tpu;
	struct task_struct *t = current;

	tpu_user = t->percpu_user;
	if (tpu_user == NULL)
		return;
	if (unlikely(t->flags & PF_EXITING))
		return;
	/*
	 * access_ok() of tpu_user has already been checked by sys_percpu().
	 */
	if (__copy_from_user(&tpu, tpu_user, sizeof(tpu))) {
		WARN_ON_ONCE(1);
		goto skip;
	}
	if (!tpu.nesting || tpu.signal_sent)
		goto skip;
	if (do_send_sig_info(tpu.signo, SEND_SIG_PRIV, t, 0)) {
		WARN_ON_ONCE(1);
		goto skip;
	}
	tpu.signal_sent = 1;
	tpu.current_cpu = cpu;
	if (__copy_to_user(tpu_user, &tpu, sizeof(tpu))) {
		WARN_ON_ONCE(1);
		goto skip;
	}
	return;

skip:
	if (__put_user(cpu, &tpu_user->current_cpu)) {
		WARN_ON_ONCE(1);
		return;
	}
}

static void percpu_user_sched_out(struct preempt_notifier *notifier,
		struct task_struct *next)
{
}

static struct preempt_ops percpu_user_ops = {
	.sched_in = percpu_user_sched_in,
	.sched_out = percpu_user_sched_out,
};

/*
 * If parent had a percpu-user preempt notifier, we need to setup our own.
 */
void percpu_user_fork(struct task_struct *t)
{
	struct task_struct *parent = current;

	if (!parent->percpu_user)
		return;
	preempt_notifier_init(&t->percpu_user_notifier, &percpu_user_ops);
	preempt_notifier_register(&t->percpu_user_notifier);
	t->percpu_user = parent->percpu_user;
}

void percpu_user_execve(struct task_struct *t)
{
	if (!t->percpu_user)
		return;
	preempt_notifier_unregister(&t->percpu_user_notifier);
	t->percpu_user = NULL;
}

/*
 * sys_percpu - setup user-space per-cpu critical section for caller thread
 */
SYSCALL_DEFINE2(percpu, struct thread_percpu_user __user *, tpu, int, flags)
{
	struct task_struct *t = current;

	if (flags)
		return -EINVAL;
	if (tpu == NULL) {
		if (t->percpu_user)
			preempt_notifier_unregister(&t->percpu_user_notifier);
		goto set_tpu;
	}
	if (!access_ok(VERIFY_WRITE, tpu, sizeof(struct thread_percpu_user)))
		return -EFAULT;
	preempt_disable();
	if (__put_user(smp_processor_id(), &tpu->current_cpu)) {
		WARN_ON_ONCE(1);
		preempt_enable();
		return -EFAULT;
	}
	preempt_enable();
	if (!current->percpu_user) {
		preempt_notifier_init(&t->percpu_user_notifier,
				&percpu_user_ops);
		preempt_notifier_register(&t->percpu_user_notifier);
	}
set_tpu:
	current->percpu_user = tpu;
	return 0;
}
