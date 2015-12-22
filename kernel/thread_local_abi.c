/*
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * thread_local_abi system call
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

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/slab.h>

static struct thread_local_abi_entry *
	add_thread_entry(struct task_struct *t,
		size_t abi_len,
		struct thread_local_abi __user *ptr)
{
	struct thread_local_abi_entry *te;

	te = kmalloc(sizeof(*te), GFP_KERNEL);
	if (!te)
		return NULL;
	te->thread_local_abi_len = abi_len;
	te->thread_local_abi = ptr;
	list_add(&te->entry, &t->thread_local_abi_head);
	return te;
}

static void remove_thread_entry(struct thread_local_abi_entry *te)
{
	list_del(&te->entry);
	kfree(te);
}

static void remove_all_thread_entry(struct task_struct *t)
{
	struct thread_local_abi_entry *te, *te_tmp;

	list_for_each_entry_safe(te, te_tmp, &t->thread_local_abi_head, entry)
		remove_thread_entry(te);
}

static struct thread_local_abi_entry *
	find_thread_entry(struct task_struct *t,
		struct thread_local_abi __user *ptr)
{
	struct thread_local_abi_entry *te;

	list_for_each_entry(te, &t->thread_local_abi_head, entry) {
		if (te->thread_local_abi == ptr)
			return te;
	}
	return NULL;
}

static int thread_local_abi_update_entry(struct thread_local_abi_entry *te)
{
	if (te->thread_local_abi_len <
			offsetof(struct thread_local_abi, cpu)
				+ sizeof(te->thread_local_abi->cpu))
		return 0;
	if (put_user(raw_smp_processor_id(), &te->thread_local_abi->cpu)) {
		/*
		 * Force unregistration of each entry causing
		 * put_user() errors.
		 */
		remove_thread_entry(te);
		return -1;
	}
	return 0;

}

static int thread_local_abi_update(struct task_struct *t)
{
	struct thread_local_abi_entry *te, *te_tmp;
	int err = 0;

	list_for_each_entry_safe(te, te_tmp, &t->thread_local_abi_head, entry) {
		if (thread_local_abi_update_entry(te))
			err = -1;
	}
	return err;
}

/*
 * This resume handler should always be executed between a migration
 * triggered by preemption and return to user-space.
 */
void __thread_local_abi_handle_notify_resume(struct task_struct *t)
{
	if (unlikely(t->flags & PF_EXITING))
		return;
	if (thread_local_abi_update(t))
		force_sig(SIGSEGV, t);
}

/*
 * If parent process has a thread-local ABI, the child inherits. Only applies
 * when forking a process, not a thread.
 */
int thread_local_abi_fork(struct task_struct *t)
{
	struct thread_local_abi_entry *te;

	list_for_each_entry(te, &current->thread_local_abi_head, entry) {
		if (!add_thread_entry(t, te->thread_local_abi_len,
				te->thread_local_abi))
			return -1;
	}
	return 0;
}

void thread_local_abi_execve(struct task_struct *t)
{
	remove_all_thread_entry(t);
}

void thread_local_abi_exit(struct task_struct *t)
{
	remove_all_thread_entry(t);
}

/*
 * sys_thread_local_abi - setup thread-local ABI for caller thread
 */
SYSCALL_DEFINE3(thread_local_abi, struct thread_local_abi __user *, tlap,
		size_t, len, int, flags)
{
	size_t minlen;
	struct thread_local_abi_entry *te;

	if (flags || !tlap)
		return -EINVAL;
	te = find_thread_entry(current, tlap);
	if (!len) {
		/* Unregistration is requested by a 0 len argument. */
		if (!te)
			return -ENOENT;
		remove_thread_entry(te);
		return 0;
	}
	/* Attempt to register tlap. Check if already there. */
	if (te)
		return -EBUSY;
	/* Agree on the intersection of userspace and kernel features. */
	minlen = min_t(size_t, len, sizeof(struct thread_local_abi));
	te = add_thread_entry(current, minlen, tlap);
	if (!te)
		return -ENOMEM;
	/*
	 * Migration walks the thread local abi entry list to see
	 * whether the notify_resume flag should be set. Therefore, we
	 * need to ensure that the scheduler sees the list update before
	 * we update the thread local abi content with the current CPU
	 * number.
	 */
	barrier();	/* Add thread entry to list before updating content. */
	if (thread_local_abi_update_entry(te))
		return -EFAULT;
	return minlen;
}
