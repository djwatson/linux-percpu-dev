#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rseq.h"

static struct rseq_lock rseq_lock;

struct percpu_lock {
	intptr_t word[CPU_SETSIZE][64 / sizeof(intptr_t)]; /* Cache aligned */
};

struct spinlock_test_data {
	struct percpu_lock lock;
	int counts[CPU_SETSIZE];
	int reps;
};

struct percpu_list_node {
	intptr_t data;
	struct percpu_list_node *next;
};

struct percpu_list {
	struct percpu_list_node *heads[CPU_SETSIZE];
};

/* A simple percpu spinlock.  Returns the cpu lock was acquired on. */
int rseq_percpu_lock(struct percpu_lock *lock)
{
	struct rseq_state start;
	int cpu;

	for (;;) {
		start = rseq_start(&rseq_lock);
		cpu = rseq_cpu_at_start(start);
		if (lock->word[cpu][0]) {
			rseq_abort(&rseq_lock, start);
			continue;
		}
		if (rseq_finish(&rseq_lock, &lock->word[cpu][0], 1, start))
			break;
	}
	smp_acquire__after_ctrl_dep();
	return cpu;
}

void rseq_percpu_unlock(struct percpu_lock *lock, int cpu)
{
	assert(lock->word[cpu][0] == 1);
	smp_store_release(&lock->word[cpu][0], 0);
}

/*
 * cmpxchg [with an additional check value].
 *
 * Returns:
 *  -1 if *p != old [ || check_ptr != check_val, ] otherwise
 *  cpu that rseq_percpu_cmpxchgcheck was executed.
 *   - If this is different from the passed cpu, no modifications were
 *     made.
 *
 * Note: When specified, check_ptr is dereferenced iff *p == old
 */
int rseq_percpu_cmpxchg(int cpu, intptr_t *p, intptr_t old, intptr_t new)
{
	struct rseq_state start;

	while (1) {
		start = rseq_start(&rseq_lock);
		if (rseq_cpu_at_start(start) != cpu) {
			rseq_abort(&rseq_lock, start);
			return rseq_cpu_at_start(start);
		}
		if (*p != old) {
			rseq_abort(&rseq_lock, start);
			return -1;
		}
		if (rseq_finish(&rseq_lock, p, new, start))
			return cpu;
	}
}

int rseq_percpu_cmpxchgcheck(int cpu, intptr_t *p, intptr_t old, intptr_t new,
			intptr_t *check_ptr, intptr_t check_val)
{
	struct rseq_state start;

	while (1) {
		start = rseq_start(&rseq_lock);
		if (rseq_cpu_at_start(start) != cpu) {
			rseq_abort(&rseq_lock, start);
			return rseq_cpu_at_start(start);
		}
		/*
		 * Note that we'd want the ultimate implementation of this to
		 * be open coded (similar to rseq_finish) so that we can
		 * guarantee *check is not dereferenced when old does not
		 * match.  This could also be facilitated with a generic
		 * rseq_read_if_valid(...) helper.
		 */
		if (*p != old || *check_ptr != check_val) {
			rseq_abort(&rseq_lock, start);
			return -1;
		}
		if (rseq_finish(&rseq_lock, p, new, start))
			return cpu;
	}
}

void *test_percpu_spinlock_thread(void *arg)
{
	struct spinlock_test_data *data = arg;
	int i, cpu;

	if (rseq_init_current_thread())
		abort();
	for (i = 0; i < data->reps; i++) {
		cpu = rseq_percpu_lock(&data->lock);
		data->counts[cpu]++;
		rseq_percpu_unlock(&data->lock, cpu);
	}

	return NULL;
}

/*
 * A simple test which implements a sharded counter using a per-cpu
 * lock.  Obviously real applications might prefer to simply use a
 * per-cpu increment; however, this is reasonable for a test and the
 * lock can be extended to synchronize more complicated operations.
 */
void test_percpu_spinlock(void)
{
	const int num_threads = 200;
	int i, sum;
	pthread_t test_threads[num_threads];
	struct spinlock_test_data data;

	memset(&data, 0, sizeof(data));
	data.reps = 5000;

	for (i = 0; i < num_threads; i++)
		pthread_create(&test_threads[i], NULL,
			test_percpu_spinlock_thread, &data);

	for (i = 0; i < num_threads; i++)
		pthread_join(test_threads[i], NULL);

	sum = 0;
	for (i = 0; i < CPU_SETSIZE; i++)
		sum += data.counts[i];

	assert(sum == data.reps * num_threads);
}

int percpu_list_push(struct percpu_list *list, struct percpu_list_node *node)
{
	int cpu;

	do {
		cpu = rseq_current_cpu();
		node->next = list->heads[cpu];
	} while (cpu != rseq_percpu_cmpxchg(cpu,
			(intptr_t *)&list->heads[cpu], (intptr_t)node->next,
			(intptr_t)node));

	return cpu;
}

struct percpu_list_node *percpu_list_pop(struct percpu_list *list)
{
	int cpu;
	struct percpu_list_node *head, *next;

	do {
		cpu = rseq_current_cpu();
		head = list->heads[cpu];
		/*
		 * Unlike a traditional lock-less linked list; the
		 * availability of a cmpxchg-check primitive allows us
		 * to implement pop without concerns over ABA-type
		 * races.
		 */
		if (!head)
			return 0;
		next = head->next;
	} while (cpu != rseq_percpu_cmpxchgcheck(cpu,
		(intptr_t *) &list->heads[cpu], (intptr_t) head, (intptr_t) next,
		(intptr_t *) &head->next, (intptr_t) next));

	return head;
}

void *test_percpu_list_thread(void *arg)
{
	int i;
	struct percpu_list *list = (struct percpu_list *)arg;

	if (rseq_init_current_thread())
		abort();

	for (i = 0; i < 100000; i++) {
		struct percpu_list_node *node = percpu_list_pop(list);
		sched_yield();  /* encourage shuffling */
		if (node)
			percpu_list_push(list, node);
	}

	return NULL;
}

/* Simultaneous modification to a per-cpu linked list from many threads.  */
void test_percpu_list(void)
{
	int i, j;
	long sum = 0, expected_sum = 0;
	struct percpu_list list;
	pthread_t test_threads[200];
	cpu_set_t allowed_cpus;

	memset(&list, 0, sizeof(list));

	/* Generate list entries for every usable cpu. */
	sched_getaffinity(0, sizeof(allowed_cpus), &allowed_cpus);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &allowed_cpus))
			continue;
		for (j = 1; j <= 100; j++) {
			struct percpu_list_node *node;

			expected_sum += j;

			node = malloc(sizeof(*node));
			assert(node);
			node->data = j;
			node->next = list.heads[i];
			list.heads[i] = node;
		}
	}

	for (i = 0; i < 200; i++)
		assert(pthread_create(&test_threads[i], NULL,
			test_percpu_list_thread, &list) == 0);

	for (i = 0; i < 200; i++)
		pthread_join(test_threads[i], NULL);

	for (i = 0; i < CPU_SETSIZE; i++) {
		cpu_set_t pin_mask;
		struct percpu_list_node *node;

		if (!CPU_ISSET(i, &allowed_cpus))
			continue;

		CPU_ZERO(&pin_mask);
		CPU_SET(i, &pin_mask);
		sched_setaffinity(0, sizeof(pin_mask), &pin_mask);

		while ((node = percpu_list_pop(&list))) {
			sum += node->data;
			free(node);
		}
	}

	/*
	 * All entries should now be accounted for (unless some external
	 * actor is interfering with our allowed affinity while this
	 * test is running).
	 */
	assert(sum == expected_sum);
}

int main(int argc, char **argv)
{
	rseq_init_lock(&rseq_lock);
	if (rseq_init_current_thread())
		return -1;
	printf("spinlock\n");
	test_percpu_spinlock();
	printf("percpu_list\n");
	test_percpu_list();

	return 0;
}

