#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

#define NR_INJECT	9
static int loop_cnt[NR_INJECT + 1];

static int opt_modulo;
static __thread unsigned int yield_mod_cnt;

static int opt_yield, opt_signal, opt_sleep, opt_fallback_cnt = 3,
		opt_disable_rseq, opt_threads = 200,
		opt_reps = 5000, opt_disable_mod = 0, opt_test = 's';

static __thread unsigned int nr_retry, signals_delivered;

static struct rseq_lock rseq_lock;

#define RSEQ_INJECT_INPUT \
	, [loop_cnt_1]"m"(loop_cnt[1]) \
	, [loop_cnt_2]"m"(loop_cnt[2]) \
	, [loop_cnt_3]"m"(loop_cnt[3]) \
	, [loop_cnt_4]"m"(loop_cnt[4])

#if defined(__x86_64__) || defined(__i386__)

#define INJECT_ASM_REG	"eax"

#define RSEQ_INJECT_CLOBBER \
	, INJECT_ASM_REG

#define RSEQ_INJECT_ASM(n) \
	"mov %[loop_cnt_" #n "], %%" INJECT_ASM_REG "\n\t" \
	"test %%" INJECT_ASM_REG ",%%" INJECT_ASM_REG "\n\t" \
	"jz 333f\n\t" \
	"222:\n\t" \
	"dec %%" INJECT_ASM_REG "\n\t" \
	"jnz 222b\n\t" \
	"333:\n\t"

#elif defined(__ARMEL__)

#define INJECT_ASM_REG	"r4"

#define RSEQ_INJECT_CLOBBER \
	, INJECT_ASM_REG

#define RSEQ_INJECT_ASM(n) \
	"ldr " INJECT_ASM_REG ", %[loop_cnt_" #n "]\n\t" \
	"cmp " INJECT_ASM_REG ", #0\n\t" \
	"beq 333f\n\t" \
	"222:\n\t" \
	"subs " INJECT_ASM_REG ", #1\n\t" \
	"bne 222b\n\t" \
	"333:\n\t"

#else
#error unsupported target
#endif

#define RSEQ_INJECT_FAILED \
	nr_retry++;

#define RSEQ_INJECT_C(n) \
{ \
	int loc_i, loc_nr_loops = loop_cnt[n]; \
	\
	for (loc_i = 0; loc_i < loc_nr_loops; loc_i++) { \
		barrier(); \
	} \
	if (loc_nr_loops == -1 && opt_modulo) { \
		if (yield_mod_cnt == opt_modulo - 1) { \
			if (opt_sleep > 0) \
				poll(NULL, 0, opt_sleep); \
			if (opt_yield) \
				sched_yield(); \
			if (opt_signal) \
				raise(SIGUSR1); \
			yield_mod_cnt = 0; \
		} else { \
			yield_mod_cnt++; \
		} \
	} \
}

#define RSEQ_FALLBACK_CNT	\
	opt_fallback_cnt

#include "rseq.h"

struct percpu_lock_entry {
	intptr_t v;
} __attribute__((aligned(128)));

struct percpu_lock {
	struct percpu_lock_entry c[CPU_SETSIZE];
};

struct test_data_entry {
	int count;
} __attribute__((aligned(128)));

struct spinlock_test_data {
	struct percpu_lock lock;
	struct test_data_entry c[CPU_SETSIZE];
};

struct spinlock_thread_test_data {
	struct spinlock_test_data *data;
	int reps;
	int reg;
};

struct cmpxchg_test_data {
	struct test_data_entry c[CPU_SETSIZE];
};

struct cmpxchg_thread_test_data {
	struct cmpxchg_test_data *data;
	int reps;
	int reg;
};

struct percpu_list_node {
	intptr_t data;
	struct percpu_list_node *next;
};

struct percpu_list_entry {
	struct percpu_list_node *head;
} __attribute__((aligned(128)));

struct percpu_list {
	struct percpu_list_entry c[CPU_SETSIZE];
};

/* A simple percpu spinlock.  Returns the cpu lock was acquired on. */
static int rseq_percpu_lock(struct percpu_lock *lock)
{
	struct rseq_state start;
	int cpu;

	for (;;) {
		start = rseq_start(&rseq_lock);
		cpu = rseq_cpu_at_start(start);
		if (unlikely(lock->c[cpu].v)) {
			rseq_abort(&rseq_lock, start);
			continue;
		}
		if (likely(rseq_finish(&rseq_lock, &lock->c[cpu].v, 1, start)))
			break;
	}
	smp_acquire__after_ctrl_dep();
	return cpu;
}

static void rseq_percpu_unlock(struct percpu_lock *lock, int cpu)
{
	assert(lock->c[cpu].v == 1);
	smp_store_release(&lock->c[cpu].v, 0);
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
static inline __attribute__((always_inline)) int rseq_percpu_cmpxchg(int cpu, intptr_t *p, intptr_t old, intptr_t new)
{
	struct rseq_state start;

	start = rseq_start(&rseq_lock);
	if (unlikely(rseq_cpu_at_start(start) != cpu)) {
		rseq_abort(&rseq_lock, start);
		return rseq_cpu_at_start(start);
	}
	if (unlikely(*p != old)) {
		rseq_abort(&rseq_lock, start);
		return -1;
	}
	if (unlikely(!rseq_finish(&rseq_lock, p, new, start)))
		return -1;
	return cpu;
}

static int rseq_percpu_cmpxchgcheck(int cpu, intptr_t *p, intptr_t old,
			intptr_t new, intptr_t *check_ptr, intptr_t check_val)
{
	struct rseq_state start;

	start = rseq_start(&rseq_lock);
	if (unlikely(rseq_cpu_at_start(start) != cpu)) {
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
	if (unlikely(*p != old || *check_ptr != check_val)) {
		rseq_abort(&rseq_lock, start);
		return -1;
	}
	if (unlikely(!rseq_finish(&rseq_lock, p, new, start)))
		return -1;
	return cpu;
}

void *test_percpu_spinlock_thread(void *arg)
{
	struct spinlock_thread_test_data *thread_data = arg;
	struct spinlock_test_data *data = thread_data->data;
	int i, cpu;

	if (!opt_disable_rseq && thread_data->reg
			&& rseq_init_current_thread())
		abort();
	for (i = 0; i < thread_data->reps; i++) {
		cpu = rseq_percpu_lock(&data->lock);
		data->c[cpu].count++;
		rseq_percpu_unlock(&data->lock, cpu);
		if (i != 0 && !(i % (thread_data->reps / 10))) {
			printf("tid %d: count %d\n", (int) gettid(), i);
		}
	}
	printf("tid %d: number of retry: %d, signals delivered: %u, nr_fallback %u, nr_fallback_wait %u\n",
		(int) gettid(), nr_retry, signals_delivered,
		__rseq_thread_state.fallback_cnt,
		__rseq_thread_state.fallback_wait_cnt);
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
	const int num_threads = opt_threads;
	int i, sum, ret;
	pthread_t test_threads[num_threads];
	struct spinlock_test_data data;
	struct spinlock_thread_test_data thread_data[num_threads];

	memset(&data, 0, sizeof(data));
	for (i = 0; i < num_threads; i++) {
		thread_data[i].reps = opt_reps;
		if (opt_disable_mod <= 0 || (i % opt_disable_mod))
			thread_data[i].reg = 1;
		else
			thread_data[i].reg = 0;
		thread_data[i].data = &data;
		ret = pthread_create(&test_threads[i], NULL,
			test_percpu_spinlock_thread, &thread_data[i]);
		if (ret) {
			errno = ret;
			perror("pthread_create");
			abort();
		}
	}

	for (i = 0; i < num_threads; i++) {
		pthread_join(test_threads[i], NULL);
		if (ret) {
			errno = ret;
			perror("pthread_join");
			abort();
		}
	}

	sum = 0;
	for (i = 0; i < CPU_SETSIZE; i++)
		sum += data.c[i].count;

	assert(sum == opt_reps * num_threads);
}

void *test_percpu_cmpxchg_thread(void *arg)
{
	struct cmpxchg_thread_test_data *thread_data = arg;
	struct cmpxchg_test_data *data = thread_data->data;
	int i, cpu;

	if (!opt_disable_rseq && thread_data->reg
			&& rseq_init_current_thread())
		abort();
	for (i = 0; i < thread_data->reps; i++) {
		int prev_count;

		do {
			cpu = rseq_current_cpu();
			prev_count = data->c[cpu].count;
		} while (cpu != rseq_percpu_cmpxchg(cpu,
				(intptr_t *)&data->c[cpu].count, (intptr_t)prev_count,
				(intptr_t)prev_count + 1));

		if (i != 0 && !(i % (thread_data->reps / 10))) {
			printf("tid %d: count %d\n", (int) gettid(), i);
		}
	}
	printf("tid %d: number of retry: %d, signals delivered: %u, nr_fallback %u, nr_fallback_wait %u\n",
		(int) gettid(), nr_retry, signals_delivered,
		__rseq_thread_state.fallback_cnt,
		__rseq_thread_state.fallback_wait_cnt);
	return NULL;
}

void test_percpu_cmpxchg(void)
{
	const int num_threads = opt_threads;
	int i, sum, ret;
	pthread_t test_threads[num_threads];
	struct cmpxchg_test_data data;
	struct cmpxchg_thread_test_data thread_data[num_threads];

	memset(&data, 0, sizeof(data));
	for (i = 0; i < num_threads; i++) {
		thread_data[i].reps = opt_reps;
		if (opt_disable_mod <= 0 || (i % opt_disable_mod))
			thread_data[i].reg = 1;
		else
			thread_data[i].reg = 0;
		thread_data[i].data = &data;
		ret = pthread_create(&test_threads[i], NULL,
			test_percpu_cmpxchg_thread, &thread_data[i]);
		if (ret) {
			errno = ret;
			perror("pthread_create");
			abort();
		}
	}

	for (i = 0; i < num_threads; i++) {
		pthread_join(test_threads[i], NULL);
		if (ret) {
			errno = ret;
			perror("pthread_join");
			abort();
		}
	}

	sum = 0;
	for (i = 0; i < CPU_SETSIZE; i++)
		sum += data.c[i].count;

	assert(sum == opt_reps * num_threads);
}

int percpu_list_push(struct percpu_list *list, struct percpu_list_node *node)
{
	int cpu;

	do {
		cpu = rseq_current_cpu();
		node->next = list->c[cpu].head;
	} while (cpu != rseq_percpu_cmpxchg(cpu,
			(intptr_t *)&list->c[cpu].head, (intptr_t)node->next,
			(intptr_t)node));

	return cpu;
}

struct percpu_list_node *percpu_list_pop(struct percpu_list *list)
{
	int cpu;
	struct percpu_list_node *head, *next;

	do {
		cpu = rseq_current_cpu();
		head = list->c[cpu].head;
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
		(intptr_t *) &list->c[cpu].head, (intptr_t) head, (intptr_t) next,
		(intptr_t *) &head->next, (intptr_t) next));

	return head;
}

void *test_percpu_list_thread(void *arg)
{
	int i;
	struct percpu_list *list = (struct percpu_list *)arg;

	if (rseq_init_current_thread())
		abort();

	for (i = 0; i < opt_reps; i++) {
		struct percpu_list_node *node = percpu_list_pop(list);
		if (opt_yield)
			sched_yield();  /* encourage shuffling */
		if (node)
			percpu_list_push(list, node);
	}

	return NULL;
}

/* Simultaneous modification to a per-cpu linked list from many threads.  */
void test_percpu_list(void)
{
	const int num_threads = opt_threads;
	int i, j, ret;
	long sum = 0, expected_sum = 0;
	struct percpu_list list;
	pthread_t test_threads[num_threads];
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
			node->next = list.c[i].head;
			list.c[i].head = node;
		}
	}

	for (i = 0; i < num_threads; i++) {
		ret = pthread_create(&test_threads[i], NULL,
			test_percpu_list_thread, &list);
		if (ret) {
			errno = ret;
			perror("pthread_create");
			abort();
		}
	}

	for (i = 0; i < num_threads; i++) {
		pthread_join(test_threads[i], NULL);
		if (ret) {
			errno = ret;
			perror("pthread_join");
			abort();
		}
	}

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

static void test_signal_interrupt_handler(int signo)
{
	signals_delivered++;
}

static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		perror("sigemptyset");
		return ret;
	}

	sa.sa_handler = test_signal_interrupt_handler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGUSR1, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	fprintf(stderr, "Signal handler set for SIGUSR1\n");

	return ret;
}

static void show_usage(int argc, char **argv)
{
	printf("Usage : %s <OPTIONS>\n",
		argv[0]);
	printf("OPTIONS:\n");
	printf("	[-1 loops] Number of loops for delay injection 1\n");
	printf("	[-2 loops] Number of loops for delay injection 2\n");
	printf("	[-3 loops] Number of loops for delay injection 3\n");
	printf("	[-4 loops] Number of loops for delay injection 4\n");
	printf("	[-5 loops] Number of loops for delay injection 5 (-1 to enable -m)\n");
	printf("	[-6 loops] Number of loops for delay injection 6 (-1 to enable -m)\n");
	printf("	[-7 loops] Number of loops for delay injection 7 (-1 to enable -m)\n");
	printf("	[-8 loops] Number of loops for delay injection 8 (-1 to enable -m)\n");
	printf("	[-9 loops] Number of loops for delay injection 9 (-1 to enable -m)\n");
	printf("	[-m N] Yield/sleep/kill every modulo N (default 0: disabled) (>= 0)\n");
	printf("	[-y] Yield\n");
	printf("	[-k] Kill thread with signal\n");
	printf("	[-s S] S: =0: disabled (default), >0: sleep time (ms)\n");
	printf("	[-f N] Use fallback every N failure (>= 1)\n");
	printf("	[-t N] Number of threads (default 200)\n");
	printf("	[-r N] Number of repetitions per thread (default 5000)\n");
	printf("	[-d] Disable rseq system call (no initialization)\n");
	printf("	[-D M] Disable rseq for each M threads\n");
	printf("	[-T test] Choose test: (s)pinlock, (l)ist, (c)mpxchg\n");
	printf("	[-h] Show this help.\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	int i;

	rseq_init_lock(&rseq_lock);
	if (set_signal_handler())
		return -1;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-')
			continue;
		switch (argv[i][1]) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			loop_cnt[argv[i][1] - '0'] = atol(argv[i + 1]);
			i++;
			break;
		case 'm':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			opt_modulo = atol(argv[i + 1]);
			if (opt_modulo < 0) {
				show_usage(argc, argv);
				return -1;
			}
			i++;
			break;
		case 's':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			opt_sleep = atol(argv[i + 1]);
			if (opt_sleep < 0) {
				show_usage(argc, argv);
				return -1;
			}
			i++;
			break;
		case 'y':
			opt_yield = 1;
			break;
		case 'k':
			opt_signal = 1;
			break;
		case 'd':
			opt_disable_rseq = 1;
			break;
		case 'D':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			opt_disable_mod = atol(argv[i + 1]);
			if (opt_disable_mod < 0) {
				show_usage(argc, argv);
				return -1;
			}
			i++;
			break;
		case 'f':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			opt_fallback_cnt = atol(argv[i + 1]);
			if (opt_fallback_cnt < 1) {
				show_usage(argc, argv);
				return -1;
			}
			i++;
			break;
		case 't':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			opt_threads = atol(argv[i + 1]);
			if (opt_threads < 0) {
				show_usage(argc, argv);
				return -1;
			}
			i++;
			break;
		case 'r':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			opt_reps = atol(argv[i + 1]);
			if (opt_reps < 0) {
				show_usage(argc, argv);
				return -1;
			}
			i++;
			break;
		case 'h':
			show_usage(argc, argv);
			return 0;
		case 'T':
			if (argc < i + 2) {
				show_usage(argc, argv);
				return -1;
			}
			opt_test = *argv[i + 1];
			switch (opt_test) {
			case 's':
			case 'l':
			case 'c':
				break;
			default:
				show_usage(argc, argv);
				return -1;
			}
			i++;
			break;
		default:
			show_usage(argc, argv);
			return -1;
		}
	}

	if (!opt_disable_rseq && rseq_init_current_thread())
		return -1;
	switch (opt_test) {
	case 's':
		printf("spinlock\n");
		test_percpu_spinlock();
		break;
	case 'l':
		printf("linked list\n");
		test_percpu_list();
		break;
	case 'c':
		printf("cmpxchg\n");
		test_percpu_cmpxchg();
		break;
	}
	return 0;
}
