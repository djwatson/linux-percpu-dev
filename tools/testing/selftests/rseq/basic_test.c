/*
 * Basic test coverage for critical regions and rseq_current_cpu().
 */

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "rseq.h"

volatile int signals_delivered;
volatile __thread struct rseq_state sigtest_start;
static struct rseq_lock rseq_lock;

void test_cpu_pointer(void)
{
	cpu_set_t affinity, test_affinity;
	int i;

	sched_getaffinity(0, sizeof(affinity), &affinity);
	CPU_ZERO(&test_affinity);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &affinity)) {
			CPU_SET(i, &test_affinity);
			sched_setaffinity(0, sizeof(test_affinity),
					&test_affinity);
			assert(rseq_current_cpu() == sched_getcpu());
			assert(rseq_current_cpu() == i);
			CPU_CLR(i, &test_affinity);
		}
	}
	sched_setaffinity(0, sizeof(affinity), &affinity);
}

/*
 * This depends solely on some environmental event triggering a counter
 * increase.
 */
void test_critical_section(void)
{
	struct rseq_state start;
	uint32_t event_counter;

	start = rseq_start(&rseq_lock);
	event_counter = start.event_counter;
	do {
		start = rseq_start(&rseq_lock);
	} while (start.event_counter == event_counter);
}

void test_signal_interrupt_handler(int signo)
{
	struct rseq_state current;

	current = rseq_start(&rseq_lock);
	/*
	 * The potential critical section bordered by 'start' must be
	 * invalid.
	 */
	assert(current.event_counter != sigtest_start.event_counter);
	signals_delivered++;
}

void test_signal_interrupts(void)
{
	struct itimerval it = { { 0, 1 }, { 0, 1 } };

	setitimer(ITIMER_PROF, &it, NULL);
	signal(SIGPROF, test_signal_interrupt_handler);

	do {
		sigtest_start = rseq_start(&rseq_lock);
	} while (signals_delivered < 10);
	setitimer(ITIMER_PROF, NULL, NULL);
}

int main(int argc, char **argv)
{
	if (rseq_init_lock(&rseq_lock)) {
		perror("rseq_init_lock");
		return -1;
	}
	if (rseq_register_current_thread())
		goto init_thread_error;
	printf("testing current cpu\n");
	test_cpu_pointer();
	printf("testing critical section\n");
	test_critical_section();
	printf("testing critical section is interrupted by signal\n");
	test_signal_interrupts();
	if (rseq_unregister_current_thread())
		goto init_thread_error;
	if (rseq_destroy_lock(&rseq_lock)) {
		perror("rseq_destroy_lock");
		return -1;
	}
	return 0;

init_thread_error:
	if (rseq_destroy_lock(&rseq_lock))
		perror("rseq_destroy_lock");
	return -1;
}
