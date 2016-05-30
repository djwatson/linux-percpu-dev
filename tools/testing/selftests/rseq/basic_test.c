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

void test_critical_section(void)
{
	/*
	 * This depends solely on some environmental event triggering a counter
	 * increase.
	 */
	struct rseq_state start;
	uint32_t event_counter;

	start = rseq_start(&rseq_lock);
	event_counter = start.event_counter;
	rseq_abort(&rseq_lock, start);
	for (;;) {
		start = rseq_start(&rseq_lock);
		if (start.event_counter == event_counter) {
			rseq_abort(&rseq_lock, start);
			continue;
		} else {
			rseq_abort(&rseq_lock, start);
			break;
		}
	}
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
	rseq_abort(&rseq_lock, current);
}

void test_signal_interrupts(void)
{
	struct itimerval it = { { 0, 1 }, { 0, 1 } };

	setitimer(ITIMER_PROF, &it, NULL);
	signal(SIGPROF, test_signal_interrupt_handler);

	do {
		sigtest_start = rseq_start(&rseq_lock);
		rseq_abort(&rseq_lock, sigtest_start);
	} while (signals_delivered < 10);
	setitimer(ITIMER_PROF, NULL, NULL);
}

int main(int argc, char **argv)
{
	rseq_init_lock(&rseq_lock);
	if (rseq_init_current_thread())
		return -1;

	printf("testing current cpu\n");
	test_cpu_pointer();
	printf("testing critical section\n");
	test_critical_section();
	printf("testing critical section is interrupted by signal\n");
	test_signal_interrupts();

	return 0;
}
