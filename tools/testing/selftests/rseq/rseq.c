#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <assert.h>
#include <signal.h>
#include <linux/membarrier.h>

#include "rseq.h"

#ifdef __NR_membarrier
# define membarrier(...)		syscall(__NR_membarrier, __VA_ARGS__)
#else
# define membarrier(...)		-ENOSYS
#endif

__thread volatile struct rseq_thread_state __rseq_thread_state = {
	.abi.cpu_id = -1,
};

int rseq_has_sys_membarrier;

static int sys_rseq(volatile struct rseq *rseq_abi, int flags)
{
	return syscall(__NR_rseq, rseq_abi, flags);
}

int rseq_init_current_thread(void)
{
	int rc;

	rc = sys_rseq(&__rseq_thread_state.abi, 0);
	if (rc) {
		fprintf(stderr,"Error: sys_rseq(...) failed(%d): %s\n",
			errno, strerror(errno));
		return -1;
	}
	assert(rseq_current_cpu() >= 0);
	return 0;
}

void rseq_init_lock(struct rseq_lock *rlock)
{
	(void) pthread_mutex_init(&rlock->lock, NULL);
	rlock->state = RSEQ_LOCK_STATE_RESTART;
}

static void signal_off_save(sigset_t *oldset)
{
	sigset_t set;
	int ret;

	sigfillset(&set);
	ret = pthread_sigmask(SIG_BLOCK, &set, oldset);
	if (ret)
		abort();
}

static void signal_restore(sigset_t oldset)
{
	int ret;

	ret = pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	if (ret)
		abort();
}

void rseq_fallback_lock(struct rseq_lock *rlock,
		struct rseq_state *rseq_state)
{
	signal_off_save((sigset_t *)&__rseq_thread_state.sigmask_saved);
	pthread_mutex_lock(&rlock->lock);
	__rseq_thread_state.fail_cnt = 0;
	__rseq_thread_state.fallback_cnt++;
	/*
	 * For concurrent threads arriving before we set LOCK:
	 * reading cpu_id after setting the state to LOCK
	 * ensures they restart.
	 */
	ACCESS_ONCE(rlock->state) = RSEQ_LOCK_STATE_LOCK;
	/*
	 * For concurrent threads arriving after we set LOCK:
	 * those will grab the lock, so we are protected by
	 * mutual exclusion.
	 */
	rseq_state->lock_state = RSEQ_LOCK_STATE_LOCK;
}

void rseq_fallback_wait(struct rseq_lock *rlock)
{
	signal_off_save((sigset_t *)&__rseq_thread_state.sigmask_saved);
	pthread_mutex_lock(&rlock->lock);
	__rseq_thread_state.fallback_wait_cnt++;
	pthread_mutex_unlock(&rlock->lock);
	signal_restore(__rseq_thread_state.sigmask_saved);
}

void rseq_fallback_unlock(struct rseq_lock *rlock,
		struct rseq_state rseq_state)
{
	/*
	 * Concurrent rseq arriving before we set state back to RESTART
	 * grab the lock. Those arriving after we set state back to
	 * RESTART will perform restartable critical sections. The next
	 * owner of the lock will take take of making sure it prevents
	 * concurrent restartable sequences from completing.  We may be
	 * writing from another CPU, so update the state with a store
	 * release semantic to ensure restartable sections will see our
	 * side effect (writing to *p) before they enter their
	 * restartable critical section.
	 *
	 * In cases where we observe that we are on the right CPU after the
	 * critical section, program order ensures that following restartable
	 * critical sections will see our stores, so we don't have to use
	 * store-release or membarrier.
	 *
	 * Use sys_membarrier when available to remove the memory barrier
	 * implied by smp_load_acquire().
	 */
	barrier();
	if (likely(rseq_current_cpu() == rseq_cpu_at_start(rseq_state))) {
		ACCESS_ONCE(rlock->state) = RSEQ_LOCK_STATE_RESTART;
	} else {
		if (!has_fast_acquire_release() && rseq_has_sys_membarrier) {
			if (membarrier(MEMBARRIER_CMD_SHARED, 0)) {
				abort();
			}
			ACCESS_ONCE(rlock->state) = RSEQ_LOCK_STATE_RESTART;
		} else {
			smp_store_release(&rlock->state,
				RSEQ_LOCK_STATE_RESTART);
		}
	}
	pthread_mutex_unlock(&rlock->lock);
	signal_restore(__rseq_thread_state.sigmask_saved);
}

/* Handle non-initialized rseq for this thread. */
void rseq_fallback_noinit(struct rseq_lock *rlock,
		struct rseq_state *rseq_state)
{
	if (rseq_state->lock_state != RSEQ_LOCK_STATE_LOCK)
		rseq_fallback_lock(rlock, rseq_state);
	rseq_state->cpu_id = sched_getcpu();
	if (rseq_state->cpu_id < 0) {
		perror("sched_getcpu()");
		abort();
	}
}

void __attribute__((constructor)) rseq_init(void)
{
	int ret;
        ret = membarrier(MEMBARRIER_CMD_QUERY, 0);
        if (ret >= 0 && (ret & MEMBARRIER_CMD_SHARED)) {
                rseq_has_sys_membarrier = 1;
        }
}
