#ifndef RSEQ_H
#define RSEQ_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <linux/rseq.h>

/*
 * Empty code injection macros, override when testing.
 * It is important to consider that the ASM injection macros need to be
 * fully reentrant (e.g. do not modify the stack).
 */
#ifndef RSEQ_INJECT_ASM
#define RSEQ_INJECT_ASM(n)
#endif

#ifndef RSEQ_INJECT_C
#define RSEQ_INJECT_C(n)
#endif

#ifndef RSEQ_INJECT_INPUT
#define RSEQ_INJECT_INPUT
#endif

#ifndef RSEQ_INJECT_CLOBBER
#define RSEQ_INJECT_CLOBBER
#endif

#ifndef RSEQ_INJECT_FAILED
#define RSEQ_INJECT_FAILED
#endif

#ifndef RSEQ_FALLBACK_CNT
#define RSEQ_FALLBACK_CNT	3
#endif

struct rseq_thread_state {
	struct rseq abi;	/* kernel ABI */
	uint32_t fail_cnt;
	uint32_t fallback_wait_cnt;
	uint32_t fallback_cnt;
	sigset_t sigmask_saved;
};

extern __thread volatile struct rseq_thread_state __rseq_thread_state;
extern int rseq_has_sys_membarrier;

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#define barrier()		__asm__ __volatile__("": : :"memory")

#define ACCESS_ONCE(x)		(*(__volatile__  __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	__extension__ ({ ACCESS_ONCE(x) = (v); })
#define READ_ONCE(x)		ACCESS_ONCE(x)

#ifdef __x86_64__

#define smp_mb()	__asm__ __volatile__ ("mfence":::"memory")
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()

#define smp_load_acquire(p)						\
__extension__ ({							\
	__typeof(*p) ____p1 = READ_ONCE(*p);				\
	barrier();							\
	____p1;								\
})

#define smp_acquire__after_ctrl_dep()	smp_rmb()

#define smp_store_release(p, v)						\
do {									\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define has_fast_acquire_release()	1

#elif __i386__

/*
 * Support older 32-bit architectures that do not implement fence
 * instructions.
 */
#define smp_mb()	__asm__ __volatile__ ("lock; addl $0,0(%%esp)":::"memory")
#define smp_rmb()	__asm__ __volatile__ ("lock; addl $0,0(%%esp)":::"memory")
#define smp_wmb()	__asm__ __volatile__ ("lock; addl $0,0(%%esp)":::"memory")

#define smp_load_acquire(p)						\
__extension__ ({							\
	__typeof(*p) ____p1 = READ_ONCE(*p);				\
	smp_mb();							\
	____p1;								\
})

#define smp_acquire__after_ctrl_dep()	smp_rmb()

#define smp_store_release(p, v)						\
do {									\
	smp_mb();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define has_fast_acquire_release()	0

#elif defined(__ARMEL__)

#define smp_mb()	__asm__ __volatile__ ("dmb":::"memory")
#define smp_rmb()	__asm__ __volatile__ ("dmb":::"memory")
#define smp_wmb()	__asm__ __volatile__ ("dmb":::"memory")

#define smp_load_acquire(p)						\
__extension__ ({							\
	__typeof(*p) ____p1 = READ_ONCE(*p);				\
	smp_mb();							\
	____p1;								\
})

#define smp_acquire__after_ctrl_dep()	smp_rmb()

#define smp_store_release(p, v)						\
do {									\
	smp_mb();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define has_fast_acquire_release()	0

#else
#error unsupported target
#endif

enum rseq_lock_state {
	RSEQ_LOCK_STATE_RESTART = 0,
	RSEQ_LOCK_STATE_LOCK = 1,
};

struct rseq_lock {
	pthread_mutex_t lock;
	int32_t state;
};

/* State exchanged between start, finish and abort (on stack). */
struct rseq_state {
	int32_t cpu_id;
	uint32_t event_counter;
	int32_t lock_state;
};

/*
 * Initialize rseq for the current thread.  Must be called once by any
 * thread which uses restartable sequences, before they start using
 * restartable sequences. If initialization is not invoked, or if it
 * fails, the restartable critical sections will fall-back on locking.
 */
int rseq_init_current_thread(void);
void rseq_init_lock(struct rseq_lock *rlock);
void rseq_fallback_lock(struct rseq_lock *rlock,
		struct rseq_state *rseq_state);
void rseq_fallback_unlock(struct rseq_lock *rlock,
		struct rseq_state rseq_state);
void rseq_fallback_wait(struct rseq_lock *rlock);
void rseq_fallback_noinit(struct rseq_lock *rlock,
		struct rseq_state *rseq_state);

static inline int32_t rseq_cpu_at_start(struct rseq_state start_value)
{
	return start_value.cpu_id;
}

static inline int32_t rseq_current_cpu(void)
{
	return ACCESS_ONCE(__rseq_thread_state.abi.cpu_id);
}

static inline struct rseq_state rseq_start(struct rseq_lock *rlock)
{
	struct rseq_state result;

retry:
	result.event_counter = ACCESS_ONCE(__rseq_thread_state.abi.event_counter);
	/*
	 * Read event counter before lock state and cpu_id. This ensures
	 * that when the state changes from RESTART to LOCK, if we have
	 * some threads that have already seen the RESTART still in
	 * flight, they need to be preempted/signalled before a thread
	 * can see the LOCK state for that same CPU. That
	 * preemption/signalling will cause them to restart, so they
	 * don't interfere with the lock.
	 */
	RSEQ_INJECT_C(6)
	if (likely(__rseq_thread_state.fail_cnt < RSEQ_FALLBACK_CNT)) {
		/*
		 * Load acquire of state is paired with store release in
		 * finish. Ensures memory ordering for finish in LOCK
		 * state running on another cpu. When sys_membarrier is
		 * available, this becomes a simple load followed by a
		 * compiler barrier.
		 */
		if (!has_fast_acquire_release() && likely(rseq_has_sys_membarrier)) {
			result.lock_state = ACCESS_ONCE(rlock->state);
			barrier();
		} else {
			result.lock_state = smp_load_acquire(&rlock->state);
		}
		if (unlikely(result.lock_state == RSEQ_LOCK_STATE_LOCK)) {
			rseq_fallback_wait(rlock);
			goto retry;
		}
	} else {
		rseq_fallback_lock(rlock, &result);
	}
	/*
	 * Read event_counter before cpu_id.
	 */
	RSEQ_INJECT_C(7)
	result.cpu_id = rseq_current_cpu();
	if (unlikely(result.cpu_id < 0))
		rseq_fallback_noinit(rlock, &result);
	/*
	 * We need to ensure that the compiler does not re-order the
	 * loads of any protected values before we read the current
	 * state.
	 */
	barrier();
	return result;
}

static inline void rseq_abort(struct rseq_lock *rlock,
		struct rseq_state start_value)
{
	if (unlikely(start_value.lock_state != RSEQ_LOCK_STATE_RESTART))
		rseq_fallback_unlock(rlock, start_value);
}

static inline bool rseq_finish(struct rseq_lock *rlock,
		intptr_t *p, intptr_t to_write,
		struct rseq_state start_value)
{
	RSEQ_INJECT_C(8)

	if (unlikely(start_value.lock_state != RSEQ_LOCK_STATE_RESTART)) {
		ACCESS_ONCE(*p) = to_write;
		rseq_fallback_unlock(rlock, start_value);
		return true;
	}

#ifdef __x86_64__
	/*
	 * abort_ip: rcx (clobber list).
	 * event_counter: edx (input operand which needs to be live for
	 * the entire critical section. Make sure that all output
	 * operands are either forced to other registers, or use early
	 * clobber).
	 * The __rseq_table section can be used by debuggers to better
	 * handle single-stepping through the restartable critical
	 * sections.
	 */
	__asm__ __volatile__ goto (
			".pushsection __rseq_table, \"aw\"\n\t"
			".balign 8\n\t"
			".quad 1f, 2f, 3f\n\t"
			".popsection\n\t"
			"1:\n\t"
			RSEQ_INJECT_ASM(1)
			"movq $3f, %%rcx\n\t"
			RSEQ_INJECT_ASM(2)
			"movq $2f, %[post_commit_ip]\n\t"
			RSEQ_INJECT_ASM(3)
			"cmpl %[start_event_counter], %[current_event_counter]\n\t"
			"jnz 3f\n\t"
			RSEQ_INJECT_ASM(4)
			"movq %[to_write], (%[target])\n\t"
			"2:\n\t"
			RSEQ_INJECT_ASM(5)
			"movq $0, %[post_commit_ip]\n\t"
			"jmp %l[succeed]\n\t"
			"3: movq $0, %[post_commit_ip]\n\t"
	  : /* no outputs */
	  : [start_event_counter]"d"(start_value.event_counter),
	    [current_event_counter]"m"(__rseq_thread_state.abi.event_counter),
	    [to_write]"r"(to_write),
	    [target]"r"(p),
	    [post_commit_ip]"m"(__rseq_thread_state.abi.post_commit_ip)
	    RSEQ_INJECT_INPUT
	  : "rcx", "memory", "cc"
	    RSEQ_INJECT_CLOBBER
	  : succeed
	);
#elif defined(__i386__)
	/*
	 * abort_ip: ecx (clobber list).
	 * event_counter: edx (input operand which needs to be live for
	 * the entire critical section. Make sure that all output
	 * operands are either forced to other registers, or use early
	 * clobber).
	 *
	 * Offset from rseq_base within the assembler on i386, because
	 * some gcc compiler versions (e.g. gcc 4.8.4) appear to have
	 * issues with register pressure when using multiple "m"
	 * operands. When passing multiple "m" operands, just clobbering
	 * eax is enough to cause the compiler to bail out.
	 *
	 * The __rseq_table section can be used by debuggers to better
	 * handle single-stepping through the restartable critical
	 * sections.
	 */
#define RSEQ_CURRENT_EVENT_COUNTER	"4(%[rseq_base])"
#define RSEQ_POST_COMMIT_IP		"8(%[rseq_base])"	/* 32-bit, little endian. */

	__asm__ __volatile__ goto (
			".pushsection __rseq_table, \"aw\"\n\t"
			".balign 4\n\t"
			".long 1f, 2f, 3f\n\t"
			".popsection\n\t"
			"1:\n\t"
			RSEQ_INJECT_ASM(1)
			"movl $3f, %%ecx\n\t"
			RSEQ_INJECT_ASM(2)
			"movl $2f, " RSEQ_POST_COMMIT_IP "\n\t"
			RSEQ_INJECT_ASM(3)
			"cmpl %[start_event_counter], " RSEQ_CURRENT_EVENT_COUNTER "\n\t"
			"jnz 3f\n\t"
			RSEQ_INJECT_ASM(4)
			"movl %[to_write], (%[target])\n\t"
			"2:\n\t"
			RSEQ_INJECT_ASM(5)
			"movl $0, " RSEQ_POST_COMMIT_IP "\n\t"
			"jmp %l[succeed]\n\t"
			"3: movl $0, " RSEQ_POST_COMMIT_IP "\n\t"
	  : /* no outputs */
	  : [start_event_counter]"d"(start_value.event_counter),
	    [rseq_base]"r"(&__rseq_thread_state.abi),
	    [to_write]"r"(to_write),
	    [target]"r"(p)
	    RSEQ_INJECT_INPUT
	  : "ecx", "memory", "cc"
	    RSEQ_INJECT_CLOBBER
	  : succeed
	);
#elif defined(__ARMEL__)
	{
		register unsigned int event_counter asm("r3") =
				start_value.event_counter;
		/*
		 * abort_ip: r2 (clobber list).
		 * event_counter: r3 (input operand which needs to be live for
		 * the entire critical section. Make sure that all output
		 * operands are either forced to other registers, or use early
		 * clobber).
		 *
		 * The __rseq_table section can be used by debuggers to better
		 * handle single-stepping through the restartable critical
		 * sections.
		 */
		__asm__ __volatile__ goto (
				".pushsection __rseq_table, \"aw\"\n\t"
				".balign 4\n\t"
				".word 1f, 2f, 3f\n\t"
				".popsection\n\t"
				"1:\n\t"
				RSEQ_INJECT_ASM(1)
				"adr r1, 2f\n\t"
				"adr r2, 3f\n\t"
				RSEQ_INJECT_ASM(2)
				"str r1, %[post_commit_ip]\n\t"
				RSEQ_INJECT_ASM(3)
				"ldr r1, %[current_event_counter]\n\t"
				"mov r0, #0\n\t"
				"cmp %[start_event_counter], r1\n\t"
				"bne 3f\n\t"
				RSEQ_INJECT_ASM(4)
				"str %[to_write], [%[target]]\n\t"
				"2:\n\t"
				RSEQ_INJECT_ASM(5)
				"str r0, %[post_commit_ip]\n\t"
				"b %l[succeed]\n\t"
				"3:\n\t"
				"mov r0, #0\n\t"
				"str r0, %[post_commit_ip]\n\t"
		  : /* no outputs */
		  : [start_event_counter]"r"(event_counter),
		    [current_event_counter]"m"(__rseq_thread_state.abi.event_counter),
		    [to_write]"r"(to_write),
		    [target]"r"(p),
		    [post_commit_ip]"m"(__rseq_thread_state.abi.post_commit_ip)
		    RSEQ_INJECT_INPUT
		  : "r0", "r1", "r2", "memory", "cc"
		    RSEQ_INJECT_CLOBBER
		  : succeed
		);
	}
#else
#error unsupported target
#endif
	RSEQ_INJECT_FAILED
	++__rseq_thread_state.fail_cnt;
	return false;
succeed:
	__rseq_thread_state.fail_cnt = 0;
	return true;
}

#endif  /* RSEQ_H_ */
