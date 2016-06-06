#undef TRACE_SYSTEM
#define TRACE_SYSTEM rseq

#if !defined(_TRACE_RSEQ_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RSEQ_H

#include <linux/tracepoint.h>
#include <linux/types.h>

TRACE_EVENT(rseq_update,

	TP_PROTO(struct task_struct *t),

	TP_ARGS(t),

	TP_STRUCT__entry(
		__field(s32, cpu_id)
		__field(u32, event_counter)
	),

	TP_fast_assign(
		__entry->cpu_id = raw_smp_processor_id();
		__entry->event_counter = t->rseq_event_counter;
	),

	TP_printk("cpu_id=%d event_counter=%u",
		__entry->cpu_id, __entry->event_counter)
);

TRACE_EVENT(rseq_ip_fixup,

	TP_PROTO(void __user *regs_ip, void __user *start_ip,
		void __user *post_commit_ip, void __user *abort_ip,
		u32 kevcount, int ret),

	TP_ARGS(regs_ip, start_ip, post_commit_ip, abort_ip, kevcount, ret),

	TP_STRUCT__entry(
		__field(void __user *, regs_ip)
		__field(void __user *, start_ip)
		__field(void __user *, post_commit_ip)
		__field(void __user *, abort_ip)
		__field(u32, kevcount)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->regs_ip = regs_ip;
		__entry->start_ip = start_ip;
		__entry->post_commit_ip = post_commit_ip;
		__entry->abort_ip = abort_ip;
		__entry->kevcount = kevcount;
		__entry->ret = ret;
	),

	TP_printk("regs_ip=%p start_ip=%p post_commit_ip=%p abort_ip=%p kevcount=%u ret=%d",
		__entry->regs_ip, __entry->start_ip, __entry->post_commit_ip,
		__entry->abort_ip, __entry->kevcount, __entry->ret)
);

#endif /* _TRACE_SOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
