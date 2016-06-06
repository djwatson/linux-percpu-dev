#undef TRACE_SYSTEM
#define TRACE_SYSTEM rseq

#if !defined(_TRACE_RSEQ_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RSEQ_H

#include <linux/tracepoint.h>

TRACE_EVENT(rseq_inc,

	TP_PROTO(uint32_t event_counter, int ret),

	TP_ARGS(event_counter, ret),

	TP_STRUCT__entry(
		__field(uint32_t, event_counter)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->event_counter = event_counter;
		__entry->ret = ret;
	),

	TP_printk("event_counter=%u ret=%d",
		__entry->event_counter, __entry->ret)
);

TRACE_EVENT(rseq_ip_fixup,

	TP_PROTO(void __user *regs_ip, void __user *post_commit_ip,
		void __user *abort_ip, uint32_t kevcount, int ret),

	TP_ARGS(regs_ip, post_commit_ip, abort_ip, kevcount, ret),

	TP_STRUCT__entry(
		__field(void __user *, regs_ip)
		__field(void __user *, post_commit_ip)
		__field(void __user *, abort_ip)
		__field(uint32_t, kevcount)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->regs_ip = regs_ip;
		__entry->post_commit_ip = post_commit_ip;
		__entry->abort_ip = abort_ip;
		__entry->kevcount = kevcount;
		__entry->ret = ret;
	),

	TP_printk("regs_ip=%p post_commit_ip=%p abort_ip=%p kevcount=%u ret=%d",
		__entry->regs_ip, __entry->post_commit_ip, __entry->abort_ip,
		__entry->kevcount, __entry->ret)
);

#endif /* _TRACE_SOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
