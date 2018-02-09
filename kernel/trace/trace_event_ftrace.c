// SPDX-License-Identifier: GPL-2.0
/*
 * trace events created on top of ftrace (functions).
 *
 * Copyright (C) 2018 VMware Inc, Steven Rostedt.
 */

#include <linux/ctype.h>
#include <linux/slab.h>

#include "trace.h"

#define FUNC_EVENT_SYSTEM	"functions"
#define WRITE_BUFSIZE		4096
#define INDIRECT_FLAG		0x10000000

struct func_arg_redirect {
	struct list_head		list;
	long				index;
	long				indirect;
};

struct func_arg {
	struct list_head		list;
	struct list_head		redirects;
	char				*type;
	char				*name;
	long				indirect;
	long				index;
	short				array;
	short				offset;
	short				size;
	s8				arg;
	u8				sign;
	u8				func_type;
};

struct func_event {
	struct list_head		list;
	char				*func;
	/* The above must match func_event_err below */
	struct trace_event_class	class;
	struct trace_event_call		call;
	struct ftrace_ops		ops;
	struct list_head		files;
	struct list_head		args;
	struct func_arg			*last_arg;
	int				arg_cnt;
	int				arg_offset;
	int				has_strings;
};

#define ERR_SIZE	(256 - (sizeof(struct list_head) + sizeof(char *)))

struct func_event_err {
	struct list_head		list;
	char				*func;
	/* The above must match func_event above */
	char				err_str[ERR_SIZE];
};

struct func_file {
	struct list_head		list;
	struct trace_event_file		*file;
};

struct func_event_hdr {
	struct trace_entry	ent;
	unsigned long		ip;
	unsigned long		parent_ip;
	char			data[0];
};

static DEFINE_MUTEX(func_event_mutex);
static LIST_HEAD(func_events);

#define FUNC_STATES				\
	C(INIT),				\
	C(FUNC),				\
	C(PARAM),				\
	C(BRACKET),				\
	C(BRACKET_END),				\
	C(INDIRECT),				\
	C(UNSIGNED),				\
	C(ADDR),				\
	C(EQUAL),				\
	C(PIPE),				\
	C(PLUS),				\
	C(TYPE),				\
	C(ARRAY),				\
	C(ARRAY_SIZE),				\
	C(ARRAY_END),				\
	C(REDIRECT_PLUS),			\
	C(REDIRECT_BRACKET),			\
	C(SYMBOL),				\
	C(VAR),					\
	C(COMMA),				\
	C(NULL),				\
	C(END),					\
	C(ERROR)

#undef C
#define C(x)	FUNC_STATE_##x

enum func_states {
	FUNC_STATES
};

#undef C
#define C(x)	#x

static char *func_state_names[] = {
	FUNC_STATES
};

typedef u64 x64;
typedef u32 x32;
typedef u16 x16;
typedef u8 x8;
typedef void * symbol;
/* 2 byte offset, 2 byte length */
typedef u32 string;

#define TYPE_TUPLE(type)			\
	{ #type, sizeof(type), is_signed_type(type) }

#define FUNC_TYPES				\
	TYPE_TUPLE(long),			\
	TYPE_TUPLE(int),			\
	TYPE_TUPLE(short),			\
	TYPE_TUPLE(char),			\
	TYPE_TUPLE(size_t),			\
	TYPE_TUPLE(u64),			\
	TYPE_TUPLE(s64),			\
	TYPE_TUPLE(x64),			\
	TYPE_TUPLE(u32),			\
	TYPE_TUPLE(s32),			\
	TYPE_TUPLE(x32),			\
	TYPE_TUPLE(u16),			\
	TYPE_TUPLE(s16),			\
	TYPE_TUPLE(x16),			\
	TYPE_TUPLE(u8),				\
	TYPE_TUPLE(s8),				\
	TYPE_TUPLE(x8),				\
	TYPE_TUPLE(symbol),			\
	TYPE_TUPLE(string)

static struct func_type {
	char		*name;
	int		size;
	int		sign;
} func_types[] = {
	FUNC_TYPES,
	{ "NULL",	0,	0 },
	{ NULL,		0,	0 }
};

#undef TYPE_TUPLE
#define TYPE_TUPLE(type)	FUNC_TYPE_##type

enum {
	FUNC_TYPES,
	FUNC_TYPE_NULL,
	FUNC_TYPE_MAX
};

#define MAX_STR		512

/* Two contexts, normal and NMI, hence the " * 2" */
struct func_string {
	char		buf[MAX_STR * 2];
};

static struct func_string __percpu *str_buffer;
static int nr_strings;

static int max_args __read_mostly = -1;

/**
 * arch_get_func_args - retrieve function arguments via pt_regs
 * @regs: The registers at the moment the function is called
 * @start: The first argument to retrieve (usually zero)
 * @end: The last argument to retrive (end - start arguments to get)
 * @args: The array to store the arguments in
 *
 * This is to be implemented by architecture code.
 *
 * If @regs is NULL, return the number of supported arguments that
 * can be retrieved (this default function supports no arguments,
 * and returns zero). The other parameters are ignored when @regs
 * is NULL.
 *
 * If the function can support 6 arguments, then it should return
 * 6 if @regs is NULL. If @regs is not NULL and it should start
 * loading the arguments into @args. If @start is 2 and @end is 4,
 * @args[0] would get the third argument (0 is the first argument)
 * and @args[1] would get the forth argument. The function would
 * return 2 (@end - @start).
 *
 * If @start is 5 and @end is 7, as @end is greater than the number
 * of supported arguments, @args[0] would get the sixth argument,
 * and 1 would be returned. The function does not error if more
 * than the supported arguments is asked for. It only load what it
 * can into @args, and return the number of arguments copied.
 *
 * Returns:
 *  If @regs is NULL, the number of supported arguments it can handle.
 *
 *  Otherwise, it returns the number of arguments copied to @args.
 */
int __weak arch_get_func_args(struct pt_regs *regs,
			      int start, int end,
			      long *args)
{
	return 0;
}

static void free_arg(struct func_arg *arg)
{
	list_del(&arg->list);
	if (arg->func_type == FUNC_TYPE_string) {
		nr_strings--;
		if (WARN_ON(nr_strings < 0))
			nr_strings = 0;
		if (!nr_strings) {
			free_percpu(str_buffer);
			str_buffer = NULL;
		}
	}
	kfree(arg->name);
	kfree(arg->type);
	kfree(arg);
}

static void free_func_event(struct func_event *func_event)
{
	struct func_arg *arg, *n;

	if (!func_event)
		return;

	/*
	 * If func is NULL then this is a func_event_err, or
	 * nothing else has been allocated for the func_event.
	 * In either case, it is safe just to free the func_event.
	 */
	if (!func_event->func) {
		kfree(func_event);
		return;
	}

	list_for_each_entry_safe(arg, n, &func_event->args, list) {
		free_arg(arg);
	}
	ftrace_free_filter(&func_event->ops);
	kfree(func_event->call.print_fmt);
	kfree(func_event->func);
	kfree(func_event);
}

static char *next_token(char **ptr, char *last)
{
	char *arg;
	char *str;

	if (!*ptr)
		return NULL;

	arg = *ptr;

	if (*last)
		*arg = *last;

	if (!*arg)
		return NULL;

	for (str = arg; *str; str++) {
		if (!isalnum(*str) && *str != '_')
			break;
	}
	if (*str) {
		if (str == arg)
			str++;
		*last = *str;
		*str = 0;
		*ptr = str;
		return arg;
	}

	*last = 0;
	*ptr = NULL;
	return arg;
}

static int add_arg(struct func_event *fevent, int ftype, int unsign)
{
	struct func_type *func_type = &func_types[ftype];
	struct func_arg *arg;

	/* Make sure the arch can support this many args */
	if (fevent->arg_cnt >= max_args)
		return -EINVAL;

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;

	INIT_LIST_HEAD(&arg->redirects);

	if (unsign)
		arg->type = kasprintf(GFP_KERNEL, "unsigned %s",
				      func_type->name);
	else
		arg->type = kstrdup(func_type->name, GFP_KERNEL);
	if (!arg->type) {
		kfree(arg);
		return -ENOMEM;
	}
	arg->size = func_type->size;
	if (!unsign)
		arg->sign = func_type->sign;
	arg->func_type = ftype;
	arg->offset = ALIGN(fevent->arg_offset, arg->size);

	if (ftype != FUNC_TYPE_NULL)
		fevent->arg_offset = arg->offset + arg->size;

	list_add_tail(&arg->list, &fevent->args);
	fevent->last_arg = arg;

	if (ftype == FUNC_TYPE_string) {
		fevent->has_strings++;
		nr_strings++;
		if (nr_strings == 1) {
			str_buffer = alloc_percpu(struct func_string);
			if (!str_buffer) {
				free_arg(arg);
				return -ENOMEM;
			}
		}
	}
	return 0;
}

static int update_arg_name(struct func_event *fevent, const char *name)
{
	struct func_arg *arg = fevent->last_arg;

	if (WARN_ON(!arg))
		return -EINVAL;

	arg->name = kstrdup(name, GFP_KERNEL);
	if (!arg->name)
		return -ENOMEM;
	return 0;
}

static int update_arg_arg(struct func_event *fevent)
{
	struct func_arg *arg = fevent->last_arg;

	if (WARN_ON(!arg))
		return -EINVAL;

	/* Make sure the arch can support this many args */
	if (fevent->arg_cnt >= max_args)
		return -EINVAL;

	arg->arg = fevent->arg_cnt;

	return 0;
}

static int add_arg_redirect(struct func_arg *arg, long index, long indirect)
{
	struct func_arg_redirect *redirect;

	redirect = kzalloc(sizeof(*redirect), GFP_KERNEL);
	if (!redirect)
		return -ENOMEM;

	redirect->index = index;
	redirect->indirect = indirect;

	list_add_tail(&redirect->list, &arg->redirects);

	return 0;
}

static int get_symbol(const char *symbol, unsigned long *val)
{
	*val = kallsyms_lookup_name(symbol);
	if (!*val)
		return -1;
	return 0;
}

static bool valid_name(const char *token)
{
	return isalpha(token[0]) || token[0] == '_';
}

static enum func_states
process_event(struct func_event *fevent, const char *token, enum func_states state)
{
	static bool update_arg;
	static int unsign;
	unsigned long val;
	char *type;
	int ret;
	int i;

	switch (state) {
	case FUNC_STATE_INIT:
		unsign = 0;
		update_arg = false;
		if (!valid_name(token))
			break;
		fevent->func = kstrdup(token, GFP_KERNEL);
		if (!fevent->func)
			break;
		return FUNC_STATE_FUNC;

	case FUNC_STATE_FUNC:
		if (token[0] != '(')
			break;
		return FUNC_STATE_PARAM;

	case FUNC_STATE_PARAM:
		if (token[0] == ')')
			return FUNC_STATE_END;
		/* Fall through */
	case FUNC_STATE_COMMA:
		if (update_arg)
			fevent->arg_cnt++;
		update_arg = false;
		/* Fall through */
	case FUNC_STATE_PIPE:
		if (strcmp(token, "NULL") == 0)
			return FUNC_STATE_NULL;
		if (strcmp(token, "unsigned") == 0) {
			unsign = 2;
			return FUNC_STATE_UNSIGNED;
		}
		/* Fall through */
	case FUNC_STATE_UNSIGNED:
		for (i = 0; func_types[i].size; i++) {
			if (strcmp(token, func_types[i].name) == 0)
				break;
		}
		if (!func_types[i].size)
			break;
		ret = add_arg(fevent, i, unsign);
		unsign = 0;
		if (ret < 0)
			break;
		return FUNC_STATE_TYPE;

	case FUNC_STATE_TYPE:
		if (token[0] == '[') {
			/* Strings are already arrays */
			if (fevent->last_arg->func_type == FUNC_TYPE_string)
				break;
			return FUNC_STATE_ARRAY;
		}
		if (fevent->last_arg->func_type == FUNC_TYPE_string) {
			type = kstrdup("__data_loc char[]", GFP_KERNEL);
			if (!type)
				break;
			kfree(fevent->last_arg->type);
			fevent->last_arg->type = type;
		}
		/* Fall through */
	case FUNC_STATE_ARRAY_END:
		if (WARN_ON(!fevent->last_arg))
			break;
		if (token[0] == '$')
			return FUNC_STATE_SYMBOL;
		if (update_arg_name(fevent, token) < 0)
			break;
		if (strncmp(token, "0x", 2) == 0)
			goto equal;
		if (!valid_name(token)) {
			kfree(fevent->last_arg->name);
			fevent->last_arg->name = NULL;
			break;
		}
		update_arg = true;
		return FUNC_STATE_VAR;

	case FUNC_STATE_VAR:
		if (token[0] == '=')
			return FUNC_STATE_EQUAL;
		if (WARN_ON(!fevent->last_arg))
			break;
		update_arg_arg(fevent);
		update_arg = true;
		switch (token[0]) {
		case ')':
			goto end;
		case ',':
			return FUNC_STATE_COMMA;
		case '|':
			return FUNC_STATE_PIPE;
		case '+':
			return FUNC_STATE_PLUS;
		case '[':
			return FUNC_STATE_BRACKET;
		}
		break;

	case FUNC_STATE_ARRAY:
	case FUNC_STATE_BRACKET:
		if (WARN_ON(!fevent->last_arg))
			break;
		ret = kstrtoul(token, 0, &val);
		if (ret)
			break;
		if (state == FUNC_STATE_BRACKET) {
			val *= fevent->last_arg->size;
			fevent->last_arg->indirect = val ^ INDIRECT_FLAG;
			return FUNC_STATE_INDIRECT;
		}
		if (!val)
			break;
		fevent->last_arg->array = val;
		type = kasprintf(GFP_KERNEL, "%s[%d]", fevent->last_arg->type, (unsigned)val);
		if (!type)
			break;
		kfree(fevent->last_arg->type);
		fevent->last_arg->type = type;
		/*
		 * arg_offset has already been updated once by size.
		 * This update needs to account for that (hence the "- 1").
		 */
		fevent->arg_offset += fevent->last_arg->size * (fevent->last_arg->array - 1);
		return FUNC_STATE_ARRAY_SIZE;

	case FUNC_STATE_ARRAY_SIZE:
		if (token[0] != ']')
			break;
		return FUNC_STATE_ARRAY_END;

	case FUNC_STATE_INDIRECT:
		if (token[0] != ']')
			break;
		return FUNC_STATE_BRACKET_END;

	case FUNC_STATE_BRACKET_END:
		switch (token[0]) {
		case ')':
			goto end;
		case ',':
			return FUNC_STATE_COMMA;
		case '|':
			return FUNC_STATE_PIPE;
		case '+':
			return FUNC_STATE_REDIRECT_PLUS;
		case '[':
			return FUNC_STATE_REDIRECT_BRACKET;
		}
		break;

	case FUNC_STATE_PLUS:
		if (WARN_ON(!fevent->last_arg))
			break;
		ret = kstrtoul(token, 0, &val);
		if (ret)
			break;
		fevent->last_arg->index += val;
		return FUNC_STATE_VAR;

	case FUNC_STATE_SYMBOL:
		if (!isalpha(token[0]) && token[0] != '_')
			break;
		goto equal;

	case FUNC_STATE_ADDR:
		switch (token[0]) {
		case ')':
			goto end;
		case ',':
			return FUNC_STATE_COMMA;
		case '|':
			return FUNC_STATE_PIPE;
		}
		break;

	case FUNC_STATE_REDIRECT_PLUS:
		if (WARN_ON(!fevent->last_arg))
			break;
		ret = kstrtoul(token, 0, &val);
		if (ret)
			break;
		ret = add_arg_redirect(fevent->last_arg, val, 0);
		if (ret)
			break;
		return FUNC_STATE_BRACKET_END;

	case FUNC_STATE_REDIRECT_BRACKET:
		if (WARN_ON(!fevent->last_arg))
			break;
		ret = kstrtoul(token, 0, &val);
		if (ret)
			break;
		val *= fevent->last_arg->size;
		val ^= INDIRECT_FLAG;
		ret = add_arg_redirect(fevent->last_arg, 0, val);
		if (ret)
			break;
		return FUNC_STATE_INDIRECT;

	case FUNC_STATE_EQUAL:
		if (token[0] == '$')
			return FUNC_STATE_SYMBOL;
		if (strncmp(token, "0x", 2) != 0)
			break;
 equal:
		if (WARN_ON(!fevent->last_arg))
			break;
		if (isalpha(token[0]) || token[0] != '_') {
			ret = get_symbol(token, &val);
			if (ret < 0)
				break;
			if (!fevent->last_arg->name) {
				if (update_arg_name(fevent, token) < 0)
					break;
			}
		} else {
			ret = kstrtoul(token, 0, &val);
			if (ret < 0)
				break;
		}
		update_arg = false;
		fevent->last_arg->index = val;
		fevent->last_arg->arg = -1;
		fevent->last_arg->indirect = INDIRECT_FLAG;
		return FUNC_STATE_ADDR;

	case FUNC_STATE_NULL:
		ret = add_arg(fevent, FUNC_TYPE_NULL, 0);
		if (ret < 0)
			break;
		switch (token[0]) {
		case ')':
			goto end;
		case ',':
			update_arg = true;
			return FUNC_STATE_COMMA;
		}
		break;

	default:
		break;
	}
	return FUNC_STATE_ERROR;
 end:
	if (update_arg)
		fevent->arg_cnt++;
	return FUNC_STATE_END;
}

static unsigned long process_redirects(struct func_arg *arg, unsigned long val,
				       char *buf)
{
	struct func_arg_redirect *redirect;
	int ret;

	if (arg->indirect) {
		ret = probe_kernel_read(buf, (void *)val, sizeof(long));
		if (ret)
			return 0;
		val = *(unsigned long *)buf;
	}

	list_for_each_entry(redirect, &arg->redirects, list) {
		val += redirect->index;
		if (redirect->indirect) {
			val += (redirect->indirect ^ INDIRECT_FLAG);
			ret = probe_kernel_read(buf, (void *)val, sizeof(long));
			if (ret)
				return 0;
			val = *(unsigned long *)buf;
		}
	}
	return val;
}

static long long __get_arg(struct func_arg *arg, unsigned long long val)
{
	char buf[8];
	int ret;

	val += arg->index;

	if (arg->indirect)
		val += (arg->indirect ^ INDIRECT_FLAG);

	if (!list_empty(&arg->redirects))
		return process_redirects(arg, val, buf);

	if (!val)
		return 0;

	/* Arrays and strings do their own indirect reads */
	if (!arg->indirect || arg->array || arg->func_type == FUNC_TYPE_string)
		return val;

	ret = probe_kernel_read(buf, (void *)val, arg->size);
	if (ret)
		return 0;

	switch (arg->size) {
		case 8:
			val = *(unsigned long long *)buf;
			break;
		case 4:
			val = *(unsigned int *)buf;
			break;
		case 2:
			val = *(unsigned short *)buf;
			break;
		case 1:
			val = *(unsigned char *)buf;
			break;
	}
	return val;
}

static long long get_arg(struct func_arg *arg, long *args)
{
	/* Is arg an address and not a parameter? */
	if (arg->arg < 0)
		return __get_arg(arg, 0);
	else
		return __get_arg(arg, args[arg->arg]);
}

static void get_array(void *dst, struct func_arg *arg, unsigned long val)
{
	void *ptr = (void *)val;
	int ret;
	int i;

	for (i = 0; i < arg->array; i++) {
		ret = probe_kernel_read(dst, ptr, arg->size);
		if (ret)
			memset(dst, 0, arg->size);
		ptr += arg->size;
		dst += arg->size;
	}
}

static int read_string(char *str, unsigned long addr)
{
	unsigned long flags;
	struct func_string *strbuf;
	char *ptr = (void *)addr;
	char *buf;
	int ret;

	if (!str_buffer)
		return 0;

	strbuf = this_cpu_ptr(str_buffer);
	buf = &strbuf->buf[0];

	if (in_nmi())
		buf += MAX_STR;

	local_irq_save(flags);
	ret = strncpy_from_unsafe(buf, ptr, MAX_STR);
	if (ret < 0)
		ret = 0;
	if (ret > 0 && str)
		memcpy(str, buf, ret);
	local_irq_restore(flags);

	return ret;
}

static int calculate_strings(struct func_event *func_event, int nr_args, long *args)
{
	struct func_arg *arg;
	unsigned long val;
	int str_count = 0;
	int size = 0;

	list_for_each_entry(arg, &func_event->args, list) {
		if (arg->func_type != FUNC_TYPE_string)
			continue;
		if (arg->arg < nr_args)
			val = get_arg(arg, args);
		else
			goto skip;
		size += read_string(NULL, val);
 skip:
		if (++str_count >= func_event->has_strings)
			return size;
	}
	return size;
}

static int get_string(unsigned long addr, unsigned int idx,
		      unsigned int *info, char *data)
{
	int len;

	len = read_string(data, addr);
	*info = len << 16 | idx;

	return len;
}

static int get_event_size(struct func_event *func_event, struct pt_regs *pt_regs,
			  long *args, int *nr_args)
{
	int size;

	size = func_event->arg_offset + sizeof(struct func_event_hdr);

	if (func_event->arg_cnt)
		*nr_args = arch_get_func_args(pt_regs, 0, func_event->arg_cnt, args);
	else
		*nr_args = 0;

	if (func_event->has_strings)
		size += calculate_strings(func_event, *nr_args, args);

	return size;
}

static void
record_entry(struct func_event_hdr *entry, struct func_event *func_event,
	     unsigned long ip, unsigned long parent_ip, int nr_args, long *args)
{
	struct func_arg *arg;
	long long val;
	int str_offset;
	int str_idx = 0;

	entry->ip = ip;
	entry->parent_ip = parent_ip;

	list_for_each_entry(arg, &func_event->args, list) {
		if (arg->func_type == FUNC_TYPE_NULL)
			continue;
		if (arg->arg < nr_args)
			val = get_arg(arg, args);
		else
			val = 0;
		if (arg->array)
			get_array(&entry->data[arg->offset], arg, val);
		else if (arg->func_type == FUNC_TYPE_string) {
			str_offset = sizeof(struct func_event_hdr) +
				func_event->arg_offset;

			str_idx += get_string(val, str_offset + str_idx,
					      (unsigned int *)&entry->data[arg->offset],
					      &entry->data[func_event->arg_offset + str_idx]);
		} else
			memcpy(&entry->data[arg->offset], &val, arg->size);
	}
}

static void func_event_trace(struct trace_event_file *trace_file,
			     struct func_event *func_event,
			     unsigned long ip, unsigned long parent_ip,
			     struct pt_regs *pt_regs)
{
	struct func_event_hdr *entry;
	struct trace_event_call *call = &func_event->call;
	struct ring_buffer_event *event;
	struct ring_buffer *buffer;
	long args[func_event->arg_cnt];
	unsigned long irq_flags;
	int nr_args;
	int size;
	int pc;

	if (trace_trigger_soft_disabled(trace_file))
		return;

	local_save_flags(irq_flags);
	pc = preempt_count();

	size = get_event_size(func_event, pt_regs, args, &nr_args);

	event = trace_event_buffer_lock_reserve(&buffer, trace_file,
						call->event.type,
						size, irq_flags, pc);
	if (!event)
		return;

	entry = ring_buffer_event_data(event);
	record_entry(entry, func_event, ip, parent_ip, nr_args, args);
	event_trigger_unlock_commit_regs(trace_file, buffer, event,
					 entry, irq_flags, pc, pt_regs);
}

#ifdef CONFIG_PERF_EVENTS
/* Kprobe profile handler */
static void func_event_perf(struct func_event *func_event,
			    unsigned long ip, unsigned long parent_ip,
			    struct pt_regs *pt_regs)
{
	struct trace_event_call *call = &func_event->call;
	struct func_event_hdr *entry;
	struct hlist_head *head;
	long args[func_event->arg_cnt];
	int nr_args = 0;
	int rctx;
	int size;

	if (bpf_prog_array_valid(call) && !trace_call_bpf(call, pt_regs))
		return;

	head = this_cpu_ptr(call->perf_events);
	if (hlist_empty(head))
		return;

	size = get_event_size(func_event, pt_regs, args, &nr_args);

	entry = perf_trace_buf_alloc(size, NULL, &rctx);
	if (!entry)
		return;

	record_entry(entry, func_event, ip, parent_ip, nr_args, args);
	perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, pt_regs,
			      head, NULL);
}
#else
static inline void func_event_perf(struct func_event *func_event,
				   unsigned long ip, unsigned long parent_ip,
				   struct pt_regs *pt_regs) { }
#endif

static void
func_event_call(unsigned long ip, unsigned long parent_ip,
		    struct ftrace_ops *op, struct pt_regs *pt_regs)
{
	struct func_event *func_event;
	struct func_file *ff;

	func_event = container_of(op, struct func_event, ops);

	if (WARN_ON_ONCE(rcu_irq_enter_disabled()))
		return;
	rcu_irq_enter_irqson();
	rcu_read_lock_sched_notrace();
	list_for_each_entry_rcu(ff, &func_event->files, list) {
		if (ff->file)
			func_event_trace(ff->file, func_event, ip, parent_ip, pt_regs);
		else
			func_event_perf(func_event, ip, parent_ip, pt_regs);
	}
	rcu_read_unlock_sched_notrace();
	rcu_irq_exit_irqson();
}

#define FMT_SIZE	8

static void make_fmt(struct func_arg *arg, char *fmt)
{
	int c = 0;

	if (arg->func_type == FUNC_TYPE_symbol) {
		strcpy(fmt, "%pS");
		return;
	}

	fmt[c++] = '%';

	if (arg->func_type == FUNC_TYPE_string) {
		fmt[c++] = 's';
		goto out;
	}

	if (arg->func_type == FUNC_TYPE_char) {
		if (arg->array)
			fmt[c++] = 's';
		else
			fmt[c++] = 'c';
		goto out;
	}

	if (arg->size == 8) {
		fmt[c++] = 'l';
		fmt[c++] = 'l';
	}

	if (arg->type[0] == 'x')
		fmt[c++] = 'x';
	else if (arg->sign)
		fmt[c++] = 'd';
	else
		fmt[c++] = 'u';

 out:
	fmt[c++] = '\0';
}

static void write_data(struct trace_seq *s, const struct func_arg *arg, const char *fmt,
		       const void *data)
{
	switch (arg->size) {
	case 8:
		trace_seq_printf(s, fmt, *(unsigned long long *)data);
		break;
	case 4:
		trace_seq_printf(s, fmt, *(unsigned *)data);
		break;
	case 2:
		trace_seq_printf(s, fmt, *(unsigned short *)data);
		break;
	case 1:
		if (arg->array && arg->func_type == FUNC_TYPE_char)
			trace_seq_printf(s, fmt, (char *)data);
		else
			trace_seq_printf(s, fmt, *(unsigned char *)data);
		break;
	}
}

static enum print_line_t
func_event_print(struct trace_iterator *iter, int flags,
		 struct trace_event *event)
{
	struct func_event_hdr *entry;
	struct trace_seq *s = &iter->seq;
	struct func_event *func_event;
	struct func_arg *arg;
	char fmt[FMT_SIZE];
	void *data;
	bool comma = false;
	int info;
	int a;

	entry = (struct func_event_hdr *)iter->ent;

	func_event = container_of(event, struct func_event, call.event);

	trace_seq_printf(s, "%ps->%ps(",
			 (void *)entry->parent_ip, (void *)entry->ip);
	list_for_each_entry(arg, &func_event->args, list) {
		if (arg->func_type == FUNC_TYPE_NULL)
			continue;
		if (comma)
			trace_seq_puts(s, ", ");
		comma = true;
		trace_seq_printf(s, "%s=", arg->name);
		data = &entry->data[arg->offset];

		make_fmt(arg, fmt);

		if (arg->array && arg->func_type != FUNC_TYPE_char) {
			comma = false;
			trace_seq_putc(s, '{');
			for (a = 0; a < arg->array; a++, data += arg->size) {
				if (comma)
					trace_seq_putc(s, ':');
				comma = true;
				write_data(s, arg, fmt, data);
			}
			trace_seq_putc(s, '}');
		} else if (arg->func_type == FUNC_TYPE_string) {
			info = *(unsigned int *)data;
			info = (info & 0xffff) - sizeof(struct func_event_hdr);
			data = &entry->data[info];
			trace_seq_printf(s, fmt, data);
		} else
			write_data(s, arg, fmt, data);
	}
	trace_seq_puts(s, ")\n");
	return trace_handle_return(s);
}

static struct trace_event_functions func_event_funcs = {
	.trace		= func_event_print,
};

static int func_event_define_fields(struct trace_event_call *event_call)
{
	struct func_event *fevent;
	struct func_event_hdr field;
	struct func_arg *arg;
	int ret;

	fevent = (struct func_event *)event_call->data;

	DEFINE_FIELD(unsigned long, ip, "__parent_ip", 0);
	DEFINE_FIELD(unsigned long, parent_ip, "__ip", 0);

	list_for_each_entry(arg, &fevent->args, list) {
		int size = arg->size;

		if (arg->func_type == FUNC_TYPE_NULL)
			continue;

		if (arg->array)
			size *= arg->array;
		ret = trace_define_field(event_call, arg->type,
					 arg->name,
					 sizeof(field) + arg->offset,
					 size, arg->sign, FILTER_OTHER);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int enable_func_event(struct func_event *func_event,
			     struct trace_event_file *file)
{
	struct func_file *ff;
	int ret;

	ff = kmalloc(sizeof(*ff), GFP_KERNEL);
	if (!ff)
		return -ENOMEM;

	if (list_empty(&func_event->files)) {
		ret = register_ftrace_function(&func_event->ops);
		if (ret < 0)
			return ret;
	}

	ff->file = file;
	/* Make sure file is visible before adding to the list */
	smp_wmb();
	list_add_rcu(&ff->list, &func_event->files);
	return 0;
}

static int disable_func_event(struct func_event *func_event,
			      struct trace_event_file *file)
{
	struct list_head *p, *n;
	struct func_file *ff;


	list_for_each_safe(p, n, &func_event->files) {
		ff = container_of(p, struct func_file, list);
		if (ff->file == file) {
			list_del_rcu(&ff->list);
			break;
		}
		ff = NULL;
	}

	if (!ff)
		return -ENODEV;

	if (list_empty(&func_event->files))
		unregister_ftrace_function(&func_event->ops);

	synchronize_sched();
	kfree(ff);

	return 0;
}

static int func_event_register(struct trace_event_call *event,
			       enum trace_reg type, void *data)
{
	struct func_event *func_event = event->data;
	struct trace_event_file *file = data;

	switch (type) {
	case TRACE_REG_REGISTER:
		return enable_func_event(func_event, file);
	case TRACE_REG_UNREGISTER:
		return disable_func_event(func_event, file);
#ifdef CONFIG_PERF_EVENTS
	case TRACE_REG_PERF_REGISTER:
		return enable_func_event(func_event, NULL);
	case TRACE_REG_PERF_UNREGISTER:
		return disable_func_event(func_event, NULL);
	case TRACE_REG_PERF_OPEN:
	case TRACE_REG_PERF_CLOSE:
	case TRACE_REG_PERF_ADD:
	case TRACE_REG_PERF_DEL:
		return 0;
#endif
	default:
		break;
	}

	return 0;
}

static int print_buf(char **ptr, int *length, const char *fmt, ...)
{
	char *buf = *ptr;
	va_list args;
	int len = *length;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, len, fmt, args);
	va_end(args);

	len -= i;
	if (len < 0)
		len = 0;

	*ptr = buf + i;
	*length = len;

	return i;
}

static int __set_print_fmt(struct func_event *func_event,
			   char *buf, int len)
{
	struct func_arg *arg;
	const char *fmt_start = "\"%pS->%pS(";
	const char *fmt_end = ")\", REC->__ip, REC->__parent_ip";
	char fmt[FMT_SIZE];
	char *ptr = buf;
	int a;
	bool comma = false;
	int total = 0;

	total += print_buf(&ptr, &len, "%s", fmt_start);
	list_for_each_entry(arg, &func_event->args, list) {
		if (arg->func_type == FUNC_TYPE_NULL)
			continue;
		if (comma)
			total += print_buf(&ptr, &len, ", ");
		comma = true;

		total += print_buf(&ptr, &len, "%s=", arg->name);

		make_fmt(arg, fmt);

		if (arg->array && arg->func_type != FUNC_TYPE_char) {
			bool colon = false;

			total += print_buf(&ptr, &len, "{");
			for (a = 0; a < arg->array; a++) {
				if (colon)
					total += print_buf(&ptr, &len, ":");
				colon = true;
				total += print_buf(&ptr, &len, "%s", fmt);
			}
			total += print_buf(&ptr, &len, "}");
		} else {
			total += print_buf(&ptr, &len, "%s", fmt);
		}
	}
	total += print_buf(&ptr, &len, "%s", fmt_end);

	list_for_each_entry(arg, &func_event->args, list) {
		if (arg->func_type == FUNC_TYPE_NULL)
			continue;
		/* Don't iterate for strings */
		if (arg->array && arg->func_type != FUNC_TYPE_char) {
			for (a = 0; a < arg->array; a++)
				total += print_buf(&ptr, &len, ", REC->%s[%d]",
						   arg->name, a);
		} else {
			if (arg->func_type == FUNC_TYPE_string)
				total += print_buf(&ptr, &len, ", __get_str(%s)",
						   arg->name);
			else
				total += print_buf(&ptr, &len, ", REC->%s", arg->name);
		}
	}

	return total;
}

static int set_print_fmt(struct func_event *func_event)
{
	int len;

	/* Get required length */
	len = __set_print_fmt(func_event, NULL, 0) + 1;
	func_event->call.print_fmt = kmalloc(len, GFP_KERNEL);
	if (!func_event->call.print_fmt)
		return -ENOMEM;
	__set_print_fmt(func_event, func_event->call.print_fmt, len);

	return 0;
}

static int func_event_create(struct func_event *func_event)
{
	struct trace_event_call *call = &func_event->call;
	int ret;

	func_event->class.system = FUNC_EVENT_SYSTEM;
	call->class = &func_event->class;
	INIT_LIST_HEAD(&call->class->fields);
	call->event.funcs = &func_event_funcs;
	call->name = func_event->func;
	call->class->define_fields = func_event_define_fields;
	ret = set_print_fmt(func_event);
	if (ret < 0)
		return ret;
	ret = register_trace_event(&call->event);
	if (ret < 0)
		return ret;
	call->flags = TRACE_EVENT_FL_FUNC;
	call->class->reg = func_event_register;
	call->data = func_event;
	ret = trace_add_event_call(call);
	if (ret) {
		pr_info("Failed to register func event: %s\n", func_event->func);
		unregister_trace_event(&call->event);
	}
	return ret;
}

static void show_func_event(struct trace_seq *s, struct func_event *func_event);

static void add_failure(struct func_event *func_event, char *token,
			enum func_states state, char *ptr, char last,
			int i, int argc, char **argv)
{
	struct func_event_err *func_err;
	struct trace_seq *s;
	char *save_token = NULL;
	int len;

	/* Don't do anything if we were not able to get the first field */
	if (!func_event->func)
		return;

	func_err = kzalloc(sizeof(*func_err), GFP_KERNEL);
	if (!func_err)
		return;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		kfree(func_err);
		return;
	}
	trace_seq_init(s);
	show_func_event(s, func_event);

	/*
	 * show_func_event() doesn't print some tokens if it crashed
	 * at a certain state.
	 */
	switch (state) {
	case FUNC_STATE_PIPE:
		trace_seq_puts(s, " | ");
		break;
	case FUNC_STATE_COMMA:
		trace_seq_puts(s, ", ");
		break;
	case FUNC_STATE_PLUS:
	case FUNC_STATE_REDIRECT_PLUS:
		trace_seq_putc(s, '+');
		break;
	case FUNC_STATE_BRACKET:
	case FUNC_STATE_ARRAY:
		trace_seq_putc(s, '[');
		break;
	case FUNC_STATE_UNSIGNED:
		trace_seq_puts(s, "unsigned ");
		break;
	case FUNC_STATE_INDIRECT:
	case FUNC_STATE_ARRAY_SIZE:
		/* show_func_event() adds a ']' for these */
		s->seq.len--;
		break;
	default:
		break;
	}
	trace_seq_putc(s, ' ');
	len = s->seq.len + 1;

	if (!token) {
		/* Parser didn't end properly */
		trace_seq_printf(s, "\n%*s\nUnexpected ending",
				 len, "^");
		goto finish;
	}

	save_token = kstrdup(token, GFP_KERNEL);
	if (!save_token) {
		kfree(func_err);
		kfree(s);
		return;
	}

	trace_seq_puts(s, token);
	trace_seq_putc(s, ' ');

	/* Finish parsing the tokens */
	for (token = next_token(&ptr, &last); token;
	     token = next_token(&ptr, &last)) {
		if (token[0] == '|')
			trace_seq_putc(s, ' ');
		trace_seq_puts(s, token);
		if (token[0] == ',' || token[0] == '|')
			trace_seq_putc(s, ' ');
	}

	/* Add the rest of the line */
	for (i++; i < argc; i++) {
		trace_seq_puts(s, argv[i]);
		trace_seq_putc(s, ' ');
	}

	trace_seq_printf(s, "\n%*s\n", len, "^");

	/* for COMMA or PARAM state, the error could be too many args */
	if ((state == FUNC_STATE_COMMA || state == FUNC_STATE_PARAM) &&
	    func_event->arg_cnt >= max_args)
		trace_seq_printf(s, "Error: Too many arguments (max of %d)",
				 max_args);
	else
		trace_seq_printf(s, "Unexpected token '%s' for %s state",
				 save_token, func_state_names[state]);

 finish:
	len = min(ERR_SIZE-1, s->seq.len);
	strncpy(func_err->err_str, s->buffer, len);
	func_err->err_str[len] = 0;

	mutex_lock(&func_event_mutex);
	list_add_tail(&func_err->list, &func_events);
	mutex_unlock(&func_event_mutex);

	kfree(save_token);
	kfree(s);
}

static int create_function_event(int argc, char **argv)
{
	struct func_event *func_event;
	enum func_states last_state, state = FUNC_STATE_INIT;
	char *token;
	char *ptr;
	char last;
	int ret = -EINVAL;
	int i;

	func_event = kzalloc(sizeof(*func_event), GFP_KERNEL);
	if (!func_event)
		return -ENOMEM;

	INIT_LIST_HEAD(&func_event->files);
	INIT_LIST_HEAD(&func_event->args);
	func_event->ops.func = func_event_call;
	func_event->ops.flags = FTRACE_OPS_FL_SAVE_REGS;
	last_state = state;

	mutex_lock(&func_event_mutex);
	for (i = 0; i < argc; i++) {
		ptr = argv[i];
		last = 0;
		for (token = next_token(&ptr, &last); token;
		     token = next_token(&ptr, &last)) {
			last_state = state;
			state = process_event(func_event, token, state);
			if (state == FUNC_STATE_ERROR)
				goto fail;
		}
	}
	if (state != FUNC_STATE_END)
		goto fail;

	ret = ftrace_set_filter(&func_event->ops, func_event->func,
				strlen(func_event->func), 0);
	if (ret < 0)
		goto fail;

	ret = func_event_create(func_event);
	if (ret < 0)
		goto fail;

	list_add_tail(&func_event->list, &func_events);
	mutex_unlock(&func_event_mutex);
	return 0;
 fail:
	mutex_unlock(&func_event_mutex);
	if (state != FUNC_STATE_END)
		add_failure(func_event, token, last_state, ptr,
			    last, i, argc, argv);
	free_func_event(func_event);
	return ret;
}

static void *func_event_seq_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&func_event_mutex);
	return seq_list_start(&func_events, *pos);
}

static void *func_event_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &func_events, pos);
}

static void func_event_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&func_event_mutex);
}

static int show_error (struct seq_file *m, struct func_event *func_event)
{
	struct func_event_err *func_err = (struct func_event_err *)func_event;

	seq_puts(m, func_err->err_str);
	seq_putc(m, '\n');
	return 0;
}

static void show_func_event(struct trace_seq *s, struct func_event *func_event)
{
	struct func_arg_redirect *redirect;
	struct func_arg *arg;
	bool comma = false;
	int last_arg = 0;

	trace_seq_printf(s, "%s(", func_event->func);

	list_for_each_entry(arg, &func_event->args, list) {
		if (comma) {
			if (last_arg == arg->arg)
				trace_seq_puts(s, " | ");
			else
				trace_seq_puts(s, ", ");
		}
		last_arg = arg->arg;
		comma = true;
		if (arg->func_type == FUNC_TYPE_NULL)
			trace_seq_puts(s, "NULL");
		else {
			if (arg->type)
				trace_seq_puts(s, arg->type);
			if (arg->name)
				trace_seq_printf(s, " %s", arg->name);
		}
		if (arg->arg < 0) {
			trace_seq_printf(s, "=0x%lx", arg->index);
		} else {
			if (arg->index)
				trace_seq_printf(s, "+%ld", arg->index);
			if (arg->indirect && arg->size)
				trace_seq_printf(s, "[%ld]",
					   (arg->indirect ^ INDIRECT_FLAG) / arg->size);
		}
		list_for_each_entry(redirect, &arg->redirects, list) {
			if (redirect->index)
				trace_seq_printf(s, "+%ld", redirect->index);
			if (redirect->indirect)
				trace_seq_printf(s, "[%ld]",
					   (redirect->indirect ^ INDIRECT_FLAG) / arg->size);
		}
	}
}

static int func_event_seq_show(struct seq_file *m, void *v)
{
	static struct trace_seq s;
	struct func_event *func_event = v;

	if (!func_event->func)
		return show_error(m, func_event);

	trace_seq_init(&s);
	show_func_event(&s, func_event);
	trace_print_seq(m, &s);
	seq_puts(m, ")\n");

	return 0;
}

static const struct seq_operations func_event_seq_op = {
	.start  = func_event_seq_start,
	.next   = func_event_seq_next,
	.stop   = func_event_seq_stop,
	.show   = func_event_seq_show
};

static int release_all_func_events(void)
{
	struct func_event *func_event, *n;
	int ret = 0;

	mutex_lock(&func_event_mutex);
	list_for_each_entry_safe(func_event, n, &func_events, list) {
		/* NULL func means it is a func_event_err message */
		if (func_event->func) {
			ret = trace_remove_event_call(&func_event->call);
			if (ret < 0)
				break;
		}
		list_del(&func_event->list);
		free_func_event(func_event);
	}
	mutex_unlock(&func_event_mutex);
	return ret;
}

static void remove_func_errors(void)
{
	struct func_event *func_event, *n;

	mutex_lock(&func_event_mutex);
	list_for_each_entry_safe(func_event, n, &func_events, list) {
		/* NULL func means it is a func_event_err message */
		if (func_event->func)
			continue;
		list_del(&func_event->list);
		free_func_event(func_event);
	}
	mutex_unlock(&func_event_mutex);
}

static int func_event_open(struct inode *inode, struct file *file)
{
	int ret;

	if (max_args < 0)
		max_args = arch_get_func_args(NULL, 0, 0, NULL);

	if ((file->f_mode & FMODE_WRITE)) {
		if (file->f_flags & O_TRUNC) {
			ret = release_all_func_events();
			if (ret < 0)
				return ret;
		} else {
			/* Only keep one error per write */
			remove_func_errors();
		}
	}

	return seq_open(file, &func_event_seq_op);
}

static ssize_t
func_event_write(struct file *filp, const char __user *ubuf,
		 size_t cnt, loff_t *ppos)
{
	return trace_parse_run_command(filp, ubuf, cnt, ppos,
				       create_function_event);
}

static const struct file_operations func_event_fops = {
	.open		= func_event_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
	.write		= func_event_write,
};

/* Make a tracefs interface for controlling probe points */
static __init int init_func_events(void)
{
	struct dentry *d_tracer;
	struct dentry *entry;

	d_tracer = tracing_init_dentry();
	if (IS_ERR(d_tracer))
		return 0;

	entry = trace_create_file("function_events", 0644, d_tracer, NULL,
				  &func_event_fops);

	/* Event list interface */
	if (!entry)
		pr_warn("Could not create tracefs 'function-events' entry\n");

	return 0;
}
fs_initcall(init_func_events);
