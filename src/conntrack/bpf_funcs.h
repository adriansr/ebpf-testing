#ifndef __BPF_FUNCS__
#define __BPF_FUNCS__

/* most of this source stolen from iproute2 examples */

/* Misc macros. */
#ifndef __maybe_unused
# define __maybe_unused		__attribute__ ((__unused__))
#endif

#ifndef __section
# define __section(NAME)	__attribute__((section(NAME), used))
#endif

#ifndef offsetof
# define offsetof		__builtin_offsetof
#endif

#ifndef htons
# define htons(x)		__constant_htons((x))
#endif

#ifndef ntohs
# define ntohs(x)		__constant_ntohs((x))
#endif

#ifndef htonl
# define htonl(x)		__constant_htonl((x))
#endif

#ifndef ntohl
# define ntohl(x)		__constant_ntohl((x))
#endif


#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

/* The verifier will translate them to actual function calls. */
static void *(*bpf_map_lookup_elem)(void *map, void *key) __maybe_unused =
	(void *) BPF_FUNC_map_lookup_elem;

static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) __maybe_unused =
	(void *) BPF_FUNC_map_update_elem;

static int (*bpf_map_delete_elem)(void *map, void *key) __maybe_unused =
	(void *) BPF_FUNC_map_delete_elem;

static unsigned int (*get_smp_processor_id)(void) __maybe_unused =
	(void *) BPF_FUNC_get_smp_processor_id;

static unsigned int (*get_prandom_u32)(void) __maybe_unused =
	(void *) BPF_FUNC_get_prandom_u32;

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;

static uint64_t (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;

/* LLVM built-in functions that an eBPF C program may use to emit
 * BPF_LD_ABS and BPF_LD_IND instructions.
 */
unsigned long long load_byte(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.byte");

unsigned long long load_half(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.half");

unsigned long long load_word(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.word");

#endif /* __BPF_FUNCS__ */
