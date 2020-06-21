/* Misc helper macros. */
#define __section(x) __attribute__((section(x), used))
#define offsetof(x, y) __builtin_offsetof(x, y)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
/* Object pinning settings */
#define PIN_NONE       0
#define PIN_OBJECT_NS  1
#define PIN_GLOBAL_NS  2
/* ELF map definition */

/* Some used BPF function calls. */
// https://elixir.bootlin.com/linux/v4.7/source/include/uapi/linux/bpf.h#L192
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) = (void *) BPF_FUNC_skb_store_bytes;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) = (void *) BPF_FUNC_l4_csum_replace;
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;
/* Some used BPF intrinsics. */
// https://kernel.googlesource.com/pub/scm/linux/kernel/git/vgupta/arc/+/arc-4.6-rc1/samples/bpf/bpf_helpers.h
unsigned long long load_byte(void *skb, unsigned long long off) asm ("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off) asm ("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");