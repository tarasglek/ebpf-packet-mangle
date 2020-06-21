#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <asm/types.h>
#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "helpers.h"

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map acc_map __section("maps") = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
};

static __inline int account_data(struct __sk_buff *skb, uint32_t dir)
{
        uint32_t *bytes;

        bytes = map_lookup_elem(&acc_map, &dir);
        if (bytes)
                lock_xadd(bytes, skb->len);

        return TC_ACT_OK;
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{
        return account_data(skb, 0);
}

static inline void set_tcp_dport(struct __sk_buff *skb, int nh_off,
__u16 old_port, __u16 new_port)
{
        bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check), old_port, new_port, sizeof(new_port));
        bpf_skb_store_bytes(skb, nh_off + offsetof(struct tcphdr, dest), &new_port, sizeof(new_port), 0);
}

static inline int lb_do_ipv4(struct __sk_buff *skb, int nh_off)
{
        __u16 dport, dport_new = 8080, off;
        __u8 ip_proto, ip_vl;
        ip_proto = load_byte(skb, nh_off + offsetof(struct iphdr, protocol));
        if (ip_proto != IPPROTO_TCP)
                return 0;
        ip_vl = load_byte(skb, nh_off);
        if (likely(ip_vl == 0x45))
                nh_off += sizeof(struct iphdr);
        else
                nh_off += (ip_vl & 0xF) << 2;
        dport = load_half(skb, nh_off + offsetof(struct tcphdr, dest));
        if (dport != 5555)
                return 0;
        off = skb->queue_mapping & 7;
        set_tcp_dport(skb, nh_off - BPF_LL_OFF, dport, __cpu_to_be16(80));
        return TC_ACT_UNSPEC;
}


__section("egress")
int tc_egress(struct __sk_buff *skb)
{
        int nh_off = BPF_LL_OFF + ETH_HLEN;
        if (skb->protocol == __constant_htons(ETH_P_IP)) {
                return lb_do_ipv4(skb, nh_off);
        }
        return account_data(skb, 1);
}

char __license[] __section("license") = "GPL";
