#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "../lib/utils.h"

#include "bpf_sockops.h"

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};
    sk_extract4_key(skops, &key);
    printt("source port: %d, destination port: %d\n", key.sport, key.dport);
    printt("source port: %ul, destination port: %ul\n", key.sip4, key.dip4); 
    sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
}

static inline void bpf_sock_ops_ipv6(struct bpf_sock_ops *skops)
{
	if (skops->remote_ip4)
		bpf_sock_ops_ipv4(skops);
}

__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == AF_INET6)
			bpf_sock_ops_ipv6(skops);
		else if (family == AF_INET)
			bpf_sock_ops_ipv4(skops);
		break;
	default:
		break;
	}
	return 0;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
