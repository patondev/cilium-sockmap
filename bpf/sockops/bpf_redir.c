#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "../lib/utils.h"

#include "bpf_sockops.h"

__section("sk_msg")
int bpf_redir_proxy(struct sk_msg_md *msg)
{
    struct sock_key key = {};
    sk_msg_extract4_key(msg, &key);
     __u64 flags = BPF_F_INGRESS;
    msg_redirect_hash(msg, &sock_ops_map, &key, flags);
    return SK_PASS;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
