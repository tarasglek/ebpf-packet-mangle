Trying to rewrite outgoing packets (dst port 5555 -> 80) and then rewrite incoming packets (srcport 80 -> 5555).

Couldn't get ingress to work (yet).

Apparently i can follow printks with:
tc exec bpf egress
but no idea how to get that to work

todo: borrow code from https://github.com/litiezi1978/bpf-mapper-agent/tree/8f3745232aad8f99b872ac390ce6e9d0cf9c9aed/old_code_from_oracle_blog/bpf