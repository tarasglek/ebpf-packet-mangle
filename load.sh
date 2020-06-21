set -e -x
DEVICE=wlp3s0
KERNEL_SRCTREE=/usr/src/linux-headers-5.6.15-050615
LIBBPF=${KERNEL_SRCTREE}/tools/lib/bpf/libbpf.a
clang -I${KERNEL_SRCTREE}/tools/lib/bpf/ -g -O2 -Wall -target bpf -c tc-example.c -o tc-example.o

tc filter show dev $DEVICE ingress

# tc qdisc add dev $DEVICE clsact # no idea what this does
#delete prior invocatoins
sudo tc filter del dev wlp3s0 egress
sudo tc filter del dev wlp3s0 ingress
#insert us
tc filter add dev $DEVICE ingress bpf da obj tc-example.o sec ingress
tc filter add dev $DEVICE egress bpf da obj tc-example.o sec egress
tc filter show dev $DEVICE ingress

# bpftool prog show
