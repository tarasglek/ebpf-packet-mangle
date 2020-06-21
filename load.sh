set -e -x
DEVICE=wlp3s0
clang -g -O2 -Wall -target bpf -c tc-example.c -o tc-example.o

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
