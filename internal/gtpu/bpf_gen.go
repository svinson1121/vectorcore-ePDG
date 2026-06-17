//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf GtpuDecap bpf/xdp_gtpu_decap.c -- -I./bpf/headers -I/usr/include/x86_64-linux-gnu -O2 -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf GtpuEncap bpf/tc_gtpu_encap.c -- -I./bpf/headers -I/usr/include -I/usr/include/x86_64-linux-gnu -O2 -Wall

package gtpu
