package ebpf

//go:generate bpf2go tracer c/tracer.bpf.c -- -Ic -I/usr/include
