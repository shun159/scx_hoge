module scx_core_dispatch

go 1.23.4

require (
	github.com/cilium/ebpf v0.15.0
	github.com/pkg/errors v0.9.1
	github.com/shun159/scx_go_utils v0.0.0-20241228072325-17c8770e9546
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

replace github.com/cilium/ebpf => ../ebpf/

replace github.com/shun159/scx_go_utils => ../scx_go_utils/
