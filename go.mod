module scx_core_dispatch

go 1.22.4

require (
	github.com/cilium/ebpf v0.15.0
	github.com/lrita/numa v1.0.3
	github.com/pkg/errors v0.9.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/intel-go/cpuid v0.0.0-20220614022739-219e067757cb // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

replace github.com/cilium/ebpf => ../ebpf/
