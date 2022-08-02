package bpf

import (
	"fmt"
	"os"

	"github.com/iovisor/gobpf/bcc"
)

func AttachKprobe(m *bcc.Module, name string, fnName string) {
	kProbe, err := m.LoadKprobe(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load '%s': %s\n", name, err)
		os.Exit(1)
	}

	err = m.AttachKprobe(fnName, kProbe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach '%s': %s\n", fnName, err)
		os.Exit(1)
	}
}

func AttachKretprobe(m *bcc.Module, name string, fnName string) {
	kProbe, err := m.LoadKprobe(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load '%s': %s\n", name, err)
		os.Exit(1)
	}

	if err := m.AttachKretprobe(fnName, kProbe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach '%s': %s\n", fnName, err)
		os.Exit(1)
	}
}
