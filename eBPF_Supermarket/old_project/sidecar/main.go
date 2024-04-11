package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/sidecar/cmd"
)

//go:embed VERSION
var version string

func main() {
	if err := cmd.Execute(version); err != nil {
		fmt.Println("execute command failed: ", err)
		os.Exit(1)
	}
}
