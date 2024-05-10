package main

import (
	"fmt"
	"os"
)

import (
	_ "embed"
	"github.com/linuxkerneltravel/lmp/eBPF_Supermarket/kernel_and_user_pod_observation/cmd"
)

//go:embed VERSION
var version string

func main() {
	if err := cmd.Execute(version); err != nil {
		fmt.Println("execute command failed: ", err)
		os.Exit(1)
	}
}
