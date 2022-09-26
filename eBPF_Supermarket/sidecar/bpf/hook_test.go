package bpf

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestGetAllHooks(t *testing.T) {
	_, err := exec.Command("bpftrace", "--version").Output()
	if err != nil {
		return
	}
	testPattern := "kprobe:net_*"
	res, err := GetAllHooks(testPattern)
	if err != nil {
		t.Errorf("test failed for '%s' for '%s'\n", testPattern, err)
	}
	fmt.Println("----------Got Hooks----------")
	fmt.Println(strings.Join(res, "\n"))
	fmt.Println("-----------------------------")
}

func TestGetHookFullName(t *testing.T) {
	_, err := exec.Command("bpftrace", "--version").Output()
	if err != nil {
		return
	}
	testPattern := "tracepoint:net:net_dev_start_xmit"
	res, err := GetHookFullName(testPattern)
	if err != nil {
		t.Errorf("test failed for '%s' for '%s'\n", testPattern, err)
	}
	fmt.Println("----------Got Hooks----------")
	fmt.Println(res)
	fmt.Println("-----------------------------")
}
