package probe

import (
	"fmt"
	"strings"
	"testing"
)

func TestGetAllHooks(t *testing.T) {
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
	testPattern := "tracepoint:net:net_dev_start_xmit"
	res, err := GetHookFullName(testPattern)
	if err != nil {
		t.Errorf("test failed for '%s' for '%s'\n", testPattern, err)
	}
	fmt.Println("----------Got Hooks----------")
	fmt.Println(res)
	fmt.Println("-----------------------------")
}
