package bpf

import (
	"fmt"
	"testing"
)

func TestGetFilterByParentProcessPidNamespace(t *testing.T) {
	pidList := []int{1, 2, 3, 4, 5}
	res, err := GetFilterByParentProcessPidNamespace(1, pidList, false)
	if err != nil {
		t.Errorf("get filter with ns failed: %s", err)
	}
	fmt.Println(res)
}
