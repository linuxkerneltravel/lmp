package probe

import (
	"fmt"
	"os/exec"
	"strings"
)

// GetAllHooks gets all hooks
func GetAllHooks(pattern string) ([]string, error) {
	resRaw, err := exec.Command("bpftrace", "-l", pattern).Output()
	if err != nil {
		return nil, fmt.Errorf("get hooks failed for pattern %s, because %s", pattern, err)
	}

	// from byte to string
	res := string(resRaw[:])
	res = strings.Trim(res, " \n")

	return strings.Split(res, "\n"), nil
}

// GetHookFullName gets the full name for hook point, mostly for C++ symbols.
func GetHookFullName(pattern string) (string, error) {
	allHooks, err := GetAllHooks(pattern)
	if err != nil {
		return "", err
	}

	if len(allHooks) == 0 {
		return "", fmt.Errorf("got no hook point for pattern: '%s'", pattern)
	}

	if len(allHooks) > 1 {
		fmt.Println(allHooks)
		return "", fmt.Errorf("got too much (%d) hook points for pattern: '%s'", len(allHooks), pattern)
	}

	return allHooks[0], nil
}
