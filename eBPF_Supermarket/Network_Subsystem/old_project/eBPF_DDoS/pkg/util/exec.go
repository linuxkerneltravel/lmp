package util

import (
	"fmt"
	"os"
	"os/exec"
)

func ExecCommand(command string) error {
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("failed to exec %q, unexpected exit code: %d, err: %v", command, code, err)
	}
	return nil
}
