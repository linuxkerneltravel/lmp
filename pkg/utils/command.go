//
// Created by Zhenwen Xu
//
package utils

import (
	"os"
	"strings"
	"os/exec"
	log "github.com/cihub/seelog"
)

// StandardEnv is for setting env
func StandardEnv() []string {
	env := os.Environ()
	return env
}

// VerboseCommand runs a command, outputing stderr and stdout
func VerboseCommand(name string, arg ...string) *exec.Cmd {
	log.Infof("Running command: %v %v", name, strings.Join(arg, " "))
	cmd := exec.Command(name, arg...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd
}

func RunMake(RepoDir string, env []string, c ...string) error {
	cmd := VerboseCommand("make", c...)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Dir = RepoDir
	log.Infof("Running make %v with env=%v wd=%v", strings.Join(c, " "), strings.Join(env, " "), cmd.Dir)
	return cmd.Run()
}