package modules

import (
	"sync"

	"github.com/urfave/cli/v2"
)

var OptModules = struct {
	sync.RWMutex
	modules []*cli.Command
}{}

func GetModules() []*cli.Command {
	return OptModules.modules
}

func registerModules(module *cli.Command) error {
	OptModules.Lock()
	defer OptModules.Unlock()

	OptModules.modules = append(OptModules.modules, module)

	return nil
}
