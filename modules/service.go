package modules

import (
	"sync"

	"github.com/urfave/cli/v2"
)

var OptModules = struct {
	sync.RWMutex
	Modules []*cli.Command
}{}

func GetModules() []*cli.Command {
	return OptModules.Modules
}
