package clicore

import (
	"fmt"
	"sync"

	"github.com/urfave/cli"
)

type CliService struct {
	Name    string
	Desc    string
	NewInst func(ctx *cli.Context, opts ...interface{}) (interface{}, error)
}

var AllServices = struct {
	sync.RWMutex
	services map[string]*CliService
}{}

func init() {
	AllServices.services = make(map[string]*CliService)
}

func AddService(svc *CliService) error {
	AllServices.Lock()
	defer AllServices.Unlock()

	if _, existed := AllServices.services[svc.Name]; existed {
		return fmt.Errorf("service existed : %s", svc.Name)
	}

	AllServices.services[svc.Name] = svc

	return nil
}

func WalkServices(fn func(nm string, svc *CliService) error) error {
	AllServices.Lock()
	defer AllServices.Unlock()

	for name, service := range AllServices.services {
		if err := fn(name, service); err != nil {
			return err
		}
	}

	return nil
}
