package services

import (
	"fmt"
	"sync"

	"github.com/urfave/cli"
)

var AllServices = struct {
	sync.RWMutex
	services map[string]*Service
}{}

func init() {
	AllServices.services = make(map[string]*Service)
}

type Service struct {
	Name    string
	Desc    string
	NewInst func(ctx *cli.Context, opts ...interface{}) (interface{}, error)
}

func AddService(svc *Service) error {
	AllServices.Lock()
	defer AllServices.Unlock()

	if _, existed := AllServices.services[svc.Name]; existed {
		return fmt.Errorf("service existed : %s", svc.Name)
	}

	AllServices.services[svc.Name] = svc

	return nil
}

func WalkServices(fn func(nm string, svc *Service) error) error {
	AllServices.Lock()
	defer AllServices.Unlock()

	for name, service := range AllServices.services {
		if err := fn(name, service); err != nil {
			return err
		}
	}

	return nil
}
