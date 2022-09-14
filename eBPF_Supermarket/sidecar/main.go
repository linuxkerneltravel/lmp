package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/eswzy/podstat/cmd"
)

//go:embed VERSION
var version string

func main() {
	if err := cmd.Execute(version); err != nil {
		fmt.Println("execute command failed: ", err)
		os.Exit(1)
	}
}
