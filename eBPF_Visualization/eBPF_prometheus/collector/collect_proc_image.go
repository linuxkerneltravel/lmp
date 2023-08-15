package collector

import (
	"bufio"
	"ebpf_prometheus/checker"
	"ebpf_prometheus/prom_core"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Proc_Setting struct {
	Name        string `yaml:"name"`
	Path        string `yaml:"path"`
	Pid         string `yaml:"pid"`
	Max_Records int    `yaml:"max_records"`
}

var proc_imageCommand = cli.Command{
	Name:    "proc_image",
	Aliases: []string{"pro"},
	Usage:   "Special collect data out from proc_image",
	Action:  procCollect,
}

func Get_Setting() (error, string, int) {
	currentDir, _ := os.Getwd()
	content, err := os.ReadFile(currentDir + "/collector/proc_setting.yaml")
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
		return err, "", 0
	}
	var setting Proc_Setting
	err = yaml.Unmarshal(content, &setting)
	if err != nil {
		log.Fatalf("Error unmarshaling YAML :%v", err)
		return err, "", 0
	}

	command := setting.Path + " -p " + setting.Pid
	maxrecords := setting.Max_Records
	return nil, command, maxrecords
}

func procCollect(ctx *cli.Context) error {
	_, command, _ := Get_Setting()
	return ProcRun(command)
}

func ProcRun(command string) error {
	_, _, maxrecords := Get_Setting()
	cmdStr := CheckFileType(command)
	cmd := exec.Command("sh", "-c", cmdStr)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	log.Println("full command is :", cmdStr)
	if err != nil {
		log.Println("get stdout failed:", err)
	}

	go listenSystemSignals(cmd)

	mapchan := make(chan map[string]interface{}, 2)

	loc, _ := time.LoadLocation("Asia/Shanghai")
	currenttime := float64(time.Now().In(loc).UnixNano()) / 1e9
	go rediectProc(stdout, mapchan)
	procdata := prom_core.ProcMetrics{Max_records: maxrecords, NowTime: currenttime}
	// process chan from redirectProc Stdout
	go procdata.BootProcService()

	go func() {
		for {
			select {
			case <-mapchan:
				procdata.Getorigindata(mapchan)
				procdata.UpdateRecords()
				<-mapchan
			default:
			}
		}
	}()

	err = cmd.Start()
	if err != nil {
		log.Printf("cmd.Start() analysis service failed: %v", err)
		os.Exit(-1)
	}

	err = cmd.Wait()
	if err != nil {
		log.Printf("cmd.Run() analysis failed with: %v", err)
		os.Exit(-1)
	}

	return nil
}

func rediectProc(stdout io.ReadCloser, mapchan chan map[string]interface{}) {
	var onemap map[string]interface{}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		line = checker.CutunexceptedSpace(line)
		if checker.IsProcOutput(line) {
			onemap = make(map[string]interface{})
			parms := strings.Fields(line)
			for _, value := range parms {
				parts := strings.Split(value, ":")
				onemap[parts[0]] = parts[1]
			}
			// log.Println(onemap)
			mapchan <- onemap
		} else {
			continue
		}
	}
}
