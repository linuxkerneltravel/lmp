package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/lmp/eBPF_Supermarket/eBPF_DDoS/pkg/config"
	"github.com/lmp/eBPF_Supermarket/eBPF_DDoS/pkg/util"
)

var rootCmd = &cobra.Command{
	Use:   "lmpddos",
	Short: "LMP: ebpf programs for mitigating DDoS attacks.",
	Long:  `LMP: ebpf programs for mitigating DDoS attacks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Usage()
	},
}

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "load ebpf programs to mitigate DDoS attacks",
	Long:  `load ebpf programs to mitigate DDoS attacks`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// get root program idx
		var rootIdx uint32
		for _, plg := range config.Plugins {
			p := config.PluginMap[plg]
			idx := p.GetProgramIndex()
			if idx > rootIdx {
				rootIdx = idx
			}
		}

		// load and attach the root xdp prog
		if err := util.ExecCommand(
			fmt.Sprintf("mount -t bpf bpf /sys/fs/bpf && cd bpf && make xdp_root ROOT=%d && ip -force link set dev %s xdpgeneric obj xdp_root.o sec xdp", rootIdx, config.Interface)); err != nil {
			return err
		}

		for _, plg := range config.Plugins {
			p := config.PluginMap[plg]
			if p == nil {
				return fmt.Errorf("plugin %q not found", plg)
			}
			if err := p.Load(); err != nil {
				return err
			}
			fmt.Printf("LMP: plugin %q loaded\n", plg)
		}

		for _, plg := range config.Plugins {
			if err := config.PluginMap[plg].Run(); err != nil {
				return err
			}
			fmt.Printf("LMP: plugin %q started\n", plg)
		}

		// clean up when it exits
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
		select {
		case <-ch:
			if err := cleanup(); err != nil {
				return fmt.Errorf("failed to clean up: %v\n", err)
			}
		}
		return nil
	},
}

var unloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "unload ebpf programs",
	Long:  `unload ebpf programs`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cleanup()
	},
}

func main() {
	if os.Getuid() != 0 {
		panic("LMP: root user required")
	}
	rootCmd.Execute()
}

func cleanup() error {
	if err := util.ExecCommand(
		fmt.Sprintf("ip -force link set dev %s xdpgeneric off && rm -f /sys/fs/bpf/xdp/globals/ddos_programs", config.Interface)); err != nil {
		return err
	}
	for _, plg := range config.Plugins {
		p := config.PluginMap[plg]
		if p == nil {
			return fmt.Errorf("plugin %q not found", plg)
		}
		if err := p.Unload(); err != nil {
			return err
		}
		fmt.Printf("plugin %q unloaded\n", plg)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(loadCmd)
	rootCmd.AddCommand(unloadCmd)
	rootCmd.PersistentFlags().StringArrayVarP(&config.Plugins, "plugins", "p", []string{}, "available plugins: dns")
}
