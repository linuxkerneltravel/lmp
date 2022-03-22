package ebpfplugins

import (
	"fmt"

	"lmp/server/global"
	"lmp/server/model/ebpfplugins"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

var Ebpfplugins = new(eplugins)

type eplugins struct{}

func (e *eplugins) TableName() string {
	return "ebpf_plugins"
}

func (e *eplugins) Initialize() error {
	entities := []ebpfplugins.EbpfPlugins{
		// cpu plugins
		{PluginName: "cpudist", PluginType: 0, PluginPath: "../plugins/cpu/cpudist.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "cpuidle", PluginType: 0, PluginPath: "../plugins/cpu/cpudile.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "cpuutilize", PluginType: 0, PluginPath: "../plugins/cpu/cpuutilize.py", DocUrl: "docs/monitor/cpu/cpuutilize/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "irq", PluginType: 0, PluginPath: "../plugins/cpu/irq.py", DocUrl: "docs/monitor/cpu/irq/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "picknext", PluginType: 0, PluginPath: "../plugins/cpu/picknext.py", DocUrl: "docs/monitor/cpu/picknext/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "runqlat", PluginType: 0, PluginPath: "../plugins/cpu/runqlat.py", DocUrl: "docs/monitor/cpu/runqlat/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "runqslower", PluginType: 0, PluginPath: "../plugins/cpu/runqslower.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "softirqs", PluginType: 0, PluginPath: "../plugins/cpu/softirqs.py", DocUrl: "docs/monitor/cpu/softirq/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "taskswitch", PluginType: 0, PluginPath: "../plugins/cpu/taskswitch.py", DocUrl: "docs/monitor/cpu/taskswitch/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "waitingqueuelength", PluginType: 0, PluginPath: "../plugins/cpu/waitingqueuelength.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},

		// fs plugins
		{PluginName: "biosnoop", PluginType: 0, PluginPath: "../plugins/fs/biosnoop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "biotop", PluginType: 0, PluginPath: "../plugins/fs/biotop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "btrfsdist", PluginType: 0, PluginPath: "../plugins/fs/btrfsdist.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "btrfsslower", PluginType: 0, PluginPath: "../plugins/fs/btrfsslower.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "cachestat", PluginType: 0, PluginPath: "../plugins/fs/cachestat.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "cachetop", PluginType: 0, PluginPath: "../plugins/fs/cachetop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "dcsnoop", PluginType: 0, PluginPath: "../plugins/fs/dcsnoop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "dcstat", PluginType: 0, PluginPath: "../plugins/fs/dcstat.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "ext4dist", PluginType: 0, PluginPath: "../plugins/fs/ext4dist.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "ext4slower", PluginType: 0, PluginPath: "../plugins/fs/ext4slower.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "filelife", PluginType: 0, PluginPath: "../plugins/fs/filelife.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "fileslower", PluginType: 0, PluginPath: "../plugins/fs/fileslower.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "filetop", PluginType: 0, PluginPath: "../plugins/fs/filetop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "harddiskreadwritetime", PluginType: 0, PluginPath: "../plugins/fs/harddiskreadwritetime.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "mdflush", PluginType: 0, PluginPath: "../plugins/fs/mdflush.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "mountsnoop", PluginType: 0, PluginPath: "../plugins/fs/mountsnoop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "nfsdist", PluginType: 0, PluginPath: "../plugins/fs/nfsdist.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "nfsslower", PluginType: 0, PluginPath: "../plugins/fs/nfsslower.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "vfscount", PluginType: 0, PluginPath: "../plugins/fs/vfscount.py", DocUrl: "docs/monitor/fs/vfscont/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "vfsstat", PluginType: 0, PluginPath: "../plugins/fs/vfsstat.py", DocUrl: "docs/monitor/fs/vfsstat/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "xfsdist", PluginType: 0, PluginPath: "../plugins/fs/xfsdist.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "xfsslower", PluginType: 0, PluginPath: "../plugins/fs/xfsslower.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "zfsdist", PluginType: 0, PluginPath: "../plugins/fs/zfsdist.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "zfsslower", PluginType: 0, PluginPath: "../plugins/fs/zfsslower.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},

		// mm plugins
		{PluginName: "drsnoop", PluginType: 0, PluginPath: "../plugins/mm/drsnoop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "freememinfo", PluginType: 0, PluginPath: "../plugins/mm/freememinfo.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "huge", PluginType: 0, PluginPath: "../plugins/mm/huge.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "memleak", PluginType: 0, PluginPath: "../plugins/mm/memleak.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "memusage", PluginType: 0, PluginPath: "../plugins/mm/memusage.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "oomkill", PluginType: 0, PluginPath: "../plugins/mm/oomkill.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "proc_mem", PluginType: 0, PluginPath: "../plugins/mm/proc_mem.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "shmsnoop", PluginType: 0, PluginPath: "../plugins/mm/shmsnoop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "slabratetop", PluginType: 0, PluginPath: "../plugins/mm/slabratetop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "swap_in", PluginType: 0, PluginPath: "../plugins/mm/swap_in.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},

		// net plugins
		{PluginName: "containerNet", PluginType: 0, PluginPath: "../plugins/net/ContainerNet.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "DNS_Latency", PluginType: 0, PluginPath: "../plugins/net/DNS_Latency.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "DNS_Request", PluginType: 0, PluginPath: "../plugins/net/DNS_Request.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "DNS_Response", PluginType: 0, PluginPath: "../plugins/net/DNS_Response.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "netlatency", PluginType: 0, PluginPath: "../plugins/net/netlatency.py", DocUrl: "docs/monitor/net/netlatency/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "sofdsnoop", PluginType: 0, PluginPath: "../plugins/net/sofdsnoop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcp_delay_aver", PluginType: 0, PluginPath: "../plugins/net/tcp_delay_aver.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcp_full_connect", PluginType: 0, PluginPath: "../plugins/net/tcp_full_connect.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcp_segment_info", PluginType: 0, PluginPath: "../plugins/net/tcp_segment_info.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcp_win", PluginType: 0, PluginPath: "../plugins/net/tcp_win.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcpconnect", PluginType: 0, PluginPath: "../plugins/net/tcpconnect.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcpconnlat", PluginType: 0, PluginPath: "../plugins/net/tcpconnlat.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcpdrop", PluginType: 0, PluginPath: "../plugins/net/tcpdrop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcpflow", PluginType: 0, PluginPath: "../plugins/net/tcpflow.py", DocUrl: "docs/monitor/net/tcpflow/index.html", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcplife", PluginType: 0, PluginPath: "../plugins/net/tcplife.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcpretrans", PluginType: 0, PluginPath: "../plugins/net/tcpretrans.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcpsubnet", PluginType: 0, PluginPath: "../plugins/net/tcpsubnet.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcpsynbl", PluginType: 0, PluginPath: "../plugins/net/tcpsynbl.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcptop", PluginType: 0, PluginPath: "../plugins/net/tcptop.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "tcptracer", PluginType: 0, PluginPath: "../plugins/net/tcptracer.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "test_retransmit", PluginType: 0, PluginPath: "../plugins/net/test_retransmit.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
		{PluginName: "udpflow", PluginType: 0, PluginPath: "../plugins/net/udpflow.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},

		// app tracer
		{PluginName: "process_trace", PluginType: 0, PluginPath: "../plugins/traceApp/process_trace.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},

		// for test only
		{PluginName: "test", PluginType: 0, PluginPath: "../plugins/test.py", DocUrl: "", Intro: "empty", State: 0, Enable: 1},
	}
	if err := global.GVA_DB.Create(&entities).Error; err != nil { // 创建 model.ExaEbpfplugins 初始化数据
		return errors.Wrap(err, e.TableName()+"表数据初始化失败!")
	}
	return nil
}

func (e *eplugins) CheckDataExist() bool {
	if errors.Is(global.GVA_DB.Where("plugin_name = ?", "containerNet").First(&ebpfplugins.EbpfPlugins{}).Error,
		gorm.ErrRecordNotFound) { // 判断是否存在数据
		fmt.Println("no data")
		return false
	}
	fmt.Println("exa_ebpfplugins has data")
	return true
}
