//go:build linux

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bufbuild/connect-go"
	"github.com/go-kit/log"
	"github.com/google/pprof/profile"
	"github.com/samber/lo"

	"github.com/go-kit/log/level"
	pushv1 "github.com/grafana/pyroscope/api/gen/proto/go/push/v1"
	"github.com/grafana/pyroscope/api/gen/proto/go/push/v1/pushv1connect"
	typesv1 "github.com/grafana/pyroscope/api/gen/proto/go/types/v1"
	"github.com/grafana/pyroscope/ebpf/pprof"
	"github.com/grafana/pyroscope/ebpf/sd"
	commonconfig "github.com/prometheus/common/config"
)

var server = flag.String("server", "http://localhost:4040", "")

var (
	logger log.Logger
)

func main() {

	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	// 创建画像数据发送信道
	profiles := make(chan *pushv1.PushRequest, 128)
	go ingest(profiles)
	for {
		time.Sleep(5 * time.Second)

		// 收集画像数据传送给数据信道
		collectProfiles(profiles)
	}
}

type CollectProfilesCallback func(target *sd.Target, stack []string, value uint64, s scale, aggregated bool)

// 收集数据并传给信道
func collectProfiles(profiles chan *pushv1.PushRequest) {
	// 创建进程数据构建器群
	builders := pprof.NewProfileBuilders(1)
	// 设定数据提取函数
	err := CollectProfiles(func(target *sd.Target, stack []string, value uint64, s scale, aggregated bool) {
		// 获取进程哈希值和进程标签组
		labelsHash, labels := target.Labels()
		builder := builders.BuilderForTarget(labelsHash, labels)
		p := builder.Profile
		p.SampleType = []*profile.ValueType{{Type: s.Type, Unit: s.Unit}}
		p.Period = s.Period
		p.PeriodType = &profile.ValueType{Type: s.Type, Unit: s.Unit}
		// 若eBPF中对数据已经进行了累计
		if aggregated {
			builder.CreateSample(stack, value)
		} else {
			// 否则，在用户态进行累计
			builder.CreateSampleOrAddValue(stack, value)
		}
	})

	if err != nil {
		panic(err)
	}
	level.Debug(logger).Log("msg", "ebpf collectProfiles done", "profiles", len(builders.Builders))

	for _, builder := range builders.Builders {
		// 将进程标签组转换为标准类型组
		protoLabels := make([]*typesv1.LabelPair, 0, builder.Labels.Len())
		for _, label := range builder.Labels {
			protoLabels = append(protoLabels, &typesv1.LabelPair{
				Name: label.Name, Value: label.Value,
			})
		}

		// 向缓存中写入样本数据
		buf := bytes.NewBuffer(nil)
		_, err := builder.Write(buf)
		if err != nil {
			panic(err)
		}

		// 创建一个push请求
		req := &pushv1.PushRequest{Series: []*pushv1.RawProfileSeries{{
			Labels: protoLabels,
			Samples: []*pushv1.RawSample{{
				RawProfile: buf.Bytes(),
			}},
		}}}
		select {
		// 传给信道
		case profiles <- req:
		// 传送失败则记录
		default:
			_ = level.Error(logger).Log("err", "dropping profile", "target", builder.Labels.String())
		}

	}

	if err != nil {
		panic(err)
	}
}

// 接收信道数据并发送
func ingest(profiles chan *pushv1.PushRequest) {
	httpClient, err := commonconfig.NewClientFromConfig(commonconfig.DefaultHTTPClientConfig, "http_playground")
	if err != nil {
		panic(err)
	}
	client := pushv1connect.NewPusherServiceClient(httpClient, *server)

	for {
		it := <-profiles
		res, err := client.Push(context.TODO(), connect.NewRequest(it))
		if err != nil {
			fmt.Println(err)
		}
		if res != nil {
			fmt.Println(res)
		}
	}

}

type psid struct {
	pid  uint32
	usid int32
	ksid int32
}

type scale struct {
	Type   string
	Unit   string
	Period int64
}

func CollectProfiles(cb CollectProfilesCallback) error {
	var s scale
	if _, err := fmt.Scanf("Type:%s Unit:%s Period:%d", &s.Type, &s.Unit, &s.Period); err != nil {
		return err
	}
	var buf string
	if _, err := fmt.Scanf("time:%s\n", &buf); err != nil {
		return err
	}
	filename := buf
	counts := make(map[psid]uint32)
	if _, err := fmt.Scanf("counts:\n"); err != nil {
		return err
	}
	if _, err := fmt.Scanf("pid\tusid\tksid\t%s\n", &buf); err != nil {
		return err
	}
	filename += buf
	for {
		var k psid
		var v float32
		if _, err := fmt.Scanf("%d\t%d\t%d\t%f\n", &k.pid, &k.usid, &k.ksid, &v); err != nil {
			break
		}
		counts[k] = uint32(v)
	}
	traces := make(map[int32][]string)
	fmt.Scanln(&buf)
	if _, err := fmt.Scanf("sid\ttrace\n"); err != nil {
		fmt.Printf("scan err at trace \"%s\"\n", buf)
		return err
	}
	for {
		var k int32
		if _, err := fmt.Scanf("%d\t", &k); err != nil {
			break
		}
		if _, err := fmt.Scanf("%s\n", &buf); err != nil {
			break
		}
		traces[k] = strings.Split(buf, ";")
	}
	groups := make(map[int32]int32)
	fmt.Scanln(&buf)
	if _, err := fmt.Scanf("pid\ttgid\n"); err != nil {
		fmt.Printf("scan err at group \"%s\"\n", buf)
		return err
	}
	for {
		var k, v int32
		if _, err := fmt.Scanf("%d\t%d\n", &k, &v); err != nil {
			break
		}
		groups[k] = v
	}
	comms := make(map[int32]string)
	fmt.Scanln(&buf)
	if _, err := fmt.Scanf("pid\tcommand\n"); err != nil {
		fmt.Printf("scan err at command \"%s\"\n", buf)
		return err
	}
	for {
		var k int32
		var comm string
		if _, err := fmt.Scanf("%d\t%s\n", &k, &comm); err != nil {
			break
		}
		comms[k] = comm
	}
	fmt.Scanln(&buf)
	for k, v := range counts {
		target := sd.NewTarget("", k.pid, sd.DiscoveryTarget{
			"__process_pid__": fmt.Sprintf("%d", k.pid),
			"__meta_process_cwd": func() string {
				if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", k.pid)); err != nil {
					return ""
				} else {
					return cwd
				}
			}(),
			"__meta_process_exe": func() string {
				if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", k.pid)); err != nil {
					return ""
				} else {
					return exe
				}
			}(),
			"__meta_process_comm": comms[int32(k.pid)],
			"__meta_process_cgroup": func() string {
				if cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", k.pid)); err != nil {
					return ""
				} else {
					return string(cgroup)
				}
			}(),
		})
		base := []string{fmt.Sprint(groups[int32(k.pid)]), fmt.Sprint(k.pid), fmt.Sprint(comms[int32(k.pid)])}
		trace := append(traces[k.usid], traces[k.ksid]...)
		cb(target, lo.Reverse(append(base, trace...)), uint64(v), s, true)
	}
	return nil
}
