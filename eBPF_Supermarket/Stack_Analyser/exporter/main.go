//go:build linux

// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: luiyanbing@foxmail.com
//
// 将采集数据发送到pyroscope服务器的发送程序，由标准输入获取数据

package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
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
	"github.com/prometheus/prometheus/model/labels"
)

var server = flag.String("server", "http://localhost:4040", "")

var (
	logger log.Logger
	// bufio reader 会先将数据存入缓存，再由readX接口读取数据，若定义为局部变量就会丢失数据
	reader bufio.Reader
)

func main() {
	flag.Parse()
	reader = *bufio.NewReader(os.Stdin)
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
		p.PeriodType = &profile.ValueType{Type: "", Unit: ""}
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

type task_info struct {
	pid  uint32
	comm string
	tgid uint32
	cid  string
}

func CollectProfiles(cb CollectProfilesCallback) error {
	var err error
	var line string
	// read time
	for {
		if line, err = reader.ReadString('\n'); err != nil {
			return err
		}
		if len(line) > 12 && line[:12] == "\033[1;35mtime:" {
			break
		}
	}
	// omit title and head of counts table
	for range lo.Range(2) {
		if line, err = reader.ReadString('\n'); err != nil {
			return err
		}
	}
	// read scale
	scales := make([]scale, 0)
	if scales_str := strings.Split(line, "\t"); len(scales_str) > 3 {
		for i, scale_str := range strings.Split(line, "\t")[3:] {
			parts := regexp.MustCompile(`([_a-zA-Z0-9]+)/([0-9]+)([a-zA-Z]+)`).FindStringSubmatch(scale_str)
			scales = append(scales, scale{
				Type: parts[1],
				Unit: parts[3],
			})
			if scales[i].Period, err = strconv.ParseInt(parts[2], 10, 64); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("no scale")
	}
	// read counts table
	counts := make(map[psid][]uint64)
	for {
		var k psid
		if line, err = reader.ReadString('\n'); err != nil {
			return err
		}
		line = strings.TrimSuffix(line, "\n")
		if _, err = fmt.Sscanf(line, "%d\t%d\t%d\t", &k.pid, &k.usid, &k.ksid); err != nil {
			// has read traces title
			break
		}
		if vals_str := strings.Split(line, "\t")[3:]; len(vals_str) == len(scales) {
			vals := make([]uint64, len(vals_str))
			for i, val_str := range vals_str {
				if vals[i], err = strconv.ParseUint(val_str, 10, 64); err != nil {
					return err
				}
			}
			counts[k] = vals
		} else {
			return fmt.Errorf("scales not match vals")
		}
	}
	// omit traces table head
	if line, err = reader.ReadString('\n'); err != nil {
		return err
	}
	traces := make(map[int32][]string)
	for {
		var k int32
		var v string
		if line, err = reader.ReadString('\n'); err != nil {
			return err
		}
		if _, err = fmt.Sscanf(line, "%d\t%s\n", &k, &v); err != nil {
			// has read info title
			break
		}
		trace := strings.Split(v, ";")
		trace = trace[:len(trace)-1]
		traces[k] = trace
	}
	// omit info table head
	if line, err = reader.ReadString('\n'); err != nil {
		return err
	}
	info := make(map[uint32]task_info)
	for {
		var pid, tgid, nspid int
		if line, err = reader.ReadString('\n'); err != nil {
			break
		}
		secs := strings.Split(line, "\t")
		if len(secs) < 5 {
			break
		}
		if pid, err = strconv.Atoi(secs[0]); err != nil {
			// has read end
			break
		}
		if nspid, err = strconv.Atoi(secs[1]); err != nil {
			break
		}
		if tgid, err = strconv.Atoi(secs[3]); err != nil {
			break
		}
		info[uint32(pid)] = task_info{
			pid:  uint32(nspid),
			comm: secs[2],
			tgid: uint32(tgid),
			cid:  secs[4],
		}
	}
	for k, v := range counts {
		base := []string{info[k.pid].cid, "tgid:" + fmt.Sprint(info[k.pid].tgid), "comm:" + info[k.pid].comm + ", pid:" + fmt.Sprint(info[k.pid].pid)}
		trace := append(traces[k.usid], traces[k.ksid]...)
		group_trace := lo.Reverse(append(base, trace...))
		for i, s := range scales {
			target := sd.NewTarget("", k.pid, sd.DiscoveryTarget{
				"__container_id__": info[k.pid].cid,
				"service_name": "Stack_Analyzer",
				labels.MetricName:  s.Type,
			})
			cb(target, group_trace, v[i], s, true)
		}
	}
	return nil
}
