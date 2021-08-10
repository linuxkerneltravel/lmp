package monitor

import (
	"bufio"
	config "collector/src/config/sysfs"
	"collector/src/dao"
	"collector/src/utils"
	"context"
	"encoding/csv"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//待写到配置文件中
var perfDataChan = make(chan []string)
var columns = []string{"ops", "opss", "throughput", "reads","writes","latency","latencys"}
var samplesPath = "./src/data/samples.csv"
var cmdString = "sudo filebench -f /home/szp/workloads/fileserver.f"
var dataPath = "./src/data/data.csv"

func ReadCsv()  {
	sysfs := config.NewSysfs()

	fs, err := os.Open(samplesPath)
	if err!=nil {
		log.Fatal("cant not open the file , err is %+v",err)
	}
	defer fs.Close()

	r := csv.NewReader(fs)

	var (
		index = 0
		attrs []string
	)
	for  {
		row, err := r.Read()
		if err != nil && err != io.EOF {
			log.Fatalf("can not read, err is %+v", err)
		}
		if index == 0 {
			attrs =row
			index++
			writeCsv(append(attrs,columns...),dataPath,os.O_CREATE|os.O_RDWR)
			continue
		}
		if err == io.EOF {
			break
		}
		var arg *dao.Arg
		for j , _ := range row{
			

			arg = dao.QueryArgByName(attrs[j])

			if arg == nil{
				log.Fatalf("can not query arg, err is %+v", err)
				break;
			}
			log.Println("本次参数：",arg)
			if arg.PreId != 0 {//判断前置是否设置
				preArg := dao.QueryArgById(arg.PreId)
				preCurrentVal := sysfs.Get(preArg.Path+preArg.Name)
				if(arg.PreArgVal != preCurrentVal){
					log.Printf("忽略本次参数设置！PreArgVal：%s，CurrentVal：%s\n", arg.PreArgVal, preCurrentVal)

						currentVal:=sysfs.Get(arg.Path+arg.Name)

						if("" ==currentVal ){
							row[j]=strconv.Itoa(0)
						}else {
							row[j]=currentVal
						}
					log.Println("忽略设置。row[j]：%v",row[j])
					continue
				}
			}
			//离散变量
			if arg.ValType==0 {
				_,float:=utils.IsFloat(row[j])
				dict, err :=dao.QueryByNumAndArgID(utils.Round(float),arg.Id)
				if err == nil {
					sysfs.Set(arg.Path+arg.Name, dict.Name)

					row[j]=dict.Name

					log.Printf("离散变量，字符串类型。setArg：%v；row[j]：%v",dict.Name,row[j])
				}else {
					intArg := utils.Round(float)
					sysfs.Set(arg.Path+arg.Name, intArg)
					row[j]=strconv.Itoa(intArg)

					log.Printf("离散变量，数字类型。float：%f；intArg：%d；row[j]：%v",float,intArg,row[j])
				}
			}else {
				if bool,float:=utils.IsFloat(row[j]); bool==true{
					intArg := utils.Round(float)
					sysfs.Set(arg.Path+arg.Name, intArg)
					row[j]= strconv.Itoa(intArg)
					log.Printf("连续变量，浮点类型。float：%f；intArg：%d；row[j]：%v",float,intArg,row[j])
				}else {
					sysfs.Set(arg.Path+arg.Name, row[j])
					log.Printf("连续变量，非浮点类型。row[j]：%v",row[j])
				}
			}
		}

		ctx, cancel := context.WithCancel(context.Background())

		go writeCsvData(row,dataPath)
		Command(ctx, cmdString)

		log.Println("Wait 10s ...")
		time.Sleep(10 * time.Second)
		cancel()
		log.Println("Mission Complete: "+ strconv.Itoa(index))
		index++
	}

}

func writeCsvData(attrs []string, path string)  {
	perfData := <-perfDataChan
	attrs = append(attrs,perfData...)
	writeCsv(attrs,path,os.O_CREATE|os.O_RDWR|os.O_APPEND)
}
func writeCsv(data []string, path string,flag int)  {
	file, err := os.OpenFile(path,flag , 0644)
	if err != nil {
		log.Println("open file is failed, err: ", err)
	}
	defer file.Close()
	w := csv.NewWriter(file)
	w.Write(data)
	w.Flush()
}

func read(ctx context.Context, wg *sync.WaitGroup, std io.ReadCloser) {
	reader := bufio.NewReader(std)
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			readString, err := reader.ReadString('\n')
			if err != nil || err == io.EOF {
				return
			}

			if strings.Contains(readString,"IO Summary:") {
				AnalysisData(readString)
			}


		}
	}
}
func AnalysisData(line string)  {
	//解析正则表达式，如果成功返回解释器
	reg := regexp.MustCompile("([0-9]+[.]?[0-9]+)")
	if reg == nil {
		log.Println("regexp err")
		return
	}
	//根据规则提取关键信息
	result := reg.FindAllString(line,-1)
	perfDataChan <- result
	log.Println("result1 = ", result)
}

func Command(ctx context.Context, cmd string) error {

	c := exec.CommandContext(ctx, "bash", "-c", cmd)
	stdout, err := c.StdoutPipe()
	if err != nil{
		return err
	}
	stderr, err := c.StderrPipe()
	if err != nil{
		return err
	}
	var wg sync.WaitGroup

	wg.Add(2)
	go read(ctx, &wg, stderr)
	go read(ctx, &wg, stdout)

	err = c.Start()
	wg.Wait()
	return err
}
