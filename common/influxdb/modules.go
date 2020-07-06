package influxdb

import (
	// "fmt"
	"time"

	"github.com/cihub/seelog"
	client "github.com/influxdata/influxdb/client/v2"
)

//该文件写influxdb的方法，CRUD

//使用字符串s创建一个新的measurement，
func (i *InfluxStore) CreateNewMeasurement(s string, bp client.BatchPoints, conn client.Client) error {
	tags := map[string]string{}
	fields := map[string]interface{}{}

	measurement := s + time.Now().Format("-20060102-1504")
	pt, err := client.NewPoint(measurement, tags, fields, time.Now())
	if err != nil {
		seelog.Error("create newpoint failed!")
	}
	//fmt.Println("create newpoint")
	bp.AddPoint(pt)
	//把行格式给到数据库
	if err := conn.Write(bp); err != nil {
		seelog.Error("write newpoint to database failed")
	}
	//fmt.Println("write newpoint to database")
	return nil
}

//从指定的数据库中读取n条连续的数据,并生成指定的文件格式
func (i *InfluxStore) ReadFromMeasurement(bp client.BatchPoints) error {
	return nil
}

//从指定的数据库中删除数据
func (i *InfluxStore) DelMeasurement(bp client.BatchPoints) error {
	return nil
}

//...
