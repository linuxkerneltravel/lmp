//
// Created by ChenYu Zhao on
// Modidied by Qiangzhixing Cheng
//
package influxdb

//该文件写数据库中数据要转成的格式

import "time"

//读出数据库的每一行数据解析成这个Message格式
type Message struct {
	TimeLocal                    time.Time
	BytesSent                    int
	Path, Method, Scheme, Status string
	UpstreamTime, RequestTime    float64
}
