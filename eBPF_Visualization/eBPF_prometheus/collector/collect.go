package collector

import (
	"example.com/m/v2/connect_sql"
	"github.com/prometheus/client_golang/prometheus"
	"log"
)

type ClusterManager struct {
	Zone        string
	VfsstatDesc *prometheus.Desc
}

func (c *ClusterManager) GetDataFromSqlite() (
	resultlist []map[string]int64,
	error error,
) {
	var vfsstatdata = map[string]int64{}
	var results = []map[string]int64{}
	if err := connect_sql.SqlConnect("/home/yuemeng/lmp/eBPF_Visualization/eBPF_server/model/data_collector/dao/tables/ebpfplugin.db"); err != nil {
		log.Println("连接数据库失败")
	}
	rows, err := connect_sql.GLOBALDB.Table("vfsstat").Rows()
	if err != nil {
		log.Println("读取数据库出错")
		return nil, err
	}
	for rows.Next() {
		result := map[string]interface{}{}
		if err := connect_sql.GLOBALDB.ScanRows(rows, &result); err != nil {
			log.Println("扫描数据库失败")
			return results, err
		}
		for name, data := range result {
			if name == "TIME" {
				continue
			} else {
				log.Println(name, data)
				vfsstatdata[name] = data.(int64)
			}
		}
		results = append(results, vfsstatdata)
	}
	return results, err
}

func (c *ClusterManager) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.VfsstatDesc
}

func (c *ClusterManager) Collect(ch chan<- prometheus.Metric) {
	vfsstatDatalist, _ := c.GetDataFromSqlite()
	for _, vfsstatData := range vfsstatDatalist {
		for name, data := range vfsstatData {
			ch <- prometheus.MustNewConstMetric(
				c.VfsstatDesc,
				prometheus.GaugeValue,
				float64(data),
				name,
			)
		}
	}
}

func NewClusterManger(zone string) *ClusterManager {
	return &ClusterManager{
		Zone: "vfsstat",
		VfsstatDesc: prometheus.NewDesc(
			"vfsstat_data",
			"test",
			[]string{"name"},
			prometheus.Labels{"zone": zone},
		),
	}
}
