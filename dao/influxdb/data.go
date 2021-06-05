package influxdb

import (
	"fmt"

	"github.com/linuxkerneltravel/lmp/settings"

	client "github.com/influxdata/influxdb1-client/v2"
)

// Gets a specified number of data
func QueryDbByNum(dbname string, num int64) (res []client.Result, err error) {
	qs := fmt.Sprintf("SELECT * FROM %s LIMIT %d", dbname, num)
	return QueryDB(qs)
}

// Gets data for a specified time period
func QueryDbByPeriod(dbname string, num int64) (res []client.Result, err error) {
	qs := fmt.Sprintf("SELECT * FROM %s LIMIT %d", dbname, num)
	return QueryDB(qs)
}

// query
func QueryDB(cmd string) (res []client.Result, err error) {
	q := client.Query{
		Command:  cmd,
		Database: settings.Conf.InfluxdbConfig.Dbname,
	}
	if response, err := db.Query(q); err == nil {
		if response.Error() != nil {
			return res, response.Error()
		}
		res = response.Results
	} else {
		return res, err
	}
	return res, nil
}
