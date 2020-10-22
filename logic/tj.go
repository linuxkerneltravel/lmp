package logic

import (
	"github.com/influxdata/influxdb1-client/v2"
	"go.uber.org/zap"
	"lmp/dao/influxdb"
)

func DoQueryIRQ() (res []client.Result, err error) {
	// 调用dao层influxdb API
	res, err = influxdb.QueryDB(`select "duration" from "irq" where time > now() - 7d`)
	if err != nil {
		zap.L().Error("ERROR in DoQueryIRQ():", zap.Error(err))
		return nil, err
	}
	return
}
