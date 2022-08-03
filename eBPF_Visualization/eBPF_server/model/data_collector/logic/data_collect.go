package logic

import (
	"bufio"
	"fmt"
	"io"
	"lmp/server/model/data_collector/dao"
)

/*
	TODO 1、拿到从python脚本中输出的信息
		 2、对输出的第一行（数据名|数据类型）进行提取，存放到字典中
		 3、之后的数据作为记录添加到数据库中
*/

func RediectStdout(stout io.ReadCloser, tableInfo *dao.TableInfo) error {
	scanner := bufio.NewScanner(stout)
	if scanner.Scan() {
		index := scanner.Text()
		fmt.Printf(index) //todo 仅用于测试
		if err := tableInfo.AppendTable(index); err != nil {
			return err
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf(line) //todo 仅用于测试
		if err := tableInfo.InsertRow(line); err != nil {
			return err
		}
	}
	return nil
}
