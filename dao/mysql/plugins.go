package mysql

import (
	"database/sql"
	"fmt"
)

type restMessage struct {
	Id          int    `db:"id"`
	Exec_path   string `db:"exec_path"`
	Instruction string `db:"instruction"`
	State       bool   `db:"state"`
}

func GetRestPluginMessageFromDB(pluginName string, pluginType string, PluginId *int, PluginExecPath *string, PluginInstruction *string, PluginState *bool) error {
	result := new(restMessage)
	sqlStr := `select id,exec_path,instruction,state from performance_index where plugin_name=? and plugin_type=?`
	err := db.Get(result, sqlStr, pluginName, pluginType)
	if err == sql.ErrNoRows {
		fmt.Println("errors in db.Get")
		return ErrorQueryFailed
	}

	if err != nil {
		fmt.Println("errors in db.Get other reason")
		return err
	}

	*PluginId = result.Id
	*PluginExecPath = result.Exec_path
	*PluginInstruction = result.Instruction
	*PluginState = result.State

	return nil
}
