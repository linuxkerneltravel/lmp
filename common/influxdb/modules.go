package influxdb

//该文件写influxdb的方法，CRUD

//使用字符串s创建一个新的measurement，
func (i *InfluxStore) CreateNewMeasurement(s string) error {
	return nil
}

//从指定的数据库中读取n条连续的数据,并生成指定的文件格式
func (i *InfluxStore) ReadFromMeasurement() error {
	return nil
}

//从指定的数据库中删除数据
func (i *InfluxStore) DelMeasurement() error {
	return nil
}

//...
