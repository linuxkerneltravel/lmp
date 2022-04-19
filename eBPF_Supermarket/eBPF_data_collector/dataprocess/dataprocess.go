package dataprocess

import (
	"strings"
)

type IndexStruct struct {
	TableName string
	Indexes   []string
}

func NewIndexStruct(name string) *IndexStruct {
	return &IndexStruct{
		TableName: name,
	}
}

func (i *IndexStruct) IndexProcess(indexes string) error {
	parms := strings.Fields(indexes)
	i.Indexes = make([]string, len(parms))

	copy(i.Indexes, parms)

	return nil
}
