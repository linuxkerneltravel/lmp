package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	res := sqlite.Open("./tables/test.db")
	_, err := gorm.Open(res, &gorm.Config{})
	if err != nil {
		fmt.Println(err)
	}
}
