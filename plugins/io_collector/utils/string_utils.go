package utils

import (
	"fmt"
	"math"
	"strconv"
)

func Format(format string, a ...interface{}) string{
	s := fmt.Sprintf(format, a...)
	return s
}

func Round(x float64) int {
	return int(math.Ceil(x-0.5))
}
func IsFloat(s string) (bool,float64) {
	float, err := strconv.ParseFloat(s, 64)
	return err == nil,float
}