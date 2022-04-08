package local_cache

import "time"

// Iterator cache存储的实际成员
type Iterator struct {
	// Val 实际存储的对象
	Val interface{}

	// Expire 过期时间
	// 0 不设置过期时间
	Expire int64
}

// Expired 判断是否过期,过期返回 true
func (i Iterator) Expired(v ...int64) bool {
	if i.Expire == 0 {
		return false
	}
	if len(v) != 0 {
		return v[0] > i.Expire
	}
	return time.Now().UnixNano() > i.Expire
}

type kv struct {
	key   string
	value interface{}
}
