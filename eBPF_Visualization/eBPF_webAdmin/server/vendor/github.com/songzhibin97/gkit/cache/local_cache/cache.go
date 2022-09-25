package local_cache

import (
	"context"
	"encoding/gob"
	"fmt"
	"github.com/songzhibin97/gkit/options"
	"io"
	"os"
	"sync"
	"time"
)

const (
	DefaultExpire time.Duration = 0
	NoExpire      time.Duration = -1
)

type Cache struct {
	*cache
}

func NewCache(options ...options.Option) Cache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Config{
		defaultExpire: 0,
		interval:      0,
		capture: func(k string, v interface{}) {
			fmt.Printf("delete k:%s v:%v\n", k, v)
		},
	}
	for _, option := range options {
		option(c)
	}
	obj := &cache{
		defaultExpire: c.defaultExpire,
		capture:       c.capture,
		cancel:        cancel,
	}
	if c.member == nil {
		c.member = map[string]Iterator{}
	}
	if c.fn == nil {
		c.fn = obj.DeleteExpire
	}
	obj.member = c.member
	obj.sentinel = NewSentinel(ctx, c.interval, c.fn)
	go obj.sentinel.Start()
	return Cache{obj}
}

type cache struct {
	sync.RWMutex

	// sentinel 维护一个周期循环的任务
	*sentinel

	// defaultExpire 默认超时时间
	defaultExpire time.Duration

	// member 维护map存储kv关系
	member map[string]Iterator

	// capture 捕获删除对象时间 会返回kv值用于用户自定义处理
	capture func(k string, v interface{})

	cancel context.CancelFunc
}

// Set 添加cache 无论是否存在都会覆盖
func (c *cache) Set(k string, v interface{}, d time.Duration) {
	var expire int64
	switch d {
	case NoExpire:
	case DefaultExpire:
		if c.defaultExpire > 0 {
			expire = time.Now().Add(c.defaultExpire).UnixNano()
		}
	default:
		if d > 0 {
			expire = time.Now().Add(d).UnixNano()
		}
		// 如果走到这里 默认是 NoExpire
	}
	c.Lock()
	c.member[k] = Iterator{
		Val:    v,
		Expire: expire,
	}
	c.Unlock()
}

// set 添加cache 无论是否存在都会覆盖 内部无锁
func (c *cache) set(k string, v interface{}, d time.Duration) {
	var expire int64
	switch d {
	case NoExpire:
	case DefaultExpire:
		if c.defaultExpire > 0 {
			expire = time.Now().Add(c.defaultExpire).UnixNano()
		}
	default:
		if d > 0 {
			expire = time.Now().Add(d).UnixNano()
		}
		// 如果走到这里 默认是 NoExpire
	}
	c.member[k] = Iterator{
		Val:    v,
		Expire: expire,
	}
}

// SetDefault 添加cache 无论是否存在都会覆盖 超时设置为创建cache的默认时间
func (c *cache) SetDefault(k string, v interface{}) {
	c.Set(k, v, DefaultExpire)
}

// SetNoExpire 添加cache 无论是否存在都会覆盖 超时设置为0
func (c *cache) SetNoExpire(k string, v interface{}) {
	c.Set(k, v, NoExpire)
}

// Get 根据key获取 cache
func (c *cache) Get(k string) (interface{}, bool) {
	c.RLock()
	if v, ok := c.member[k]; !ok {
		c.RUnlock()
		return nil, false
	} else {
		if v.Expired() {
			c.RUnlock()
			c.Delete(k)
			return nil, false
		} else {
			c.RUnlock()
			return v.Val, true
		}

	}
}

// get 根据key获取 cache
func (c *cache) get(k string) (interface{}, bool) {
	if v, ok := c.member[k]; !ok {
		return nil, false
	} else {
		if v.Expired() {
			c._delete(k)
			return nil, false
		}
		c._delete(k)
		return v.Val, true
	}
}

// GetWithExpire 根据key获取 cache 并带出超时时间
func (c *cache) GetWithExpire(k string) (interface{}, time.Time, bool) {
	c.RLock()
	if v, ok := c.member[k]; !ok {
		c.RUnlock()
		return nil, time.Time{}, false
	} else {
		if v.Expired() {
			c.RUnlock()
			c.Delete(k)
			return nil, time.Time{}, false
		}
		c.RUnlock()
		if v.Expire > 0 {
			return v.Val, time.Unix(0, v.Expire), true
		}
		return v.Val, time.Time{}, true
	}
}

// Add 添加cache 如果存在则抛出异常
func (c *cache) Add(k string, x interface{}, d time.Duration) error {
	c.Lock()
	if _, ok := c.get(k); ok {
		c.Unlock()
		return CacheExist
	}
	c.set(k, x, d)
	c.Unlock()
	return nil
}

// Replace 替换cache 如果有就设置没有就抛出异常
func (c *cache) Replace(k string, x interface{}, d time.Duration) error {
	c.Lock()
	if _, ok := c.get(k); !ok {
		c.Unlock()
		return CacheNoExist
	}
	c.set(k, x, d)
	c.Unlock()
	return nil
}

// Increment 为k对应的value增加n n必须为数字类型
func (c *cache) Increment(k string, n int64) error {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return CacheExpire
		}
		switch v.Val.(type) {
		case int:
			v.Val = v.Val.(int) + int(n)
		case int8:
			v.Val = v.Val.(int8) + int8(n)
		case int16:
			v.Val = v.Val.(int16) + int16(n)
		case int32:
			v.Val = v.Val.(int32) + int32(n)
		case int64:
			v.Val = v.Val.(int64) + n
		case uint:
			v.Val = v.Val.(uint) + uint(n)
		case uintptr:
			v.Val = v.Val.(uintptr) + uintptr(n)
		case uint8:
			v.Val = v.Val.(uint8) + uint8(n)
		case uint16:
			v.Val = v.Val.(uint16) + uint16(n)
		case uint32:
			v.Val = v.Val.(uint32) + uint32(n)
		case uint64:
			v.Val = v.Val.(uint64) + uint64(n)
		case float32:
			v.Val = v.Val.(float32) + float32(n)
		case float64:
			v.Val = v.Val.(float64) + float64(n)
		default:
			c.Unlock()
			return CacheTypeErr
		}
		c.member[k] = v
		c.Unlock()
		return nil
	}
}

// IncrementFloat 为k对应的value增加n n必须为浮点数类型
func (c *cache) IncrementFloat(k string, n float64) error {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return CacheExpire
		}
		switch v.Val.(type) {
		case float32:
			v.Val = v.Val.(float32) + float32(n)
		case float64:
			v.Val = v.Val.(float64) + n
		default:
			c.Unlock()
			return CacheTypeErr
		}
		c.member[k] = v
		c.Unlock()
		return nil
	}
}

// IncrementInt 为k对应的value增加n n必须为int类型
func (c *cache) IncrementInt(k string, n int) (int, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementInt8 为k对应的value增加n n必须为int8类型
func (c *cache) IncrementInt8(k string, n int8) (int8, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int8); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementInt16 为k对应的value增加n n必须为int16类型
func (c *cache) IncrementInt16(k string, n int16) (int16, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int16); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementInt32 为k对应的value增加n n必须为int32类型
func (c *cache) IncrementInt32(k string, n int32) (int32, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int32); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementInt64 为k对应的value增加n n必须为int64类型
func (c *cache) IncrementInt64(k string, n int64) (int64, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int64); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementUint 为k对应的value增加n n必须为uint类型
func (c *cache) IncrementUint(k string, n uint) (uint, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementUint8 为k对应的value增加n n必须为uint8类型
func (c *cache) IncrementUint8(k string, n uint8) (uint8, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint8); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementUint16 为k对应的value增加n n必须为uint16类型
func (c *cache) IncrementUint16(k string, n uint16) (uint16, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint16); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementUint32 为k对应的value增加n n必须为uint32类型
func (c *cache) IncrementUint32(k string, n uint32) (uint32, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint32); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementUint64 为k对应的value增加n n必须为uint64类型
func (c *cache) IncrementUint64(k string, n uint64) (uint64, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint64); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementUintPtr 为k对应的value增加n n必须为uintptr类型
func (c *cache) IncrementUintPtr(k string, n uintptr) (uintptr, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uintptr); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementFloat32 为k对应的value增加n n必须为float32类型
func (c *cache) IncrementFloat32(k string, n float32) (float32, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(float32); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// IncrementFloat64 为k对应的value增加n n必须为float64类型
func (c *cache) IncrementFloat64(k string, n float64) (float64, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(float64); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i + n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// Decrement 为k对应的value减少n n必须为数字类型
func (c *cache) Decrement(k string, n int64) error {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return CacheExpire
		}
		switch v.Val.(type) {
		case int:
			v.Val = v.Val.(int) - int(n)
		case int8:
			v.Val = v.Val.(int8) - int8(n)
		case int16:
			v.Val = v.Val.(int16) - int16(n)
		case int32:
			v.Val = v.Val.(int32) - int32(n)
		case int64:
			v.Val = v.Val.(int64) - n
		case uint:
			v.Val = v.Val.(uint) - uint(n)
		case uintptr:
			v.Val = v.Val.(uintptr) - uintptr(n)
		case uint8:
			v.Val = v.Val.(uint8) - uint8(n)
		case uint16:
			v.Val = v.Val.(uint16) - uint16(n)
		case uint32:
			v.Val = v.Val.(uint32) - uint32(n)
		case uint64:
			v.Val = v.Val.(uint64) - uint64(n)
		case float32:
			v.Val = v.Val.(float32) - float32(n)
		case float64:
			v.Val = v.Val.(float64) - float64(n)
		default:
			c.Unlock()
			return CacheTypeErr
		}
		c.member[k] = v
		c.Unlock()
		return nil
	}
}

// DecrementFloat 为k对应的value减少n n必须为浮点数类型
func (c *cache) DecrementFloat(k string, n float64) error {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return CacheExpire
		}
		switch v.Val.(type) {
		case float32:
			v.Val = v.Val.(float32) - float32(n)
		case float64:
			v.Val = v.Val.(float64) - n
		default:
			c.Unlock()
			return CacheTypeErr
		}
		c.member[k] = v
		c.Unlock()
		return nil
	}
}

// DecrementInt 为k对应的value减少n n必须为int类型
func (c *cache) DecrementInt(k string, n int) (int, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementInt8 为k对应的value减少n n必须为int8类型
func (c *cache) DecrementInt8(k string, n int8) (int8, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int8); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementInt16 为k对应的value减少n n必须为int16类型
func (c *cache) DecrementInt16(k string, n int16) (int16, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int16); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementInt32 为k对应的value减少n n必须为int32类型
func (c *cache) DecrementInt32(k string, n int32) (int32, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int32); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementInt64 为k对应的value减少n n必须为int64类型
func (c *cache) DecrementInt64(k string, n int64) (int64, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(int64); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementUint 为k对应的value减少n n必须为uint类型
func (c *cache) DecrementUint(k string, n uint) (uint, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementUint8 为k对应的value减少n n必须为uint8类型
func (c *cache) DecrementUint8(k string, n uint8) (uint8, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint8); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementUint16 为k对应的value减少n n必须为uint16类型
func (c *cache) DecrementUint16(k string, n uint16) (uint16, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint16); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementUint32 为k对应的value减少n n必须为uint32类型
func (c *cache) DecrementUint32(k string, n uint32) (uint32, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint32); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementUint64 为k对应的value减少n n必须为uint64类型
func (c *cache) DecrementUint64(k string, n uint64) (uint64, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uint64); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementUintPtr 为k对应的value减少n n必须为uintptr类型
func (c *cache) DecrementUintPtr(k string, n uintptr) (uintptr, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(uintptr); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementFloat32 为k对应的value减少n n必须为float32类型
func (c *cache) DecrementFloat32(k string, n float32) (float32, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(float32); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// DecrementFloat64 为k对应的value减少n n必须为float64类型
func (c *cache) DecrementFloat64(k string, n float64) (float64, error) {
	c.Lock()
	if v, ok := c.member[k]; !ok {
		c.Unlock()
		return 0, CacheNoExist
	} else {
		if v.Expired() {
			c.Unlock()
			c.Delete(k)
			return 0, CacheExpire
		}
		if i, ok := v.Val.(float64); !ok {
			c.Unlock()
			return 0, CacheTypeErr
		} else {
			ret := i - n
			v.Val = ret
			c.member[k] = v
			c.Unlock()
			return ret, nil
		}
	}
}

// Delete 删除k的cache 如果 capture != nil 会调用 capture 函数 将 kv传入
func (c *cache) Delete(k string) {
	c.Lock()
	v, ok := c.delete(k)
	c.Unlock()
	if ok {
		c.capture(k, v)
	}
}

func (c *cache) _delete(k string) {
	v, ok := c.delete(k)
	if ok {
		c.capture(k, v)
	}
}

// delete 删除k的cache 如果具有 capture != nil 则会携带v返回
func (c *cache) delete(k string) (interface{}, bool) {
	if c.capture != nil {
		if v, ok := c.member[k]; ok {
			delete(c.member, k)
			return v.Val, true
		}
	}
	delete(c.member, k)
	return nil, false
}

// DeleteExpire 删除已经过期的kv
func (c *cache) DeleteExpire() {
	var kvList []kv
	if c.capture != nil {
		kvList = make([]kv, 0, len(c.member)/4)
	}
	c.Lock()
	t := time.Now().UnixNano()
	for k, v := range c.member {
		if v.Expired(t) {
			if vv, ok := c.delete(k); ok && c.capture != nil {
				kvList = append(kvList, kv{k, vv})
			}
		}
	}
	c.Unlock()
	for _, v := range kvList {
		c.capture(v.key, v.value)
	}
}

// ChangeCapture 替换cache中capture的处理函数
func (c *cache) ChangeCapture(f func(string, interface{})) {
	c.Lock()
	c.capture = f
	c.Unlock()
}

// Save 将 c.member 写入到 w 中
func (c *cache) Save(w io.Writer) (err error) {
	enc := gob.NewEncoder(w)
	defer func() {
		if e := recover(); e != nil {
			err = CacheGobErr
		}
	}()
	c.Lock()
	defer c.Unlock()
	for _, iterator := range c.member {
		gob.Register(iterator.Val)
	}
	return enc.Encode(&c.member)
}

// SaveFile 将 c.member 保存到 path 中
func (c *cache) SaveFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.Save(f)
}

// Load 从r 中加载 c.member
func (c *cache) Load(r io.Reader) error {
	dec := gob.NewDecoder(r)
	member := map[string]Iterator{}
	if err := dec.Decode(&member); err != nil {
		return err
	} else {
		c.Lock()
		for k, iterator := range member {
			if v, ok := c.member[k]; !ok || v.Expired() {
				c.member[k] = iterator
			}
		}
		c.Unlock()
	}
	return nil
}

// LoadFile 从 path 中加载 c.member
func (c *cache) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.Load(f)
}

// Iterator 返回 cache 中所有有效的对象
func (c *cache) Iterator() map[string]Iterator {
	c.RLock()

	ret := make(map[string]Iterator, len(c.member))
	keys := make([]string, 0, 10)
	for k, v := range c.member {
		if !v.Expired() {
			ret[k] = v
		} else {
			keys = append(keys, k)
		}
	}
	c.RUnlock()
	// 清除过期key
	for _, key := range keys {
		c.Delete(key)
	}
	return ret
}

// Count 计算现在 member 中 kv的数量 (所有)
func (c *cache) Count() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.member)
}

// Flush 释放member成员
func (c *cache) Flush() {
	c.Lock()
	defer c.Unlock()
	c.member = make(map[string]Iterator)
}

func (c *cache) Shutdown() error {
	c.Flush()
	c.cancel()
	return nil
}
